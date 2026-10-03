package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// scan-request flags
var (
	scanReqInput  string
	scanReqTarget string
)

var scanRequestCmd = &cobra.Command{
	Use:   "scan-request",
	Short: "Scan a raw HTTP request for vulnerabilities",
	Long: `Read a raw HTTP request from file or stdin and run scanner modules against it.
Designed for pipeline integration and AI agent workflows.
Accepts raw HTTP requests, curl commands, and supports format auto-detection.`,
	Args: cobra.NoArgs,
	RunE: runScanRequestCmd,
}

func init() {
	rootCmd.AddCommand(scanRequestCmd)
	flags := scanRequestCmd.Flags()

	flags.StringVarP(&scanReqInput, "input", "i", "-", "Input file or - for stdin")
	flags.StringVarP(&scanReqTarget, "target", "t", "", "Override target URL (scheme://host)")
	flags.BoolVar(&scanURLNoPassive, "no-passive", false, "Skip passive modules")
	registerScanModuleFlags(flags)
	registerModuleSelectionFlags(flags)
	registerHTTPClientFlags(flags)
	registerPhaseFlags(flags)
	registerLightweightScanIOFlags(flags)
}

func runScanRequestCmd(_ *cobra.Command, _ []string) error {
	defer syncLogger()

	if err := resetFailOnGate(); err != nil {
		return err
	}
	if err := validateModuleSelectionFlags(scanURLNoPassive); err != nil {
		return err
	}
	// Validate --format before any network activity so an unknown format (or
	// fs/sqlite) fails fast instead of being silently ignored on the direct path.
	if err := validateGlobalFormats(); err != nil {
		return err
	}
	if err := validateEventsFlag(scanOpts.Events); err != nil {
		return asUsageError(err)
	}
	// Validated here, not only in runRunnerScan: without -S/-o this command takes
	// the direct in-memory path, which never reaches the Runner — so a check
	// there alone let `scan-url --keep-db-on-error` exit 0 having done nothing
	// with the flag, which is the shape of control this plan exists to remove.
	if err := validateKeepDBOnError(globalStateless); err != nil {
		return err
	}

	// Read raw HTTP request
	var raw []byte
	var err error

	if scanReqInput == "-" {
		raw, err = readStdin()
	} else {
		// Bounded like the stdin branch rather than an unbounded os.ReadFile:
		// -i accepts a FIFO or /dev/stdin just as readily as a regular file, and
		// those have neither a size nor an end a plain ReadFile can rely on.
		// No deadline — a named file is not a producer that can stall, and
		// --input-read-timeout is documented as the stdin dial.
		var f *os.File
		if f, err = os.Open(scanReqInput); err == nil {
			defer func() { _ = f.Close() }()
			raw, err = clicommon.ReadBounded(f, scanReqInput, clicommon.DefaultStdinLimit, 0)
		}
	}
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	rawStr := string(raw)
	if strings.TrimSpace(rawStr) == "" {
		return fmt.Errorf("empty request input")
	}

	// Detect format and parse request. Detection runs on the fully trimmed text
	// — surrounding whitespace says nothing about whether this is curl or raw
	// HTTP — but the raw parser gets the byte-preserving normalization instead,
	// because for a request with a body those bytes ARE the request.
	var rr *httpmsg.HttpRequestResponse
	trimmed := strings.TrimSpace(rawStr)
	detected := detect.DetectStdinFormat(trimmed)
	if detected == detect.FormatCurl {
		// Curl command detected — parse via curl parser
		items, parseErr := detect.ParseStdinContent(trimmed, detect.FormatCurl)
		if parseErr != nil {
			return fmt.Errorf("failed to parse curl command: %w", parseErr)
		}
		rr = items[0]
	} else {
		// Raw HTTP (or fallback) — use existing raw HTTP parser
		normalized := normalizeRawRequestInput(rawStr)
		if scanReqTarget != "" {
			rr, err = httpmsg.ParseRawRequestWithURL(normalized, scanReqTarget)
		} else {
			rr, err = httpmsg.ParseRawRequest(normalized)
		}
		if err != nil {
			return fmt.Errorf("failed to parse raw request: %w", err)
		}
		if scanReqTarget == "" {
			// No -t override: the request line carries no scheme, so the scheme
			// was inferred. Surface how it was resolved (and how to override with
			// -t) so an http service on a non-standard port isn't silently hit
			// over https.
			warnInferredRequestScheme(normalized, rr)
		}
	}

	// Extract method and target for output
	method := rr.Request().Method()
	target := rr.Target()

	// One cancellation context for the invocation — scan-request scans exactly one
	// request, but the handler lives in the direct path shared with scan-url, and
	// installing the signal trap per request is what leaked a goroutine there.
	ctx, stop := lightweightScanContext()
	defer stop()

	// Route through the Runner when output/persistence/phase flags are in play;
	// otherwise take the fast in-memory direct path.
	return withFailOnGate(dispatchSingleScan(ctx, rr, target, method))
}

// normalizeRawRequestInput prepares a raw HTTP request for the parser while
// preserving the bytes that are part of the message.
//
// Leading whitespace is always stripped: a blank first line would be read as
// the request line, and nothing legitimate precedes the method. Trailing
// whitespace is a different matter. `scan-request` used to hand the parser
// strings.TrimSpace(input), which silently rewrote the body of every request
// whose payload ends in whitespace — a trailing newline in a JSON body, the
// CRLF a chunked encoder emits, a form field whose value ends with a space. The
// request that then went on the wire was not the request the operator pasted,
// and with Content-Length still declaring the original length the server saw a
// truncated body.
//
// So trailing whitespace is only trimmed when the headers say there is no body
// to damage: no Content-Length and no Transfer-Encoding. That keeps the old
// forgiving behavior for the common bodyless GET pasted out of a terminal, and
// stops guessing the moment the request declares a body.
func normalizeRawRequestInput(raw string) string {
	raw = strings.TrimLeft(raw, " \t\r\n")
	if rawRequestDeclaresBody(raw) {
		return raw
	}
	return strings.TrimRight(raw, " \t\r\n")
}

// rawRequestDeclaresBody reports whether the header block of raw carries a
// Content-Length or Transfer-Encoding header. Only the header block is scanned
// — a body containing the literal text "Content-Length:" must not make the
// whole message look body-bearing — and the match is case-insensitive at the
// start of a line, as HTTP field names are.
func rawRequestDeclaresBody(raw string) bool {
	head := raw
	if i := strings.Index(head, "\r\n\r\n"); i >= 0 {
		head = head[:i]
	} else if i := strings.Index(head, "\n\n"); i >= 0 {
		head = head[:i]
	}
	for _, line := range strings.Split(head, "\n") {
		name := strings.TrimSpace(strings.ToLower(line))
		if strings.HasPrefix(name, "content-length:") || strings.HasPrefix(name, "transfer-encoding:") {
			return true
		}
	}
	return false
}

// warnInferredRequestScheme emits a heads-up when the scheme of a raw request had
// to be inferred (no scheme on the request line, no -t override) and the Host
// port is non-standard, so the choice is genuinely ambiguous. It names the
// resolved target, the signal used (a same-origin Origin/Referer header or the
// https default), and the -t flag to pin it explicitly. A well-known port
// (80/443) unambiguously fixes the scheme, so nothing is printed there.
func warnInferredRequestScheme(raw string, rr *httpmsg.HttpRequestResponse) {
	if rr == nil {
		return
	}
	svc := rr.Service()
	if svc == nil {
		return
	}
	// An absolute-form request line already carries the scheme — no inference.
	if requestLineHasScheme(raw) {
		return
	}
	port := svc.Port()
	if port == 80 || port == 443 {
		return
	}
	host := svc.Host()
	authority := fmt.Sprintf("%s:%d", host, port)
	target := rr.Target()
	if s, header, ok := httpmsg.OriginRefererScheme(raw, host, port); ok {
		fmt.Fprintf(os.Stderr, "%s request line has no scheme — inferred %s from the %s header; sending to %s\n",
			terminal.WarnPrefix(), terminal.BoldYellow(s+"://"), header, terminal.Cyan(target))
		fmt.Fprintf(os.Stderr, "  pass %s to pin the scheme (use %s to force TLS)\n",
			terminal.BoldCyan("-t "+s+"://"+authority), terminal.Cyan("https://"))
		return
	}
	fmt.Fprintf(os.Stderr, "%s request line has no scheme and no Origin/Referer to infer from — defaulting to %s; sending to %s\n",
		terminal.WarnPrefix(), terminal.BoldYellow("https://"), terminal.Cyan(target))
	fmt.Fprintf(os.Stderr, "  if the target is plain http, pass %s\n",
		terminal.BoldCyan("-t http://"+authority))
}

// requestLineHasScheme reports whether the request line uses absolute-form (an
// explicit http(s):// on the request target), in which case the scheme is
// already pinned and needs no inference.
func requestLineHasScheme(raw string) bool {
	line := raw
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	target := strings.ToLower(fields[1])
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
}
