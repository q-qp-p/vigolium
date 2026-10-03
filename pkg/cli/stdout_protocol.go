package cli

import (
	"context"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// Who owns stdout.
//
// A scan command can be asked to write up to four different things there, and
// three of them are streams with no framing of their own:
//
//   - `--events ndjson`, one event object per line, for the whole run;
//   - `--format jsonl` with no -o, the bulk export streamed to stdout;
//   - `--ci-output-format`, one finding object per line;
//   - `--print-finding` / `--print-traffic` / `--print-traffic-tree`, Markdown.
//
// Any two of those interleave into a stream that is not what either contract
// describes: a consumer reading NDJSON events hits a Markdown heading, or two
// different object shapes on alternate lines with no `type` to tell them apart.
// Nothing detected the combination, so the corruption was silent and the exit
// code was 0.
//
// --events is the one that owns the stream, because it is the only one that
// writes DURING the run and therefore cannot be relocated after the fact: the
// others all have an -o or a file destination. So the rule is one-way: asking
// for --events alongside another stdout writer is a usage error (exit 2) naming
// the conflict and the fix, rather than a corrupt stream.

// validateStdoutProtocol rejects a flag set in which --events would share stdout
// with another writer. It is a no-op when --events was not asked for.
func validateStdoutProtocol(opts *types.Options) error {
	if opts == nil || strings.TrimSpace(opts.Events) == "" {
		return nil
	}
	const fix = "Add -o <file> or drop --events"
	switch {
	case opts.CIOutput:
		return usageErrorf("--events owns stdout; --ci-output-format writes one finding per line there too. %s", fix)
	// jsonl WITH -o goes to the file, so only the stdout case conflicts. This
	// also covers --json on the scan path, which reconcileOutputFormats maps to
	// jsonl.
	case opts.HasFormat("jsonl") && strings.TrimSpace(opts.Output) == "":
		return usageErrorf("--events owns stdout; --format jsonl without -o would also write there. %s", fix)
	case scanPrintFinding:
		return usageErrorf("--events owns stdout; --print-finding writes Markdown there too. %s", fix)
	case scanPrintTraffic:
		return usageErrorf("--events owns stdout; --print-traffic writes Markdown there too. %s", fix)
	case scanPrintTrafficTree:
		return usageErrorf("--events owns stdout; --print-traffic-tree writes a tree there too. %s", fix)
	}
	return nil
}

// scanInput is one parsed request the lightweight commands were asked to scan,
// carried with the target and method its result reports. Built up front so the
// aggregation below can count what it did not get to.
type scanInput struct {
	rr     *httpmsg.HttpRequestResponse
	target string
	method string
}

// scanInputs runs fn over each input, stopping as soon as ctx is cancelled.
//
// It returns the results it collected, the targets it never dispatched, and the
// last error. The not-scanned list is the point: a Ctrl-C partway through
// `scan-url -t a -t b -t c` used to leave the caller with results for `a` and
// no statement at all about `b` and `c`, which reads identically to a run that
// scanned all three and found nothing on two of them.
//
// fn is a parameter so the cancellation behaviour is testable without a network.
func scanInputs(
	ctx context.Context,
	inputs []scanInput,
	fn func(context.Context, scanInput) (*scanResult, error),
) (results []*scanResult, notScanned []string, err error) {
	for i, in := range inputs {
		if ctx.Err() != nil {
			for _, rest := range inputs[i:] {
				notScanned = append(notScanned, rest.target)
			}
			return results, notScanned, err
		}
		res, scanErr := fn(ctx, in)
		if scanErr != nil {
			err = scanErr
		}
		if res != nil {
			results = append(results, res)
		}
	}
	return results, notScanned, err
}

// writeDirectScanBatch publishes several direct-path results as ONE -j document.
//
// Each result used to be encoded separately, so `scan-url -j -t a -t b` wrote
// two top-level objects to stdout — a stream that `json.Unmarshal` rejects and
// that the documented "exactly one document per invocation" contract does not
// allow. They now travel as the `items` array of the standard envelope, with
// `targets_not_scanned` naming anything an interrupt cut off.
func writeDirectScanBatch(command string, results []*scanResult, notScanned []string) error {
	items := make([]any, 0, len(results))
	for _, r := range results {
		items = append(items, r)
	}
	// Always an array, never null: a consumer that reads this field to decide
	// whether to re-run the remainder should not have to special-case a nil.
	if notScanned == nil {
		notScanned = []string{}
	}
	env := newAgentEnvelope(command, "", items, int64(len(results)), 0, len(results)).
		With("targets_not_scanned", notScanned)
	return writeAgentJSON(env)
}
