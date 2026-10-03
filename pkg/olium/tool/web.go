package tool

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	urlpkg "net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// ---------- web_fetch ----------
//
// Dual-mode:
//   - Default: plain HTTP(S) GET/POST via net/http. Fast, no browser.
//   - mode="browser": drives Chromium via spitolas (CDP) for JS-rendered
//     pages, SPAs, login-gated content. Spawns a fresh headless browser,
//     navigates, optionally waits for a selector, then returns the
//     post-render DOM. When the tool is wired with a capture sink, every
//     XHR/fetch the page issues during render is persisted as an
//     http_record (source="web-fetch-browser") so query_records sees the
//     real network surface, not just the document.
//
// The tool keeps a single schema so the model doesn't have to choose two
// different tools — it decides per-call via the `mode` parameter.

type webFetchTool struct {
	client *http.Client

	// captureSink + captureProject, when both set, persist every successful
	// fetch (HTTP and browser modes) as an http_record under source=
	// "web-fetch" / "web-fetch-browser". Lets query_records / inspect_record /
	// replay_request immediately act on whatever the agent just fetched
	// without a separate ingest step. Nil sink disables capture.
	captureSink    spitolas.CaptureSink
	captureProject string

	// probe renders browser mode; nil means spitolas.ProbeURL. Overridable so
	// tests don't spawn real browsers.
	probe func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error)

	// readOnly restricts the tool to safe methods (GET/HEAD) in http mode and
	// refuses browser mode, which executes page script with side effects the
	// tool cannot bound. Only this variant may claim IsReadOnly.
	readOnly bool
}

// NewWebFetch returns the no-capture variant. Used by TUI chat, tests, and
// other callers that don't have a database wired. It still accepts mutating
// methods and browser mode, so it is not read-only — see NewWebFetchReadOnly.
func NewWebFetch() Tool {
	return &webFetchTool{client: &http.Client{Timeout: 30 * time.Second}}
}

// NewWebFetchReadOnly returns the genuinely read-only variant: GET/HEAD over
// plain HTTP, no browser mode, no capture. Anything else is refused with an
// error result naming the restriction. Registered by RegisterReadOnlyBuiltins
// so strictly read-only contexts cannot issue state-changing requests.
func NewWebFetchReadOnly() Tool {
	return &webFetchTool{client: &http.Client{Timeout: 30 * time.Second}, readOnly: true}
}

// NewWebFetchWithCapture wires a CaptureSink so every successful fetch is
// persisted to the project DB. Records appear in query_records under
// source="web-fetch" (HTTP mode) or "web-fetch-browser" (rendered HTML).
// Pass nil sink or empty projectUUID to fall back to the no-capture variant.
func NewWebFetchWithCapture(sink spitolas.CaptureSink, projectUUID string) Tool {
	if sink == nil || projectUUID == "" {
		return NewWebFetch()
	}
	return &webFetchTool{
		client:         &http.Client{Timeout: 30 * time.Second},
		captureSink:    sink,
		captureProject: projectUUID,
	}
}

func (*webFetchTool) Name() string     { return "web_fetch" }
func (*webFetchTool) Label() string    { return "Fetch URL" }
func (*webFetchTool) Category() string { return CategoryBuiltin }

// IsReadOnly gates whether the engine may fan this tool out concurrently with
// other read-only calls, and the contract is "no observable side effects"
// (tool.go). The general tool accepts state-changing methods and browser mode
// (page script runs), and the capture variant also writes http_records, so it
// is never read-only — whether a database happens to be wired does not change
// what a request can do to the target. Only NewWebFetchReadOnly qualifies.
func (w *webFetchTool) IsReadOnly() bool { return w.readOnly }
func (w *webFetchTool) Description() string {
	if w.readOnly {
		return "Fetch a URL with a read-only HTTP request (GET or HEAD only; no browser mode, nothing persisted). Returns the raw response."
	}
	return "Fetch a URL. Default mode is plain HTTP (fast, returns raw response, one record persisted). Set mode='browser' to render via headless Chromium (handles JS SPAs, client-side routing) — every XHR/fetch the page issues during render is also captured, so a single browser fetch typically produces many http_records. Use browser mode when the initial HTTP response is empty or missing content that clearly depends on JavaScript. HTTP-mode returns Details.record_uuid; browser-mode persists multiple records — call query_records with the target hostname to enumerate them."
}
func (w *webFetchTool) Schema() map[string]any {
	modes := []string{"http", "browser"}
	modeDesc := "'http' = raw HTTP request (fast, one record); 'browser' = render with headless Chromium via CDP (also captures every XHR/fetch issued during render)."
	method := map[string]any{"type": "string", "default": "GET", "description": "HTTP method (http mode only)."}
	if w.readOnly {
		modes = []string{"http"}
		modeDesc = "'http' only — this variant is read-only."
		method["enum"] = readOnlyMethods
		method["description"] = "HTTP method: GET or HEAD only (read-only variant)."
	}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{"type": "string", "description": "HTTP or HTTPS URL."},
			"mode": map[string]any{
				"type":        "string",
				"enum":        modes,
				"description": modeDesc,
				"default":     "http",
			},
			"method":  method,
			"headers": map[string]any{"type": "object", "description": "Extra request headers (http mode only)."},
			"body":    map[string]any{"type": "string", "description": "Request body (http mode only)."},
			"max_bytes": map[string]any{
				"type":        "integer",
				"description": "Truncate response body after N bytes. Default 512000.",
				"default":     512000,
			},
			"wait_selector": map[string]any{
				"type":        "string",
				"description": "(browser mode) CSS selector to wait for before grabbing HTML.",
			},
			"wait_ms": map[string]any{
				"type":        "integer",
				"description": "(browser mode) Extra ms to wait after load. Default 1500.",
				"default":     1500,
			},
		},
		"required": []string{"url"},
	}
}

func (w *webFetchTool) Execute(ctx context.Context, args map[string]any, onUpdate UpdateFn) (Result, error) {
	url, _ := args["url"].(string)
	if url == "" {
		return Result{
			Content: "web_fetch: 'url' is required - an absolute http(s) URL to request, e.g. {\"url\": \"https://host/path\"}. " +
				"To search traffic vigolium has already captured use query_records; for findings use list_findings.",
			IsError: true,
		}, nil
	}
	mode, _ := args["mode"].(string)
	if mode == "" {
		mode = "http"
	}
	if w.readOnly {
		if msg := readOnlyViolation(mode, args); msg != "" {
			return Result{Content: msg, IsError: true}, nil
		}
	}

	switch mode {
	case "browser":
		return w.executeBrowser(ctx, url, args)
	case "http":
		return w.executeHTTP(ctx, url, args)
	default:
		// Falling through to plain HTTP for an unrecognized mode is worse
		// than an error: the model asked for a rendered page, got the raw
		// document with no warning, and concludes the page has no
		// JS-rendered content.
		return Result{
			Content: fmt.Sprintf("web_fetch: unknown mode %q - use 'http' (raw request) or 'browser' (render with headless Chromium).", mode),
			IsError: true,
		}, nil
	}
}

// readOnlyMethods are the only methods the read-only variant sends: safe by
// HTTP semantics, so a fan-out of them cannot change target state.
var readOnlyMethods = []string{"GET", "HEAD"}

// readOnlyViolation names why a call cannot run on the read-only variant, or
// returns "" when it can.
func readOnlyViolation(mode string, args map[string]any) string {
	if mode == "browser" {
		return "web_fetch (read-only): mode='browser' is not available here — rendering runs page script, which can change application state. Use a plain GET."
	}
	method, _ := args["method"].(string)
	if method == "" {
		return ""
	}
	if !slices.Contains(readOnlyMethods, strings.ToUpper(method)) {
		return fmt.Sprintf("web_fetch (read-only): method %q is not allowed — only GET and HEAD can be sent from this context.", method)
	}
	return ""
}

func (w *webFetchTool) executeHTTP(ctx context.Context, url string, args map[string]any) (Result, error) {
	method, _ := args["method"].(string)
	if method == "" {
		method = "GET"
	}
	method = strings.ToUpper(method)

	var bodyReader io.Reader
	if bodyStr, ok := args["body"].(string); ok && bodyStr != "" {
		bodyReader = strings.NewReader(bodyStr)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return Result{Content: fmt.Sprintf("bad request: %v", err), IsError: true}, nil
	}
	req.Header.Set("User-Agent", "olium/0.1 (+https://vigolium.com)")
	if headers, ok := args["headers"].(map[string]any); ok {
		for k, v := range headers {
			if vs, ok := v.(string); ok {
				req.Header.Set(k, vs)
			}
		}
	}

	maxBytes := int64(512_000)
	if v, ok := args["max_bytes"].(float64); ok && int64(v) > 0 {
		maxBytes = int64(v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return Result{Content: fmt.Sprintf("request failed: %v", err), IsError: true}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	// Read one byte past the cap so a response landing exactly on maxBytes
	// isn't misreported as truncated. Trim the sentinel byte back off when the
	// body actually overflowed.
	limited := io.LimitReader(resp.Body, maxBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return Result{Content: fmt.Sprintf("read body: %v", err), IsError: true}, nil
	}

	truncated := int64(len(raw)) > maxBytes
	if truncated {
		raw = raw[:maxBytes]
	}
	var out strings.Builder
	fmt.Fprintf(&out, "HTTP/%d %s\n", resp.StatusCode, resp.Status)
	for k, vs := range resp.Header {
		fmt.Fprintf(&out, "%s: %s\n", k, strings.Join(vs, ", "))
	}
	out.WriteString("\n")
	out.Write(raw)
	if truncated {
		fmt.Fprintf(&out, "\n\n[truncated at %d bytes]", maxBytes)
	}

	details := map[string]any{
		"mode":         "http",
		"status":       resp.StatusCode,
		"content_type": resp.Header.Get("Content-Type"),
		"bytes":        len(raw),
		"truncated":    truncated,
	}

	// The client follows redirects, so resp answers the LAST hop's request, not
	// req. The record pairs the response with the request that produced it.
	final := req
	if resp.Request != nil {
		final = resp.Request
	}
	if hops := redirectHops(resp); hops > 0 {
		details["redirect_chain"] = map[string]any{
			"hops":         hops,
			"original_url": req.URL.String(),
			"final_url":    final.URL.String(),
		}
		if requestBodyUnreadable(final) {
			// The hop re-sent a body this side cannot re-read, so the stored
			// request would read as bodiless when it was not.
			details["body_omitted"] = "redirect"
		}
	}

	// Persist for downstream tools (query_records, inspect_record,
	// replay_request). Capture failures are non-fatal — the model still
	// gets the body even if persistence breaks — but they are reported, so
	// the model is never told a record exists that does not.
	if w.captureSink != nil && w.captureProject != "" {
		recUUID, perr := w.persistHTTPFetch(ctx, final, resp, raw)
		details["persisted"] = perr == nil && recUUID != ""
		switch {
		case perr != nil:
			details["persist_error"] = perr.Error()
		case recUUID != "":
			details["record_uuid"] = recUUID
		}
	}

	return Result{
		Content: out.String(),
		Details: details,
	}, nil
}

// redirectHops counts the redirects the client followed to produce resp: each
// hop's request links to the response that redirected it.
func redirectHops(resp *http.Response) int {
	n := 0
	for r := resp.Request; r != nil && r.Response != nil; r = r.Response.Request {
		n++
	}
	return n
}

// requestBodyUnreadable reports a request that carried a body which cannot be
// re-read for serialization (no GetBody).
func requestBodyUnreadable(req *http.Request) bool {
	return req.GetBody == nil && req.Body != nil && req.Body != http.NoBody
}

// persistHTTPFetch serialises the just-completed request/response pair into
// raw HTTP bytes and hands it to the capture sink. req must be the request
// that produced resp — resp.Request after redirects, not the original. Returns the new record's
// UUID (or empty when capture is disabled or fails). All errors are
// surfaced to the caller as a flag, not propagated — fetch already succeeded
// and the model has the body, so a persistence hiccup shouldn't fail the
// tool call.
func (w *webFetchTool) persistHTTPFetch(ctx context.Context, req *http.Request, resp *http.Response, body []byte) (string, error) {
	if w.captureSink == nil || w.captureProject == "" {
		return "", nil
	}

	host, port := splitHostPort(req.URL)
	scheme := req.URL.Scheme
	svc, err := httpmsg.NewService(host, port, scheme)
	if err != nil {
		return "", err
	}

	rawReq := buildRawRequest(req)
	rawResp := buildRawResponse(resp, body)

	rr := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequestWithService(svc, rawReq),
		httpmsg.NewHttpResponse(rawResp),
	)
	return w.captureSink.SaveRecord(ctx, rr, "web-fetch", w.captureProject)
}

// buildRawRequest serialises a sent net/http.Request back to wire bytes
// (request line + headers + body). Stable header ordering so the
// request_hash stays deterministic across calls.
func buildRawRequest(req *http.Request) []byte {
	var b bytes.Buffer

	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, path)

	// Host header up front (some servers care about ordering).
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	fmt.Fprintf(&b, "Host: %s\r\n", host)

	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range req.Header.Values(k) {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")

	if req.GetBody != nil {
		if rc, err := req.GetBody(); err == nil {
			if data, err := io.ReadAll(rc); err == nil {
				b.Write(data)
			}
			_ = rc.Close()
		}
	}
	return b.Bytes()
}

// buildRawResponse rebuilds the response wire bytes from a *http.Response +
// already-read body. Used by capture paths where we've consumed resp.Body
// into a buffer.
func buildRawResponse(resp *http.Response, body []byte) []byte {
	var b bytes.Buffer
	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	fmt.Fprintf(&b, "%s %s\r\n", proto, resp.Status)

	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range resp.Header.Values(k) {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	// Synthesize Content-Length when missing so downstream parsers don't
	// have to guess where the body ends.
	if resp.Header.Get("Content-Length") == "" && len(body) > 0 {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

// readinessDetails renders a probe's wait_selector outcome as tool-result
// details; empty when no selector was waited for.
func readinessDetails(res *spitolas.ProbeResult) map[string]any {
	if res.Readiness == "" {
		return nil
	}
	d := map[string]any{"readiness": res.Readiness}
	if res.ReadinessDetail != "" {
		d["readiness_detail"] = res.ReadinessDetail
	}
	return d
}

// captureDetails renders a capture receipt as tool-result details.
func captureDetails(rc spitolas.CaptureReceipt) map[string]any {
	d := map[string]any{
		"records_persisted": rc.Persisted,
		"records_failed":    rc.Lost(),
		"capture_complete":  rc.Enabled && rc.Clean(),
		"bodies_retained":   rc.BodiesRetained,
	}
	if rc.Err != "" {
		d["capture_error"] = rc.Err
	}
	return d
}

// captureSummary is the one-line capture account appended to a tool's text.
func captureSummary(rc spitolas.CaptureReceipt, source string) string {
	if !rc.Enabled {
		msg := "not running, nothing persisted"
		if rc.Err != "" {
			msg += " (" + rc.Err + ")"
		}
		return msg
	}
	msg := fmt.Sprintf("%d record(s) persisted under source='%s'", rc.Persisted, source)
	if lost := rc.Lost(); lost > 0 {
		msg += fmt.Sprintf(", %d lost", lost)
	}
	if !rc.Clean() {
		msg += " — capture incomplete"
	}
	if rc.Persisted > 0 {
		msg += "; use query_records to enumerate"
	}
	return msg
}

// splitHostPort returns hostname + numeric port, defaulting to 80/443 per
// scheme when the URL omits it.
func splitHostPort(u *urlpkg.URL) (string, int) {
	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		if u.Scheme == "https" {
			return host, 443
		}
		return host, 80
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// executeBrowser drives spitolas (Chromium via CDP) for JS-rendered pages.
// Spitolas does what agent-browser used to: navigate, wait, grab the
// post-JS DOM. The big win over agent-browser is CDP-level network capture
// — every XHR/fetch the page issues during render is persisted, not just
// the final document. When the tool is wired with a capture sink, those
// requests land in query_records under source="web-fetch-browser" with no
// extra plumbing.
func (w *webFetchTool) executeBrowser(ctx context.Context, url string, args map[string]any) (Result, error) {
	maxBytes := int64(512_000)
	if v, ok := args["max_bytes"].(float64); ok && int64(v) > 0 {
		maxBytes = int64(v)
	}
	waitMS := 1500
	if v, ok := args["wait_ms"].(float64); ok && int(v) > 0 {
		waitMS = int(v)
	}
	waitSel, _ := args["wait_selector"].(string)

	cfg := spitolas.ProbeConfig{
		URL:          url,
		WaitSelector: waitSel,
		WaitExtra:    time.Duration(waitMS) * time.Millisecond,
		NavTimeout:   45 * time.Second,
		CollectHTML:  true,
	}
	// When wired, pump every XHR/fetch the browser issues straight into
	// the project DB. Source is distinct from browser_probe so the agent
	// can tell which tool surfaced the traffic.
	if w.captureSink != nil && w.captureProject != "" {
		cfg.CaptureSink = w.captureSink
		cfg.CaptureProjectUUID = w.captureProject
		cfg.CaptureSource = spitolas.CaptureSourceWebFetchBrowser
		// The records are promised to query_records/replay_request, which need
		// the response, not just the request line.
		cfg.CaptureBodies = true
	}

	probe := w.probe
	if probe == nil {
		probe = spitolas.ProbeURL
	}
	res, err := probe(ctx, cfg)
	if err != nil {
		// Render the partial result if spitolas got us a final URL despite
		// the error — useful when navigation fails late (e.g. JS errors).
		msg := fmt.Sprintf("browser fetch failed: %v", err)
		if res != nil && res.FinalURL != "" {
			msg += fmt.Sprintf(" (final_url=%s)", res.FinalURL)
		}
		return Result{Content: msg, IsError: true}, nil
	}

	html := res.HTML
	truncated := false
	if int64(len(html)) > maxBytes {
		html = html[:maxBytes] + fmt.Sprintf("\n\n[truncated at %d bytes]", maxBytes)
		truncated = true
	}

	var out strings.Builder
	fmt.Fprintf(&out, "URL: %s\nTitle: %s\n", res.FinalURL, res.Title)
	if res.ReadinessFailed {
		// The page was sampled without its readiness condition: say so before
		// the HTML, so it is not read as the fully rendered page.
		fmt.Fprintf(&out, "Readiness: %s — %s; the HTML below may be incomplete.\n", res.Readiness, res.ReadinessDetail)
	}
	out.WriteString("\n")
	out.WriteString(html)

	details := map[string]any{
		"mode":      "browser",
		"url":       res.FinalURL,
		"title":     res.Title,
		"bytes":     len(res.HTML),
		"truncated": truncated,
	}
	if len(res.Dialogs) > 0 {
		details["dialogs"] = len(res.Dialogs)
	}
	maps.Copy(details, readinessDetails(res))
	// CDP capture writes many records per page (one per XHR), so there is no
	// single record_uuid as in HTTP mode. What is reported comes from the
	// capture receipt — what the writer confirmed after it drained — never
	// from the fact that a sink was configured.
	if cfg.CaptureSink != nil {
		maps.Copy(details, captureDetails(res.Capture))
		fmt.Fprintf(&out, "\n\n[capture: %s]", captureSummary(res.Capture, spitolas.CaptureSourceWebFetchBrowser))
	}

	return Result{
		Content: out.String(),
		Details: details,
	}, nil
}
