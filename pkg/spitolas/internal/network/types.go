package network

import "time"

// TrafficEntry represents a single HTTP request/response captured from the browser.
type TrafficEntry struct {
	Timestamp    time.Time     `json:"timestamp"`
	Hash         string        `json:"hash"`
	Request      RequestData   `json:"request"`
	Response     *ResponseData `json:"response,omitempty"`
	ResourceType string        `json:"resourceType"`
	Error        string        `json:"error,omitempty"`

	// httpx computed fields (populated at capture time)
	Host          string `json:"-"`
	Port          string `json:"-"`
	Scheme        string `json:"-"`
	Path          string `json:"-"`
	ContentType   string `json:"-"`
	WebServer     string `json:"-"`
	ContentLength int    `json:"-"`
	Words         int    `json:"-"`
	Lines         int    `json:"-"`
	TargetHost    string `json:"-"`
	// DurationMs is the wall-clock time from the browser issuing the request to
	// the response arriving. Zero means NOT MEASURED (an entry rebuilt from a
	// stored capture has no pending timer), never "instant".
	DurationMs int64 `json:"-"`
	// BodyFetchMs is the time spent pulling the body over CDP after the response
	// arrived — the crawler's overhead, kept out of DurationMs.
	BodyFetchMs int64 `json:"-"`
	// BodySource says where Response.Body came from, so a missing body is never
	// mistaken for an empty one (one of the BodySource* values; "" when the
	// entry has no response).
	BodySource string `json:"-"`
}

// Response body provenance (TrafficEntry.BodySource).
const (
	BodySourceCDP           = "cdp"            // fetched over CDP and kept
	BodySourceOmittedPolicy = "omitted-policy" // fetched for metrics, not kept (include_response_body off)
	BodySourceSkippedStatic = "skipped-static" // a static asset not worth fetching
	BodySourceTooLarge      = "too-large"      // over the fetch ceiling; ContentLength carries the encoded size
	BodySourceFailed        = "failed"         // the CDP fetch errored
	BodySourceUnavailable   = "unavailable"    // no body to fetch (redirect hop, closed page)
)

// RequestData contains HTTP request information.
type RequestData struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body,omitempty"`
}

// ResponseData contains HTTP response information.
type ResponseData struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
}
