package server

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/internal/redact"
)

// redactedPlaceholder, sensitiveJSONFields and sensitiveHeaderNames come from
// the shared internal/redact table, which the browser crawl's artifact
// redaction also reads — one table, two consumers.
const redactedPlaceholder = redact.Placeholder

var (
	sensitiveJSONFields  = redact.JSONFields
	sensitiveHeaderNames = redact.HeaderNames
)

// redactJSONBody parses body as JSON, scrubs values for any key in
// sensitiveJSONFields (recursively, including inside arrays and nested
// objects), and re-emits compact JSON. On parse failure the function
// returns a placeholder rather than the raw bytes — non-JSON request
// bodies are rare enough on agent endpoints that leaking them is a worse
// trade-off than losing the debug detail.
//
// Returns nil for an empty body. Returns the original bytes verbatim
// when no sensitive fields were found, avoiding a re-marshal allocation
// on the typical no-secrets path.
func redactJSONBody(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}
	trimmed := strings.TrimLeft(string(body), " \t\r\n")
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return []byte("<non-JSON body redacted, " + lengthSummary(len(body)) + ">")
	}
	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return []byte("<malformed JSON body redacted, " + lengthSummary(len(body)) + ">")
	}
	scrubbed, changed := scrubJSON(parsed)
	if !changed {
		return body
	}
	out, err := json.Marshal(scrubbed)
	if err != nil {
		return []byte("<unprintable body redacted>")
	}
	return out
}

// scrubJSON walks a parsed JSON value and replaces values keyed by any
// name in sensitiveJSONFields with redactedPlaceholder. Returns a new
// tree plus a flag indicating whether anything was scrubbed; callers
// can short-circuit re-marshal when the body is clean.
func scrubJSON(v any) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		changed := false
		out := make(map[string]any, len(t))
		for k, val := range t {
			if _, hit := sensitiveJSONFields[strings.ToLower(k)]; hit {
				if s, ok := val.(string); ok && s == "" {
					out[k] = ""
					continue
				}
				out[k] = redactedPlaceholder
				changed = true
				continue
			}
			scrubbedChild, childChanged := scrubJSON(val)
			out[k] = scrubbedChild
			if childChanged {
				changed = true
			}
		}
		return out, changed
	case []any:
		changed := false
		out := make([]any, len(t))
		for i, val := range t {
			scrubbedChild, childChanged := scrubJSON(val)
			out[i] = scrubbedChild
			if childChanged {
				changed = true
			}
		}
		return out, changed
	default:
		return v, false
	}
}

// redactSensitiveHeaders returns a copy of hdrs with values for any name
// in sensitiveHeaderNames replaced by redactedPlaceholder. Comparison is
// case-insensitive.
func redactSensitiveHeaders(hdrs map[string][]string) map[string]string {
	out := make(map[string]string, len(hdrs))
	for k, v := range hdrs {
		if _, hit := sensitiveHeaderNames[strings.ToLower(k)]; hit {
			out[k] = redactedPlaceholder
			continue
		}
		out[k] = strings.Join(v, ", ")
	}
	return out
}

// lengthSummary renders a byte-count hint for unredactable bodies. Used in
// debug logs only — the exact byte count is fine to surface.
func lengthSummary(n int) string {
	switch {
	case n < 1024:
		return strconv.Itoa(n) + "B"
	case n < 1024*1024:
		return strconv.Itoa(n/1024) + "KiB"
	default:
		return strconv.Itoa(n/(1024*1024)) + "MiB"
	}
}
