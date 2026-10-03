// Package redact is the shared table of credential-bearing names: the exact
// JSON keys and header names the server scrubs from its logs, and the broader
// name match the browser crawl applies to the artifacts it writes (crawl
// graphs, form training). One table, so a name added for one consumer protects
// the other too.
package redact

import (
	"net/url"
	"strings"
)

// Placeholder is the literal substituted for a redacted value. Distinct from
// "***" so an operator can grep for the exact string when checking whether
// redaction fired.
const Placeholder = "<redacted>"

// JSONFields is the set of JSON object keys whose value must be redacted
// before a request body lands in any operator-visible log. Keys are compared
// case-insensitively (callers lower-case them).
//
// Keep this set in sync with:
//   - the BYOK fields on AgentAuditRequest / AgentAutopilotRequest /
//     AgentSwarmRequest / AgentAuditDriverRequest / AgenticScanRequest
//   - the cred fields on OliumConfig (agent.olium.*) since the same body
//     can be sent to the config-write endpoint
var JSONFields = map[string]struct{}{
	"api_key":            {},
	"oauth_token":        {},
	"oauth_cred_file":    {},
	"oauth_cred_json":    {},
	"llm_api_key":        {},
	"password":           {},
	"secret":             {},
	"anthropic_api_key":  {},
	"openai_api_key":     {},
	"claude_oauth_token": {},
}

// HeaderNames is the set of request/response header names whose value must be
// redacted before logging. Compared case-insensitively (callers lower-case).
//
// Authorization is the obvious one but BYOK proxy deployments often pipe
// keys through one of the X-* shapes too, so all of them are masked.
var HeaderNames = map[string]struct{}{
	"authorization":       {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
	"x-anthropic-key":     {},
	"x-openai-key":        {},
	"proxy-authorization": {},
}

// nameKeywords mark a form-field, query-parameter or attribute name as
// credential-bearing when they appear anywhere in it. Over-matching only costs
// a redacted value in an artifact; under-matching leaks a credential.
var nameKeywords = []string{
	"password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "api-key",
	"accesskey", "access_key", "auth", "cookie", "session", "otp", "card", "cvv",
	"cvc", "ssn", "csrf", "xsrf", "nonce", "credential", "private", "signature",
}

// exactNames are short credential names too generic to match as substrings
// ("code" would catch "zipcode"), so they only match the whole name.
var exactNames = map[string]struct{}{
	"code": {}, "key": {}, "pass": {}, "pin": {}, "sid": {}, "jwt": {}, "sig": {},
}

// IsSensitiveName reports whether a field, parameter or attribute name reads
// as credential-bearing: an entry of JSONFields, HeaderNames or the exact-name
// set, or a name containing one of the credential keywords.
func IsSensitiveName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if _, ok := JSONFields[n]; ok {
		return true
	}
	if _, ok := HeaderNames[n]; ok {
		return true
	}
	if _, ok := exactNames[n]; ok {
		return true
	}
	for _, k := range nameKeywords {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

// URL strips userinfo from raw and replaces the value of every sensitive query
// parameter — and of every sensitive key=value pair in the fragment, where an
// OAuth implicit flow puts its access_token — with Placeholder. Parameter names
// are kept so the URL's shape survives. An unparseable URL is returned
// unchanged when it has no "@", "?" or "#", and as Placeholder otherwise.
func URL(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		if strings.ContainsAny(raw, "@?#") {
			return Placeholder
		}
		return raw
	}
	changed := false
	if u.User != nil {
		u.User = nil
		changed = true
	}
	if q, ok := redactPairs(u.RawQuery); ok {
		u.RawQuery = q
		changed = true
	}
	if frag := u.EscapedFragment(); strings.Contains(frag, "=") {
		if f, ok := redactPairs(frag); ok {
			// Set both forms so String() emits the escaped one as is.
			if unescaped, uerr := url.PathUnescape(f); uerr == nil {
				u.Fragment = unescaped
			}
			u.RawFragment = f
			changed = true
		}
	}
	if !changed {
		return raw
	}
	return u.String()
}

// redactPairs rewrites an &-separated key=value list with sensitive values
// replaced, preserving order and the untouched pairs byte for byte. ok is
// false when nothing was sensitive.
func redactPairs(s string) (string, bool) {
	if s == "" {
		return s, false
	}
	parts := strings.Split(s, "&")
	changed := false
	for i, p := range parts {
		k, _, hasValue := strings.Cut(p, "=")
		name, err := url.QueryUnescape(k)
		if err != nil {
			name = k
		}
		if hasValue && IsSensitiveName(name) {
			parts[i] = k + "=" + url.QueryEscape(Placeholder)
			changed = true
		}
	}
	return strings.Join(parts, "&"), changed
}
