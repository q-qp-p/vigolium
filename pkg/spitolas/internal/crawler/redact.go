package crawler

import (
	"strings"

	"github.com/vigolium/vigolium/internal/redact"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
)

// urlAttributes are element attributes holding a URL, whose credential-bearing
// query parameters (and userinfo) are scrubbed rather than the whole value.
var urlAttributes = map[string]bool{"href": true, "src": true, "action": true, "formaction": true}

// redactGraphDump scrubs the values a crawl graph can carry that may be
// credentials, keeping everything a replay needs — selectors, field names,
// non-sensitive input values — intact:
//   - userinfo and sensitive query/fragment parameters in the target and state
//     URLs and in URL-valued attributes;
//   - an element's value attribute and data-* payloads (an anti-CSRF token, a
//     prefilled field, client state);
//   - the submitted values of password and hidden fields (a hidden field is
//     where a page keeps its anti-CSRF token) and of fields whose name reads as
//     credential-bearing (the shared internal/redact table).
func redactGraphDump(d *GraphDump) {
	d.Target = redact.URL(d.Target)
	for i := range d.States {
		d.States[i].URL = redact.URL(d.States[i].URL)
	}
	for i := range d.Edges {
		e := &d.Edges[i]
		e.Attributes = redactAttributes(e.Attributes)
		for j := range e.FormInputs {
			in := &e.FormInputs[j]
			if sensitiveFormInput(in) {
				for k := range in.Inputs {
					in.Inputs[k] = redact.Placeholder
				}
			}
		}
	}
}

// redactAttributes returns attrs without value/data-* entries and with
// URL-valued attributes scrubbed. A fresh map: the input is the live edge's.
func redactAttributes(attrs map[string]string) map[string]string {
	if len(attrs) == 0 {
		return attrs
	}
	out := make(map[string]string, len(attrs))
	for k, v := range attrs {
		lk := strings.ToLower(k)
		switch {
		case lk == "value", strings.HasPrefix(lk, "data-"):
			continue
		case urlAttributes[lk]:
			out[k] = redact.URL(v)
		case redact.IsSensitiveName(lk):
			out[k] = redact.Placeholder
		default:
			out[k] = v
		}
	}
	return out
}

// sensitiveFormInput reports whether a recorded form field's values must be
// redacted: a password or hidden field, or one whose identifying name reads as
// credential-bearing. An XPath identification carries no name to judge, so
// only the type decides there.
func sensitiveFormInput(in *GraphDumpInput) bool {
	if strings.EqualFold(in.Type, string(action.InputTypePassword)) ||
		strings.EqualFold(in.Type, string(action.InputTypeHidden)) {
		return true
	}
	if in.How == string(action.HowXPath) {
		return false
	}
	return redact.IsSensitiveName(in.Value)
}
