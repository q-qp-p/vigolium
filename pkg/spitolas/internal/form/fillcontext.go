package form

import (
	"net/url"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
)

// FieldSemantic is the meaning of a form field, inferred from its
// name/id/placeholder/label and type. Only the identity-bearing semantics are
// modelled — these are the fields whose value must stay consistent across a
// multi-step register→login flow, and the ones the login-credential pass reuses.
type FieldSemantic string

const (
	SemUnknown  FieldSemantic = ""
	SemEmail    FieldSemantic = "email"
	SemUsername FieldSemantic = "username"
	SemPassword FieldSemantic = "password"
	SemName     FieldSemantic = "name"
	SemPhone    FieldSemantic = "phone"
)

// crawlLocalPart is the local-part of the generated email address (at the
// identity email domain, never the target's). Kept deterministic (not random)
// so a value submitted to a registration form can be replayed verbatim into a
// later login form.
const crawlLocalPart = "vigolium-crawl"

// FillContext carries per-crawl state that makes form filling response-aware:
// the target's registrable domain (so a username can be derived from the target
// itself — email addresses never are) and a memory of the value chosen for each identity semantic (so the
// same email/username/password is reused across pages — a signup filled on one
// page can be logged in with on another). It is shared between the form Handler
// and the crawler's login-credential pass, and every method is safe for the
// crawler's parallel consumers.
type FillContext struct {
	mu     sync.RWMutex
	domain string
	memory map[FieldSemantic]string
}

// NewFillContext builds a FillContext for a target URL. The registrable-ish
// domain is the host with a leading "www." stripped; a nil/host-less URL yields
// an empty domain, which simply disables the target-derived value sources.
func NewFillContext(target *url.URL) *FillContext {
	domain := ""
	if target != nil {
		domain = strings.ToLower(target.Hostname())
		domain = strings.TrimPrefix(domain, "www.")
	}
	return &FillContext{
		domain: domain,
		memory: make(map[FieldSemantic]string),
	}
}

// Domain returns the target-derived domain ("" when unknown).
func (fc *FillContext) Domain() string {
	if fc == nil {
		return ""
	}
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return fc.domain
}

// Recall returns the value previously chosen for a semantic, if any.
func (fc *FillContext) Recall(sem FieldSemantic) (string, bool) {
	if fc == nil || sem == SemUnknown {
		return "", false
	}
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	v, ok := fc.memory[sem]
	return v, ok
}

// Remember records the value chosen for a semantic so later forms reuse it.
// The first non-empty value wins — a signup that runs before a login page seeds
// the identity the login page then reuses.
func (fc *FillContext) Remember(sem FieldSemantic, value string) {
	if fc == nil || sem == SemUnknown || value == "" {
		return
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if _, exists := fc.memory[sem]; !exists {
		fc.memory[sem] = value
	}
}

// UsernameFromDomain derives a username from the target's primary domain label
// (e.g. "acme.com" → "acme_crawl"), so submitted data reads as native to the
// app. Returns "" when no domain is known.
func (fc *FillContext) UsernameFromDomain() string {
	d := fc.Domain()
	if d == "" {
		return ""
	}
	label := d
	if i := strings.IndexByte(label, '.'); i > 0 {
		label = label[:i]
	}
	label = sanitizeLabel(label)
	if label == "" {
		return ""
	}
	return label + "_crawl"
}

// sanitizeLabel keeps only [a-z0-9] from a domain label so it is a valid
// username local segment.
func sanitizeLabel(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Identity field keyword lists, shared by classifyField (routing) and
// getSmartValue (value selection) so a synonym added in one place takes effect
// in both. Matched case-insensitively against name/id/placeholder/label.
var (
	emailFieldKeywords     = []string{"email", "mail", "e-mail", "correo"}
	passwordFieldKeywords  = []string{"password", "passwd", "pwd", "pass", "secret"}
	usernameFieldKeywords  = []string{"username", "user_name", "login", "userid", "user_id"}
	phoneFieldKeywords     = []string{"phone", "tel", "mobile", "cell", "fax", "telefono"}
	firstNameFieldKeywords = []string{"firstname", "first_name", "fname", "given_name", "givenname"}
	lastNameFieldKeywords  = []string{"lastname", "last_name", "lname", "surname", "family_name", "familyname"}
	fullNameFieldKeywords  = []string{"fullname", "full_name"}
)

// classifyField infers the identity semantic of an input from its type and its
// name/id/placeholder/label, using the shared keyword lists above (same order as
// getSmartValue). Only the identity-bearing semantics are returned.
func classifyField(input *DetectedInput) FieldSemantic {
	if input == nil || input.FormInput == nil {
		return SemUnknown
	}

	// Strong type signals first.
	switch input.Type {
	case action.InputTypePassword:
		return SemPassword
	case action.InputTypeEmail:
		return SemEmail
	}

	name := strings.ToLower(input.Name)
	id := strings.ToLower(input.ID)
	placeholder := strings.ToLower(input.Placeholder)
	label := strings.ToLower(input.Label)
	targets := []string{name, id, placeholder, label}

	switch {
	case containsAny(targets, emailFieldKeywords...):
		return SemEmail
	case containsAny(targets, passwordFieldKeywords...):
		return SemPassword
	case containsAny(targets, usernameFieldKeywords...):
		return SemUsername
	case containsAny(targets, firstNameFieldKeywords...),
		containsAny(targets, lastNameFieldKeywords...),
		containsAny(targets, fullNameFieldKeywords...):
		return SemName
	case (name == "name" || id == "name") && !containsAny(targets, "user"):
		return SemName
	case containsAny(targets, phoneFieldKeywords...):
		return SemPhone
	}
	return SemUnknown
}

// exampleValue returns a concrete value the page itself offers for this field: a
// pre-filled value, a <datalist> suggestion, or an example-shaped placeholder.
// Returns "" when the page offers no usable example (e.g. an instructional
// placeholder like "Enter your email").
func exampleValue(input *DetectedInput) string {
	if input == nil {
		return ""
	}
	if v := strings.TrimSpace(input.DefaultValue); v != "" {
		return v
	}
	for _, opt := range input.DatalistOptions {
		if o := strings.TrimSpace(opt); o != "" {
			return o
		}
	}
	return exampleFromPlaceholder(input.Placeholder)
}

// placeholderInstructionWords mark a placeholder as an instruction ("Enter your
// email") rather than a concrete example value, so it is not used verbatim.
var placeholderInstructionWords = []string{
	"enter", "your", "please", "choose", "select", "type", "add", "search",
	"username", "password", "required", "optional",
}

// exampleFromPlaceholder extracts a concrete example value from a placeholder,
// stripping a leading "e.g."/"ex:"/"example:" lead-in. It returns "" unless the
// remainder is a short, single-token value with no instruction words — so
// "e.g. jane@acme.com" yields the address but "Enter your name" yields nothing.
func exampleFromPlaceholder(placeholder string) string {
	p := strings.TrimSpace(placeholder)
	if p == "" {
		return ""
	}
	lower := strings.ToLower(p)
	for _, lead := range []string{"e.g.", "eg.", "ex:", "example:", "example -", "sample:"} {
		if strings.HasPrefix(lower, lead) {
			p = strings.TrimSpace(p[len(lead):])
			lower = strings.ToLower(p)
			break
		}
	}
	if p == "" || len(p) > 40 {
		return ""
	}
	// A concrete example is a single token (no spaces); multi-word placeholders
	// are prose instructions.
	if strings.ContainsAny(p, " \t") {
		return ""
	}
	for _, w := range placeholderInstructionWords {
		if strings.Contains(lower, w) {
			return ""
		}
	}
	return p
}
