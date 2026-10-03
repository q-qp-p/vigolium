package form

import (
	"net/url"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func TestNewFillContextDomain(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"https://www.acme.com/login", "acme.com"},
		{"https://Shop.Example.io/", "shop.example.io"},
		{"http://localhost:8080/", "localhost"},
	}
	for _, tt := range tests {
		fc := NewFillContext(mustURL(t, tt.raw))
		if got := fc.Domain(); got != tt.want {
			t.Errorf("Domain(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
	if got := NewFillContext(nil).Domain(); got != "" {
		t.Errorf("Domain(nil) = %q, want empty", got)
	}
}

func TestFillContextMemoryFirstWins(t *testing.T) {
	fc := NewFillContext(mustURL(t, "https://acme.com"))
	if _, ok := fc.Recall(SemEmail); ok {
		t.Fatal("empty context should not recall")
	}
	fc.Remember(SemEmail, "first@acme.com")
	fc.Remember(SemEmail, "second@acme.com") // must NOT overwrite
	if v, ok := fc.Recall(SemEmail); !ok || v != "first@acme.com" {
		t.Errorf("Recall = %q,%v, want first@acme.com,true", v, ok)
	}
	// Empty values and unknown semantics are ignored.
	fc.Remember(SemUsername, "")
	if _, ok := fc.Recall(SemUsername); ok {
		t.Error("empty value should not be remembered")
	}
	fc.Remember(SemUnknown, "x")
	if _, ok := fc.Recall(SemUnknown); ok {
		t.Error("unknown semantic should not be remembered")
	}
}

func TestUsernameFromDomain(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"https://acme.com", "acme_crawl"},
		{"https://www.shop-site.io", "shopsite_crawl"},
		{"http://localhost", "localhost_crawl"},
	}
	for _, tt := range tests {
		fc := NewFillContext(mustURL(t, tt.raw))
		if got := fc.UsernameFromDomain(); got != tt.want {
			t.Errorf("UsernameFromDomain(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
	if got := NewFillContext(nil).UsernameFromDomain(); got != "" {
		t.Errorf("UsernameFromDomain(nil) = %q, want empty", got)
	}
}

func TestClassifyField(t *testing.T) {
	tests := []struct {
		name string
		typ  action.InputType
		attr string // used as the name attribute
		want FieldSemantic
	}{
		{"password type wins", action.InputTypePassword, "whatever", SemPassword},
		{"email type wins", action.InputTypeEmail, "whatever", SemEmail},
		{"email by name", action.InputTypeText, "user_email", SemEmail},
		{"password by name", action.InputTypeText, "passwd", SemPassword},
		{"username by name", action.InputTypeText, "username", SemUsername},
		{"login by name", action.InputTypeText, "login", SemUsername},
		{"firstname", action.InputTypeText, "first_name", SemName},
		{"bare name", action.InputTypeText, "name", SemName},
		{"phone", action.InputTypeText, "mobile", SemPhone},
		{"unknown", action.InputTypeText, "colour", SemUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := detectedInput(tt.typ, tt.attr)
			if got := classifyField(d); got != tt.want {
				t.Errorf("classifyField(name=%q,type=%v) = %q, want %q", tt.attr, tt.typ, got, tt.want)
			}
		})
	}
}

func TestExampleFromPlaceholder(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"e.g. jane@acme.com", "jane@acme.com"},
		{"ex: ACME-123", "ACME-123"},
		{"jane@acme.com", "jane@acme.com"},
		{"Enter your email", ""},            // instruction
		{"Please choose a username", ""},    // instruction
		{"e.g. your full company name", ""}, // multi-word after lead-in
		{"", ""},
	}
	for _, tt := range tests {
		if got := exampleFromPlaceholder(tt.in); got != tt.want {
			t.Errorf("exampleFromPlaceholder(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestExampleValuePrefersDefaultThenDatalist(t *testing.T) {
	d := detectedInput(action.InputTypeText, "country")
	d.DefaultValue = "United States"
	d.DatalistOptions = []string{"Canada"}
	if got := exampleValue(d); got != "United States" {
		t.Errorf("exampleValue prefers DefaultValue, got %q", got)
	}
	d.DefaultValue = ""
	if got := exampleValue(d); got != "Canada" {
		t.Errorf("exampleValue falls to datalist, got %q", got)
	}
	d.DatalistOptions = nil
	d.Placeholder = "e.g. Germany"
	if got := exampleValue(d); got != "Germany" {
		t.Errorf("exampleValue falls to placeholder example, got %q", got)
	}
}

// TestResponseAwareValueTargetDerived verifies that, WITH a FillContext, an email
// field is filled with the crawl's address at the identity domain — never the
// target's own domain — and reused consistently, while a username is derived
// from the domain. Without a FillContext the original fixed values are
// preserved.
func TestResponseAwareValueTargetDerived(t *testing.T) {
	h := newTestHandler(config.FormFillNormal)

	// No FillContext → original fixed behavior.
	if got := h.getValueForInput(detectedInput(action.InputTypeEmail, "email")); got != FixedEmail {
		t.Errorf("without FillContext email = %q, want FixedEmail %q", got, FixedEmail)
	}

	// With FillContext → identity-domain address + consistent reuse.
	h.SetFillContext(NewFillContext(mustURL(t, "https://acme.com")))
	email := h.getValueForInput(detectedInput(action.InputTypeEmail, "email"))
	if email != "vigolium-crawl@example.com" {
		t.Errorf("email = %q, want vigolium-crawl@example.com (never the target's domain)", email)
	}
	// A second, differently-named email field reuses the same value.
	if again := h.getValueForInput(detectedInput(action.InputTypeText, "user_email")); again != email {
		t.Errorf("second email = %q, want reuse %q", again, email)
	}

	user := h.getValueForInput(detectedInput(action.InputTypeText, "username"))
	if user != "acme_crawl" {
		t.Errorf("username = %q, want acme_crawl", user)
	}

	// Password keeps the strong fixed value even with a FillContext.
	if pass := h.getValueForInput(detectedInput(action.InputTypePassword, "password")); pass != FixedPassword {
		t.Errorf("password = %q, want FixedPassword %q", pass, FixedPassword)
	}
}

// TestResponseAwareValuePrefersPageExample verifies a page-provided email example
// is used over the target-derived value.
func TestResponseAwareValuePrefersPageExample(t *testing.T) {
	h := newTestHandler(config.FormFillNormal)
	h.SetFillContext(NewFillContext(mustURL(t, "https://acme.com")))

	d := detectedInput(action.InputTypeEmail, "email")
	d.DefaultValue = "prefill@acme.com"
	if got := h.getValueForInput(d); got != "prefill@acme.com" {
		t.Errorf("email with page example = %q, want prefill@acme.com", got)
	}
}
