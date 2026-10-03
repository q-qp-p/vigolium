package form

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// TestIdentityEmailDomain pins that no generated address lands at the target's
// domain or at a real mail provider: the default is the reserved example.com,
// and spidering.identity_email_domain overrides it everywhere an address is
// generated.
func TestIdentityEmailDomain(t *testing.T) {
	if !strings.HasSuffix(FixedEmail, "@"+config.DefaultIdentityEmailDomain) {
		t.Errorf("FixedEmail = %q, want an address at %s", FixedEmail, config.DefaultIdentityEmailDomain)
	}
	c, err := config.New("https://acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.IdentityEmailDomain != "example.com" {
		t.Errorf("default IdentityEmailDomain = %q, want example.com", c.IdentityEmailDomain)
	}

	for _, tc := range []struct {
		name, domain, want string
	}{
		{"default", "", "example.com"},
		{"override", "mail.test.internal", "mail.test.internal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// With a FillContext (the crawl path) and without one (the smart
			// fallback), for a typed email field and a name-classified one.
			withCtx := NewHandler(&config.Config{FormFillMode: config.FormFillNormal, IdentityEmailDomain: tc.domain})
			withCtx.SetFillContext(NewFillContext(mustURL(t, "https://www.acme.com/signup")))
			noCtx := NewHandler(&config.Config{FormFillMode: config.FormFillNormal, IdentityEmailDomain: tc.domain})

			for label, got := range map[string]string{
				"fill context": withCtx.getValueForInput(detectedInput(action.InputTypeEmail, "email")),
				"smart value":  noCtx.getValueForInput(detectedInput(action.InputTypeText, "contact_email")),
			} {
				if !strings.HasSuffix(got, "@"+tc.want) {
					t.Errorf("%s: email = %q, want an address at %s", label, got, tc.want)
				}
				if strings.Contains(got, "acme.com") {
					t.Errorf("%s: email %q derived from the target's domain", label, got)
				}
			}
		})
	}

	// A page-provided example address is still preferred.
	h := NewHandler(&config.Config{FormFillMode: config.FormFillNormal})
	h.SetFillContext(NewFillContext(mustURL(t, "https://acme.com")))
	d := detectedInput(action.InputTypeEmail, "email")
	d.DefaultValue = "prefill@acme.com"
	if got := h.getValueForInput(d); got != "prefill@acme.com" {
		t.Errorf("page example = %q, want prefill@acme.com", got)
	}
}
