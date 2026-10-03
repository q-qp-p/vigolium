package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSpideringValidate_Dialogs(t *testing.T) {
	for _, v := range append([]string{""}, SpideringDialogPolicies...) {
		c := DefaultSpideringConfig()
		c.Interaction.Dialogs = v
		if err := c.Validate(); err != nil {
			t.Errorf("dialogs=%q: unexpected error %v", v, err)
		}
	}

	c := DefaultSpideringConfig()
	c.Interaction.Dialogs = "bogus"
	err := c.Validate()
	if err == nil {
		t.Fatal("dialogs=bogus: expected a validation error")
	}
	// The error must name every accepted value so the operator can fix it.
	for _, v := range SpideringDialogPolicies {
		if !strings.Contains(err.Error(), v) {
			t.Errorf("error %q does not name accepted value %q", err, v)
		}
	}
}

// TestApplyProfile_InteractionKeysSurviveOverlay guards the pointer-valued
// interaction section under the key-preserving overlay: a project overlay that
// denies registration must not be reset by a later profile that only names an
// unrelated interaction key.
func TestApplyProfile_InteractionKeysSurviveOverlay(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) *ProfileSettings {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		p, err := LoadProfile(path)
		if err != nil {
			t.Fatalf("LoadProfile(%s): %v", name, err)
		}
		return p
	}

	settings := DefaultSettings()
	project := write("project.yaml", "spidering:\n  interaction:\n    register_account: false\n")
	profile := write("profile.yaml", "spidering:\n  max_depth: 3\n  interaction:\n    dialogs: accept-all\n")
	if err := ApplyProfile(settings, project); err != nil {
		t.Fatalf("apply project: %v", err)
	}
	if err := ApplyProfile(settings, profile); err != nil {
		t.Fatalf("apply profile: %v", err)
	}

	in := settings.Spidering.Interaction
	if in.RegisterAccount == nil || *in.RegisterAccount {
		t.Errorf("RegisterAccount = %v, want explicit false to survive the profile overlay", in.RegisterAccount)
	}
	if in.Dialogs != "accept-all" {
		t.Errorf("Dialogs = %q, want accept-all from the profile", in.Dialogs)
	}
	if in.SubmitForms != nil || in.EditFields != nil {
		t.Errorf("keys no file named must stay unset, got submit=%v edit=%v", in.SubmitForms, in.EditFields)
	}
	if settings.Spidering.MaxDepth != 3 {
		t.Errorf("MaxDepth = %d, want 3", settings.Spidering.MaxDepth)
	}
}

func TestSetField_InteractionKey(t *testing.T) {
	settings := DefaultSettings()
	if err := SetField(settings, "spidering.interaction.submit_forms", "false"); err != nil {
		t.Fatalf("SetField: %v", err)
	}
	if v := settings.Spidering.Interaction.SubmitForms; v == nil || *v {
		t.Errorf("SubmitForms = %v, want explicit false", v)
	}
}

func TestSpideringValidate_IdentityEmailDomain(t *testing.T) {
	for _, ok := range []string{"", "example.com", "qa.example.net"} {
		c := DefaultSpideringConfig()
		c.IdentityEmailDomain = ok
		if err := c.Validate(); err != nil {
			t.Errorf("identity_email_domain=%q: unexpected error %v", ok, err)
		}
	}
	for _, bad := range []string{"user@example.com", "https://example.com", "localhost", "exa mple.com"} {
		c := DefaultSpideringConfig()
		c.IdentityEmailDomain = bad
		if err := c.Validate(); err == nil {
			t.Errorf("identity_email_domain=%q: expected a validation error", bad)
		}
	}
}

func TestSpideringValidate_MaxCaptureBodyBytes(t *testing.T) {
	for _, ok := range []int64{0, -1, 1 << 20} {
		c := DefaultSpideringConfig()
		c.MaxCaptureBodyBytes = ok
		if err := c.Validate(); err != nil {
			t.Errorf("max_capture_body_bytes=%d: unexpected error %v", ok, err)
		}
	}
	c := DefaultSpideringConfig()
	c.MaxCaptureBodyBytes = -2
	if err := c.Validate(); err == nil {
		t.Error("max_capture_body_bytes=-2: expected a validation error")
	}
}

// TestSpideringMaxDurationZeroMeansDefault is the F21 regression for the
// fail-silent crawl: `spidering.max_duration: 0s` validated, parsed to 0, and was
// then handed to context.WithTimeout per target — an expired deadline, so the
// crawl ended before it began and the phase reported success.
func TestSpideringMaxDurationZeroMeansDefault(t *testing.T) {
	for _, value := range []string{"", "0s", "0", "garbage"} {
		c := DefaultSpideringConfig()
		c.MaxDuration = value
		if got := c.MaxDurationParsed(); got != 30*time.Minute {
			t.Errorf("max_duration %q parsed to %s, want the 30m default", value, got)
		}
	}
	c := DefaultSpideringConfig()
	c.MaxDuration = "9m"
	if got := c.MaxDurationParsed(); got != 9*time.Minute {
		t.Errorf("max_duration 9m parsed to %s", got)
	}
}

// TestSpideringValidateRejectsNegativeDuration: negative parses fine, so only an
// explicit check keeps it out.
func TestSpideringValidateRejectsNegativeDuration(t *testing.T) {
	c := DefaultSpideringConfig()
	c.MaxDuration = "-5m"
	if err := c.Validate(); err == nil {
		t.Fatal("expected a negative spidering.max_duration to be rejected")
	}
	c.MaxDuration = "0s"
	if err := c.Validate(); err != nil {
		t.Errorf("zero must remain valid (it means the default), got %v", err)
	}
}
