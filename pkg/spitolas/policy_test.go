package spitolas

import "testing"

func TestEffectivePolicy_LegacySwitches(t *testing.T) {
	// A caller that predates Policy keeps its behavior.
	cfg := SpiderConfig{NoForms: true, SelfRegister: true, LoginCredentialAttempts: true}
	p := cfg.EffectivePolicy()
	if p.EditFields || p.SubmitForms || p.UploadFiles {
		t.Errorf("NoForms must turn edits, submits and uploads off, got %+v", p)
	}
	if !p.RegisterAccount || !p.LoginAttempts {
		t.Errorf("SelfRegister/LoginCredentialAttempts must carry over, got %+v", p)
	}
	if p.DialogResponse != DialogRecordDismiss || p.DownloadFiles {
		t.Errorf("unrelated categories must keep their defaults, got %+v", p)
	}

	if got := (SpiderConfig{}).EffectivePolicy(); got != DefaultInteractionPolicy() {
		t.Errorf("zero SpiderConfig policy = %+v, want the default", got)
	}
	if d := DefaultInteractionPolicy(); !d.UploadFiles || d.DownloadFiles {
		t.Errorf("default policy = %+v, want uploads on and downloads off", d)
	}
}

func TestEffectivePolicy_ExplicitWins(t *testing.T) {
	explicit := InteractionPolicy{SubmitForms: true, DialogResponse: DialogAcceptAll}
	cfg := SpiderConfig{NoForms: true, SelfRegister: true, Policy: &explicit}
	if got := cfg.EffectivePolicy(); got != explicit {
		t.Errorf("EffectivePolicy = %+v, want the explicit policy %+v", got, explicit)
	}
}

// TestBuildCrawlerConfig_PolicyDerivation asserts the derived crawler switches
// that still gate their own mechanisms follow the policy exactly.
func TestBuildCrawlerConfig_PolicyDerivation(t *testing.T) {
	for _, p := range []InteractionPolicy{
		DefaultInteractionPolicy(),
		{SubmitForms: true},
		{EditFields: true, RegisterAccount: true, LoginAttempts: true, DialogResponse: DialogAcceptAll},
		{},
	} {
		p := p
		c, err := buildCrawlerConfig(SpiderConfig{TargetURL: "https://example.com/", Policy: &p})
		if err != nil {
			t.Fatalf("buildCrawlerConfig: %v", err)
		}
		if c.FormFillEnabled != p.EditFields ||
			c.SubmitGetForms != p.SubmitForms || c.SubmitPostForms != p.SubmitForms ||
			c.SelfRegister != p.RegisterAccount || c.LoginCredentialAttempts != p.LoginAttempts {
			t.Errorf("policy %+v: derived switches diverge (fill=%v get=%v post=%v reg=%v login=%v)",
				p, c.FormFillEnabled, c.SubmitGetForms, c.SubmitPostForms, c.SelfRegister, c.LoginCredentialAttempts)
		}
		if c.Policy.UploadFiles != p.UploadFiles || c.Policy.DownloadFiles != p.DownloadFiles {
			t.Errorf("policy %+v: upload/download not carried: %+v", p, c.Policy)
		}
		wantDialog := string(p.DialogResponse)
		if wantDialog == "" {
			wantDialog = string(DialogRecordDismiss)
		}
		if string(c.Policy.DialogResponse) != wantDialog {
			t.Errorf("dialog policy = %q, want %q", c.Policy.DialogResponse, wantDialog)
		}
	}
}

func TestEffectiveCompat(t *testing.T) {
	if got := (SpiderConfig{}).EffectiveCompat(); got != DefaultBrowserCompat() {
		t.Errorf("nil compat = %+v, want the default", got)
	}
	if d := DefaultBrowserCompat(); d.NoSandbox || !d.IgnoreTLSErrors || d.AllowInsecureContent || d.DisableWebSecurity {
		t.Errorf("default posture = %+v, want sandbox on, tls errors ignored, mixed content blocked, web security on", d)
	}
	explicit := BrowserCompat{DisableWebSecurity: true}
	c, err := buildCrawlerConfig(SpiderConfig{TargetURL: "https://example.com/", BrowserCompat: &explicit})
	if err != nil {
		t.Fatal(err)
	}
	if c.BrowserCompat.DisableWebSecurity != true || c.BrowserCompat.IgnoreTLSErrors {
		t.Errorf("explicit compat not carried: %+v", c.BrowserCompat)
	}
}

func TestBrowserSecurityFields(t *testing.T) {
	f := BrowserSecurity{BrowserCompat: InsecureBrowserCompat()}.Fields()
	want := map[string]any{"sandbox": "off", "tls": "ignore-errors", "mixed_content": "allow", "web_security": "off"}
	for k, v := range want {
		if f[k] != v {
			t.Errorf("Fields()[%q] = %v, want %v", k, f[k], v)
		}
	}
	if _, ok := f["sandbox_reason"]; ok {
		t.Error("sandbox_reason only appears when the host forced the sandbox off")
	}
	for _, k := range SecurityFieldOrder {
		if _, ok := f[k]; !ok {
			t.Errorf("SecurityFieldOrder names %q, missing from Fields()", k)
		}
	}
}
