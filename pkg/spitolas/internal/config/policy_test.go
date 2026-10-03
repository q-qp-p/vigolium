package config

import "testing"

func TestNew_PolicyMatchesDerivedSwitches(t *testing.T) {
	c, err := New("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.Policy != DefaultInteractionPolicy() {
		t.Errorf("default Policy = %+v, want %+v", c.Policy, DefaultInteractionPolicy())
	}
	if c.FormFillEnabled != c.Policy.EditFields || c.SubmitGetForms != c.Policy.SubmitForms ||
		c.SubmitPostForms != c.Policy.SubmitForms || c.SelfRegister != c.Policy.RegisterAccount ||
		c.LoginCredentialAttempts != c.Policy.LoginAttempts {
		t.Errorf("New() derived switches disagree with its Policy: %+v", c)
	}
}

func TestApplyPolicy(t *testing.T) {
	c, _ := New("https://example.com")
	c.ApplyPolicy(InteractionPolicy{EditFields: true, LoginAttempts: true})
	if !c.FormFillEnabled || c.SubmitGetForms || c.SubmitPostForms || c.SelfRegister || !c.LoginCredentialAttempts {
		t.Errorf("ApplyPolicy did not derive the switches: fill=%v get=%v post=%v reg=%v login=%v",
			c.FormFillEnabled, c.SubmitGetForms, c.SubmitPostForms, c.SelfRegister, c.LoginCredentialAttempts)
	}
	if c.Policy.DialogResponse != DialogRecordDismiss {
		t.Errorf("an empty dialog policy must normalize to record-dismiss, got %q", c.Policy.DialogResponse)
	}

	// The legacy setters keep Policy in step.
	c.EnableFormFill(false).SetLoginCredentialAttempts(false, false)
	if c.Policy.EditFields || c.Policy.LoginAttempts {
		t.Errorf("setters left Policy stale: %+v", c.Policy)
	}
}

func TestValidate_DialogPolicy(t *testing.T) {
	c, _ := New("https://example.com")
	c.Policy.DialogResponse = "bogus"
	if err := c.Validate(); err == nil {
		t.Error("Validate must reject an unknown dialog policy")
	}
	c.Policy.DialogResponse = DialogAcceptAll
	if err := c.Validate(); err != nil {
		t.Errorf("accept-all rejected: %v", err)
	}
}
