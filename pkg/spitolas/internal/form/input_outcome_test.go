package form

import (
	"errors"
	"testing"
)

// elemStub stands in for *browser.Element in the verifying fills. checked is
// the control's state; click flips it unless stuck is set (a control whose
// value does not stick); readErrAfterClick makes the read-back fail.
type elemStub struct {
	checked           bool
	stuck             bool
	clicks            int
	readErrAfterClick bool
	clickErr          error
	evalResult        interface{}
	evalErr           error
}

func (e *elemStub) Property(name string) (interface{}, error) {
	if e.readErrAfterClick && e.clicks > 0 {
		return nil, errors.New("read failed")
	}
	return e.checked, nil
}

func (e *elemStub) Click() error {
	if e.clickErr != nil {
		return e.clickErr
	}
	e.clicks++
	if !e.stuck {
		e.checked = !e.checked
	}
	return nil
}

func (e *elemStub) EvalWithResult(string) (interface{}, error) { return e.evalResult, e.evalErr }

func TestFillCheckboxOutcome(t *testing.T) {
	tests := []struct {
		name   string
		elem   elemStub
		want   bool
		expect FillOutcome
		clicks int
	}{
		{"already in state", elemStub{checked: true}, true, FillVerified, 0},
		{"toggled and verified", elemStub{}, true, FillVerified, 1},
		{"uncheck verified", elemStub{checked: true}, false, FillVerified, 1},
		{"click did not stick", elemStub{stuck: true}, true, FillRejected, 1},
		{"read-back unavailable", elemStub{readErrAfterClick: true}, true, FillAttempted, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := tt.elem
			got, err := fillCheckbox(&e, tt.want)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != tt.expect || e.clicks != tt.clicks {
				t.Errorf("outcome = %q (clicks %d), want %q (clicks %d)", got, e.clicks, tt.expect, tt.clicks)
			}
		})
	}

	e := elemStub{clickErr: errors.New("detached")}
	if _, err := fillCheckbox(&e, true); err == nil {
		t.Error("a failed click must be an error, not an outcome")
	}
}

func TestFillRadioOutcome(t *testing.T) {
	tests := []struct {
		name   string
		elem   elemStub
		value  string
		expect FillOutcome
	}{
		{"value asks for no change", elemStub{}, "0", FillSkipped},
		{"already selected", elemStub{checked: true}, "1", FillVerified},
		{"selected and verified", elemStub{}, "true", FillVerified},
		{"click did not select", elemStub{stuck: true}, "checked", FillRejected},
		{"read-back unavailable", elemStub{readErrAfterClick: true}, "1", FillAttempted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := tt.elem
			got, err := fillRadio(&e, tt.value)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != tt.expect {
				t.Errorf("outcome = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestFillSelectOutcome(t *testing.T) {
	tests := []struct {
		name   string
		result interface{}
		expect FillOutcome
	}{
		{"verified", map[string]interface{}{"found": true, "selected": "us", "verified": true}, FillVerified},
		{"set but did not stick", map[string]interface{}{"found": true, "selected": "us", "verified": false, "actual": ""}, FillRejected},
		{"no matching option", map[string]interface{}{"found": false, "available": []interface{}{"ca"}}, FillRejected},
		{"unexpected shape", "ok", FillAttempted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := elemStub{evalResult: tt.result}
			got, err := fillSelect(&e, "us")
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != tt.expect {
				t.Errorf("outcome = %q, want %q", got, tt.expect)
			}
		})
	}

	e := elemStub{evalErr: errors.New("context canceled")}
	if _, err := fillSelect(&e, "us"); err == nil {
		t.Error("an eval failure must be an error, not an outcome")
	}
}

func TestFillSelectMultipleOutcome(t *testing.T) {
	tests := []struct {
		name   string
		result interface{}
		expect FillOutcome
	}{
		{"all selected", map[string]interface{}{"matched": 2.0, "verified": 2.0}, FillVerified},
		{"one value unmatched", map[string]interface{}{"matched": 1.0, "verified": 1.0}, FillRejected},
		{"matched but not selected", map[string]interface{}{"matched": 2.0, "verified": 1.0}, FillRejected},
		{"unexpected shape", nil, FillAttempted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := elemStub{evalResult: tt.result}
			got, err := fillSelectMultiple(&e, []string{"en", "fr"})
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != tt.expect {
				t.Errorf("outcome = %q, want %q", got, tt.expect)
			}
		})
	}
}
