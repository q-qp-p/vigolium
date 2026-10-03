package form

import (
	"errors"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// TestFillInputs_SkippedIsNotSuccess guards the counter that used to count
// disabled/readonly controls as filled. FillInput returns before touching the
// page for these inputs, so a nil page is enough.
func TestFillInputs_SkippedIsNotSuccess(t *testing.T) {
	cfg := &config.Config{FormFillMode: config.FormFillNormal}
	cfg.ApplyPolicy(config.InteractionPolicy{EditFields: true, SubmitForms: true}) // uploads denied
	h := NewHandler(cfg)

	disabled := detectedInput(action.InputTypeText, "a")
	disabled.Disabled = true
	readonly := detectedInput(action.InputTypeText, "b")
	readonly.ReadOnly = true
	upload := detectedInput(action.InputTypeFile, "c")

	r := h.FillInputs(nil, []*DetectedInput{disabled, readonly, upload})
	if r.Skipped != 2 || r.Unsupported != 1 {
		t.Errorf("skipped=%d unsupported=%d, want 2 and 1", r.Skipped, r.Unsupported)
	}
	if r.Succeeded() != 0 || r.Verified != 0 || r.Attempted != 0 || r.Failed != 0 {
		t.Errorf("nothing was filled, got succeeded=%d verified=%d attempted=%d failed=%d",
			r.Succeeded(), r.Verified, r.Attempted, r.Failed)
	}
	for _, fr := range r.Results {
		if fr.Success() {
			t.Errorf("%s: Success=true for outcome %q", fr.Input.Name, fr.Outcome)
		}
	}
	if r.HasErrors() || len(r.Errors()) != 0 {
		t.Errorf("skips and policy refusals are not errors: %v", r.Errors())
	}
}

func TestFillInputsResult_Counters(t *testing.T) {
	r := &FillInputsResult{}
	for _, fr := range []*FillResult{
		{Outcome: FillVerified},
		{Outcome: FillAttempted},
		{Outcome: FillRejected},
		{Outcome: FillSkipped},
		{Outcome: FillUnsupported, Error: ErrUploadNotPermitted},
		{Error: errors.New("element not found")},
	} {
		r.add(fr)
	}
	if r.Verified != 1 || r.Attempted != 1 || r.Rejected != 1 || r.Skipped != 1 || r.Unsupported != 1 || r.Failed != 1 {
		t.Errorf("counters = %+v", r)
	}
	if r.Succeeded() != 2 {
		t.Errorf("Succeeded = %d, want Verified+Attempted = 2", r.Succeeded())
	}
	if !r.HasUnverified() || !r.HasErrors() || len(r.Errors()) != 1 {
		t.Errorf("HasUnverified=%v HasErrors=%v Errors=%v", r.HasUnverified(), r.HasErrors(), r.Errors())
	}
	if r.Results[2].Success() {
		t.Error("a rejected fill must not be a success")
	}
	if (&FillInputsResult{Verified: 1}).HasUnverified() {
		t.Error("a fully verified result has nothing unverified")
	}
}

func TestParseInputData_FormKey(t *testing.T) {
	h := NewHandler(&config.Config{})
	in := h.parseInputData(map[string]interface{}{
		"type": "text", "name": "q", "formKey": "form[1]#search|/find",
	})
	if in.FormKey != "form[1]#search|/find" {
		t.Errorf("FormKey = %q", in.FormKey)
	}
	if orphan := h.parseInputData(map[string]interface{}{"type": "text", "name": "q"}); orphan.FormKey != "" {
		t.Errorf("orphan FormKey = %q, want empty", orphan.FormKey)
	}
}
