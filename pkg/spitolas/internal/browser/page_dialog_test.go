package browser

import (
	"errors"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

func TestRecordDialogAppendsAndReads(t *testing.T) {
	p := &Page{}

	p.recordDialog(DialogEvent{Type: "alert", Message: "one", URL: "u1", At: time.Now()})
	p.recordDialog(DialogEvent{Type: "confirm", Message: "two", URL: "u2", At: time.Now()})

	got := p.DialogEvents()
	if len(got) != 2 {
		t.Fatalf("DialogEvents len = %d, want 2", len(got))
	}
	if got[0].Message != "one" || got[1].Message != "two" {
		t.Fatalf("unexpected dialog messages: %+v", got)
	}

	// Returned slice must be a copy: mutating it must not affect Page state.
	got[0].Message = "MUTATED"
	again := p.DialogEvents()
	if again[0].Message != "one" {
		t.Fatalf("DialogEvents returned a shared slice; got %q after mutation", again[0].Message)
	}
}

func TestRecordDialogCapsAtMax(t *testing.T) {
	p := &Page{}
	for i := 0; i < maxRecordedDialogs+10; i++ {
		p.recordDialog(DialogEvent{Type: "alert", Message: "m", URL: "u", At: time.Now()})
	}
	if got := len(p.DialogEvents()); got != maxRecordedDialogs {
		t.Fatalf("dialog log size = %d, want capped at %d", got, maxRecordedDialogs)
	}
}

func TestDrainDialogsClears(t *testing.T) {
	p := &Page{}
	p.recordDialog(DialogEvent{Type: "alert", Message: "a"})
	p.recordDialog(DialogEvent{Type: "alert", Message: "b"})

	drained := p.DrainDialogs()
	if len(drained) != 2 {
		t.Fatalf("DrainDialogs returned %d, want 2", len(drained))
	}
	if got := p.DialogEvents(); len(got) != 0 {
		t.Fatalf("after drain, DialogEvents len = %d, want 0", len(got))
	}

	if again := p.DrainDialogs(); again != nil {
		t.Fatalf("second drain returned %d events, want nil", len(again))
	}
}

func TestDialogResponse(t *testing.T) {
	cases := []struct {
		policy config.DialogPolicy
		kind   string
		accept bool
	}{
		{config.DialogRecordDismiss, "alert", true},
		{config.DialogRecordDismiss, "confirm", false},
		{config.DialogRecordDismiss, "prompt", false},
		{config.DialogRecordDismiss, "beforeunload", true},
		// An empty policy is the default.
		{"", "alert", true},
		{"", "confirm", false},
		{"", "prompt", false},
		{"", "beforeunload", true},
		{config.DialogAcceptAll, "alert", true},
		{config.DialogAcceptAll, "confirm", true},
		{config.DialogAcceptAll, "prompt", true},
		{config.DialogAcceptAll, "beforeunload", true},
	}
	for _, c := range cases {
		accept, prompt := dialogResponse(c.policy, c.kind)
		if accept != c.accept {
			t.Errorf("dialogResponse(%q, %q) accept = %v, want %v", c.policy, c.kind, accept, c.accept)
		}
		if prompt != "" {
			t.Errorf("dialogResponse(%q, %q) prompt text = %q, want empty", c.policy, c.kind, prompt)
		}
	}
}

// TestHandleDialogRecordsBeforeResponding is the ordering guard: the dialog is
// in the log before the browser is answered, including when it is dismissed.
func TestHandleDialogRecordsBeforeResponding(t *testing.T) {
	cfg := &config.Config{Policy: config.DefaultInteractionPolicy()}
	p := &Page{config: cfg}

	var respondedAccept *bool
	p.handleDialog(&proto.PageJavascriptDialogOpening{Type: proto.PageDialogTypeConfirm, Message: "Delete account?", URL: "https://t/"},
		func(accept bool, _ string) error {
			if got := p.DialogEvents(); len(got) != 1 || got[0].Message != "Delete account?" {
				t.Fatalf("respond ran before the dialog was recorded: %+v", got)
			}
			respondedAccept = &accept
			return nil
		})
	if respondedAccept == nil || *respondedAccept {
		t.Fatalf("confirm under record-dismiss must be dismissed, got %v", respondedAccept)
	}
	if got := p.DialogEvents()[0].Answered; got != DialogDismissed {
		t.Errorf("Answered = %q, want %q", got, DialogDismissed)
	}

	// accept-all answers the same dialog with accept, and says so.
	p = &Page{config: &config.Config{Policy: config.InteractionPolicy{DialogResponse: config.DialogAcceptAll}}}
	p.handleDialog(&proto.PageJavascriptDialogOpening{Type: proto.PageDialogTypeConfirm}, func(accept bool, _ string) error {
		if !accept {
			t.Error("accept-all must accept a confirm")
		}
		return nil
	})
	if got := p.DialogEvents()[0].Answered; got != DialogAccepted {
		t.Errorf("Answered = %q, want %q", got, DialogAccepted)
	}

	// A respond error never loses the record.
	p = &Page{}
	p.handleDialog(&proto.PageJavascriptDialogOpening{Type: proto.PageDialogTypeAlert, Message: "xss"}, func(bool, string) error {
		return errors.New("cdp gone")
	})
	if got := p.DialogEvents(); len(got) != 1 || got[0].Answered != DialogAccepted {
		t.Errorf("alert with a failing respond: got %+v", got)
	}
}
