package spitolas

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
)

func TestConvertDialogsEmpty(t *testing.T) {
	if got := convertDialogs(nil); got != nil {
		t.Errorf("convertDialogs(nil) = %v, want nil", got)
	}
	if got := convertDialogs([]browser.DialogEvent{}); got != nil {
		t.Errorf("convertDialogs(empty) = %v, want nil", got)
	}
}

func TestConvertDialogs(t *testing.T) {
	now := time.Now()
	in := []browser.DialogEvent{
		{Type: "alert", Message: "xss", URL: "http://t/a", At: now, Answered: browser.DialogAccepted},
		{Type: "confirm", Message: "ok?", URL: "http://t/b", At: now.Add(time.Second), Answered: browser.DialogDismissed},
	}

	out := convertDialogs(in)
	if len(out) != 2 {
		t.Fatalf("convertDialogs len = %d, want 2", len(out))
	}
	for i := range in {
		if out[i].Type != in[i].Type ||
			out[i].Message != in[i].Message ||
			out[i].URL != in[i].URL ||
			out[i].Answered != in[i].Answered ||
			!out[i].At.Equal(in[i].At) {
			t.Errorf("dialog[%d] mismatch: got %+v, want %+v", i, out[i], in[i])
		}
	}
}

// TestApplyReadiness: a selector wait that ended without the selector is
// reported as such — never as a clean result — and is an error only when the
// caller required it.
func TestApplyReadiness(t *testing.T) {
	timeoutErr := fmt.Errorf("rod: %w", context.DeadlineExceeded)
	cases := []struct {
		name       string
		cfg        ProbeConfig
		waitErr    error
		wantState  string
		wantFailed bool
		wantErr    bool
	}{
		{"no selector", ProbeConfig{}, nil, "", false, false},
		{"ready", ProbeConfig{WaitSelector: "#app"}, nil, ReadinessReady, false, false},
		{"timeout tolerated", ProbeConfig{WaitSelector: "#app"}, timeoutErr, ReadinessTimeout, true, false},
		{"timeout required", ProbeConfig{WaitSelector: "#app", RequireSelector: true}, timeoutErr, ReadinessTimeout, true, true},
		{"other failure", ProbeConfig{WaitSelector: "#app"}, errors.New("invalid selector"), ReadinessFailed, true, false},
		{"other failure required", ProbeConfig{WaitSelector: "#app", RequireSelector: true}, context.Canceled, ReadinessFailed, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := &ProbeResult{FinalURL: "https://t/", HTML: "<html></html>"}
			err := applyReadiness(res, tc.cfg, tc.waitErr, 45*time.Second)
			if res.Readiness != tc.wantState || res.ReadinessFailed != tc.wantFailed {
				t.Fatalf("readiness = %q failed=%v, want %q failed=%v", res.Readiness, res.ReadinessFailed, tc.wantState, tc.wantFailed)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrReadinessFailed) {
				t.Errorf("err %v does not wrap ErrReadinessFailed", err)
			}
			if tc.wantFailed && !strings.Contains(res.ReadinessDetail, "#app") {
				t.Errorf("detail %q does not name the selector", res.ReadinessDetail)
			}
			if res.HTML == "" || res.FinalURL == "" {
				t.Error("the partial result was dropped")
			}
		})
	}
}
