package browser

import (
	"strings"
	"testing"

	"github.com/go-rod/rod/lib/proto"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

func TestDownloadBehavior(t *testing.T) {
	deny := downloadBehavior(config.InteractionPolicy{}, "/tmp/x")
	if deny.Behavior != proto.BrowserSetDownloadBehaviorBehaviorDeny || deny.DownloadPath != "" {
		t.Errorf("downloads not permitted: got %+v, want deny with no path", deny)
	}
	// Permitted but no run-owned directory available: still deny rather than
	// fall back to the operator's Downloads folder.
	if got := downloadBehavior(config.InteractionPolicy{DownloadFiles: true}, ""); got.Behavior != proto.BrowserSetDownloadBehaviorBehaviorDeny {
		t.Errorf("permitted without a directory: got %+v, want deny", got)
	}
	allow := downloadBehavior(config.InteractionPolicy{DownloadFiles: true}, "/run/owned")
	if allow.Behavior != proto.BrowserSetDownloadBehaviorBehaviorAllowAndName || allow.DownloadPath != "/run/owned" {
		t.Errorf("permitted: got %+v, want allowAndName into the run-owned dir", allow)
	}
}

func TestNeedsSubmitGuard(t *testing.T) {
	if needsSubmitGuard(nil) {
		t.Error("nil config must not install a guard")
	}
	cfg := &config.Config{Policy: config.DefaultInteractionPolicy()}
	if needsSubmitGuard(cfg) {
		t.Error("default policy permits submits; no guard")
	}
	cfg.Policy.SubmitForms = false
	if !needsSubmitGuard(cfg) {
		t.Error("submits denied: guard required")
	}
}

// TestSubmitGuardScriptShape pins the parts of the guard the policy depends on:
// a capture-phase submit listener that stops the page's own handlers, the
// prototype overrides that catch form.submit(), and the per-document opt-out.
func TestSubmitGuardScriptShape(t *testing.T) {
	for _, want := range []string{
		"addEventListener('submit'",
		"stopImmediatePropagation",
		"}, true);",
		"P.submit = function",
		"P.requestSubmit = function",
		"window.__vigAllowSubmit === true",
	} {
		if !strings.Contains(submitGuardScript, want) {
			t.Errorf("submitGuardScript lost %q", want)
		}
	}
}
