package tool

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas"
)

func TestBrowserProbeSchemaShape(t *testing.T) {
	tool := NewBrowserProbe()
	schema := tool.Schema()

	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema missing properties")
	}
	for _, p := range []string{"url", "wait_ms", "wait_selector", "nav_timeout_ms"} {
		if _, ok := props[p]; !ok {
			t.Errorf("schema missing property %q", p)
		}
	}
	required, _ := schema["required"].([]string)
	if len(required) == 0 || required[0] != "url" {
		t.Errorf("schema required = %v, want [url]", required)
	}

	if tool.IsReadOnly() {
		t.Errorf("browser_probe must report IsReadOnly=false (executes attacker JS)")
	}
}

func TestBrowserProbeRequiresURL(t *testing.T) {
	tool := NewBrowserProbe()
	res, err := tool.Execute(context.Background(), map[string]any{}, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.IsError {
		t.Errorf("expected IsError when url missing")
	}
}

func TestBrowserProbeReportsDialog(t *testing.T) {
	called := false
	probe := func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		called = true
		if cfg.URL != "https://example.com/?p=x" {
			t.Errorf("probe got URL %q", cfg.URL)
		}
		return &spitolas.ProbeResult{
			FinalURL: cfg.URL,
			Title:    "Example",
			Dialogs: []spitolas.DialogEvent{
				{Type: "alert", Message: "vig-x-12345", URL: cfg.URL, At: time.Now(), Answered: "accepted"},
			},
		}, nil
	}

	tool := &browserProbeTool{probe: probe}
	res, err := tool.Execute(context.Background(), map[string]any{
		"url": "https://example.com/?p=x",
	}, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !called {
		t.Fatalf("probe not invoked")
	}
	if res.IsError {
		t.Fatalf("unexpected IsError; content=%s", res.Content)
	}
	if !strings.Contains(res.Content, "vig-x-12345") {
		t.Errorf("content missing dialog message: %s", res.Content)
	}
	if got, _ := res.Details["dialog_fired"].(bool); !got {
		t.Errorf("Details.dialog_fired = false, want true")
	}
	// How the browser answered the dialog is reported, not just that it fired.
	dialogs, _ := res.Details["dialogs"].([]map[string]any)
	if len(dialogs) != 1 || dialogs[0]["answered"] != "accepted" {
		t.Errorf("Details.dialogs = %v, want one entry answered=accepted", res.Details["dialogs"])
	}
	if !strings.Contains(res.Content, "accepted") {
		t.Errorf("content does not say how the dialog was answered: %s", res.Content)
	}
}

func TestBrowserProbeNoDialog(t *testing.T) {
	probe := func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		return &spitolas.ProbeResult{FinalURL: cfg.URL, Title: "OK"}, nil
	}
	tool := &browserProbeTool{probe: probe}
	res, err := tool.Execute(context.Background(), map[string]any{"url": "https://example.com"}, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected IsError")
	}
	if got, _ := res.Details["dialog_fired"].(bool); got {
		t.Errorf("Details.dialog_fired = true, want false")
	}
	if !strings.Contains(res.Content, "No JavaScript dialogs") {
		t.Errorf("content missing no-dialogs note: %s", res.Content)
	}
}

func TestBrowserProbeNavErrorWithDialogStillSucceeds(t *testing.T) {
	// javascript: URLs and similar can return a navigation error even though
	// the page already executed JS and fired a dialog. The tool should still
	// report success when dialogs are present.
	probe := func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		return &spitolas.ProbeResult{
			Dialogs: []spitolas.DialogEvent{{Type: "alert", Message: "fired"}},
		}, errors.New("navigation aborted")
	}
	tool := &browserProbeTool{probe: probe}
	res, err := tool.Execute(context.Background(), map[string]any{"url": "x"}, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected success despite nav error; content=%s", res.Content)
	}
}

func TestBrowserProbeNavErrorNoDialogFails(t *testing.T) {
	probe := func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		return nil, errors.New("connection refused")
	}
	tool := &browserProbeTool{probe: probe}
	res, err := tool.Execute(context.Background(), map[string]any{"url": "x"}, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.IsError {
		t.Errorf("expected IsError on nav failure with no result")
	}
}

// TestProbeToolsReportReadiness: a wait_selector that timed out reaches the
// details and the text of both browser tools, so the model is never told the
// page was ready when it was not.
func TestProbeToolsReportReadiness(t *testing.T) {
	failed := func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		if cfg.WaitSelector != "#app" {
			t.Errorf("wait_selector not passed through: %q", cfg.WaitSelector)
		}
		return &spitolas.ProbeResult{
			FinalURL:        cfg.URL,
			HTML:            "<html><body>Loading…</body></html>",
			Readiness:       spitolas.ReadinessTimeout,
			ReadinessFailed: true,
			ReadinessDetail: `selector "#app" did not appear within 25s`,
		}, nil
	}
	args := map[string]any{"url": "https://example.com/", "wait_selector": "#app", "mode": "browser"}

	bp := &browserProbeTool{probe: failed}
	res, err := bp.Execute(context.Background(), args, nil)
	if err != nil || res.IsError {
		t.Fatalf("browser_probe: err=%v result=%s", err, res.Content)
	}
	if res.Details["readiness"] != "timeout" || !strings.Contains(res.Content, "Readiness:  timeout") {
		t.Errorf("browser_probe readiness not surfaced: details=%v content=%s", res.Details, res.Content)
	}

	wf := &webFetchTool{probe: failed}
	res, err = wf.Execute(context.Background(), args, nil)
	if err != nil || res.IsError {
		t.Fatalf("web_fetch: err=%v result=%s", err, res.Content)
	}
	if res.Details["readiness"] != "timeout" || res.Details["readiness_detail"] == nil {
		t.Errorf("web_fetch readiness details = %v", res.Details)
	}
	if !strings.Contains(res.Content, "Readiness: timeout") || !strings.Contains(res.Content, "may be incomplete") {
		t.Errorf("web_fetch text does not flag the unready page: %s", res.Content)
	}

	ready := func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		return &spitolas.ProbeResult{FinalURL: cfg.URL, Readiness: spitolas.ReadinessReady}, nil
	}
	res, _ = (&webFetchTool{probe: ready}).Execute(context.Background(), args, nil)
	if res.Details["readiness"] != "ready" || strings.Contains(res.Content, "Readiness:") {
		t.Errorf("ready page misreported: details=%v content=%s", res.Details, res.Content)
	}
}
