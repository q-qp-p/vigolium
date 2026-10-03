package tool

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// failingCaptureSink rejects every save, so the tools' persistence reporting
// can be checked against a store that loses records.
type failingCaptureSink struct{}

func (failingCaptureSink) SaveRecord(context.Context, *httpmsg.HttpRequestResponse, string, string) (string, error) {
	return "", errors.New("database is locked")
}
func (failingCaptureSink) SaveRecordBatch(context.Context, []*httpmsg.HttpRequestResponse, string, string) ([]string, error) {
	return nil, errors.New("database is locked")
}

// TestWebFetchBrowserReportsReceipt: browser-mode capture details come from
// the probe's receipt — what was persisted — not from a sink being wired.
func TestWebFetchBrowserReportsReceipt(t *testing.T) {
	var gotCfg spitolas.ProbeConfig
	w := NewWebFetchWithCapture(stubCaptureSink{}, "proj").(*webFetchTool)
	w.probe = func(_ context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		gotCfg = cfg
		return &spitolas.ProbeResult{
			FinalURL: cfg.URL,
			Title:    "app",
			HTML:     "<html></html>",
			Capture: spitolas.CaptureReceipt{
				Enabled: true, BodiesRetained: true, HeadersRetained: true,
				Accepted: 5, Persisted: 3, Failed: 2, DrainComplete: true, Err: "repository writer: 2 record(s) dropped",
			},
		}, nil
	}
	res, err := w.Execute(context.Background(), map[string]any{"url": "https://app.example/", "mode": "browser"}, nil)
	if err != nil || res.IsError {
		t.Fatalf("Execute: err=%v content=%s", err, res.Content)
	}
	if gotCfg.CaptureSink == nil || !gotCfg.CaptureBodies {
		t.Errorf("browser mode with a sink must capture with bodies: %+v", gotCfg)
	}
	if res.Details["records_persisted"] != 3 || res.Details["records_failed"] != 2 ||
		res.Details["capture_complete"] != false || res.Details["bodies_retained"] != true {
		t.Errorf("capture details = %v", res.Details)
	}
	if _, stale := res.Details["capture"]; stale {
		t.Error("the configuration-derived 'capture' claim must be gone")
	}
	if !strings.Contains(res.Content, "3 record(s) persisted") || !strings.Contains(res.Content, "capture incomplete") {
		t.Errorf("content does not state the receipt: %s", res.Content)
	}
}

// TestWebFetchBrowserNoSinkNoCaptureClaim: without a sink nothing is claimed.
func TestWebFetchBrowserNoSinkNoCaptureClaim(t *testing.T) {
	w := NewWebFetch().(*webFetchTool)
	w.probe = func(_ context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		if cfg.CaptureSink != nil || cfg.CaptureBodies {
			t.Errorf("no-capture variant configured capture: %+v", cfg)
		}
		return &spitolas.ProbeResult{FinalURL: cfg.URL}, nil
	}
	res, _ := w.Execute(context.Background(), map[string]any{"url": "https://app.example/", "mode": "browser"}, nil)
	if _, ok := res.Details["records_persisted"]; ok || strings.Contains(res.Content, "capture:") {
		t.Errorf("no capture was configured, none may be reported: %v / %s", res.Details, res.Content)
	}
}

// TestWebFetchHTTPReportsPersistFailure: a failed save is reported instead of
// swallowed; a successful one carries the record UUID.
func TestWebFetchHTTPReportsPersistFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res, _ := NewWebFetchWithCapture(failingCaptureSink{}, "proj").Execute(context.Background(), map[string]any{"url": srv.URL}, nil)
	if res.IsError {
		t.Fatalf("a persistence failure must not fail the fetch: %s", res.Content)
	}
	if res.Details["persisted"] != false || !strings.Contains(res.Details["persist_error"].(string), "database is locked") {
		t.Errorf("details = %v, want persisted=false with the error", res.Details)
	}
	if _, ok := res.Details["record_uuid"]; ok {
		t.Error("no record_uuid may be reported for a failed save")
	}

	res, _ = NewWebFetchWithCapture(stubCaptureSink{}, "proj").Execute(context.Background(), map[string]any{"url": srv.URL}, nil)
	if res.Details["persisted"] != true || res.Details["record_uuid"] != "rec-uuid" {
		t.Errorf("details = %v, want persisted=true with the record UUID", res.Details)
	}

	res, _ = NewWebFetch().Execute(context.Background(), map[string]any{"url": srv.URL}, nil)
	if _, ok := res.Details["persisted"]; ok {
		t.Errorf("the no-capture variant must not report persistence: %v", res.Details)
	}
}

// TestBrowserProbeCaptureReportsReceipt: capture=true reports the receipt; a
// capture that never started says so.
func TestBrowserProbeCaptureReportsReceipt(t *testing.T) {
	tool := NewBrowserProbeWithCapture(stubCaptureSink{}, "proj").(*browserProbeTool)
	tool.probe = func(_ context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		if (cfg.CaptureSink != nil) != cfg.CaptureBodies {
			t.Errorf("bodies are retained exactly when capture is requested: sink=%v bodies=%v", cfg.CaptureSink != nil, cfg.CaptureBodies)
		}
		return &spitolas.ProbeResult{FinalURL: cfg.URL, Capture: spitolas.CaptureReceipt{Err: "capture start failed: boom"}}, nil
	}
	res, _ := tool.Execute(context.Background(), map[string]any{"url": "https://x.example/", "capture": true}, nil)
	if res.Details["records_persisted"] != 0 || res.Details["capture_complete"] != false || res.Details["capture_error"] == nil {
		t.Errorf("details = %v", res.Details)
	}
	if !strings.Contains(res.Content, "nothing persisted") {
		t.Errorf("content must say nothing was persisted: %s", res.Content)
	}

	// Without capture=true no receipt is reported.
	res, _ = tool.Execute(context.Background(), map[string]any{"url": "https://x.example/"}, nil)
	if _, ok := res.Details["records_persisted"]; ok {
		t.Errorf("capture not requested, none may be reported: %v", res.Details)
	}
}
