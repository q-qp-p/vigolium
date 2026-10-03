//go:build integration

package spitolas

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRunSpiderWritesGraphWithManifest drives a real crawl and checks the
// graph it leaves: run-identified name, owner-only, redacted by default, and a
// manifest carrying the policy, the security posture and the final capture
// receipt.
func TestRunSpiderWritesGraphWithManifest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body>
<a href="/next?token=GRAPHCANARY">next</a>
<form action="/login" method="post"><input name="user"><input type="password" name="pw"><button>Go</button></form>
</body></html>`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := RunSpider(ctx, SpiderConfig{
		TargetURL: srv.URL, MaxStates: 3, MaxDepth: 2, MaxDuration: 40 * time.Second,
		Headless: true, IncludeResponseBody: true, IncludeHeaders: true,
		GraphOutputDir: dir, RunID: "scan-1234",
	}, &memSink{})
	if err != nil {
		t.Fatalf("RunSpider: %v", err)
	}
	if !res.Capture.Enabled || !res.Capture.Clean() {
		t.Errorf("capture receipt = %+v", res.Capture)
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "crawl-graph-127.0.0.1-scan-1234-*.json"))
	if len(matches) != 1 {
		entries, _ := os.ReadDir(dir)
		t.Fatalf("graph files = %v (dir: %v)", matches, entries)
	}
	info, _ := os.Stat(matches[0])
	if info.Mode().Perm() != 0o600 {
		t.Errorf("graph mode = %o, want 600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(matches[0])
	if strings.Contains(string(data), "GRAPHCANARY") {
		t.Error("graph carries an unredacted token")
	}
	var dump struct {
		RunID    string         `json:"run_id"`
		Redacted bool           `json:"redacted"`
		Policy   map[string]any `json:"policy"`
		Security map[string]any `json:"security"`
		Capture  CaptureReceipt `json:"capture"`
	}
	if err := json.Unmarshal(data, &dump); err != nil {
		t.Fatal(err)
	}
	if dump.RunID != "scan-1234" || !dump.Redacted || dump.Policy["submit_forms"] != true || dump.Security["sandbox"] == nil {
		t.Errorf("manifest = %+v", dump)
	}
	if dump.Capture != res.Capture {
		t.Errorf("graph capture %+v != result capture %+v (must be the final receipt)", dump.Capture, res.Capture)
	}
}
