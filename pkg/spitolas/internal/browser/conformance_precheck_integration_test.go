//go:build integration

package browser

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// TestConformancePrecheck is the gate `make test-browser-conformance` runs
// before the suite: it fails when no headless browser can be launched here, so
// an environment without one is reported as such instead of as a run whose
// browser tests skipped or failed for an unrelated-looking reason.
func TestConformancePrecheck(t *testing.T) {
	cfg, err := config.New("http://127.0.0.1/")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Headless = true
	b, err := New(cfg)
	if err != nil {
		t.Fatalf("no launchable browser: %v", err)
	}
	page, err := b.NewPage()
	if err != nil {
		_ = b.Close()
		t.Fatalf("browser launched but cannot open a tab: %v", err)
	}
	_ = page.Close()
	if err := b.Close(); err != nil {
		t.Logf("close: %v", err)
	}
}
