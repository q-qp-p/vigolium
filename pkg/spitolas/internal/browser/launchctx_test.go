package browser

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/cftbrowser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// stubCfTDownload replaces the Chrome for Testing download for one test and
// records the context it was handed.
func stubCfTDownload(t *testing.T) *[]context.Context {
	t.Helper()
	var seen []context.Context
	orig := ensureCfTBrowser
	ensureCfTBrowser = func(ctx context.Context) (string, error) {
		seen = append(seen, ctx)
		return "", errors.New("download stubbed out")
	}
	t.Cleanup(func() { ensureCfTBrowser = orig })
	return &seen
}

// TestLaunchCtxCancelledBeforeProvisioning: a caller whose context already
// ended gets a context error at once, and no candidate is resolved — in
// particular nothing is downloaded.
func TestLaunchCtxCancelledBeforeProvisioning(t *testing.T) {
	downloads := stubCfTDownload(t)
	cfg, err := config.New("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	cfg.BrowserPath = "/nonexistent/should-not-be-launched"

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	b, err := NewWithContext(ctx, cfg)
	if b != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("NewWithContext = (%v, %v), want a context.Canceled error", b, err)
	}
	if _, err := NewPoolWithContext(ctx, cfg); !errors.Is(err, context.Canceled) {
		t.Fatalf("NewPoolWithContext err = %v, want context.Canceled", err)
	}
	// launch itself stops before the first candidate.
	if err := (&Browser{config: cfg}).launch(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("launch err = %v, want context.Canceled", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("cancelled provisioning took %v", el)
	}
	if len(*downloads) != 0 {
		t.Fatalf("a cancelled launch attempted %d Chrome for Testing download(s)", len(*downloads))
	}
}

// TestLaunchCtxReachesDownload: the download candidate is handed the launch
// context (previously context.Background), so cancelling a scan stops it.
func TestLaunchCtxReachesDownload(t *testing.T) {
	if !cftbrowser.IsSupported() {
		t.Skip("Chrome for Testing is not offered on this platform")
	}
	downloads := stubCfTDownload(t)
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "launch")

	embedded := func() (string, error) { return "", nil }
	var resolved bool
	for _, c := range buildBrowserCandidates(ctx, "linux", "amd64", "", nil, embedded) {
		if c.label == "Chrome for Testing (download)" {
			_, _ = c.resolve()
			resolved = true
		}
	}
	if !resolved {
		t.Fatal("no Chrome for Testing download candidate")
	}
	if len(*downloads) != 1 || (*downloads)[0].Value(ctxKey{}) != "launch" {
		t.Fatalf("download got %d call(s) without the launch context", len(*downloads))
	}
}
