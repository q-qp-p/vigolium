//go:build integration && (linux || darwin)

package browser

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestLaunchCtxTabCreation: tab creation is bounded (a cancelled crawl context
// fails it promptly), and a tab created under the bound outlives the bound —
// the watchdog is disarmed once the tab exists, so the page does not expire
// tabCreateTimeout after creation.
func TestLaunchCtxTabCreation(t *testing.T) {
	b := newHeadlessBrowser(t, "http://127.0.0.1/")

	orig := tabCreateTimeout
	tabCreateTimeout = 2 * time.Second
	t.Cleanup(func() { tabCreateTimeout = orig })

	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}
	time.Sleep(tabCreateTimeout + 500*time.Millisecond)
	if _, err := page.RodPage().Eval(`() => 1 + 1`); err != nil {
		t.Fatalf("page unusable after the creation bound elapsed: %v", err)
	}
	if err := page.Close(); err != nil {
		t.Logf("close: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b.SetCrawlContext(ctx)
	start := time.Now()
	if _, err := b.NewPage(); err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("NewPage under a cancelled crawl context = %v, want a context.Canceled error", err)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("cancelled tab creation took %v", el)
	}
}
