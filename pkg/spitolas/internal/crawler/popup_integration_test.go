//go:build integration

package crawler

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/testutil"
)

// =============================================================================
// Integration tests for popup handling with exact state/edge count assertions.
// =============================================================================

// TestPopups tests crawling pages with JavaScript popups (alert, confirm, prompt).
// Expected: NUMBER_OF_STATES = 3, NUMBER_OF_EDGES = 5 — the alert/prompt/confirm
// links change nothing, "load" and "leave?" each reach a content state from the
// index, each content state re-clicks the other link (click-once is per state),
// and one reload edge backtracks. Crawljax, whose fixture this is, counts 3: it
// clicks an element once across all states and records no reload edges.
func TestPopups(t *testing.T) {
	const (
		NUMBER_OF_STATES = 3
		NUMBER_OF_EDGES  = 5
	)

	server := testutil.PopupSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 3
	cfg.MaxDuration = 60 * time.Second
	cfg.WaitAfterEvent = 100 * time.Millisecond
	cfg.WaitAfterReload = 100 * time.Millisecond

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := crawler.Run(ctx)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d",
			result.StateCount(), NUMBER_OF_STATES)
	}

	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}
