//go:build integration

package crawler

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/testutil"
)

// =============================================================================
// Integration tests for iframe crawling with exact state/edge count assertions.
//
// The fixtures are Crawljax's iframe test site, but the counts are this
// crawler's, not Crawljax's. Two behaviours add edges Crawljax does not have:
//   - click-once is scoped per state (see CandidateElementExtractor.markChecked),
//     so a link still present in a state reached by another link is clicked
//     again from that state;
//   - backtracking records a "reload" edge from the state it leaves to the index
//     (the state the crawl ends in has none).
// =============================================================================

// TestIFrameCrawlable tests crawling into iframes, including nested ones.
// Expected: 12 states, 21 edges
//
// The site has 11 clickable elements across five frame contexts:
// - index.html: 3 anchors (#top-click-1, #top-click-2, #top-click-3)
// - iframe.html (frame0): 2 anchors
// - page0-0-0.html (frame0.nested): 1 anchor + 2 inputs (button001, button002)
// - iframe2.html (frame1): 2 anchors
// - subiframe.html (frame1.frame10): 1 anchor
//
// MaxDepth is 1: with per-state click-once every state reached re-offers all
// eleven elements, so a deeper crawl of this site does not converge within any
// reasonable budget and its counts would only measure how far it got. At depth
// one each element is clicked once from the index (11 states + the index, 11
// click edges) and every state but the last backtracks (10 reload edges).
func TestIFrameCrawlable(t *testing.T) {
	const (
		NUMBER_OF_STATES = 12
		NUMBER_OF_EDGES  = 21
	)

	server := testutil.IFrameSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 1
	cfg.CrawlFrames = true
	cfg.MaxDuration = 120 * time.Second
	cfg.WaitAfterEvent = 100 * time.Millisecond
	cfg.WaitAfterReload = 100 * time.Millisecond
	cfg.ClickSelectors = []string{"a", "input"}
	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := crawler.Run(ctx)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	assertCrawledFrames(t, result, []string{"", "frame0", "frame0.nested", "frame1", "frame1.frame10"}, nil)

	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d",
			result.StateCount(), NUMBER_OF_STATES)
	}

	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}

// assertCrawledFrames checks which frame contexts the crawl clicked in: every
// frame in want must have at least one click edge, and none in excluded may.
// The top-level document is "".
func assertCrawledFrames(t *testing.T, result *Result, want, excluded []string) {
	t.Helper()
	clicked := make(map[string]int)
	for _, e := range result.Graph.AllEdges() {
		if e.EventType == action.EventTypeClick {
			clicked[e.RelatedFrame]++
		}
	}
	for _, f := range want {
		if clicked[f] == 0 {
			t.Errorf("no click edge in frame %q; clicks per frame: %v", f, clicked)
		}
	}
	for _, f := range excluded {
		if clicked[f] != 0 {
			t.Errorf("excluded frame %q was clicked %d time(s)", f, clicked[f])
		}
	}
}

// TestIFrameExclusions tests excluding specific iframes from crawling.
// Expected: NUMBER_OF_STATES = 4, NUMBER_OF_EDGES = 11 — no frame is crawled, so the
// three top links give 3 edges from the index, 6 re-clicks between the three
// content states, and 2 reload edges.
func TestIFrameExclusions(t *testing.T) {
	const (
		NUMBER_OF_STATES = 4
		NUMBER_OF_EDGES  = 11
	)

	server := testutil.IFrameSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 3
	cfg.CrawlFrames = true
	cfg.MaxDuration = 120 * time.Second
	cfg.WaitAfterEvent = 100 * time.Millisecond
	cfg.WaitAfterReload = 100 * time.Millisecond

	cfg.ExcludeFrames = []string{"frame1", "sub", "frame0"}

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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

// TestIFramesNotCrawled tests disabling iframe crawling entirely.
// Expected: NUMBER_OF_STATES = 4, NUMBER_OF_EDGES = 11 — no frame is crawled, so the
// three top links give 3 edges from the index, 6 re-clicks between the three
// content states, and 2 reload edges.
func TestIFramesNotCrawled(t *testing.T) {
	const (
		NUMBER_OF_STATES = 4
		NUMBER_OF_EDGES  = 11
	)

	server := testutil.IFrameSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 3
	cfg.CrawlFrames = false
	cfg.MaxDuration = 120 * time.Second
	cfg.WaitAfterEvent = 100 * time.Millisecond
	cfg.WaitAfterReload = 100 * time.Millisecond

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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

// TestIFramesWildcardsNotCrawled tests wildcard exclusion of iframes.
// Expected: NUMBER_OF_STATES = 4, NUMBER_OF_EDGES = 11 — no frame is crawled, so the
// three top links give 3 edges from the index, 6 re-clicks between the three
// content states, and 2 reload edges.
func TestIFramesWildcardsNotCrawled(t *testing.T) {
	const (
		NUMBER_OF_STATES = 4
		NUMBER_OF_EDGES  = 11
	)

	server := testutil.IFrameSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 3
	cfg.CrawlFrames = true
	cfg.MaxDuration = 120 * time.Second
	cfg.WaitAfterEvent = 100 * time.Millisecond
	cfg.WaitAfterReload = 100 * time.Millisecond

	// Using glob pattern - frame% matches frame0, frame1, etc.
	cfg.ExcludeFrames = []string{"frame*", "sub"}

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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

// TestCrawlingOnlySubFrames tests excluding a nested frame path while its
// parent frame is still crawled.
// Expected: NUMBER_OF_STATES = 11, NUMBER_OF_EDGES = 19 — TestIFrameCrawlable's
// depth-one crawl minus the one element inside frame1.frame10 (one state, its
// click edge and its reload edge). See TestIFrameCrawlable for why MaxDepth is 1.
func TestCrawlingOnlySubFrames(t *testing.T) {
	const (
		NUMBER_OF_STATES = 11
		NUMBER_OF_EDGES  = 19
	)

	server := testutil.IFrameSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 1
	cfg.CrawlFrames = true
	cfg.MaxDuration = 120 * time.Second
	cfg.WaitAfterEvent = 100 * time.Millisecond
	cfg.WaitAfterReload = 100 * time.Millisecond
	cfg.ClickSelectors = []string{"a", "input"}

	cfg.ExcludeFrames = []string{"frame1.frame10"}

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := crawler.Run(ctx)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	assertCrawledFrames(t, result, []string{"", "frame0", "frame0.nested", "frame1"}, []string{"frame1.frame10"})

	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d",
			result.StateCount(), NUMBER_OF_STATES)
	}

	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}
