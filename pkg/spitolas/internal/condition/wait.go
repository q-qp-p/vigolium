package condition

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"go.uber.org/zap"
)

// WaitResult represents the result of a wait condition.
type WaitResult int

const (
	WaitSuccess     WaitResult = 1  // Condition was satisfied
	WaitTimeout     WaitResult = 0  // Condition timed out
	WaitURLMismatch WaitResult = -1 // URL did not match, so the condition does not apply
	WaitCancelled   WaitResult = -2 // The caller's context ended first; says nothing about the page
)

// WaitCondition waits for a specific element on matching URLs.
type WaitCondition struct {
	// URLMatch limits the condition to pages whose URL matches it under
	// Matcher: a case-insensitive substring (the default) or, with
	// config.URLMatchRegex, a regular expression. Empty applies everywhere.
	URLMatch string
	Matcher  string
	Selector string        // CSS selector to wait for
	Visible  bool          // Wait for visibility (not just existence)
	Timeout  time.Duration // Max wait time
	Polling  time.Duration // Poll interval

	urlRe *regexp.Regexp // compiled URLMatch when Matcher is regex
}

// waitPage is the slice of *browser.Page a wait condition reads. An interface
// so the polling and matching logic is testable without a browser.
type waitPage interface {
	URL() (string, error)
	HasElement(selector string) bool
	ElementVisible(selector string) bool
}

// pageTarget adapts *browser.Page to waitPage.
type pageTarget struct{ page *browser.Page }

func (p pageTarget) URL() (string, error)            { return p.page.URL() }
func (p pageTarget) HasElement(selector string) bool { return p.page.HasElement(selector) }
func (p pageTarget) ElementVisible(selector string) bool {
	elem, err := p.page.Element(selector)
	return err == nil && elem != nil && elem.IsVisible()
}

// NewWaitCondition creates a new wait condition.
func NewWaitCondition(selector string, timeout time.Duration) *WaitCondition {
	return &WaitCondition{
		Selector: selector,
		Visible:  false,
		Timeout:  timeout,
		Polling:  100 * time.Millisecond,
	}
}

// NewWaitConditionFromConfig creates a wait condition from config. The config
// is validated at load (config.Validate), so a regex that fails to compile
// here is unreachable in practice; it is logged and the condition treated as
// never applying rather than panicking.
func NewWaitConditionFromConfig(cfg config.WaitConditionConfig) *WaitCondition {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 500 * time.Millisecond
	}

	w := &WaitCondition{
		URLMatch: cfg.EffectiveURLMatch(),
		Matcher:  cfg.Matcher,
		Selector: cfg.Selector,
		Visible:  cfg.Visible,
		Timeout:  timeout,
		Polling:  100 * time.Millisecond,
	}
	if w.Matcher == config.URLMatchRegex {
		re, err := regexp.Compile(w.URLMatch)
		if err != nil {
			zap.L().Warn("Wait condition URL regex does not compile; condition will not apply",
				zap.String("regex", w.URLMatch), zap.Error(err))
		}
		w.urlRe = re
	}
	return w
}

// ForURL limits the condition to pages whose URL contains substring
// (case-insensitive).
func (w *WaitCondition) ForURL(substring string) *WaitCondition {
	w.URLMatch = substring
	w.Matcher = config.URLMatchSubstring
	w.urlRe = nil
	return w
}

// WithVisibility sets whether to wait for element visibility.
func (w *WaitCondition) WithVisibility(visible bool) *WaitCondition {
	w.Visible = visible
	return w
}

// WithPolling sets the polling interval.
func (w *WaitCondition) WithPolling(d time.Duration) *WaitCondition {
	w.Polling = d
	return w
}

// matchesURL reports whether the condition applies to url.
func (w *WaitCondition) matchesURL(url string) bool {
	if w.URLMatch == "" {
		return true
	}
	if w.Matcher == config.URLMatchRegex {
		return w.urlRe != nil && w.urlRe.MatchString(url)
	}
	return strings.Contains(strings.ToLower(url), strings.ToLower(w.URLMatch))
}

// applies reads the page URL and checks it against the matcher. Prefer
// appliesTo when several conditions are evaluated against the same tick: every
// call here is a CDP round trip for a value that cannot change within a tick.
func (w *WaitCondition) applies(page waitPage) bool {
	if w.URLMatch == "" {
		return true
	}
	url, err := page.URL()
	return err == nil && w.matchesURL(url)
}

// appliesTo checks the condition against a URL already read for this tick.
// urlErr is the error from that read, which disqualifies every URL-scoped
// condition exactly as a failed per-condition read would.
func (w *WaitCondition) appliesTo(url string, urlErr error) bool {
	if w.URLMatch == "" {
		return true
	}
	return urlErr == nil && w.matchesURL(url)
}

// satisfied checks the element once.
func (w *WaitCondition) satisfied(page waitPage) bool {
	if !page.HasElement(w.Selector) {
		return false
	}
	return !w.Visible || page.ElementVisible(w.Selector)
}

// Wait waits for the condition to be satisfied, polling until Timeout or until
// ctx ends — a cancelled crawl stops waiting at once.
// Returns:
//   - WaitSuccess (1): condition was satisfied
//   - WaitTimeout (0): condition timed out
//   - WaitURLMismatch (-1): the page URL does not match, so it does not apply
//   - WaitCancelled (-2): ctx ended first
func (w *WaitCondition) Wait(ctx context.Context, page *browser.Page) WaitResult {
	return w.wait(ctx, pageTarget{page})
}

func (w *WaitCondition) wait(ctx context.Context, page waitPage) WaitResult {
	if ctx.Err() != nil {
		return WaitCancelled
	}
	if !w.applies(page) {
		return WaitURLMismatch
	}
	return pollUntil(ctx, w.Timeout, w.Polling, func() bool { return w.satisfied(page) })
}

// pollUntil checks ok immediately and then every interval until it holds
// (WaitSuccess), timeout elapses (WaitTimeout) or ctx ends (WaitCancelled).
func pollUntil(ctx context.Context, timeout, interval time.Duration, ok func() bool) WaitResult {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if ok() {
			return WaitSuccess
		}
		select {
		case <-ctx.Done():
			return WaitCancelled
		case <-deadline.C:
			return WaitTimeout
		case <-tick.C:
		}
	}
}

// WaitAll waits for all conditions to be satisfied.
// Returns on first failure or when all succeed.
func WaitAll(ctx context.Context, page *browser.Page, conditions ...*WaitCondition) WaitResult {
	for _, c := range conditions {
		result := c.Wait(ctx, page)
		if result != WaitSuccess {
			return result
		}
	}
	return WaitSuccess
}

// WaitAny waits for any condition to be satisfied.
// Returns on first success or when all fail.
func WaitAny(ctx context.Context, page *browser.Page, conditions ...*WaitCondition) WaitResult {
	if len(conditions) == 0 {
		return WaitSuccess
	}
	return waitAny(ctx, pageTarget{page}, conditions)
}

func waitAny(ctx context.Context, page waitPage, conditions []*WaitCondition) WaitResult {
	if ctx.Err() != nil {
		return WaitCancelled
	}
	// Poll every condition until one succeeds, bounded by the longest timeout.
	maxTimeout := time.Duration(0)
	for _, c := range conditions {
		if c.Timeout > maxTimeout {
			maxTimeout = c.Timeout
		}
	}
	// At most one URL read per tick, and none at all when nothing is URL-scoped:
	// page.URL() is a CDP round trip (~1-5ms) for a value that cannot change
	// within a tick, so asking each URL-scoped condition separately spent a real
	// fraction of a 100ms tick re-reading the same string.
	scoped := false
	for _, c := range conditions {
		if c.URLMatch != "" {
			scoped = true
			break
		}
	}
	return pollUntil(ctx, maxTimeout, 100*time.Millisecond, func() bool {
		var url string
		var urlErr error
		if scoped {
			url, urlErr = page.URL()
		}
		for _, c := range conditions {
			if c.appliesTo(url, urlErr) && c.satisfied(page) {
				return true
			}
		}
		return false
	})
}

// WaitForElement is a helper to wait for an element to exist.
func WaitForElement(ctx context.Context, page *browser.Page, selector string, timeout time.Duration) bool {
	return NewWaitCondition(selector, timeout).Wait(ctx, page) == WaitSuccess
}

// WaitForVisible is a helper to wait for an element to be visible.
func WaitForVisible(ctx context.Context, page *browser.Page, selector string, timeout time.Duration) bool {
	cond := NewWaitCondition(selector, timeout)
	cond.Visible = true
	return cond.Wait(ctx, page) == WaitSuccess
}
