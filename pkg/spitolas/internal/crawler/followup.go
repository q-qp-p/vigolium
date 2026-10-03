package crawler

import (
	"context"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
	"go.uber.org/zap"
)

// followUpMaxRevisits bounds how many distinct locations a follow-up pass
// re-visits. Re-extraction is a navigation apiece, so on a large graph the pass
// has to sample; states are visited in discovery order, which puts the seed
// neighbourhood — where a newly-unlocked navigation actually appears — first.
const followUpMaxRevisits = 150

// failedAction is an action that errored and the state it was queued under, so
// the retry sweep can put it back where it came from.
type failedAction struct {
	act     *action.CandidateCrawlAction
	stateID string
}

// runFollowUpPasses re-walks the application after the queue has drained.
//
// The first pass sees the application as it was when each state was captured,
// and actions unlock state out of order: a navigation item that only renders
// once a preference is set, a section that appears after a form is submitted,
// an entire authenticated menu that appears after a login or registration that
// happened halfway through the crawl. Every state captured before that point
// was extracted against the old view and its new actions were never queued.
//
// A pass re-visits known locations and re-extracts. Per-state click-once dedup
// means only genuinely new elements are added, so a pass that finds nothing
// costs navigations and stops — and stops the sequence with it, since a second
// pass over an unchanged application would find nothing either.
func (c *Crawler) runFollowUpPasses(ctx context.Context) {
	if c.config == nil || c.config.FollowUpPasses <= 0 {
		return
	}
	for pass := 0; pass < c.config.FollowUpPasses; pass++ {
		// Covers budget exhaustion, the state cap, and a failure streak: if the
		// crawl stopped for any of those, another sweep is not wanted.
		if c.shouldTerminate(ctx) {
			return
		}
		added := c.reExtractKnownStates(ctx)
		if added == 0 {
			zap.L().Debug("Follow-up pass found no new actions, stopping", zap.Int("pass", pass+1))
			return
		}

		c.mu.Lock()
		c.stats.FollowUpPassesRun++
		c.mu.Unlock()
		zap.L().Info("Spidering: follow-up pass queued newly-available actions",
			zap.Int("pass", pass+1), zap.Int("actions", added))

		if err := c.crawlLoop(ctx); err != nil {
			zap.L().Debug("Follow-up crawl loop ended", zap.Error(err))
			return
		}
	}
}

// reExtractKnownStates re-visits known locations and queues any actions that
// were not available the first time. Returns how many were added.
//
// Locations are deduplicated by URL: a single-page app mints many states behind
// one URL, and navigating to it once per state would pay the same navigation
// repeatedly for one re-extraction's worth of information.
func (c *Crawler) reExtractKnownStates(ctx context.Context) int {
	page := c.browser.CurrentPage()
	if page == nil {
		return 0
	}

	seenURL := make(map[string]bool)
	added, visited := 0, 0

	for _, s := range c.graph.AllStates() {
		if visited >= followUpMaxRevisits || c.shouldTerminate(ctx) {
			break
		}
		if s == nil || s.URL == "" || seenURL[s.URL] {
			continue
		}
		// A state already at the depth cap contributes no further actions.
		if c.config.MaxDepth > 0 && s.Depth >= c.config.MaxDepth {
			continue
		}
		seenURL[s.URL] = true

		if err := page.NavigateCtx(ctx, s.URL); err != nil {
			zap.L().Debug("Follow-up revisit failed", zap.String("url", s.URL), zap.Error(err))
			continue
		}
		visited++
		// Gated rather than unconditional: this loop pays a navigation per
		// location already, and most revisits land on a page that is done
		// rendering by the time NavigateCtx returns.
		c.settleBeforeCapture(ctx, page, "")
		if !c.isInScope(page) || !c.shouldCrawl(page) {
			continue
		}

		targetID := c.followUpTargetState(ctx, page, s)
		c.extractor.SetCurrentState(targetID)
		actions, err := c.extractor.Extract(ctx, page)
		if err != nil || len(actions) == 0 {
			continue
		}
		c.candidates.AddActions(actions, targetID)
		added += len(actions)
		zap.L().Debug("Follow-up re-extraction found new actions",
			zap.String("url", s.URL), zap.Int("count", len(actions)))
	}

	zap.L().Debug("Follow-up re-extraction complete",
		zap.Int("locations_visited", visited), zap.Int("actions_added", added))
	return added
}

// followUpTargetState returns the ID of the state a revisit of s.URL actually
// rendered, which is where its re-extracted actions must be queued.
//
// Loading a state's URL does not always reproduce that state: a state reached
// by an in-page action (an AJAX swap, a "#" link) records the URL it was
// reached on, and loading that URL renders the page it started from. Queued
// under s, the base page's actions would be replayed against s's DOM, where
// the same XPaths name different elements — wrong clicks and edges labelled
// with the wrong element. A DOM matching no known state is the case the pass
// exists for (the location has new content), so it stays attributed to s.
func (c *Crawler) followUpTargetState(ctx context.Context, page *browser.Page, s *state.State) string {
	rendered, err := c.captureState(ctx, page, s.Depth)
	if err != nil || rendered.ID == s.ID {
		return s.ID
	}
	if known, ok := c.graph.GetState(rendered.ID); ok {
		zap.L().Debug("Follow-up revisit rendered a different known state",
			zap.String("url", s.URL), zap.String("revisited", s.Name), zap.String("rendered", known.Name))
		return known.ID
	}
	return s.ID
}

// recordFailedAction remembers an action the crawl gave up on so the retry sweep
// can re-attempt it. Only called for actions being dropped for good — an action
// the normal path already re-queued does not belong here.
func (c *Crawler) recordFailedAction(act *action.CandidateCrawlAction, stateID string) {
	if act == nil || stateID == "" || c.config == nil || !c.config.RetryFailedActions {
		return
	}
	c.failedActionsMu.Lock()
	defer c.failedActionsMu.Unlock()
	if len(c.failedActions) >= c.config.RetryMaxActions {
		return
	}
	c.failedActions = append(c.failedActions, failedAction{act: act, stateID: stateID})
}

// takeFailedActions drains the recorded failures.
func (c *Crawler) takeFailedActions() []failedAction {
	c.failedActionsMu.Lock()
	defer c.failedActionsMu.Unlock()
	out := c.failedActions
	c.failedActions = nil
	return out
}

// retryFailedActions re-attempts the actions the crawl gave up on.
//
// A click fails for reasons that mostly have nothing to do with the element: a
// consent or chat overlay covering it, a node detached by a re-render between
// extraction and click, a route still loading. Those conditions are gone by the
// end of the crawl, and whatever the element guarded — often a whole section —
// was silently dropped with it. Re-queueing them and running the loop once more
// recovers that at the cost of a bounded number of clicks.
//
// The element's direct-access and disabled-input marks are left as the first
// attempt set them, so the retry is the cheap variant (no form fill) rather than
// a replay of the attempt that already failed.
func (c *Crawler) retryFailedActions(ctx context.Context) {
	if c.config == nil || !c.config.RetryFailedActions {
		return
	}
	// A failure streak means the application is not answering, which no retry
	// fixes; budget exhaustion means there is nothing to spend.
	if c.shouldTerminate(ctx) {
		return
	}

	pending := c.takeFailedActions()
	if len(pending) == 0 {
		return
	}

	for _, f := range pending {
		c.candidates.ReAddAction(f.act, f.stateID)
	}

	c.mu.Lock()
	c.stats.ActionsRetried = len(pending)
	executedBefore := c.stats.ActionsExecuted
	c.mu.Unlock()

	zap.L().Info("Spidering: retrying actions that failed mid-crawl",
		zap.Int("count", len(pending)))

	if err := c.crawlLoop(ctx); err != nil {
		zap.L().Debug("Retry crawl loop ended", zap.Error(err))
	}

	c.mu.Lock()
	recovered := c.stats.ActionsExecuted - executedBefore
	if recovered > 0 {
		c.stats.ActionsRecovered = recovered
	}
	c.mu.Unlock()

	if recovered > 0 {
		zap.L().Info("Spidering: recovered actions on retry", zap.Int("count", recovered))
	}
}
