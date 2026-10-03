package crawler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/fragment"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// Result holds the complete crawl result.
type Result struct {
	Config    *config.Config
	Graph     *state.Graph
	Stats     Stats
	Fragments fragment.FragmentStats
	Session   *CrawlSession

	// HarvestedCookies is the browser's cookie jar at end of crawl (including any
	// WAF/bot clearance cookies the real browser earned). BrowserUserAgent is the
	// UA the browser presented. Both are carried forward so later scan phases can
	// inherit the cleared session. Empty when harvesting was unavailable.
	HarvestedCookies []*http.Cookie
	BrowserUserAgent string

	// HarvestedAuthorization is a JWT/Bearer token read from the app's client
	// storage after a confirmed default-credential login (bare, no "Bearer "
	// prefix). Token-based SPAs send it as an Authorization header rather than a
	// cookie, so it is carried forward separately. Empty when no login succeeded.
	HarvestedAuthorization string

	// DOMXssFindings holds browser-confirmed DOM-based XSS on reflected client
	// routes discovered during the crawl. The runner emits these as findings.
	DOMXssFindings []DOMXssFinding
}

// Summary returns a text summary of the crawl.
func (r *Result) Summary() string {
	duration := r.Stats.EndTime.Sub(r.Stats.StartTime)

	return fmt.Sprintf(`Crawl Summary
=============
URL: %s
Duration: %s

States:
  - Discovered: %d
  - Duplicate: %d

Actions:
  - Executed: %d
  - Failed: %d
  - Forms Submitted: %d (prevented by policy: %d, uncertain: %d)

Fragments:
  - Total: %d
  - Dynamic: %d
  - Static: %d
`,
		r.Config.URL.String(),
		duration.Round(time.Second),
		r.Stats.StatesDiscovered,
		r.Stats.StatesDuplicate,
		r.Stats.ActionsExecuted,
		r.Stats.ActionsFailed,
		r.Stats.FormsSubmitted,
		r.Stats.FormSubmitsPrevented,
		r.Stats.FormSubmitsUncertain,
		r.Fragments.TotalFragments,
		r.Fragments.DynamicFragments,
		r.Fragments.StaticFragments,
	)
}

// StateCount returns the number of states.
func (r *Result) StateCount() int {
	return r.Graph.StateCount()
}

// EdgeCount returns the number of edges.
func (r *Result) EdgeCount() int {
	return r.Graph.EdgeCount()
}

// Duration returns the crawl duration.
func (r *Result) Duration() time.Duration {
	return r.Stats.EndTime.Sub(r.Stats.StartTime)
}

// Success returns true if crawl completed successfully.
func (r *Result) Success() bool {
	return r.Stats.StatesDiscovered > 0 && r.Stats.ActionsFailed < r.Stats.ActionsExecuted
}

// GetState returns a state by ID.
func (r *Result) GetState(id string) (*state.State, bool) {
	return r.Graph.GetState(id)
}

// GetIndexState returns the index state.
func (r *Result) GetIndexState() *state.State {
	return r.Graph.GetIndexState()
}

// PathBetween finds the shortest path between two states.
func (r *Result) PathBetween(sourceID, targetID string) []*action.Eventable {
	return r.Graph.ShortestPath(sourceID, targetID)
}
