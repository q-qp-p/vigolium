package crawler

import (
	"errors"
	"strings"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"go.uber.org/zap"
)

// ErrActionNotPermitted is returned when the interaction policy forbids an
// action the crawl selected. The action is consumed — never retried, never
// counted as a failure — and the denial is counted in Stats.FormSubmitsPrevented.
var ErrActionNotPermitted = errors.New("action not permitted by the interaction policy")

// Submission mechanisms. Every path that dispatches a form submission counts it
// through countSubmitDispatched with one of these, so Stats.FormsSubmitted is
// the total across all of them; a drift-guard test fails when a mechanism is
// added without a call site, or a call site uses a name outside this table.
const (
	submitMechClick        = "click"         // a submit control clicked by the interaction crawl
	submitMechEnter        = "enter"         // an Enter-key action
	submitMechGetSynthesis = "get-synthesis" // a GET form's submit URL synthesized and fetched
	submitMechPostTrigger  = "post-trigger"  // a POST form triggered (page handler or fallback)
	submitMechLoginAttempt = "login-attempt" // a credential pair submitted to a login form
	submitMechRegister     = "register"      // a signup form submitted
)

// submitMechanisms is the closed set of mechanism names.
var submitMechanisms = []string{
	submitMechClick, submitMechEnter, submitMechGetSynthesis,
	submitMechPostTrigger, submitMechLoginAttempt, submitMechRegister,
}

// countSubmitDispatched adds n dispatched form submissions for mechanism. The
// only writer of Stats.FormsSubmitted.
func (c *Crawler) countSubmitDispatched(mechanism string, n int) {
	if n <= 0 {
		return
	}
	c.mu.Lock()
	c.stats.FormsSubmitted += n
	c.mu.Unlock()
	zap.L().Debug("Form submission dispatched", zap.String("mechanism", mechanism), zap.Int("count", n))
}

// submitLikeCandidate reports whether dispatching candidate natively submits a
// form: an <input type=submit|image>, or a <button> whose type is submit —
// which is also what a missing or unrecognized type means. It reads only the
// already-extracted tag and attributes, so it needs no page. A button outside
// any form is inert, so treating it as submit-like costs at most one harmless
// skipped click when submits are denied; the reverse error would submit.
//
// Script-driven submissions from other elements (a div whose handler calls
// form.submit()) are not visible here; the page-level submit guard installed
// when submits are denied (browser.submitGuardScript) covers those.
func submitLikeCandidate(c *action.CandidateElement) bool {
	if c == nil {
		return false
	}
	typ := strings.ToLower(strings.TrimSpace(attrValue(c.Attributes, "type")))
	switch strings.ToLower(c.TagName) {
	case "input":
		return typ == "submit" || typ == "image"
	case "button":
		return typ != "button" && typ != "reset"
	}
	return false
}

// attrValue returns the value of name in an extracted attribute string — the
// sorted, space-joined "name=value" list Element.GetAllAttributes produces.
func attrValue(attrs, name string) string {
	prefix := name + "="
	for _, tok := range strings.Fields(attrs) {
		if strings.HasPrefix(strings.ToLower(tok), prefix) {
			return tok[len(prefix):]
		}
	}
	return ""
}

// checkSubmitPermitted is the dispatch gate for the interaction crawl: an
// Enter action, or a click on a submit-like control, is refused when the policy
// denies form submission. Needs no page — the decision is made from the
// candidate before anything is filled or clicked.
func (c *Crawler) checkSubmitPermitted(candidate *action.CandidateElement, eventType action.EventType) error {
	if c.config == nil || c.config.Policy.SubmitForms {
		return nil
	}
	submits := eventType == action.EventTypeEnter ||
		(eventType == action.EventTypeClick && submitLikeCandidate(candidate))
	if !submits {
		return nil
	}
	c.mu.Lock()
	c.stats.FormSubmitsPrevented++
	c.mu.Unlock()
	tag := ""
	if candidate != nil {
		tag = candidate.TagName
	}
	zap.L().Debug("Form submission not permitted by policy",
		zap.String("event", string(eventType)), zap.String("tag", tag))
	return ErrActionNotPermitted
}
