package crawler

import (
	"fmt"
	"strings"
	"testing"
)

func TestSelectUnsubmittedPostFormsDedupBySignature(t *testing.T) {
	c := &Crawler{}
	// A stock-check form that recurs on every product page: same action + same field
	// names → one signature → submitted once even though it appears many times.
	descs := []postFormDescriptor{
		{Index: 0, Sig: "https://x.test/catalog/product/stock post productId,storeId"},
		{Index: 1, Sig: "https://x.test/catalog/product/stock post productId,storeId"},
		{Index: 2, Sig: "https://x.test/catalog/subscribe post email"},
	}
	got := c.selectUnsubmittedPostForms(descs, 0)
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct signatures, got %d (%v)", len(got), got)
	}
	// The duplicate stock form (index 1) must be dropped; index 0 kept.
	if got[0] != 0 || got[1] != 2 {
		t.Errorf("expected indices [0 2], got %v", got)
	}
	// Re-submitting the same forms across a later page adds nothing (crawl-wide dedup).
	if again := c.selectUnsubmittedPostForms(descs, 0); len(again) != 0 {
		t.Errorf("expected 0 on re-submit, got %d (%v)", len(again), again)
	}
}

func TestSelectUnsubmittedPostFormsSharesCapWithGetForms(t *testing.T) {
	c := &Crawler{}
	// The GET-form budget and the POST-form budget share config.SubmitFormMaxVariants:
	// selectUnsubmittedForms fills two GET slots, leaving one before the cap of 3.
	if got := c.selectUnsubmittedForms([]string{"https://x.test/a?q=1", "https://x.test/b?q=1"}, 3); len(got) != 2 {
		t.Fatalf("expected 2 GET forms selected, got %d", len(got))
	}
	descs := []postFormDescriptor{
		{Index: 0, Sig: "https://x.test/one post a"},
		{Index: 1, Sig: "https://x.test/two post b"},
	}
	got := c.selectUnsubmittedPostForms(descs, 3)
	if len(got) != 1 {
		t.Fatalf("expected the shared cap (3) to leave room for exactly 1 POST form, got %d (%v)", len(got), got)
	}
}

func TestSelectUnsubmittedPostFormsSkipsEmptySignature(t *testing.T) {
	c := &Crawler{}
	descs := []postFormDescriptor{
		{Index: 0, Sig: ""},
		{Index: 1, Sig: "https://x.test/real post name"},
	}
	got := c.selectUnsubmittedPostForms(descs, 0)
	if len(got) != 1 || got[0] != 1 {
		t.Fatalf("expected only the non-empty signature (index 1), got %v", got)
	}
}

func postFormCrawler() (*Crawler, []postFormDescriptor, []int) {
	c := &Crawler{}
	descs := []postFormDescriptor{
		{Index: 0, Sig: "https://x.test/stock post productId"},
		{Index: 1, Sig: "https://x.test/plain post q"},
		{Index: 2, Sig: "https://x.test/subscribe post email"},
		{Index: 3, Sig: "https://x.test/late post a"},
		{Index: 4, Sig: "https://x.test/broken post b"},
		{Index: 5, Sig: "https://x.test/silent post c"},
	}
	return c, descs, c.selectUnsubmittedPostForms(descs, 0)
}

// TestApplyPostFormOutcomes covers each outcome's accounting: dispatched
// submissions are counted, uncertain ones are counted separately and stay
// consumed (no later page may retry them — the duplicate write the outcome
// exists to avoid), and only a never-triggered form is released.
func TestApplyPostFormOutcomes(t *testing.T) {
	c, descs, approved := postFormCrawler()
	c.applyPostFormOutcomes(descs, approved, []postFormOutcome{
		{Index: 0, Action: "https://x.test/stock", Outcome: postOutcomeHandler},
		{Index: 1, Action: "https://x.test/plain", Outcome: postOutcomeFallback},
		{Index: 2, Action: "https://x.test/subscribe", Outcome: postOutcomeUncertain},
		{Index: 3, Action: "https://x.test/late", Outcome: postOutcomeNotTriggered},
		{Index: 4, Action: "https://x.test/broken", Outcome: postOutcomeFallbackFailed},
		// index 5 unreported → uncertain
	})
	if c.stats.FormsSubmitted != 2 {
		t.Errorf("FormsSubmitted = %d, want 2 (handler + fallback)", c.stats.FormsSubmitted)
	}
	if c.stats.FormSubmitsUncertain != 2 {
		t.Errorf("FormSubmitsUncertain = %d, want 2 (reported uncertain + unreported)", c.stats.FormSubmitsUncertain)
	}

	again := c.selectUnsubmittedPostForms(descs, 0)
	if len(again) != 1 || again[0] != 3 {
		t.Errorf("only the not-triggered form may be selected again, got %v", again)
	}
}

// TestApplyPostFormOutcomes_EvalLost: when the trigger eval returns nothing
// usable, every approved form is uncertain and none is retried.
func TestApplyPostFormOutcomes_EvalLost(t *testing.T) {
	c, descs, approved := postFormCrawler()
	outcomes, ok := parsePostFormOutcomes(nil)
	if ok || outcomes != nil {
		t.Fatalf("parse(nil) = %v, %v", outcomes, ok)
	}
	c.applyPostFormOutcomes(descs, approved, nil)
	if c.stats.FormSubmitsUncertain != len(approved) || c.stats.FormsSubmitted != 0 {
		t.Errorf("uncertain=%d submitted=%d, want %d and 0", c.stats.FormSubmitsUncertain, c.stats.FormsSubmitted, len(approved))
	}
	if again := c.selectUnsubmittedPostForms(descs, 0); len(again) != 0 {
		t.Errorf("no form may be retried after a lost eval, got %v", again)
	}
}

func TestParsePostFormOutcomes(t *testing.T) {
	got, ok := parsePostFormOutcomes(`[{"i":2,"action":"https://x.test/a","outcome":"uncertain"}]`)
	if !ok || len(got) != 1 || got[0].Index != 2 || got[0].Outcome != postOutcomeUncertain {
		t.Errorf("parse = %+v, %v", got, ok)
	}
	for _, bad := range []interface{}{"", "<nil>", "not json", 3} {
		if _, ok := parsePostFormOutcomes(bad); ok {
			t.Errorf("parse(%v) must fail", bad)
		}
	}
}

// TestSubmitPostFormsScriptShape is a source-shape guard on the in-page half,
// which needs a browser to exercise (formsubmit_integration_test.go does): the
// decision must not be a single-tick wait, a request must be attributed to the
// form's action before it counts, and the fallback must sit behind both the
// attributed and the unattributed checks.
func TestSubmitPostFormsScriptShape(t *testing.T) {
	s := submitPostFormsScript
	if strings.Contains(s, "setTimeout(r, 0)") {
		t.Error("the outcome must not be decided after a single tick")
	}
	for _, want := range []string{"underPath(url.pathname, current.action.pathname)", "graceMs", "deadline", "setTimeout(r, 25)"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lost %q", want)
		}
	}
	attributed := strings.Index(s, "if (rec.attributed > 0)")
	unattributed := strings.Index(s, "if (rec.other > 0)")
	fallback := strings.Index(s, "outcome: 'fallback_sent'")
	if attributed == -1 || unattributed == -1 || fallback == -1 {
		t.Fatal("outcome branches not found; update this guard")
	}
	if attributed >= fallback || unattributed >= fallback {
		t.Error("the fallback POST must come after both the attributed and the uncertain checks")
	}
	for _, o := range []string{postOutcomeHandler, postOutcomeFallback, postOutcomeFallbackFailed, postOutcomeUncertain, postOutcomeNotTriggered} {
		if !strings.Contains(s, "'"+o+"'") {
			t.Errorf("script never reports outcome %q", o)
		}
	}
	if got := fmt.Sprintf(s, "[0,1]", 750, 45000); strings.Contains(got, "%!") {
		t.Errorf("format verbs do not match the arguments: %s", got[:120])
	}
}
