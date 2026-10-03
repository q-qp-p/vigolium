package crawler

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

func cand(tag, attrs string) *action.CandidateElement {
	return &action.CandidateElement{TagName: tag, Attributes: attrs}
}

func TestSubmitLikeCandidate(t *testing.T) {
	cases := []struct {
		name string
		c    *action.CandidateElement
		want bool
	}{
		{"input submit", cand("input", "name=go type=submit value=Go"), true},
		{"input image", cand("input", "src=/b.png type=image"), true},
		{"input submit upper", cand("INPUT", "type=SUBMIT"), true},
		{"input button", cand("input", "type=button value=Go"), false},
		{"input text", cand("input", "name=q type=text"), false},
		{"button no type", cand("button", "class=btn"), true},
		{"button type submit", cand("button", "type=submit"), true},
		{"button type button", cand("button", "onclick=go() type=button"), false},
		{"button type reset", cand("button", "type=reset"), false},
		{"button invalid type is submit", cand("button", "type=bogus"), true},
		{"anchor", cand("a", "href=/next"), false},
		{"div role=button", cand("div", "role=button"), false},
		{"div role=button form attr", cand("div", "form=f1 role=button"), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := submitLikeCandidate(c.c); got != c.want {
			t.Errorf("%s: submitLikeCandidate = %v, want %v", c.name, got, c.want)
		}
	}
}

func policyCrawler(p config.InteractionPolicy) *Crawler {
	cfg, _ := config.New("https://example.com")
	cfg.ApplyPolicy(p)
	return &Crawler{config: cfg}
}

func TestCheckSubmitPermitted(t *testing.T) {
	deny := policyCrawler(config.InteractionPolicy{EditFields: true})
	if err := deny.checkSubmitPermitted(cand("input", "type=submit"), action.EventTypeClick); !errors.Is(err, ErrActionNotPermitted) {
		t.Errorf("submit click under deny: err = %v, want ErrActionNotPermitted", err)
	}
	if err := deny.checkSubmitPermitted(cand("input", "type=text"), action.EventTypeEnter); !errors.Is(err, ErrActionNotPermitted) {
		t.Errorf("enter under deny: err = %v, want ErrActionNotPermitted", err)
	}
	if err := deny.checkSubmitPermitted(cand("a", "href=/x"), action.EventTypeClick); err != nil {
		t.Errorf("link click under deny must pass, got %v", err)
	}
	if err := deny.checkSubmitPermitted(cand("button", ""), action.EventTypeHover); err != nil {
		t.Errorf("hover is never a submission, got %v", err)
	}
	if got := deny.stats.FormSubmitsPrevented; got != 2 {
		t.Errorf("FormSubmitsPrevented = %d, want 2", got)
	}
	if deny.stats.FormsSubmitted != 0 {
		t.Errorf("a denied submission must not count as dispatched")
	}

	allow := policyCrawler(config.DefaultInteractionPolicy())
	if err := allow.checkSubmitPermitted(cand("input", "type=submit"), action.EventTypeClick); err != nil {
		t.Errorf("submit click under allow: %v", err)
	}
	if allow.stats.FormSubmitsPrevented != 0 {
		t.Errorf("allow must not count a prevention")
	}
}

// TestSubmissionSynthesisGatedByPolicy: with submits denied, both synthesis
// passes return before touching the page. A zero browser.Page has no rod page
// behind it, so reaching any page call would panic.
func TestSubmissionSynthesisGatedByPolicy(t *testing.T) {
	c := policyCrawler(config.InteractionPolicy{EditFields: true})
	page := &browser.Page{}
	c.submitGetForms(t.Context(), page, true)
	c.submitPostForms(t.Context(), page, true)
	if c.stats.FormsSubmitted != 0 {
		t.Errorf("FormsSubmitted = %d, want 0", c.stats.FormsSubmitted)
	}

	// A config whose mechanism switch was left on while the permission is off
	// (not reachable through ApplyPolicy) is still refused.
	c.config.SubmitGetForms, c.config.SubmitPostForms = true, true
	c.submitGetForms(t.Context(), page, true)
	c.submitPostForms(t.Context(), page, true)
}

func TestCountSubmitDispatched(t *testing.T) {
	c := &Crawler{}
	c.countSubmitDispatched(submitMechGetSynthesis, 3)
	c.countSubmitDispatched(submitMechClick, 1)
	c.countSubmitDispatched(submitMechPostTrigger, 0)
	if c.stats.FormsSubmitted != 4 {
		t.Errorf("FormsSubmitted = %d, want 4", c.stats.FormsSubmitted)
	}
}

// TestSubmitMechanismDriftGuard keeps the counter honest: every mechanism in the
// table has a call site, every call site names a mechanism from the table, and
// nothing else writes FormsSubmitted.
func TestSubmitMechanismDriftGuard(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	constOf := map[string]string{
		"submitMechClick": submitMechClick, "submitMechEnter": submitMechEnter,
		"submitMechGetSynthesis": submitMechGetSynthesis, "submitMechPostTrigger": submitMechPostTrigger,
		"submitMechLoginAttempt": submitMechLoginAttempt, "submitMechRegister": submitMechRegister,
	}
	callRe := regexp.MustCompile(`countSubmitDispatched\((\w+),`)
	writeRe := regexp.MustCompile(`stats\.FormsSubmitted\s*(\+\+|\+=|=)`)
	used := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range callRe.FindAllStringSubmatch(string(src), -1) {
			mech, ok := constOf[m[1]]
			if !ok {
				t.Errorf("%s: countSubmitDispatched called with %s, not a submitMech* constant", f, m[1])
				continue
			}
			used[mech] = true
		}
		if f != "crawler_policy.go" && writeRe.Match(src) {
			t.Errorf("%s writes stats.FormsSubmitted directly; go through countSubmitDispatched", f)
		}
	}
	var got []string
	for m := range used {
		got = append(got, m)
	}
	sort.Strings(got)
	want := slices.Clone(submitMechanisms)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Errorf("mechanisms with a call site = %v, table = %v", got, want)
	}
	if len(constOf) != len(submitMechanisms) {
		t.Errorf("test constant map is stale: %d entries, table has %d", len(constOf), len(submitMechanisms))
	}
}
