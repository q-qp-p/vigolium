package condition

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// stubWaitPage is a page whose URL and element state the test controls.
type stubWaitPage struct {
	url      string
	urlErr   error
	present  atomic.Bool
	visible  atomic.Bool
	hasCalls atomic.Int32
}

func (p *stubWaitPage) URL() (string, error) { return p.url, p.urlErr }
func (p *stubWaitPage) HasElement(string) bool {
	p.hasCalls.Add(1)
	return p.present.Load()
}
func (p *stubWaitPage) ElementVisible(string) bool { return p.visible.Load() }

func TestWaitConditionURLMatchers(t *testing.T) {
	const url = "https://App.example.com/Admin/users?id=7"
	cases := []struct {
		name    string
		cfg     config.WaitConditionConfig
		applies bool
	}{
		{"empty applies everywhere", config.WaitConditionConfig{}, true},
		{"substring case-insensitive", config.WaitConditionConfig{URLMatch: "/admin/"}, true},
		{"substring explicit", config.WaitConditionConfig{URLMatch: "users?id=", Matcher: config.URLMatchSubstring}, true},
		{"substring miss", config.WaitConditionConfig{URLMatch: "/billing"}, false},
		{"substring is literal, not regex", config.WaitConditionConfig{URLMatch: "/Admin/.*"}, false},
		{"deprecated URLPattern alias", config.WaitConditionConfig{URLPattern: "/ADMIN"}, true},                     //nolint:staticcheck // exercises the deprecated alias
		{"URLMatch wins over alias", config.WaitConditionConfig{URLMatch: "/billing", URLPattern: "/admin"}, false}, //nolint:staticcheck // exercises the deprecated alias
		{"regex match", config.WaitConditionConfig{URLMatch: `/Admin/users\?id=\d+$`, Matcher: config.URLMatchRegex}, true},
		{"regex is case-sensitive", config.WaitConditionConfig{URLMatch: `/admin/`, Matcher: config.URLMatchRegex}, false},
		{"regex case-insensitive flag", config.WaitConditionConfig{URLMatch: `(?i)/admin/`, Matcher: config.URLMatchRegex}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			tc.cfg.Selector = "#x"
			page := &stubWaitPage{url: url}
			page.present.Store(true)
			got := NewWaitConditionFromConfig(tc.cfg).wait(context.Background(), page)
			want := WaitURLMismatch
			if tc.applies {
				want = WaitSuccess
			}
			if got != want {
				t.Fatalf("wait = %d, want %d", got, want)
			}
		})
	}
}

func TestWaitConditionConfigValidate(t *testing.T) {
	bad := []config.WaitConditionConfig{
		{URLMatch: "/admin/(", Matcher: config.URLMatchRegex},
		{URLPattern: "[", Matcher: config.URLMatchRegex}, //nolint:staticcheck // exercises the deprecated alias
		{URLMatch: "/admin", Matcher: "glob"},
	}
	for _, wc := range bad {
		if err := wc.Validate(); err == nil {
			t.Errorf("Validate(%+v) = nil, want an error", wc)
		}
	}

	cfg, err := config.New("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	cfg.WaitConditions = append(cfg.WaitConditions, config.WaitConditionConfig{URLMatch: "(", Matcher: config.URLMatchRegex, Selector: "#x"})
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "WaitConditions[0]") {
		t.Fatalf("config.Validate = %v, want an error naming WaitConditions[0]", err)
	}
}

func TestWaitConditionPolling(t *testing.T) {
	t.Run("appears mid-wait", func(t *testing.T) {
		page := &stubWaitPage{}
		go func() {
			time.Sleep(30 * time.Millisecond)
			page.present.Store(true)
		}()
		w := NewWaitCondition("#x", 2*time.Second).WithPolling(5 * time.Millisecond)
		if got := w.wait(context.Background(), page); got != WaitSuccess {
			t.Fatalf("wait = %d, want WaitSuccess", got)
		}
	})
	t.Run("times out", func(t *testing.T) {
		page := &stubWaitPage{}
		w := NewWaitCondition("#x", 40*time.Millisecond).WithPolling(5 * time.Millisecond)
		if got := w.wait(context.Background(), page); got != WaitTimeout {
			t.Fatalf("wait = %d, want WaitTimeout", got)
		}
	})
	t.Run("visibility required", func(t *testing.T) {
		page := &stubWaitPage{}
		page.present.Store(true)
		w := NewWaitCondition("#x", 40*time.Millisecond).WithPolling(5 * time.Millisecond).WithVisibility(true)
		if got := w.wait(context.Background(), page); got != WaitTimeout {
			t.Fatalf("present but hidden: wait = %d, want WaitTimeout", got)
		}
		page.visible.Store(true)
		if got := w.wait(context.Background(), page); got != WaitSuccess {
			t.Fatalf("visible: wait = %d, want WaitSuccess", got)
		}
	})
	t.Run("checked once even with a zero timeout", func(t *testing.T) {
		page := &stubWaitPage{}
		page.present.Store(true)
		if got := NewWaitCondition("#x", 0).wait(context.Background(), page); got != WaitSuccess {
			t.Fatalf("wait = %d, want WaitSuccess", got)
		}
	})
	t.Run("URL read failure does not apply", func(t *testing.T) {
		page := &stubWaitPage{urlErr: errors.New("page gone")}
		page.present.Store(true)
		if got := NewWaitCondition("#x", time.Second).ForURL("/a").wait(context.Background(), page); got != WaitURLMismatch {
			t.Fatalf("wait = %d, want WaitURLMismatch", got)
		}
	})
}

// TestWaitConditionCancellation: a cancelled crawl stops waiting at once, both
// before the first check and mid-poll, and reports neither success nor timeout.
func TestWaitConditionCancellation(t *testing.T) {
	t.Run("already cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		page := &stubWaitPage{}
		start := time.Now()
		if got := NewWaitCondition("#x", time.Minute).wait(ctx, page); got != WaitCancelled {
			t.Fatalf("wait = %d, want WaitCancelled", got)
		}
		if el := time.Since(start); el > 100*time.Millisecond {
			t.Fatalf("cancelled wait took %v", el)
		}
		if page.hasCalls.Load() != 0 {
			t.Error("a cancelled wait still queried the page")
		}
	})
	t.Run("cancelled mid-poll", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(30*time.Millisecond, cancel)
		start := time.Now()
		got := NewWaitCondition("#x", time.Minute).WithPolling(5*time.Millisecond).wait(ctx, &stubWaitPage{})
		if got != WaitCancelled {
			t.Fatalf("wait = %d, want WaitCancelled", got)
		}
		if el := time.Since(start); el > time.Second {
			t.Fatalf("wait outlived its context by %v", el)
		}
	})
	t.Run("WaitAny", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(30*time.Millisecond, cancel)
		conds := []*WaitCondition{NewWaitCondition("#a", time.Minute), NewWaitCondition("#b", time.Minute)}
		if got := waitAny(ctx, &stubWaitPage{}, conds); got != WaitCancelled {
			t.Fatalf("waitAny = %d, want WaitCancelled", got)
		}
	})
}

func TestWaitAnyStub(t *testing.T) {
	page := &stubWaitPage{url: "https://example.com/dash"}
	page.present.Store(true)
	conds := []*WaitCondition{
		NewWaitCondition("#a", 50*time.Millisecond).ForURL("/other"),
		NewWaitCondition("#b", 50*time.Millisecond).ForURL("/dash"),
	}
	if got := waitAny(context.Background(), page, conds); got != WaitSuccess {
		t.Fatalf("waitAny = %d, want WaitSuccess", got)
	}
	if got := waitAny(context.Background(), page, conds[:1]); got != WaitTimeout {
		t.Fatalf("waitAny (only non-matching URL) = %d, want WaitTimeout", got)
	}
}
