package condition

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// TestNewWaitCondition verifies default field values.
func TestNewWaitCondition(t *testing.T) {
	w := NewWaitCondition("#main", 2*time.Second)
	if w.Selector != "#main" {
		t.Errorf("Selector = %q, want %q", w.Selector, "#main")
	}
	if w.Timeout != 2*time.Second {
		t.Errorf("Timeout = %v, want %v", w.Timeout, 2*time.Second)
	}
	if w.Visible {
		t.Error("Visible should default to false")
	}
	if w.URLMatch != "" {
		t.Errorf("URLMatch = %q, want empty", w.URLMatch)
	}
	if w.Polling != 100*time.Millisecond {
		t.Errorf("Polling = %v, want %v", w.Polling, 100*time.Millisecond)
	}
}

// TestNewWaitConditionFromConfig verifies config translation, including the
// default timeout when none is supplied.
func TestNewWaitConditionFromConfig(t *testing.T) {
	t.Run("explicit timeout", func(t *testing.T) {
		cfg := config.WaitConditionConfig{
			URLPattern: "/dashboard", //nolint:staticcheck // the deprecated alias must still be honored
			Selector:   "#widget",
			Visible:    true,
			Timeout:    3 * time.Second,
		}
		w := NewWaitConditionFromConfig(cfg)
		if w.URLMatch != "/dashboard" {
			t.Errorf("URLMatch = %q, want %q (deprecated URLPattern carried over)", w.URLMatch, "/dashboard")
		}
		if w.Selector != "#widget" {
			t.Errorf("Selector = %q, want %q", w.Selector, "#widget")
		}
		if !w.Visible {
			t.Error("Visible = false, want true")
		}
		if w.Timeout != 3*time.Second {
			t.Errorf("Timeout = %v, want %v", w.Timeout, 3*time.Second)
		}
	})

	t.Run("default timeout", func(t *testing.T) {
		w := NewWaitConditionFromConfig(config.WaitConditionConfig{Selector: "#x"})
		if w.Timeout != 500*time.Millisecond {
			t.Errorf("Timeout = %v, want %v (default)", w.Timeout, 500*time.Millisecond)
		}
	})
}

// TestWaitConditionBuilders verifies the fluent setters.
func TestWaitConditionBuilders(t *testing.T) {
	w := NewWaitCondition("#x", time.Second).
		ForURL("/admin").
		WithVisibility(true).
		WithPolling(50 * time.Millisecond)

	if w.URLMatch != "/admin" || w.Matcher != config.URLMatchSubstring {
		t.Errorf("URLMatch = %q (matcher %q), want %q (substring)", w.URLMatch, w.Matcher, "/admin")
	}
	if !w.Visible {
		t.Error("Visible = false, want true")
	}
	if w.Polling != 50*time.Millisecond {
		t.Errorf("Polling = %v, want %v", w.Polling, 50*time.Millisecond)
	}
}

// TestWaitResultConstants documents the result code values.
func TestWaitResultConstants(t *testing.T) {
	if WaitSuccess != 1 {
		t.Errorf("WaitSuccess = %d, want 1", WaitSuccess)
	}
	if WaitTimeout != 0 {
		t.Errorf("WaitTimeout = %d, want 0", WaitTimeout)
	}
	if WaitURLMismatch != -1 {
		t.Errorf("WaitURLMismatch = %d, want -1", WaitURLMismatch)
	}
}

// TestWaitAnyEmpty verifies WaitAny with no conditions returns success without
// touching the page.
func TestWaitAnyEmpty(t *testing.T) {
	if got := WaitAny(context.Background(), nil); got != WaitSuccess {
		t.Errorf("WaitAny() with no conditions = %d, want WaitSuccess", got)
	}
}
