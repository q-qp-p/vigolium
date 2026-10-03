package source

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

// TestBuildDeparosConfigCarriesEgressSeam pins the plumbing: the source's own
// counter (not a per-target one) and the caller's egress filter both reach the
// engine config. A per-target counter would reset every target and report the
// last target's traffic as the phase's total.
func TestBuildDeparosConfigCarriesEgressSeam(t *testing.T) {
	filter := func(u *url.URL) bool { return !strings.HasPrefix(u.Path, "/admin") }
	d, err := NewDeparosDiscoverySource(context.Background(), DeparosDiscoveryConfig{
		Targets:       []string{"https://example.com"},
		RequestFilter: filter,
	})
	if err != nil {
		t.Fatalf("construct source: %v", err)
	}

	cfg := d.buildDeparosConfig("https://example.com")
	if cfg.Engine.RequestFilter == nil {
		t.Fatal("the engine config did not receive the request filter")
	}
	excluded, _ := url.Parse("https://example.com/admin")
	if cfg.Engine.RequestFilter(excluded) {
		t.Fatal("the filter that reached the engine is not the one configured")
	}
	if cfg.Engine.RequestCounter != &d.requestsSent {
		t.Fatal("the engine must count into the SOURCE's counter, not a per-target one")
	}

	// Every target shares the same counter, so the phase total survives the walk.
	second := d.buildDeparosConfig("https://other.example.com")
	if second.Engine.RequestCounter != cfg.Engine.RequestCounter {
		t.Fatal("two targets got two different counters")
	}
}

func TestBuildDeparosConfigWithoutFilter(t *testing.T) {
	d, err := NewDeparosDiscoverySource(context.Background(), DeparosDiscoveryConfig{
		Targets: []string{"https://example.com"},
	})
	if err != nil {
		t.Fatalf("construct source: %v", err)
	}
	if cfg := d.buildDeparosConfig("https://example.com"); cfg.Engine.RequestFilter != nil {
		t.Fatal("no filter configured must mean no filter on the engine")
	}
}

func TestRequestsSentReadsTheCounter(t *testing.T) {
	var nilSource *DeparosDiscoverySource
	if got := nilSource.RequestsSent(); got != 0 {
		t.Fatalf("nil source reports %d, want 0", got)
	}

	d, err := NewDeparosDiscoverySource(context.Background(), DeparosDiscoveryConfig{
		Targets: []string{"https://example.com"},
	})
	if err != nil {
		t.Fatalf("construct source: %v", err)
	}
	if got := d.RequestsSent(); got != 0 {
		t.Fatalf("fresh source reports %d, want 0", got)
	}
	d.requestsSent.Add(42)
	if got := d.RequestsSent(); got != 42 {
		t.Fatalf("RequestsSent = %d, want 42", got)
	}
}
