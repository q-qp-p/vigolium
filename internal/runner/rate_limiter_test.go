package runner

import (
	"testing"

	"golang.org/x/time/rate"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestBuildScanRateLimiter verifies the opt-in gating: no limiter is built unless
// an explicit positive rate is set, so default scans keep their current
// throughput; a positive rate yields a token bucket at that rate.
func TestBuildScanRateLimiter(t *testing.T) {
	if l := buildScanRateLimiter(0); l != nil {
		t.Errorf("rate 0 must yield no limiter (unlimited), got %v", l)
	}
	if l := buildScanRateLimiter(-5); l != nil {
		t.Errorf("negative rate must yield no limiter, got %v", l)
	}

	l := buildScanRateLimiter(10)
	if l == nil {
		t.Fatal("rate 10 must yield a limiter")
	}
	if got := l.Limit(); got != rate.Limit(10) {
		t.Errorf("limiter rate = %v, want 10", got)
	}
	if got := l.Burst(); got != 10 {
		t.Errorf("limiter burst = %d, want 10", got)
	}
}

// TestEffectiveRateLimit pins the single source of truth: the limiter and every
// surface that reports the rate read Options, not the configured pace. Before
// this, a scan could advertise one number and run at another.
func TestEffectiveRateLimit(t *testing.T) {
	if got := effectiveRateLimit(nil); got != 0 {
		t.Errorf("nil options = %d, want 0", got)
	}
	if got := effectiveRateLimit(&types.Options{RateLimit: -5}); got != 0 {
		t.Errorf("negative rate = %d, want 0 (unlimited)", got)
	}
	if got := effectiveRateLimit(&types.Options{RateLimit: 5}); got != 5 {
		t.Errorf("rate = %d, want 5", got)
	}
}

// TestConfigSnapshotReportsEnforcedRate is the F19 regression: the snapshot used
// to print settings.ScanningPace.RateLimit while the limiter was built from
// Options.RateLimit, so a scan recorded a rate it never ran at.
func TestConfigSnapshotReportsEnforcedRate(t *testing.T) {
	settings := &config.Settings{}
	settings.ScanningPace = *config.DefaultScanningPaceConfig()
	settings.ScanningPace.RateLimit = 50 // the configured pace, deliberately different
	opts := &types.Options{RateLimit: 5, Modules: []string{}}

	r := &Runner{options: opts, settings: settings}
	meta := r.configSnapshotMeta()

	if got := meta["rate_limit"]; got != 5 {
		t.Errorf("snapshot rate_limit = %v, want 5 (the rate the limiter enforces)", got)
	}
	if got := meta["rate_limit_known_issue_scan"]; got != 50 {
		t.Errorf("snapshot rate_limit_known_issue_scan = %v, want 50 (the resolved phase pace)", got)
	}

	limiter := buildScanRateLimiter(effectiveRateLimit(opts))
	if limiter == nil || limiter.Limit() != rate.Limit(5) {
		t.Errorf("limiter must enforce the rate the snapshot reports, got %v", limiter)
	}
}
