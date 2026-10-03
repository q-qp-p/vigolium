package runner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// settingsWithPace returns settings whose spidering budget is the documented
// default: a factor of the common max_duration rather than an explicit value.
func settingsWithPace(common string) *config.Settings {
	s := &config.Settings{}
	s.ScanningPace = *config.DefaultScanningPaceConfig()
	s.ScanningPace.MaxDuration = common
	return s
}

func TestPhaseBudget(t *testing.T) {
	settings := settingsWithPace("1h") // spidering factor 0.1 -> 6m

	t.Run("pace value carries the factor that produced it", func(t *testing.T) {
		d, f := phaseBudget(settings, "spidering", 0)
		assert.Equal(t, 6*time.Minute, d)
		assert.InDelta(t, 0.1, f, 0.0001)
	})

	t.Run("an override wins and drops the factor", func(t *testing.T) {
		// --spider-max-time 5m used to be announced as the profile's 6m0s while
		// the phase went on to crawl for 5m.
		d, f := phaseBudget(settings, "spidering", 5*time.Minute)
		assert.Equal(t, 5*time.Minute, d)
		assert.Zero(t, f)
	})

	t.Run("an override equal to the pace value keeps the factor", func(t *testing.T) {
		d, f := phaseBudget(settings, "spidering", 6*time.Minute)
		assert.Equal(t, 6*time.Minute, d)
		assert.InDelta(t, 0.1, f, 0.0001)
	})

	t.Run("nil settings reports the override alone", func(t *testing.T) {
		d, f := phaseBudget(nil, "spidering", 5*time.Minute)
		assert.Equal(t, 5*time.Minute, d)
		assert.Zero(t, f)
	})
}

// SpideringBudget is the one answer the phase and the banner both read, so the
// fallback to spidering.max_duration has to be part of it: an agent or REST run
// never sets the option, and a banner that skipped the fallback would announce a
// budget the crawl does not use.
func TestSpideringBudget(t *testing.T) {
	settings := settingsWithPace("1h")
	settings.Spidering.MaxDuration = "12m"

	assert.Equal(t, 5*time.Minute,
		SpideringBudget(settings, &types.Options{SpideringMaxDuration: 5 * time.Minute}),
		"the option wins when set")
	assert.Equal(t, 12*time.Minute, SpideringBudget(settings, &types.Options{}),
		"falls back to spidering.max_duration, not the scanning_pace value")
	assert.Zero(t, SpideringBudget(nil, nil))
}

func TestPhaseSpeedDetail(t *testing.T) {
	settings := settingsWithPace("1h")

	assert.Equal(t, "max-duration=6m0s (duration_factor=0.1)",
		terminal.StripANSI(PhaseSpeedDetail(settings, "spidering", 0)))
	assert.Equal(t, "max-duration=5m0s",
		terminal.StripANSI(PhaseSpeedDetail(settings, "spidering", 5*time.Minute)),
		"the factor goes once it no longer explains the number")
	assert.Empty(t, PhaseSpeedDetail(&config.Settings{}, "spidering", 0),
		"no budget renders no fragment, so the caller adds no separator")
}

// TestSpideringBudgetZeroDuration is the F21 regression: `spidering.max_duration:
// 0s` passed validation and was handed to context.WithTimeout as an expired
// deadline, so every crawl finished instantly and the phase reported nothing
// wrong. Zero now means the default.
func TestSpideringBudgetZeroDuration(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"zero", "0s"},
		{"unset", ""},
		{"unparseable", "not-a-duration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &config.Settings{}
			s.Spidering = *config.DefaultSpideringConfig()
			s.Spidering.MaxDuration = tc.value
			assert.Equal(t, 30*time.Minute, SpideringBudget(s, nil))
		})
	}

	// A real budget is still honored, and the option still outranks it.
	s := &config.Settings{}
	s.Spidering = *config.DefaultSpideringConfig()
	s.Spidering.MaxDuration = "7m"
	assert.Equal(t, 7*time.Minute, SpideringBudget(s, nil))
	assert.Equal(t, 5*time.Minute, SpideringBudget(s, &types.Options{SpideringMaxDuration: 5 * time.Minute}))
}

// TestDiscoveryBudget covers the precedence the banner and buildDeparosConfig
// must agree on. The unset case used to render as "no budget" while targets ran
// for the input source's default hour.
func TestDiscoveryBudget(t *testing.T) {
	assert.Equal(t, source.DefaultDiscoveryMaxDuration, DiscoveryBudget(nil, nil),
		"nothing configured must report the source's own default, not 0")

	s := settingsWithPace("1h")
	s.ScanningPace.Discovery.MaxDuration = "12m"
	assert.Equal(t, 12*time.Minute, DiscoveryBudget(s, nil))
	assert.Equal(t, 3*time.Minute, DiscoveryBudget(s, &types.Options{DiscoverMaxDuration: 3 * time.Minute}))
}
