package runner

import (
	"fmt"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// SpideringBudget returns the wall-clock budget one spidering target gets.
//
// It exists so the phase and the banner cannot answer this differently. The
// budget comes from the option when set (--spider-max-time, else the
// scanning_pace value runNativeScan copies in) and otherwise from
// spidering.max_duration, a separate config key -- and a banner that read only
// one of those advertised a budget the phase would not use, which is the defect
// this whole file exists to close. runSpideringPhase calls it too.
func SpideringBudget(settings *config.Settings, options *types.Options) time.Duration {
	if options != nil && options.SpideringMaxDuration > 0 {
		return options.SpideringMaxDuration
	}
	if settings == nil {
		return 0
	}
	return settings.Spidering.MaxDurationParsed()
}

// DiscoveryBudget returns the wall-clock budget one discovery target gets.
//
// Same contract as SpideringBudget, for the phase whose fallback lived inside
// the input source: option (--discover-max-time, else the scanning_pace value)
// first, then scanning_pace.discovery.max_duration, then the source's own
// default. Without this the banner printed the unset option — 0, rendered as no
// budget at all — while every target ran for the source's default hour.
func DiscoveryBudget(settings *config.Settings, options *types.Options) time.Duration {
	if options != nil && options.DiscoverMaxDuration > 0 {
		return options.DiscoverMaxDuration
	}
	if settings != nil {
		if d := settings.ScanningPace.ResolvePhase("discovery").MaxDuration; d > 0 {
			return d
		}
	}
	return source.DefaultDiscoveryMaxDuration
}

// phaseBudget reports the time budget a phase will run with, and the
// scanning_pace duration_factor behind it when that factor is still what
// produced the number (0 otherwise).
//
// effective is the phase's own resolved max-duration where the caller has one,
// or 0 for a phase whose budget lives only in scanning_pace. It WINS, because
// that is the precedence the phase itself applies. The factor is dropped once an
// override is in force: it no longer explains the number, and naming it invites
// the operator to multiply it out and land back on the budget that is not being
// used.
func phaseBudget(settings *config.Settings, phaseKey string, effective time.Duration) (time.Duration, float64) {
	var resolved config.ResolvedPhasePace
	if settings != nil {
		resolved = settings.ScanningPace.ResolvePhase(phaseKey)
	}
	if effective > 0 && effective != resolved.MaxDuration {
		return effective, 0
	}
	return resolved.MaxDuration, resolved.DurationFactor
}

// PhaseLabel renders one entry of the banner's "Phases:" line: a status symbol,
// the phase name, and the budget it will run with ("Spidering (6m0s, x0.1)").
//
// `--spider-max-time 5m` used to be announced as the profile's 6m0s -- 0.1 x the
// 1h scan budget -- while the phase went on to crawl for the 5m it was told to.
func PhaseLabel(settings *config.Settings, name, phaseKey string, enabled bool, effective time.Duration) string {
	if !enabled {
		return terminal.Gray(terminal.SymbolError) + " " + terminal.Gray(name)
	}
	duration, factor := phaseBudget(settings, phaseKey, effective)
	if duration > 0 {
		if factor > 0 {
			name += " " + terminal.Gray(fmt.Sprintf("(%s, x%.1f)", duration, factor))
		} else {
			name += " " + terminal.Gray("("+duration.String()+")")
		}
	}
	return terminal.Green(terminal.SymbolSuccess) + " " + terminal.HiCyan(name)
}

// PhaseSpeedDetail renders the budget fragment a phase prints on its own detail
// line -- "max-duration=6m0s (duration_factor=0.1)" -- or "" when the phase has
// no budget. Callers supply the separator, because one of them opens a line with
// it and the rest append to a list.
//
// A factor never arrives without a duration: ResolvePhase only sets one in the
// branch that multiplies it into the other.
func PhaseSpeedDetail(settings *config.Settings, phaseKey string, effective time.Duration) string {
	duration, factor := phaseBudget(settings, phaseKey, effective)
	if duration <= 0 {
		return ""
	}
	detail := "max-duration=" + terminal.HiTeal(duration.String())
	if factor > 0 {
		detail += fmt.Sprintf(" (duration_factor=%s)", terminal.HiBlue(fmt.Sprintf("%.1f", factor)))
	}
	return detail
}
