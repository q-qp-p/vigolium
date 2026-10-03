package config

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/vigolium/vigolium/pkg/types"
)

// ScanningPaceConfig provides centralized speed control parameters.
// Common values serve as a baseline for all phases; per-phase subsections
// override specific values. CLI flags still take higher precedence.
type ScanningPaceConfig struct {
	Concurrency int    `yaml:"concurrency"`
	RateLimit   int    `yaml:"rate_limit"`
	MaxPerHost  int    `yaml:"max_per_host"`
	MaxDuration string `yaml:"max_duration"`

	// AdaptivePerHost enables AIMD per-host concurrency control: each host starts
	// at MaxPerHost and backs off (halving, bounded by MinPerHost) on distress
	// signals (429/503/502/504, connection error, timeout), recovering toward the
	// ceiling as healthy responses accrue. Off by default — a healthy scan then
	// behaves exactly like the static MaxPerHost semaphore.
	AdaptivePerHost bool `yaml:"adaptive_per_host"`
	// MinPerHost is the adaptive back-off floor (0 = auto: max(1, MaxPerHost/10)).
	MinPerHost int `yaml:"min_per_host"`
	// MaxPerHostCeiling is the adaptive ramp ceiling. 0 means "pick by mode": with
	// adaptive_per_host on it defaults to 2x MaxPerHost so a healthy host can
	// actually ramp, and with only the WAF auto-arm throttle active it stays at
	// MaxPerHost (a host recovering from a block returns to the configured
	// concurrency, never past it). Set explicitly to pin either mode.
	MaxPerHostCeiling int `yaml:"max_per_host_ceiling"`

	Discovery         PhasePace `yaml:"discovery"`
	Probe             PhasePace `yaml:"probe"`
	Spidering         PhasePace `yaml:"spidering"`
	KnownIssueScan    PhasePace `yaml:"known_issue_scan"`
	ExternalHarvester PhasePace `yaml:"external_harvester"`
	DynamicAssessment PhasePace `yaml:"dynamic-assessment"`
}

// PhasePace holds per-phase speed overrides.
// Zero values mean "not set" and fall through to common or built-in defaults.
type PhasePace struct {
	Concurrency          int     `yaml:"concurrency"`
	RateLimit            int     `yaml:"rate_limit"`
	MaxPerHost           int     `yaml:"max_per_host"`
	MaxDuration          string  `yaml:"max_duration"`
	ConcurrencyFactor    float64 `yaml:"concurrency_factor"`
	DurationFactor       float64 `yaml:"duration_factor"`
	ParallelPassive      *bool   `yaml:"parallel_passive,omitempty"`
	FeedbackDrainTimeout string  `yaml:"feedback_drain_timeout,omitempty"`
	ActiveModuleTimeout  string  `yaml:"active_module_timeout,omitempty"`
}

// ResolvedPhasePace is the result of merging common + per-phase values.
type ResolvedPhasePace struct {
	Concurrency          int
	RateLimit            int
	MaxPerHost           int
	MaxDuration          time.Duration
	ConcurrencyFactor    float64
	DurationFactor       float64
	ParallelPassive      bool
	FeedbackDrainTimeout time.Duration
	ActiveModuleTimeout  time.Duration
}

// DefaultScanningPaceConfig returns default scanning pace configuration
// matching the values shown in the example YAML config.
func DefaultScanningPaceConfig() *ScanningPaceConfig {
	return &ScanningPaceConfig{
		Concurrency: types.DefaultConcurrency,
		RateLimit:   100,
		MaxPerHost:  40,
		MaxDuration: "45m",

		Discovery:         PhasePace{DurationFactor: 0.5},
		KnownIssueScan:    PhasePace{DurationFactor: 0.5},
		Spidering:         PhasePace{DurationFactor: 0.1},
		ExternalHarvester: PhasePace{DurationFactor: 0.1},
		DynamicAssessment: PhasePace{DurationFactor: 1.0, ParallelPassive: boolPtr(true), FeedbackDrainTimeout: "500ms"},
	}
}

// maxDurationParsed parses the common max_duration string into a time.Duration.
// Returns 0 if unset or unparseable.
func (c *ScanningPaceConfig) maxDurationParsed() time.Duration {
	if c.MaxDuration == "" {
		return 0
	}
	d, err := time.ParseDuration(c.MaxDuration)
	if err != nil {
		return 0
	}
	return d
}

// MaxDurationParsed parses the max_duration string into a time.Duration.
// Returns 0 if unset or unparseable.
func (p *PhasePace) MaxDurationParsed() time.Duration {
	if p.MaxDuration == "" {
		return 0
	}
	d, err := time.ParseDuration(p.MaxDuration)
	if err != nil {
		return 0
	}
	return d
}

// Section returns the per-phase pace slot for a canonical phase id, or nil when
// the phase has none.
//
// It is the ONE place the phase→section vocabulary lives. It used to be spelled
// out in ResolvePhase and again in Validate, and a third copy in the CLI
// promptly disagreed with both — it said "external-harvest" where these said
// "external_harvester", so a per-phase override for that phase was written to
// the struct and then never read back. Both spellings are accepted here for
// exactly that reason: `external_harvester` is the YAML key operators already
// have in their config files, and `external-harvest` is the canonical phase id
// every other surface (--only/--skip, `run <phase>`, the event stream) uses.
func (c *ScanningPaceConfig) Section(phase string) *PhasePace {
	switch phase {
	case "discovery":
		return &c.Discovery
	case "probe":
		return &c.Probe
	case "spidering":
		return &c.Spidering
	case "known-issue-scan":
		return &c.KnownIssueScan
	case "external-harvest", "external_harvester":
		return &c.ExternalHarvester
	case "dynamic-assessment":
		return &c.DynamicAssessment
	default:
		return nil
	}
}

// paceSectionNames are the canonical phase ids Section resolves. Only canonical
// spellings belong here: `external_harvester` is accepted by Section as a
// legacy YAML key, but advertising it would offer operators a second spelling
// for a phase that already has one.
//
// This list and Section's switch are the one coupling in this file, and
// TestPhaseSectionNamesMatchSection holds them together — the comment here used
// to claim the list "derives from Section itself", which it never did, and a
// claim like that is exactly how a phase gets added to one and not the other.
var paceSectionNames = []string{
	"discovery", "probe", "spidering", "known-issue-scan",
	"external-harvest", "dynamic-assessment",
}

// PhaseSectionNames lists the canonical phase ids Section accepts, sorted.
func PhaseSectionNames() []string {
	names := append([]string(nil), paceSectionNames...)
	sort.Strings(names)
	return names
}

// phasePaceSupport states which pace fields each phase actually ENFORCES.
//
// It exists because a pace section accepts all three dials for every phase while
// most phases read only one of them. `--rate-limit spidering=5` parsed, was
// written into the config, appeared in the phase header and in the scan.started
// pace table, and changed nothing: the spidering phase has no limiter to put it
// in. A number presented as effective and silently ignored is worse than no knob
// at all, so display, flag validation and the pace table all read this one table.
//
// Honest as of improvement-2 WP11. Flipping an entry to true is part of the
// change that makes it true, never a separate bookkeeping step.
var phasePaceSupport = map[string]struct{ Concurrency, RateLimit, MaxPerHost bool }{
	// Deparos engine threads, and (WP11) a per-engine token bucket. Targets run
	// sequentially, so the per-engine bucket is the phase-wide rate.
	"discovery": {Concurrency: true, RateLimit: true},
	// The crawler is a single browser with no limiter fields at all.
	"spidering": {},
	// probePaceInfra builds a phase-local requester for all three.
	"probe": {Concurrency: true, RateLimit: true, MaxPerHost: true},
	// Workers only: the limiter and host semaphore are scan-wide.
	"dynamic-assessment": {Concurrency: true},
	// Nuclei owns its own HTTP stack and takes both.
	"known-issue-scan": {Concurrency: true, RateLimit: true},
	// Archive/API fan-out, bounded by worker count.
	"external-harvest": {Concurrency: true},
}

// Pace field names, as they appear in warnings and in the support table.
const (
	PaceFieldConcurrency = "concurrency"
	PaceFieldRateLimit   = "rate_limit"
	PaceFieldMaxPerHost  = "max_per_host"
)

// DiscoveryRateLimit resolves the requests-per-second ceiling the discovery
// engine will enforce. 0 means unpaced.
//
// Only an EXPLICIT setting counts: `scanning_pace.discovery.rate_limit`, or a
// typed `--rate-limit` on the command line. It deliberately does NOT fall through
// to the resolved global rate the way every other pace field does, because that
// rate carries a 100 rps default — discovery has never been paced, and adopting
// that default would quietly change the speed of every scan that merely loaded a
// config file (triage C13).
//
// The section value wins over the global flag: it is the more specific statement,
// and it is the form `--rate-limit discovery=N` writes. It lives here rather than
// in the runner so the number the banner and the scan.started pace table print is
// the number buildDeparosConfig hands the engine.
//
// Nil-safe on both arguments.
func (c *ScanningPaceConfig) DiscoveryRateLimit(opts *types.Options) int {
	if c != nil && c.Discovery.RateLimit > 0 {
		return c.Discovery.RateLimit
	}
	if opts != nil && opts.RateLimitExplicitlySet && opts.RateLimit > 0 {
		return opts.RateLimit
	}
	return 0
}

// PhasePaceSupports reports whether phase actually enforces the named pace field.
// An unknown phase or field reports false — the fail-closed direction, since the
// consequence is a warning or an omitted table entry rather than a changed scan.
func PhasePaceSupports(phase, field string) bool {
	support, ok := phasePaceSupport[phase]
	if !ok {
		return false
	}
	switch field {
	case PaceFieldConcurrency:
		return support.Concurrency
	case PaceFieldRateLimit:
		return support.RateLimit
	case PaceFieldMaxPerHost:
		return support.MaxPerHost
	default:
		return false
	}
}

// ResolvePhase merges common values with per-phase overrides for the named phase.
// Non-zero per-phase values win over common values.
func (c *ScanningPaceConfig) ResolvePhase(phase string) ResolvedPhasePace {
	var pp PhasePace
	if section := c.Section(phase); section != nil {
		pp = *section
	}

	resolved := ResolvedPhasePace{
		Concurrency: c.Concurrency,
		RateLimit:   c.RateLimit,
		MaxPerHost:  c.MaxPerHost,
	}

	// Concurrency: explicit per-phase > factor × common > common
	if pp.Concurrency > 0 {
		resolved.Concurrency = pp.Concurrency
	} else if pp.ConcurrencyFactor > 0 && c.Concurrency > 0 {
		resolved.Concurrency = int(math.Round(float64(c.Concurrency) * pp.ConcurrencyFactor))
		resolved.ConcurrencyFactor = pp.ConcurrencyFactor
	}

	if pp.RateLimit > 0 {
		resolved.RateLimit = pp.RateLimit
	}
	if pp.MaxPerHost > 0 {
		resolved.MaxPerHost = pp.MaxPerHost
	}

	// MaxDuration: explicit per-phase > factor × common > common
	commonDuration := c.maxDurationParsed()
	if pp.MaxDuration != "" {
		resolved.MaxDuration = pp.MaxDurationParsed()
	} else if pp.DurationFactor > 0 && commonDuration > 0 {
		resolved.MaxDuration = time.Duration(float64(commonDuration) * pp.DurationFactor)
		resolved.DurationFactor = pp.DurationFactor
	} else {
		resolved.MaxDuration = commonDuration
	}

	// ParallelPassive: per-phase pointer overrides common default (false)
	if pp.ParallelPassive != nil {
		resolved.ParallelPassive = *pp.ParallelPassive
	}

	// FeedbackDrainTimeout: per-phase overrides common default (0 = executor default)
	if pp.FeedbackDrainTimeout != "" {
		if d, err := time.ParseDuration(pp.FeedbackDrainTimeout); err == nil {
			resolved.FeedbackDrainTimeout = d
		}
	}

	// ActiveModuleTimeout: per-phase overrides common default (0 = executor default)
	if pp.ActiveModuleTimeout != "" {
		if d, err := time.ParseDuration(pp.ActiveModuleTimeout); err == nil {
			resolved.ActiveModuleTimeout = d
		}
	}

	return resolved
}

// boolPtr returns a pointer to a bool value. Used for optional YAML fields.
func boolPtr(b bool) *bool { return &b }

// validateNonNegDuration parses a duration setting and rejects negative values.
//
// Parsing alone was not enough: "-5m" is a perfectly valid time.Duration, so a
// negative budget passed validation and then flowed into context.WithTimeout as
// an already-expired deadline. The phase it governed did nothing and reported no
// error. An empty string means "unset" and is always accepted; what a zero means
// is per-setting and is decided by the consumer, not here.
func validateNonNegDuration(field, s string) error {
	if s == "" {
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("%s: invalid duration %q: %w", field, s, err)
	}
	if d < 0 {
		return fmt.Errorf("%s: duration must not be negative, got %q", field, s)
	}
	return nil
}

// Validate rejects negative values and invalid duration strings.
func (c *ScanningPaceConfig) Validate() error {
	if c.Concurrency < 0 {
		return fmt.Errorf("scanning_pace.concurrency must be >= 0")
	}
	if c.RateLimit < 0 {
		return fmt.Errorf("scanning_pace.rate_limit must be >= 0")
	}
	if c.MaxPerHost < 0 {
		return fmt.Errorf("scanning_pace.max_per_host must be >= 0")
	}
	if err := validateNonNegDuration("scanning_pace.max_duration", c.MaxDuration); err != nil {
		return err
	}

	for _, name := range PhaseSectionNames() {
		pp := c.Section(name)
		if pp.Concurrency < 0 {
			return fmt.Errorf("scanning_pace.%s.concurrency must be >= 0", name)
		}
		if pp.RateLimit < 0 {
			return fmt.Errorf("scanning_pace.%s.rate_limit must be >= 0", name)
		}
		if pp.MaxPerHost < 0 {
			return fmt.Errorf("scanning_pace.%s.max_per_host must be >= 0", name)
		}
		if err := validateNonNegDuration(fmt.Sprintf("scanning_pace.%s.max_duration", name), pp.MaxDuration); err != nil {
			return err
		}
		if pp.ConcurrencyFactor < 0 {
			return fmt.Errorf("scanning_pace.%s.concurrency_factor must be >= 0", name)
		}
		if pp.DurationFactor < 0 {
			return fmt.Errorf("scanning_pace.%s.duration_factor must be >= 0", name)
		}
		if err := validateNonNegDuration(fmt.Sprintf("scanning_pace.%s.feedback_drain_timeout", name), pp.FeedbackDrainTimeout); err != nil {
			return err
		}
		if err := validateNonNegDuration(fmt.Sprintf("scanning_pace.%s.active_module_timeout", name), pp.ActiveModuleTimeout); err != nil {
			return err
		}
	}

	return nil
}
