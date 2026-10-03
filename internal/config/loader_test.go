package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	deparosconfig "github.com/vigolium/vigolium/pkg/deparos/config"
)

// TestKnownIssueScanSeveritiesByIntensity pins the per-intensity known-issue-scan
// severity filter. The default (balanced) ships critical+high only so the phase
// stays within its time budget; deep sweeps all severities. Because the profile
// overlay round-trips through YAML, a profile that omits `severities` resets the
// field to empty (= all) — so EVERY bundled profile that has a known_issue_scan
// block MUST set severities explicitly (including quick.yaml, the fastest tier,
// which must never end up broader than balanced). This test guards that wiring.
func TestKnownIssueScanSeveritiesByIntensity(t *testing.T) {
	// Out-of-the-box default (plain `vigolium scan`, no profile).
	if got := DefaultSettings().KnownIssueScan.Severities; !reflect.DeepEqual(got, []string{"critical", "high"}) {
		t.Errorf("default KnownIssueScan.Severities = %v, want [critical high]", got)
	}

	cases := map[string][]string{
		"quick":    {"critical", "high"},                          // --intensity quick
		"standard": {"critical", "high"},                          // --intensity balanced
		"full":     {"critical", "high", "medium", "low", "info"}, // --intensity deep
	}
	for name, want := range cases {
		settings := DefaultSettings()
		profile, err := LoadProfile(filepath.Join("..", "..", "public", "presets", "profiles", name+".yaml"))
		if err != nil {
			t.Fatalf("LoadProfile(%s): %v", name, err)
		}
		if err := ApplyProfile(settings, profile); err != nil {
			t.Fatalf("ApplyProfile(%s): %v", name, err)
		}
		if got := settings.KnownIssueScan.Severities; !reflect.DeepEqual(got, want) {
			t.Errorf("profile %q: KnownIssueScan.Severities = %v, want %v", name, got, want)
		}
	}
}

func TestExpandEnvVars(t *testing.T) {
	const testVar = "VIGOLIUM_TEST_EXPAND_VAR"

	tests := []struct {
		name   string
		input  string
		envVal string // empty means unset
		want   string
	}{
		{
			name:  "plain string no vars",
			input: "oast.pro",
			want:  "oast.pro",
		},
		{
			name:   "simple var set",
			input:  "${VIGOLIUM_TEST_EXPAND_VAR}",
			envVal: "custom.server",
			want:   "custom.server",
		},
		{
			name:  "simple var unset",
			input: "${VIGOLIUM_TEST_EXPAND_VAR}",
			want:  "",
		},
		{
			name:   "default when var is set",
			input:  "${VIGOLIUM_TEST_EXPAND_VAR:-fallback}",
			envVal: "custom.server",
			want:   "custom.server",
		},
		{
			name:  "default when var is unset",
			input: "${VIGOLIUM_TEST_EXPAND_VAR:-fallback}",
			want:  "fallback",
		},
		{
			name:  "empty default when var is unset",
			input: "${VIGOLIUM_TEST_EXPAND_VAR:-}",
			want:  "",
		},
		{
			name:  "default with special chars",
			input: "${VIGOLIUM_TEST_EXPAND_VAR:-https://oast.example.com}",
			want:  "https://oast.example.com",
		},
		{
			name:   "mixed text and var with default",
			input:  "server: ${VIGOLIUM_TEST_EXPAND_VAR:-oast.pro}:443",
			envVal: "my.server",
			want:   "server: my.server:443",
		},
		{
			name:  "multiple vars with defaults",
			input: "${VIGOLIUM_TEST_EXPAND_VAR:-a}/${VIGOLIUM_TEST_EXPAND_VAR:-b}",
			want:  "a/b",
		},
		{
			name:   "dollar-var syntax (no default support)",
			input:  "$VIGOLIUM_TEST_EXPAND_VAR",
			envVal: "val",
			want:   "val",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Unsetenv(testVar)
			if tt.envVal != "" {
				t.Setenv(testVar, tt.envVal)
			}

			got := ExpandEnvVars(tt.input)
			if got != tt.want {
				t.Errorf("ExpandEnvVars(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestApplyProfile_PreservesStrategyPhaseTables guards against the regression
// where a profile that only meant to set default_strategy would silently
// zero the per-strategy phase tables (Lite/Balanced/Deep) via a YAML
// round-trip. After the fix, a profile that omits those tables must leave
// them untouched.
func TestApplyProfile_PreservesStrategyPhaseTables(t *testing.T) {
	settings := DefaultSettings()
	// Sanity: defaults populate Balanced with discovery+spidering+known-issue+dynamic enabled.
	if !settings.ScanningStrategy.Balanced.DynamicAssessment {
		t.Fatalf("precondition failed: default Balanced.DynamicAssessment should be true")
	}
	if !settings.ScanningStrategy.Balanced.Discovery {
		t.Fatalf("precondition failed: default Balanced.Discovery should be true")
	}
	if !settings.ScanningStrategy.Deep.ExternalHarvesting {
		t.Fatalf("precondition failed: default Deep.ExternalHarvesting should be true")
	}

	// Profile that only nudges default_strategy — the shape every bundled
	// profile under public/presets/profiles/ uses.
	profile := &ProfileSettings{
		ScanningStrategy: &ProfileScanningStrategy{
			DefaultStrategy: "deep",
		},
	}

	if err := ApplyProfile(settings, profile); err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	if settings.ScanningStrategy.DefaultStrategy != "deep" {
		t.Errorf("DefaultStrategy = %q, want %q", settings.ScanningStrategy.DefaultStrategy, "deep")
	}
	if !settings.ScanningStrategy.Balanced.DynamicAssessment {
		t.Errorf("Balanced.DynamicAssessment was clobbered to false")
	}
	if !settings.ScanningStrategy.Balanced.Discovery {
		t.Errorf("Balanced.Discovery was clobbered to false")
	}
	if !settings.ScanningStrategy.Balanced.Spidering {
		t.Errorf("Balanced.Spidering was clobbered to false")
	}
	if !settings.ScanningStrategy.Balanced.KnownIssueScan {
		t.Errorf("Balanced.KnownIssueScan was clobbered to false")
	}
	if !settings.ScanningStrategy.Deep.ExternalHarvesting {
		t.Errorf("Deep.ExternalHarvesting was clobbered to false")
	}

	// Heuristics-check should also be merge-only (not clobbered) when absent.
	if profile.ScanningStrategy.HeuristicsCheck == "" &&
		settings.ScanningStrategy.HeuristicsCheck == "" {
		t.Errorf("HeuristicsCheck was clobbered from default to empty")
	}
}

// TestApplyProfile_HeuristicsCheckOverride confirms the explicit-merge path
// honors a profile that DOES set heuristics_check.
func TestApplyProfile_HeuristicsCheckOverride(t *testing.T) {
	settings := DefaultSettings()
	settings.ScanningStrategy.HeuristicsCheck = "basic"

	profile := &ProfileSettings{
		ScanningStrategy: &ProfileScanningStrategy{
			HeuristicsCheck: "advanced",
		},
	}

	if err := ApplyProfile(settings, profile); err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	if settings.ScanningStrategy.HeuristicsCheck != "advanced" {
		t.Errorf("HeuristicsCheck = %q, want %q", settings.ScanningStrategy.HeuristicsCheck, "advanced")
	}
}

// TestApplyProfile_PreservesDiscoveryJSTangleBudget guards the regression where
// applying a bundled scanning profile (quick/standard/full — i.e. --intensity
// quick/balanced/deep) zero-clobbered discovery.jstangle.memory_budget_mb. Those
// profiles set a top-level `discovery:` block but omit `jstangle:`; the old typed
// YAML round-trip in ApplyProfile therefore reset memory_budget_mb (and every
// other omitted field) to 0, and the deparos engine then rejected the config
// (memory_budget_mb < 128) and ran no content discovery at all. The key-preserving
// overlay must leave the omitted jstangle budget at its global/default value.
func TestApplyProfile_PreservesDiscoveryJSTangleBudget(t *testing.T) {
	defaults := DefaultDiscoveryConfig()
	for _, name := range []string{"quick", "standard", "full"} {
		t.Run(name, func(t *testing.T) {
			settings := DefaultSettings()
			profile, err := LoadProfile(filepath.Join("..", "..", "public", "presets", "profiles", name+".yaml"))
			if err != nil {
				t.Fatalf("LoadProfile(%s): %v", name, err)
			}
			if err := ApplyProfile(settings, profile); err != nil {
				t.Fatalf("ApplyProfile(%s): %v", name, err)
			}

			js := settings.Discovery.JSTangle
			if js.MemoryBudgetMB < deparosconfig.MinJSTangleMemoryBudgetMB {
				t.Errorf("MemoryBudgetMB = %d, want >= %d (deparos would reject and skip all discovery)",
					js.MemoryBudgetMB, deparosconfig.MinJSTangleMemoryBudgetMB)
			}
			if js.MemoryBudgetMB != defaults.JSTangle.MemoryBudgetMB {
				t.Errorf("MemoryBudgetMB = %d, want %d (profile omits jstangle; default must survive)",
					js.MemoryBudgetMB, defaults.JSTangle.MemoryBudgetMB)
			}
			// A second omitted jstangle field and an omitted engine field, to prove
			// this is a general key-preservation fix and not a one-field special case.
			if js.WorkerMaxRSSMB != defaults.JSTangle.WorkerMaxRSSMB {
				t.Errorf("WorkerMaxRSSMB = %d, want %d (preserved)", js.WorkerMaxRSSMB, defaults.JSTangle.WorkerMaxRSSMB)
			}
			if js.MaxASTNodes != defaults.JSTangle.MaxASTNodes {
				t.Errorf("MaxASTNodes = %d, want %d (preserved)", js.MaxASTNodes, defaults.JSTangle.MaxASTNodes)
			}

			// The effective discovery config must pass its own validation — the same
			// check the scan path runs before launching the phase.
			if err := settings.Discovery.Validate(); err != nil {
				t.Errorf("effective discovery config invalid after profile %q: %v", name, err)
			}
		})
	}
}

// TestApplyProfile_KeyPreservingOverlayFromFile pins the mechanism: a profile that
// sets only a couple of discovery keys must apply exactly those and leave every
// omitted key (including nested ones) at its default. This is the property that
// prevents the jstangle-budget class of regression for ANY future field.
func TestApplyProfile_KeyPreservingOverlayFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "partial.yaml")
	// Sets discovery.mode and a nested discovery.engine.timeout; omits everything
	// else under discovery (notably jstangle and engine.observed_max_items).
	content := "" +
		"discovery:\n" +
		"  mode: files_only\n" +
		"  engine:\n" +
		"    timeout: 20s\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp profile: %v", err)
	}

	settings := DefaultSettings()
	defaults := DefaultDiscoveryConfig()
	profile, err := LoadProfile(path)
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	if err := ApplyProfile(settings, profile); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}

	// Keys the profile set are applied…
	if settings.Discovery.Mode != "files_only" {
		t.Errorf("Mode = %q, want files_only", settings.Discovery.Mode)
	}
	if settings.Discovery.Engine.Timeout != "20s" {
		t.Errorf("Engine.Timeout = %q, want 20s", settings.Discovery.Engine.Timeout)
	}
	// …and keys it omitted keep their defaults, at both the top and nested levels.
	if settings.Discovery.JSTangle.MemoryBudgetMB != defaults.JSTangle.MemoryBudgetMB {
		t.Errorf("JSTangle.MemoryBudgetMB = %d, want %d (omitted; must survive)",
			settings.Discovery.JSTangle.MemoryBudgetMB, defaults.JSTangle.MemoryBudgetMB)
	}
	if settings.Discovery.Engine.ObservedMaxItems != defaults.Engine.ObservedMaxItems {
		t.Errorf("Engine.ObservedMaxItems = %d, want %d (omitted nested; must survive)",
			settings.Discovery.Engine.ObservedMaxItems, defaults.Engine.ObservedMaxItems)
	}
}

// TestApplyProfile_OverwritesScanningPaceRateLimit documents why pkg/cli/scan.go
// copies a typed --rate-limit into the pace AFTER ApplyProfile rather than
// before. A profile carrying its own scanning_pace.rate_limit overwrites whatever
// is there; done in the wrong order, known-issue-scan quietly paced itself at the
// profile's rate while the native scan honored the operator's flag.
func TestApplyProfile_OverwritesScanningPaceRateLimit(t *testing.T) {
	settings := &Settings{}
	settings.ScanningPace = *DefaultScanningPaceConfig()
	settings.ScanningPace.RateLimit = 5 // stands in for the typed flag's value

	path := filepath.Join(t.TempDir(), "profile.yaml")
	if err := os.WriteFile(path, []byte("scanning_pace:\n  rate_limit: 200\n"), 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	profile, err := LoadProfile(path)
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	if err := ApplyProfile(settings, profile); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}
	if settings.ScanningPace.RateLimit != 200 {
		t.Fatalf("profile rate_limit = %d, want 200 — the overwrite this ordering guards against is gone",
			settings.ScanningPace.RateLimit)
	}
}
