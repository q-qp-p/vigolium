package runner

import (
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/types"
)

// base returns the basename of p, or "" for an empty path, so assertions can
// ignore the temp-dir prefix the embedded defaults are materialized under.
func base(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}

func newWordlistRunner(opts *types.Options, settings *config.Settings) *Runner {
	return &Runner{options: opts, settings: settings}
}

func TestResolveDiscoveryWordlists_EmbeddedDefaults(t *testing.T) {
	t.Setenv(wordlistDirEnv, t.TempDir())

	settings := &config.Settings{Discovery: *config.DefaultDiscoveryConfig()}

	t.Run("balanced uses short lists only", func(t *testing.T) {
		r := newWordlistRunner(&types.Options{}, settings)
		w := r.resolveDiscoveryWordlists()

		if base(w.shortFile) != "file-short.txt" || base(w.shortDir) != "dir-short.txt" {
			t.Errorf("short lists: file=%q dir=%q", base(w.shortFile), base(w.shortDir))
		}
		if w.longFile != "" || w.longDir != "" || w.fuzz != "" {
			t.Errorf("long/fuzz should be empty on balanced: long=%q,%q fuzz=%q", w.longFile, w.longDir, w.fuzz)
		}
		if !w.usingEmbedded || w.usingConfigured {
			t.Errorf("flags: usingEmbedded=%v usingConfigured=%v (want true,false)", w.usingEmbedded, w.usingConfigured)
		}
	})

	t.Run("deep adds long lists and fuzz", func(t *testing.T) {
		r := newWordlistRunner(&types.Options{Intensity: "deep"}, settings)
		w := r.resolveDiscoveryWordlists()

		if base(w.shortFile) != "file-short.txt" || base(w.longFile) != "file-long.txt" ||
			base(w.shortDir) != "dir-short.txt" || base(w.longDir) != "dir-long.txt" ||
			base(w.fuzz) != "fuzz.txt" {
			t.Errorf("deep lists: %q %q %q %q %q", base(w.shortFile), base(w.longFile), base(w.shortDir), base(w.longDir), base(w.fuzz))
		}
		if !w.usingEmbedded {
			t.Error("usingEmbedded should be true at deep")
		}
	})
}

func TestResolveDiscoveryWordlists_DiscoveryOnlyEnablesFuzz(t *testing.T) {
	t.Setenv(wordlistDirEnv, t.TempDir())

	settings := &config.Settings{Discovery: *config.DefaultDiscoveryConfig()}
	// `vigolium run discover` sets OnlyPhase="discovery"; fuzzing must turn on even
	// at default (non-deep) intensity.
	r := newWordlistRunner(&types.Options{OnlyPhase: "discovery"}, settings)
	w := r.resolveDiscoveryWordlists()

	if base(w.fuzz) != "fuzz.txt" {
		t.Errorf("discovery-only run should default fuzz.txt: %q", base(w.fuzz))
	}
	// Long lists remain deep-only — discovery-only must not pull them in.
	if w.longFile != "" || w.longDir != "" {
		t.Errorf("long lists should stay off when not deep: long=%q,%q", w.longFile, w.longDir)
	}
}

func TestDiscoveryFuzzingState(t *testing.T) {
	cases := []struct {
		name string
		opts *types.Options
		want bool
	}{
		{"balanced full scan off", &types.Options{}, false},
		{"deep on", &types.Options{Intensity: "deep"}, true},
		{"discovery-only on", &types.Options{OnlyPhase: "discovery"}, true},
		{"fuzz-wordlist on", &types.Options{FuzzWordlistPath: "/x/f.txt"}, true},
		{"other phase off", &types.Options{OnlyPhase: "spidering"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newWordlistRunner(c.opts, nil)
			got, reason := r.discoveryFuzzingState()
			if got != c.want {
				t.Errorf("discoveryFuzzingState() = %v (%q), want %v", got, reason, c.want)
			}
		})
	}
}

func boolPtr(b bool) *bool { return &b }

func TestShouldAutoFuzzDiscovery(t *testing.T) {
	discoverOpts := func(mut func(*types.Options)) *types.Options {
		o := &types.Options{DiscoverEnabled: true, Targets: []string{"https://t.example.com"}}
		if mut != nil {
			mut(o)
		}
		return o
	}
	lowYield := spideringOutcome{ran: true, records: 2}
	ssoYield := spideringOutcome{ran: true, records: 9, sawSSO: true, ssoHosts: []string{"idp.example.com"}}
	richYield := spideringOutcome{ran: true, records: 50}
	// Found plenty, persisted little: the low count is a capture loss, not a
	// low-yield target.
	lostYield := spideringOutcome{ran: true, records: 2, lost: 40}

	cases := []struct {
		name      string
		opts      *types.Options
		settings  *config.Settings
		spidering spideringOutcome
		want      bool
	}{
		{"low-yield triggers", discoverOpts(nil), nil, lowYield, true},
		{"sso wall triggers", discoverOpts(nil), nil, ssoYield, true},
		{"rich yield does not trigger", discoverOpts(nil), nil, richYield, false},
		{"records lost to capture do not read as low yield", discoverOpts(nil), nil, lostYield, false},
		{"spidering did not run", discoverOpts(nil), nil, spideringOutcome{ran: false, records: 0}, false},
		{"already fuzzing (deep) does not re-trigger", discoverOpts(func(o *types.Options) { o.Intensity = "deep" }), nil, lowYield, false},
		{"discover disabled does not trigger", discoverOpts(func(o *types.Options) { o.DiscoverEnabled = false }), nil, lowYield, false},
		{"no CLI targets does not trigger", discoverOpts(func(o *types.Options) { o.Targets = nil }), nil, lowYield, false},
		{
			"config opt-out disables",
			discoverOpts(nil),
			&config.Settings{Discovery: config.DiscoveryConfig{AutoFuzzLowYield: boolPtr(false)}},
			ssoYield,
			false,
		},
		{
			"config opt-in (true) keeps it on",
			discoverOpts(nil),
			&config.Settings{Discovery: config.DiscoveryConfig{AutoFuzzLowYield: boolPtr(true)}},
			lowYield,
			true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newWordlistRunner(c.opts, c.settings)
			r.spidering = c.spidering
			if got := r.shouldAutoFuzzDiscovery(); got != c.want {
				t.Errorf("shouldAutoFuzzDiscovery() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestDiscoveryFuzzingState_AutoFuzz confirms the auto-fuzz flag flips the shared
// fuzzing-state helper on (so resolveDiscoveryWordlists materializes fuzz.txt).
func TestDiscoveryFuzzingState_AutoFuzz(t *testing.T) {
	r := newWordlistRunner(&types.Options{}, nil)
	if on, _ := r.discoveryFuzzingState(); on {
		t.Fatal("expected fuzzing off on a balanced run before auto-fuzz")
	}
	r.autoFuzzDiscovery = true
	on, reason := r.discoveryFuzzingState()
	if !on {
		t.Errorf("expected fuzzing on once autoFuzzDiscovery is set; reason=%q", reason)
	}
}

// TestNoDiscoveryFuzzBeatsEveryAutoEnable is the whole contract of the flag:
// every other arm of discoveryFuzzingState switches fuzzing ON from a heuristic,
// and an explicit off that a heuristic can overrule is a knob that silently does
// nothing on exactly the runs it was typed for.
func TestNoDiscoveryFuzzBeatsEveryAutoEnable(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Runner)
	}{
		{"intensity deep", func(r *Runner) { r.options.Intensity = "deep" }},
		{"discovery-only run", func(r *Runner) { r.options.OnlyPhase = "discovery" }},
		{"multi-phase --only containing discovery", func(r *Runner) { r.options.OnlyPhase = "discovery,spidering" }},
		{"low-yield auto-fuzz already latched", func(r *Runner) { r.autoFuzzDiscovery = true }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newWordlistRunner(&types.Options{NoDiscoveryFuzz: true}, nil)
			c.mut(r)
			on, reason := r.discoveryFuzzingState()
			if on {
				t.Fatalf("fuzzing on despite --no-discovery-fuzz; reason=%q", reason)
			}
			if reason != "via --no-discovery-fuzz" {
				t.Errorf("reason = %q, want the flag named so the header explains itself", reason)
			}
		})
	}

	// The low-yield auto-enable must not even latch: r.autoFuzzDiscovery also
	// drives the "Fuzzing auto-enabled" banner and the SSO-host scope filtering,
	// which would then describe fuzzing that never happens.
	r := newWordlistRunner(&types.Options{
		NoDiscoveryFuzz: true,
		DiscoverEnabled: true,
		Targets:         []string{"https://t.example.com"},
	}, nil)
	r.spidering = spideringOutcome{ran: true, records: 1}
	if r.shouldAutoFuzzDiscovery() {
		t.Error("shouldAutoFuzzDiscovery() = true under --no-discovery-fuzz")
	}
}

// TestNoDiscoveryFuzzClearsConfiguredWordlist covers the path the flag could
// have missed: deparos creates its FuzzTask from a non-empty FuzzWordlistPath,
// so a fuzz list configured in YAML has to be cleared, not merely left
// un-materialized — otherwise the host is brute-forced while the phase header
// reports fuzzing as disabled.
func TestNoDiscoveryFuzzClearsConfiguredWordlist(t *testing.T) {
	t.Setenv(wordlistDirEnv, t.TempDir())

	settings := &config.Settings{Discovery: *config.DefaultDiscoveryConfig()}
	settings.Discovery.Wordlists.FuzzWordlistPath = "/custom/my-fuzz.txt"

	// Sanity: without the flag, a discovery-only run does route that list through.
	on := newWordlistRunner(&types.Options{OnlyPhase: "discovery"}, settings)
	if w := on.resolveDiscoveryWordlists(); base(w.fuzz) != "my-fuzz.txt" {
		t.Fatalf("baseline: configured fuzz list should be used, got %q", base(w.fuzz))
	}

	off := newWordlistRunner(&types.Options{OnlyPhase: "discovery", NoDiscoveryFuzz: true}, settings)
	if w := off.resolveDiscoveryWordlists(); w.fuzz != "" {
		t.Errorf("fuzz wordlist = %q under --no-discovery-fuzz, want empty", w.fuzz)
	}
}

func TestFilterOutHosts(t *testing.T) {
	targets := []string{
		"https://app.example.com/",
		"https://idp.example.com/login",
		"https://api.example.com/v1",
	}
	got := filterOutHosts(targets, []string{"idp.example.com"})
	want := []string{"https://app.example.com/", "https://api.example.com/v1"}
	if len(got) != len(want) {
		t.Fatalf("filterOutHosts returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("filterOutHosts[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// Empty block list is a no-op.
	if out := filterOutHosts(targets, nil); len(out) != len(targets) {
		t.Errorf("empty block should be a no-op, got %v", out)
	}
}

// TestFilterOutHostsNormalizesBlockShapes pins that the block list works
// whichever spelling a producer contributed — bare hostname or host:port — and
// blocks the target host regardless of the port on the target URL.
func TestFilterOutHostsNormalizesBlockShapes(t *testing.T) {
	targets := []string{
		"https://app.example.com/",
		"https://idp.example.com/login",
		"https://sso.example.net:8443/auth",
	}
	got := filterOutHosts(targets, []string{"idp.example.com", "sso.example.net:8443"})
	if len(got) != 1 || got[0] != "https://app.example.com/" {
		t.Errorf("filterOutHosts = %v, want only the app target", got)
	}
}

func TestNormalizeSSOHost(t *testing.T) {
	tests := map[string]string{
		"SSO.Example.com":      "sso.example.com",
		"sso.example.net:8443": "sso.example.net",
		"  idp.example.org  ":  "idp.example.org",
		"[2001:db8::1]:8443":   "2001:db8::1",
		"":                     "",
	}
	for in, want := range tests {
		if got := normalizeSSOHost(in); got != want {
			t.Errorf("normalizeSSOHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSSOHostsFromSpider pins the "whole chain, not just the landing" rule that
// all three phases feeding the block list now share. An OAuth bounce crosses an
// authorize endpoint on one host before reaching the login form on another, and
// taking only the landing left the first host a fuzz target.
func TestSSOHostsFromSpider(t *testing.T) {
	got := ssoHostsFromSpider(
		[]string{"idp.example.net", "SSO.example.com", "", "sso.example.com"},
		"https://sso.example.com:8443/u/login/identifier?state=abc",
	)
	want := []string{"idp.example.net", "sso.example.com"}
	if len(got) != len(want) {
		t.Fatalf("ssoHostsFromSpider = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ssoHostsFromSpider[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// Landing alone, with no crawler-denied hosts, still yields the wall.
	if got := ssoHostsFromSpider(nil, "https://idp.example.org/login"); len(got) != 1 || got[0] != "idp.example.org" {
		t.Errorf("ssoHostsFromSpider(nil, landing) = %v, want [idp.example.org]", got)
	}
	if got := ssoHostsFromSpider(nil, ""); len(got) != 0 {
		t.Errorf("ssoHostsFromSpider(nil, \"\") = %v, want empty", got)
	}
}

func TestResolveDiscoveryWordlists_OperatorConfigWins(t *testing.T) {
	t.Setenv(wordlistDirEnv, t.TempDir())

	settings := &config.Settings{Discovery: *config.DefaultDiscoveryConfig()}
	settings.Discovery.Wordlists.ShortFilePath = "/custom/my-files.txt"

	r := newWordlistRunner(&types.Options{}, settings)
	w := r.resolveDiscoveryWordlists()

	if base(w.shortFile) != "my-files.txt" {
		t.Errorf("configured short_file should win: %q", base(w.shortFile))
	}
	if base(w.shortDir) != "dir-short.txt" {
		t.Errorf("unconfigured short_dir should fall back to embedded: %q", base(w.shortDir))
	}
	if !w.usingConfigured || !w.usingEmbedded {
		t.Errorf("flags: usingConfigured=%v usingEmbedded=%v (want true,true)", w.usingConfigured, w.usingEmbedded)
	}
}

func TestResolveDiscoveryWordlists_FuzzOverrideAppliesAtBalanced(t *testing.T) {
	t.Setenv(wordlistDirEnv, t.TempDir())

	settings := &config.Settings{Discovery: *config.DefaultDiscoveryConfig()}
	r := newWordlistRunner(&types.Options{FuzzWordlistPath: "/custom/fuzz-list.txt"}, settings)
	w := r.resolveDiscoveryWordlists()

	// --fuzz-wordlist is an explicit override, so it applies even on balanced
	// where the embedded fuzz.txt would otherwise stay off.
	if base(w.fuzz) != "fuzz-list.txt" {
		t.Errorf("fuzz override should apply at balanced: %q", base(w.fuzz))
	}
	if !w.usingConfigured {
		t.Error("usingConfigured should be true with --fuzz-wordlist")
	}
}

func TestResolveDiscoveryWordlists_NilSettings(t *testing.T) {
	t.Setenv(wordlistDirEnv, t.TempDir())

	r := newWordlistRunner(&types.Options{}, nil)
	w := r.resolveDiscoveryWordlists()

	// Even with no YAML settings loaded, the embedded short lists still back the
	// scan so deparos is never silently observed-only by accident.
	if base(w.shortFile) != "file-short.txt" || base(w.shortDir) != "dir-short.txt" {
		t.Errorf("nil settings should still get embedded short lists: file=%q dir=%q", base(w.shortFile), base(w.shortDir))
	}
}
