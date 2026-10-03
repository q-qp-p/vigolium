package browser

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// containsChromium reports whether a candidate name refers to Chromium (vs real
// Chrome). Used only to assert the Chrome-before-Chromium ordering invariant.
func isChromiumName(name string) bool {
	return strings.Contains(strings.ToLower(name), "chromium")
}

func isChromeName(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "chrome") && !isChromiumName(name)
}

// TestBrowserPreferenceOrderChromeFirst asserts that on every platform real
// Google Chrome is tried before Chromium — the order the user expects (Chrome →
// Chromium → Chrome for Testing last, the last handled outside this list).
func TestBrowserPreferenceOrderChromeFirst(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		order := browserPreferenceOrderFor(goos)
		if len(order) == 0 {
			t.Fatalf("%s: empty preference order", goos)
		}
		firstChrome, firstChromium := -1, -1
		for i, name := range order {
			if firstChrome == -1 && isChromeName(name) {
				firstChrome = i
			}
			if firstChromium == -1 && isChromiumName(name) {
				firstChromium = i
			}
		}
		if firstChrome == -1 {
			t.Errorf("%s: no Chrome entry in preference order %v", goos, order)
		}
		if firstChromium != -1 && firstChrome > firstChromium {
			t.Errorf("%s: Chrome (idx %d) should precede Chromium (idx %d) in %v",
				goos, firstChrome, firstChromium, order)
		}
	}
}

func TestSystemBrowserBinsOrdering(t *testing.T) {
	order := []string{"google-chrome", "chrome", "chromium", "chromium-browser"}
	resolved := map[string]string{
		"google-chrome":    "/usr/bin/google-chrome",
		"chromium":         "/usr/bin/chromium",
		"chromium-browser": "/usr/bin/chromium", // symlink → same real path
	}
	lookPath := func(name string) (string, bool) {
		p, ok := resolved[name]
		return p, ok
	}
	validateAll := func(string) bool { return true }

	got := systemBrowserBins(order, lookPath, validateAll)
	want := []string{"/usr/bin/google-chrome", "/usr/bin/chromium"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (Chrome must precede Chromium; dups collapsed)", got, want)
		}
	}
}

func TestSystemBrowserBinsValidateFilters(t *testing.T) {
	order := []string{"chromium", "google-chrome"}
	lookPath := func(name string) (string, bool) {
		return "/usr/bin/" + name, true
	}
	// Simulate a snap stub: /usr/bin/chromium resolves but fails validation.
	validate := func(p string) bool { return !strings.HasSuffix(p, "chromium") }

	got := systemBrowserBins(order, lookPath, validate)
	if len(got) != 1 || got[0] != "/usr/bin/google-chrome" {
		t.Fatalf("validation should drop the stub chromium, got %v", got)
	}
}

func TestSystemBrowserBinsNoneFound(t *testing.T) {
	got := systemBrowserBins(
		[]string{"chrome", "chromium"},
		func(string) (string, bool) { return "", false },
		func(string) bool { return true },
	)
	if len(got) != 0 {
		t.Fatalf("expected no bins when nothing resolves, got %v", got)
	}
}

func TestBinPathOrAuto(t *testing.T) {
	if got := binPathOrAuto(""); got != "auto-download" {
		t.Errorf("binPathOrAuto(\"\") = %q, want auto-download", got)
	}
	if got := binPathOrAuto("/usr/bin/chromium"); got != "/usr/bin/chromium" {
		t.Errorf("binPathOrAuto(path) = %q, want the path", got)
	}
}

// --- platform matrix -------------------------------------------------------

func labelsOf(cands []browserCandidate) []string {
	out := make([]string, len(cands))
	for i, c := range cands {
		out[i] = c.label
	}
	return out
}

// TestBuildBrowserCandidatesPlatformMatrix pins the ordered candidate list — and
// the platform-specific tail — across every deployment target. Docker vs. bare
// metal is intentionally NOT a separate axis: both are GOOS=linux and resolve
// identically; the axis that actually matters is the arch, because rod's
// auto-download is broken on linux/arm64 and Chrome for Testing has no build
// there (so that leg falls off and the run relies on a system browser).
func TestBuildBrowserCandidatesPlatformMatrix(t *testing.T) {
	embedded := func() (string, error) { return "", nil } // resolver; not invoked when only reading labels
	sysBins := []string{"/usr/bin/chromium"}

	baseTail := []string{
		"embedded browser",
		"system browser /usr/bin/chromium",
		"Chrome for Testing (cached)",
		"Chrome for Testing (download)",
	}
	withRodAuto := append(append([]string{}, baseTail...), "rod auto-download")

	tests := []struct {
		name         string
		goos, goarch string
		want         []string
		wantRodAuto  bool
	}{
		{"linux/amd64 (bare or docker)", "linux", "amd64", withRodAuto, true},
		{"linux/arm64 (bare or docker) — no rod auto-download", "linux", "arm64", baseTail, false},
		{"darwin/arm64 (Apple Silicon)", "darwin", "arm64", withRodAuto, true},
		{"darwin/amd64 (Intel Mac)", "darwin", "amd64", withRodAuto, true},
		{"windows/amd64", "windows", "amd64", withRodAuto, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := labelsOf(buildBrowserCandidates(context.Background(), tt.goos, tt.goarch, "", sysBins, embedded))
			if len(got) != len(tt.want) {
				t.Fatalf("labels = %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("labels = %v, want %v", got, tt.want)
				}
			}
			if hasRod := slices.Contains(got, "rod auto-download"); hasRod != tt.wantRodAuto {
				t.Errorf("rod auto-download present=%v, want %v (only linux/arm64 skips it)", hasRod, tt.wantRodAuto)
			}
			// Chrome for Testing is always offered before rod's own download,
			// on every platform (it self-gates on IsSupported at resolve time).
			if !slices.Contains(got, "Chrome for Testing (download)") {
				t.Errorf("CfT download candidate missing on %s/%s", tt.goos, tt.goarch)
			}
		})
	}
}

// TestBuildBrowserCandidatesConfigPathFirst verifies an explicit browser_path
// sorts ahead of everything and resolves to the configured value.
func TestBuildBrowserCandidatesConfigPathFirst(t *testing.T) {
	embedded := func() (string, error) { return "", nil }
	cands := buildBrowserCandidates(context.Background(), "linux", "amd64", "/opt/cft/chrome", []string{"/usr/bin/chromium"}, embedded)

	if len(cands) == 0 || cands[0].label != "configured browser_path" {
		t.Fatalf("configured browser_path should be first, got %v", labelsOf(cands))
	}
	p, err := cands[0].resolve()
	if err != nil || p != "/opt/cft/chrome" {
		t.Fatalf("config candidate resolve = (%q, %v), want (/opt/cft/chrome, nil)", p, err)
	}
	// Without a config path, the first candidate is the embedded engine.
	noCfg := buildBrowserCandidates(context.Background(), "linux", "amd64", "", nil, embedded)
	if len(noCfg) == 0 || noCfg[0].label != "embedded browser" {
		t.Fatalf("with no config path, embedded browser should lead, got %v", labelsOf(noCfg))
	}
}

// TestLinuxARM64UsesSystemChromium documents the supported arm64 story: on
// linux/arm64 (bare metal, Docker, Raspberry Pi, Graviton) an installed system
// Chromium IS a launch candidate and IS tried — the ONLY thing dropped is rod's
// own broken auto-download. arm64 is not second-class; it just requires a
// browser to be present (system Chromium, or the embedded ungoogled arm64
// engine) because neither CfT nor rod publish an arm64 Linux download.
func TestLinuxARM64UsesSystemChromium(t *testing.T) {
	embedded := func() (string, error) { return "", nil }

	// With an apt-installed chromium, arm64 uses it just like any other host.
	withChromium := labelsOf(buildBrowserCandidates(context.Background(), "linux", "arm64", "", []string{"/usr/bin/chromium"}, embedded))
	if !slices.Contains(withChromium, "system browser /usr/bin/chromium") {
		t.Fatalf("arm64 must try the installed system chromium, got %v", withChromium)
	}
	if slices.Contains(withChromium, "rod auto-download") {
		t.Errorf("arm64 should drop only rod auto-download, got %v", withChromium)
	}

	// The embedded ungoogled arm64 engine is always offered ahead of the system
	// browser, so an arm64 build using --browser-engine ungoogled needs nothing
	// installed at all.
	if withChromium[0] != "embedded browser" {
		t.Errorf("embedded engine should lead on arm64 (covers the no-system-browser case), got %v", withChromium)
	}

	// With NO browser installed, the ladder still self-skips the unavailable CfT
	// rungs and offers no rod auto-download — so launch() emits the install hint
	// rather than hanging.
	bare := labelsOf(buildBrowserCandidates(context.Background(), "linux", "arm64", "", nil, embedded))
	if slices.Contains(bare, "rod auto-download") {
		t.Errorf("arm64 with no system browser must not offer rod auto-download, got %v", bare)
	}
}

func TestIsLinuxARM64For(t *testing.T) {
	cases := []struct {
		goos, goarch string
		want         bool
	}{
		{"linux", "arm64", true}, // Raspberry Pi / arm64 docker / Graviton
		{"linux", "amd64", false},
		{"linux", "386", false},
		{"darwin", "arm64", false}, // Apple Silicon — rod auto-download is fine
		{"darwin", "amd64", false},
		{"windows", "amd64", false},
		{"windows", "arm64", false},
	}
	for _, c := range cases {
		if got := isLinuxARM64For(c.goos, c.goarch); got != c.want {
			t.Errorf("isLinuxARM64For(%q,%q) = %v, want %v", c.goos, c.goarch, got, c.want)
		}
	}
}

// TestBrowserPreferenceOrderPlatformEntries checks the concrete per-OS binary
// lists (not just the Chrome-before-Chromium ordering asserted elsewhere).
func TestBrowserPreferenceOrderPlatformEntries(t *testing.T) {
	linux := browserPreferenceOrderFor("linux")
	for _, want := range []string{"google-chrome", "chromium", "/usr/bin/chromium", "/usr/lib/chromium/chromium"} {
		if !slices.Contains(linux, want) {
			t.Errorf("linux order missing %q: %v", want, linux)
		}
	}

	darwin := browserPreferenceOrderFor("darwin")
	if !slices.Contains(darwin, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome") {
		t.Errorf("darwin order missing the Google Chrome.app path: %v", darwin)
	}
	if !slices.Contains(darwin, "chromium") {
		t.Errorf("darwin order missing chromium: %v", darwin)
	}

	win := browserPreferenceOrderFor("windows")
	if len(win) == 0 || win[0] != "chrome" {
		t.Errorf("windows order should lead with chrome: %v", win)
	}
}

// TestBrowserPreferenceOrderWindowsInstallPaths pins the Windows list to the
// real install locations. Chrome is effectively never on PATH on Windows, so
// before these were added the whole list was two bare names that never resolve
// — every Windows user silently fell through to a Chrome-for-Testing download
// even with Chrome installed. The env lookup is stubbed so this runs anywhere.
func TestBrowserPreferenceOrderWindowsInstallPaths(t *testing.T) {
	env := map[string]string{
		"LOCALAPPDATA":      `C:\Users\tester\AppData\Local`,
		"ProgramFiles":      `C:\Program Files`,
		"ProgramFiles(x86)": `C:\Program Files (x86)`,
	}
	got := browserPreferenceOrderForEnv("windows", func(k string) string { return env[k] })

	for _, want := range []string{
		"chrome",
		`C:\Users\tester\AppData\Local\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		`C:\Users\tester\AppData\Local\Google\Chrome SxS\Application\chrome.exe`,
		"chromium",
		`C:\Program Files\Chromium\Application\chrome.exe`,
	} {
		if !slices.Contains(got, want) {
			t.Errorf("windows order missing %q: %v", want, got)
		}
	}

	// Real Chrome must sort ahead of Chromium, matching the documented policy.
	chromeAt := slices.Index(got, `C:\Program Files\Google\Chrome\Application\chrome.exe`)
	chromiumAt := slices.Index(got, `C:\Program Files\Chromium\Application\chrome.exe`)
	if chromeAt < 0 || chromiumAt < 0 || chromeAt > chromiumAt {
		t.Errorf("Chrome should precede Chromium: chrome=%d chromium=%d in %v", chromeAt, chromiumAt, got)
	}

	// Separators must be literal backslashes regardless of the host running the
	// test — filepath.Join would emit "/" here on linux/darwin.
	for _, p := range got {
		if strings.Contains(p, "/") {
			t.Errorf("windows path contains a forward slash: %q", p)
		}
	}
}

// TestBrowserPreferenceOrderWindowsBareEnv covers a stripped environment (a
// service account, a locked-down CI shell): ProgramFiles may be unset, and the
// standard literal locations must still be offered rather than a bare "C:\".
func TestBrowserPreferenceOrderWindowsBareEnv(t *testing.T) {
	got := browserPreferenceOrderForEnv("windows", func(string) string { return "" })
	if !slices.Contains(got, `C:\Program Files\Google\Chrome\Application\chrome.exe`) {
		t.Errorf("empty env should still yield the default Program Files path: %v", got)
	}
	// LOCALAPPDATA-derived entries have no sane default, so they are omitted
	// rather than guessed at a wrong user profile.
	for _, p := range got {
		if strings.Contains(p, "AppData") {
			t.Errorf("unset LOCALAPPDATA should not produce an AppData path: %q", p)
		}
	}

	// An unknown GOOS must still yield a usable (non-empty) fallback list.
	other := browserPreferenceOrderFor("freebsd")
	if len(other) == 0 {
		t.Error("unknown GOOS should fall back to a non-empty default order")
	}
}
