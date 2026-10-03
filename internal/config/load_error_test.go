package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vigolium/vigolium/public"
)

// TestLoadSettingsExplicitInvalidIsLoadError: a --config the operator named and
// vigolium cannot parse must be an error, not a silent switch to defaults.
func TestLoadSettingsExplicitInvalidIsLoadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.yaml")
	if err := os.WriteFile(path, []byte("database:\n  sqlite:\n   path: [unterminated\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadSettings(path)
	if err == nil {
		t.Fatal("expected an error for an unparseable explicit config")
	}
	var loadErr *LoadError
	if !errors.As(err, &loadErr) {
		t.Fatalf("err = %T (%v), want *LoadError", err, err)
	}
	if !loadErr.Explicit {
		t.Error("Explicit = false, want true")
	}
	if loadErr.Op != "parse" {
		t.Errorf("Op = %q, want \"parse\"", loadErr.Op)
	}
	// The message must name the file: the operator typed a path, and "failed to
	// parse config file" with no path is unactionable when several exist.
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name %s", err, path)
	}
}

// A --config path that does not exist is a stat LoadError that still unwraps to
// the stdlib sentinel, so the CLI's error classifier keeps reporting it as a
// missing source by identity rather than by message text.
func TestLoadSettingsExplicitMissingUnwrapsNotExist(t *testing.T) {
	_, err := LoadSettings(filepath.Join(t.TempDir(), "nope.yaml"))
	var loadErr *LoadError
	if !errors.As(err, &loadErr) || loadErr.Op != "stat" || !loadErr.Explicit {
		t.Fatalf("err = %#v, want an explicit stat LoadError", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Error("explicit missing config should unwrap to fs.ErrNotExist")
	}
}

// TestLoadSettingsImplicitInvalid: the same broken file found by DISCOVERY is
// still an error here — the fallback-to-defaults policy lives in the CLI helper,
// not in the loader, so the loader never hides which file broke.
func TestLoadSettingsImplicitInvalid(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".vigolium"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".vigolium", "vigolium-configs.yaml")
	if err := os.WriteFile(path, []byte("server: [1, 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadSettings("")
	var loadErr *LoadError
	if !errors.As(err, &loadErr) {
		t.Fatalf("err = %T (%v), want *LoadError", err, err)
	}
	if loadErr.Explicit {
		t.Error("Explicit = true for a discovered config, want false")
	}
	if loadErr.Path != path {
		t.Errorf("Path = %q, want %q", loadErr.Path, path)
	}
}

// A missing home config still falls through to the cwd candidate and then to
// defaults — discovery order is unchanged.
func TestLoadSettingsMissingFallsThroughToDefaults(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	settings, warnings, err := LoadSettingsWithWarnings("")
	if err != nil {
		t.Fatalf("LoadSettingsWithWarnings: %v", err)
	}
	if settings == nil {
		t.Fatal("expected default settings")
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

// TestLoadSettingsWarnsUnknownKey: a typo'd key is accepted (so a config written
// for another version still applies what it can) and reported, because "I set it
// and nothing happened" is otherwise invisible.
func TestLoadSettingsWarnsUnknownKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "typo.yaml")
	if err := os.WriteFile(path, []byte("scanning_strategy:\n  default_stratgy: deep\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	settings, warnings, err := LoadSettingsWithWarnings(path)
	if err != nil {
		t.Fatalf("an unknown key must not fail the load: %v", err)
	}
	if settings == nil {
		t.Fatal("settings = nil")
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly one", warnings)
	}
	for _, want := range []string{"default_stratgy", path} {
		if !strings.Contains(warnings[0], want) {
			t.Errorf("warning %q missing %q", warnings[0], want)
		}
	}
}

// A clean config produces no warnings, so the signal stays worth reading.
func TestLoadSettingsCleanConfigWarnsNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.yaml")
	if err := os.WriteFile(path, []byte("scanning_strategy:\n  default_strategy: deep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	settings, warnings, err := LoadSettingsWithWarnings(path)
	if err != nil {
		t.Fatalf("LoadSettingsWithWarnings: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
	if settings.ScanningStrategy.DefaultStrategy != "deep" {
		t.Errorf("DefaultStrategy = %q, want deep", settings.ScanningStrategy.DefaultStrategy)
	}
}

// TestLoadSettingsWarnsShadowedCwd: discovery is first-match-wins, so a
// ./vigolium-configs.yaml dropped in a repo does nothing whenever the home file
// exists. Say so rather than leaving it as a mystery.
func TestLoadSettingsWarnsShadowedCwd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".vigolium"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".vigolium", "vigolium-configs.yaml"),
		[]byte("scanning_strategy:\n  default_strategy: lite\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, "vigolium-configs.yaml"),
		[]byte("scanning_strategy:\n  default_strategy: deep\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	settings, warnings, err := LoadSettingsWithWarnings("")
	if err != nil {
		t.Fatalf("LoadSettingsWithWarnings: %v", err)
	}
	// The home file won — the warning describes reality, it does not change it.
	if settings.ScanningStrategy.DefaultStrategy != "lite" {
		t.Errorf("DefaultStrategy = %q, want lite (discovery order is unchanged)",
			settings.ScanningStrategy.DefaultStrategy)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "./vigolium-configs.yaml") {
		t.Fatalf("warnings = %v, want one naming ./vigolium-configs.yaml", warnings)
	}
	if !strings.Contains(warnings[0], "--config") {
		t.Errorf("warning %q should say how to use the cwd file", warnings[0])
	}
}

// TestDefaultConfigTemplateHasNoUnknownKeys: the template vigolium WRITES must
// not trip the warning vigolium prints. Two keys used to —
// scanning_strategy.whitebox and dynamic-assessment.max_findings_per_module —
// both inert, one of them documenting a default the CLI does not use.
func TestDefaultConfigTemplateHasNoUnknownKeys(t *testing.T) {
	var throwaway Settings
	dec := yaml.NewDecoder(strings.NewReader(ExpandEnvVars(string(public.DefaultConfigYAML))))
	dec.KnownFields(true)
	if err := dec.Decode(&throwaway); err != nil {
		t.Fatalf("public/vigolium-configs.example.yaml has keys Settings does not define:\n%v", err)
	}
}

// chdirTemp moves the test into a fresh directory for the duration of the test,
// so "./vigolium-configs.yaml" means something controlled.
func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	// macOS hands out /var/... which is a symlink to /private/var; resolve it so
	// a path comparison in the caller compares the same spelling.
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		return resolved
	}
	return dir
}
