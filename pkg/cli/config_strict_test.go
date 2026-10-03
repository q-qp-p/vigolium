package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// withGlobalConfig points --config at path for one test and restores it.
func withGlobalConfig(t *testing.T, path string) {
	t.Helper()
	prev := globalConfig
	globalConfig = path
	t.Cleanup(func() { globalConfig = prev })
}

// TestResetDatabaseRefusesOnConfigError: `db clean --reset` DELETES a file, and
// the config is what names which one. Falling back to defaults there does not
// mean "use default settings", it means "delete a different database".
func TestResetDatabaseRefusesOnConfigError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clicommon.ResetDBCache()
	t.Cleanup(clicommon.ResetDBCache)

	// A decoy at the default location. It must survive.
	if err := os.MkdirAll(filepath.Join(home, ".vigolium"), 0o755); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(home, ".vigolium", "database-vgnm.sqlite")
	if err := os.WriteFile(decoy, []byte("decoy"), 0o644); err != nil {
		t.Fatal(err)
	}

	broken := filepath.Join(home, "broken.yaml")
	if err := os.WriteFile(broken, []byte("database: [1, 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withGlobalConfig(t, broken)

	err := resetDatabase()
	if err == nil {
		t.Fatal("resetDatabase should refuse when the config cannot be read")
	}
	if !strings.Contains(err.Error(), "which database to reset") {
		t.Errorf("error %q should say it cannot determine the target", err)
	}
	if got, readErr := os.ReadFile(decoy); readErr != nil || string(got) != "decoy" {
		t.Errorf("the default database was touched: %q, %v", got, readErr)
	}
}

// TestModuleEnableWritesExplicitConfig: with --config set, the command used to
// READ that file and WRITE the discovered one — so a one-module edit against a
// team config overwrote the operator's personal config with the team's content.
func TestModuleEnableWritesExplicitConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".vigolium"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The file that must NOT be written.
	defaultCfg := filepath.Join(home, ".vigolium", "vigolium-configs.yaml")
	const sentinel = "# personal config, do not clobber\n"
	if err := os.WriteFile(defaultCfg, []byte(sentinel), 0o644); err != nil {
		t.Fatal(err)
	}

	explicit := filepath.Join(home, "team.yaml")
	if err := os.WriteFile(explicit, []byte("dynamic-assessment:\n  enabled_modules:\n    active_modules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withGlobalConfig(t, explicit)

	prevExact := moduleExactID
	moduleExactID = true
	t.Cleanup(func() { moduleExactID = prevExact })

	// Any real module id; the assertion is about WHICH FILE moved, not which
	// module landed in it.
	ids := expandAllModuleIDs("active")
	if len(ids) == 0 {
		t.Skip("no active modules registered")
	}
	if err := runModuleEnable(nil, []string{ids[0]}); err != nil {
		t.Fatalf("runModuleEnable: %v", err)
	}

	got, err := os.ReadFile(defaultCfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Errorf("the discovered config was rewritten; it should have been left alone:\n%s", got)
	}

	written, err := config.LoadSettings(explicit)
	if err != nil {
		t.Fatalf("reload the explicit config: %v", err)
	}
	found := false
	for _, m := range written.DynamicAssessment.EnabledModules.ActiveModules {
		if m == ids[0] {
			found = true
		}
	}
	if !found {
		t.Errorf("%s not enabled in %s: %v", ids[0], explicit,
			written.DynamicAssessment.EnabledModules.ActiveModules)
	}
}
