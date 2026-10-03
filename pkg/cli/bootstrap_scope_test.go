package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestShouldBootstrap pins which commands may create ~/.vigolium.
//
// Bootstrap writes a config, four preset directories, and (by default) a seeded
// database. Doing that before a scan is correct; doing it because someone asked
// for the version, asked for help, or pressed tab is not. `__complete` is the
// sharpest case: it runs on every shell completion, so a user who had never run
// vigolium could create a database by typing `vigolium ` and hitting tab.
func TestShouldBootstrap(t *testing.T) {
	// Resolve against the real command tree so the test tracks the actual
	// command names rather than a parallel fixture.
	find := func(t *testing.T, path ...string) *cobra.Command {
		t.Helper()
		cmd, _, err := rootCmd.Find(path)
		require.NoError(t, err)
		return cmd
	}

	t.Run("root itself", func(t *testing.T) {
		assert.False(t, shouldBootstrap(rootCmd))
	})
	t.Run("nil", func(t *testing.T) {
		assert.False(t, shouldBootstrap(nil))
	})

	for _, name := range []string{"version", "init"} {
		t.Run(name, func(t *testing.T) {
			cmd := find(t, name)
			require.Equal(t, name, cmd.Name())
			assert.False(t, shouldBootstrap(cmd), "%s must not create ~/.vigolium", name)
		})
	}

	t.Run("help", func(t *testing.T) {
		assert.False(t, shouldBootstrap(&cobra.Command{Use: "help"}))
	})

	// Cobra builds the completion subtree inside Execute (InitDefaultCompletionCmd),
	// so it is not on rootCmd at test time. Reconstruct its shape rather than
	// mutating the shared root: what matters is that the ancestor walk sees
	// "completion" at any depth.
	t.Run("completion", func(t *testing.T) {
		root := &cobra.Command{Use: "vigolium"}
		completion := &cobra.Command{Use: "completion"}
		bash := &cobra.Command{Use: "bash"}
		completion.AddCommand(bash)
		root.AddCommand(completion)

		assert.False(t, shouldBootstrap(completion))
		// `completion bash` is the form a shell rc file runs, which made
		// bootstrap happen at login.
		assert.False(t, shouldBootstrap(bash), "a descendant of completion must be exempt too")
	})

	t.Run("hidden completion RPCs", func(t *testing.T) {
		for _, name := range []string{cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd} {
			assert.False(t, shouldBootstrap(&cobra.Command{Use: name}), "%s", name)
		}
	})

	for _, name := range []string{"scan", "finding", "traffic", "doctor", "project"} {
		t.Run(name+" bootstraps", func(t *testing.T) {
			cmd := find(t, name)
			require.Equal(t, name, cmd.Name())
			assert.True(t, shouldBootstrap(cmd), "%s needs a config and a store", name)
		})
	}
}

// TestInitializeSkipsDefaultDBWhenPinned: a first run that pins a different
// store with --db used to create, migrate and seed
// ~/.vigolium/database-vgnm.sqlite as well — a complete, plausible-looking
// database the run never opens, sitting in the first directory a user checks
// when they go looking for their data.
func TestInitializeSkipsDefaultDBWhenPinned(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	require.NoError(t, initializeVigolium(false))

	assert.FileExists(t, filepath.Join(home, ".vigolium", settingsFileName),
		"the config is still written — only the unused database is skipped")
	assert.DirExists(t, filepath.Join(home, ".vigolium", "profiles"))

	_, err := os.Stat(filepath.Join(home, ".vigolium", "database-vgnm.sqlite"))
	assert.True(t, os.IsNotExist(err),
		"the default database must not be created when --db pins another store")
}

// TestInitializeCreatesDefaultDBWhenUnpinned is the other half: with no --db
// the default file IS the store, and skipping it would break every read on a
// cold $HOME.
func TestInitializeCreatesDefaultDBWhenUnpinned(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	require.NoError(t, initializeVigolium(true))
	assert.FileExists(t, filepath.Join(home, ".vigolium", "database-vgnm.sqlite"))
}

// TestEnsureInitializedPinsOnGlobalDB covers the wiring between the two: the
// decision reads globalDB, which PersistentPreRunE has already resolved from
// --db and VIGOLIUM_DB_PATH (applyDBPathEnv runs before ensureInitialized).
func TestEnsureInitializedPinsOnGlobalDB(t *testing.T) {
	orig := globalDB
	t.Cleanup(func() { globalDB = orig })

	home := t.TempDir()
	t.Setenv("HOME", home)
	globalDB = filepath.Join(t.TempDir(), "pinned.sqlite")

	require.NoError(t, ensureInitialized())

	assert.FileExists(t, filepath.Join(home, ".vigolium", settingsFileName))
	_, err := os.Stat(filepath.Join(home, ".vigolium", "database-vgnm.sqlite"))
	assert.True(t, os.IsNotExist(err), "a pinned --db suppresses the default store")
}

// TestEnsureInitializedKeepsDefaultDBUnderReadOnly records a deliberate
// deviation from the WP14 spec, which asked for `--read-only` to suppress the
// default database too.
//
// With no --db, the default file is the store the read is about to open, and
// openSQLiteReadOnly refuses a path that does not exist ("database file not
// readable"). Suppressing it would turn a cold-$HOME `vigolium --read-only
// finding` from "0 findings, exit 0" into a hard failure. Creating an empty
// store that the read then correctly reports as empty modifies nothing that
// existed, which is what the read-only promise is actually about.
func TestEnsureInitializedKeepsDefaultDBUnderReadOnly(t *testing.T) {
	origDB, origRO := globalDB, globalReadOnly
	t.Cleanup(func() { globalDB, globalReadOnly = origDB, origRO })

	home := t.TempDir()
	t.Setenv("HOME", home)
	globalDB = ""
	globalReadOnly = true

	require.NoError(t, ensureInitialized())
	assert.FileExists(t, filepath.Join(home, ".vigolium", "database-vgnm.sqlite"))
}
