package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	oliumresources "github.com/vigolium/vigolium/internal/resources/olium"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/diagnostics"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/public"
	"go.uber.org/zap"
)

const (
	settingsFileName   = "vigolium-configs.yaml"
	initMarkerFileName = "initialized"
)

// writeInitMarker stamps ~/.vigolium/initialized with the binary version and
// current timestamp. The marker means "first-run dependency setup is
// complete" — written by ensureCoreDeps after the core native-scan tooling
// (chromium + nuclei templates) is confirmed present. Once stamped, scan
// commands fast-path past the dep check on every invocation.
func writeInitMarker(vigoliumDir string) error {
	path := filepath.Join(vigoliumDir, initMarkerFileName)
	payload := fmt.Sprintf(`{"version":%q,"initialized_at":%q}`+"\n",
		Version,
		time.Now().UTC().Format(time.RFC3339))
	return os.WriteFile(path, []byte(payload), 0644)
}

// initializeVigolium initializes Vigolium on first run: it writes the default
// config, profiles, extensions, prompts and skills into ~/.vigolium.
//
// createDefaultDB decides whether ~/.vigolium/database-vgnm.sqlite is created
// too. It is false when the invocation has pinned a different store with --db
// (or VIGOLIUM_DB_PATH, which applyDBPathEnv has already folded into globalDB
// by the time ensureInitialized runs): creating the default database there
// produces a seeded, schema-migrated file the run will never open, in the one
// directory a user is most likely to inspect to find out where their data went.
// The pinned store is created and seeded by whichever path first opens it,
// exactly as it already is on a warm $HOME.
func initializeVigolium(createDefaultDB bool) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	vigoliumDir := filepath.Join(homeDir, ".vigolium")
	settingsPath := filepath.Join(vigoliumDir, settingsFileName)

	// Check if settings file already exists
	if _, err := os.Stat(settingsPath); err == nil {
		// Settings file exists, Vigolium is already initialized
		return nil
	}

	// First run - initialize Vigolium
	fmt.Fprintf(os.Stderr, "%s %s\n",
		terminal.Cyan(terminal.SymbolRunning),
		terminal.BoldCyan("First-time run detected — checking for mandatory configuration and dependencies..."))
	zap.L().Info("First run detected - initializing Vigolium...")

	// Create .vigolium directory
	if err := os.MkdirAll(vigoliumDir, 0755); err != nil {
		return fmt.Errorf("failed to create .vigolium directory: %w", err)
	}

	// Write the curated example YAML as the default config — preserves comments,
	// formatting, and avoids zero-value noise from struct marshalling.
	// Replace the auth_api_key placeholder with a real random key.
	configData := bytes.Replace(
		public.DefaultConfigYAML,
		[]byte(`auth_api_key: "auto-generated-on-first-run"`),
		[]byte(fmt.Sprintf(`auth_api_key: "%s"`, config.GenerateRandomHex(40))),
		1,
	)
	if err := os.WriteFile(settingsPath, configData, 0600); err != nil {
		return fmt.Errorf("failed to write default config: %w", err)
	}

	// Load settings back for database initialization and display below.
	settings := config.DefaultSettings()

	zap.L().Info("Created default settings file",
		zap.String("path", settingsPath))

	// Initialize database
	if createDefaultDB && settings.Database.Enabled {
		fmt.Fprintf(os.Stderr, "  %s Creating database schema...\n", terminal.InfoSymbol())
		zap.L().Info("Initializing database...")

		db, err := database.NewDB(&settings.Database)
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}
		defer func() { _ = db.Close() }()

		ctx := context.Background()
		if err := db.CreateSchema(ctx); err != nil {
			return fmt.Errorf("failed to create database schema: %w", err)
		}

		fmt.Fprintf(os.Stderr, "  %s Seeding default project and search indexes...\n", terminal.InfoSymbol())
		if err := db.SeedDefaults(ctx); err != nil {
			return fmt.Errorf("failed to seed default data: %w", err)
		}

		zap.L().Debug("Database initialized successfully",
			zap.String("driver", settings.Database.Driver),
			zap.String("path", settings.Database.SQLite.Path))
	}

	fmt.Fprintf(os.Stderr, "  %s Installing default profiles, extensions, prompts, and skills...\n", terminal.InfoSymbol())

	// Bootstrap default profiles
	bootstrapDefaultProfiles(vigoliumDir)

	// Bootstrap preset extensions
	bootstrapExtensions(vigoliumDir)

	// Bootstrap prompt templates
	bootstrapPrompts(vigoliumDir)

	// Bootstrap agentic-scan skills (~/.vigolium/skills or VIGOLIUM_SKILLS_DIR)
	bootstrapSkills()

	// Note: the ~/.vigolium/initialized marker is intentionally NOT written
	// here. The marker tracks core dep installation (chromium + nuclei
	// templates), which is handled by ensureCoreDeps. Config bootstrap by
	// itself does not satisfy "first-run setup".

	// Print success message
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.SuccessSymbol(), terminal.BoldGreen("Mandatory configuration initialized."))
	fmt.Fprintf(os.Stderr, "  %s Config: %s\n", terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(settingsPath)))
	// Only name the default database when this run actually created it. Naming
	// a file that is not there, on a run that is deliberately using a different
	// store, is the opposite of informative.
	if createDefaultDB {
		fmt.Fprintf(os.Stderr, "  %s Database: %s\n", terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(config.ExpandPath(settings.Database.SQLite.Path))))
	} else {
		fmt.Fprintf(os.Stderr, "  %s Database: %s\n", terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(config.ExpandPath(globalDB))))
	}
	fmt.Fprintf(os.Stderr, "  %s Docs & guides: %s\n", terminal.InfoSymbol(), terminal.Cyan("https://docs.vigolium.com"))
	fmt.Fprintf(os.Stderr, "  %s Run %s for a full setup (browser, templates, and agentic-scan runtimes).\n",
		terminal.TipSymbol(), terminal.BoldCyan("vigolium doctor --fix"))

	return nil
}

// bootstrapDefaultProfiles copies embedded profile YAMLs to the profiles directory
// if the directory does not exist yet. This runs during first-time initialization.
func bootstrapDefaultProfiles(vigoliumDir string) {
	profilesDir := filepath.Join(vigoliumDir, "profiles")

	// Only bootstrap if the profiles directory does not exist
	if _, err := os.Stat(profilesDir); err == nil {
		return
	}

	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		zap.L().Debug("Failed to create profiles directory", zap.Error(err))
		return
	}

	entries, err := public.StaticFS.ReadDir("presets/profiles")
	if err != nil {
		zap.L().Debug("Failed to read embedded profiles", zap.Error(err))
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, readErr := public.StaticFS.ReadFile("presets/profiles/" + entry.Name())
		if readErr != nil {
			continue
		}
		dest := filepath.Join(profilesDir, entry.Name())
		if err := os.WriteFile(dest, data, 0644); err != nil {
			zap.L().Debug("Failed to write default profile", zap.String("dest", dest), zap.Error(err))
		}
	}

	zap.L().Info("Bootstrapped default scanning profiles",
		zap.String("dir", profilesDir))
}

// bootstrapPrompts copies embedded prompt templates to the prompts directory.
func bootstrapPrompts(vigoliumDir string) {
	bootstrapEmbeddedDir(vigoliumDir, "prompts", "presets/prompts", "prompt templates")
}

// bootstrapExtensions copies embedded preset extensions to the extensions directory.
func bootstrapExtensions(vigoliumDir string) {
	bootstrapEmbeddedDir(vigoliumDir, "extensions", "presets/extensions", "preset extensions")
}

// bootstrapSkills materializes the embedded built-in olium skills into the
// user-scope skills directory (~/.vigolium/skills, or VIGOLIUM_SKILLS_DIR) so
// operators get editable copies that the autopilot/swarm loader prefers over
// the embedded fallback. Write-if-missing — re-runs and operator edits are
// preserved. Best-effort: skills still load from the embed if this fails.
func bootstrapSkills() {
	dir := skill.UserSkillsDir()
	if dir == "" {
		return
	}
	n, err := oliumresources.EnsureOnDisk(dir)
	if err != nil {
		zap.L().Debug("Failed to materialize skills", zap.String("dir", dir), zap.Error(err))
		return
	}
	if n > 0 {
		zap.L().Info("Bootstrapped skills", zap.String("dir", dir), zap.Int("written", n))
	}
}

// bootstrapEmbeddedDir copies files from an embedded FS path into a subdirectory
// of vigoliumDir, preserving directory structure. It only runs if the target
// directory does not exist yet.
func bootstrapEmbeddedDir(vigoliumDir, subDir, embedPath, label string) {
	targetDir := filepath.Join(vigoliumDir, subDir)

	if _, err := os.Stat(targetDir); err == nil {
		return
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		zap.L().Debug("Failed to create "+subDir+" directory", zap.Error(err))
		return
	}

	copyEmbeddedDir(targetDir, embedPath)

	zap.L().Info("Bootstrapped "+label, zap.String("dir", targetDir))
}

// copyEmbeddedDir recursively copies files from the embedded FS into targetDir.
func copyEmbeddedDir(targetDir, embedPath string) {
	entries, err := public.StaticFS.ReadDir(embedPath)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			subTarget := filepath.Join(targetDir, entry.Name())
			if err := os.MkdirAll(subTarget, 0755); err != nil {
				zap.L().Debug("Failed to create bootstrap subdir", zap.String("dir", subTarget), zap.Error(err))
				continue
			}
			copyEmbeddedDir(subTarget, embedPath+"/"+entry.Name())
			continue
		}
		data, readErr := public.StaticFS.ReadFile(embedPath + "/" + entry.Name())
		if readErr != nil {
			continue
		}
		dest := filepath.Join(targetDir, entry.Name())
		if err := os.WriteFile(dest, data, 0644); err != nil {
			zap.L().Debug("Failed to write bootstrapped file", zap.String("dest", dest), zap.Error(err))
		}
	}
}

// coreDepCommands lists the leaf cobra command names (cmd.Name()) that drive
// a native scan and therefore need chromium + nuclei templates available
// before they run. The set deliberately excludes:
//   - informational commands (version, doctor, config, help, examples, license, log)
//   - data-management commands (project, scope, source, traffic, finding, db, …)
//   - the olium TUI and the agent query/olium/audit subcommands (LLM-only, no native scan)
//
// Adding a new scan command? List its leaf name here.
var coreDepCommands = map[string]bool{
	"scan":         true,
	"scan-url":     true,
	"scan-request": true,
	"run":          true,
	"autopilot":    true, // `vigolium agent autopilot` — uses chromium for spidering
	"swarm":        true, // `vigolium agent swarm`     — drives the native scan pipeline
	"server":       true, // long-running API server that hosts scan endpoints
	"ingest":       true, // populates the queue feeding scan workers
}

// needsCoreDeps reports whether the given command should trigger the
// first-run chromium + nuclei-templates install.
func needsCoreDeps(cmd *cobra.Command) bool {
	return coreDepCommands[cmd.Name()]
}

// coreDepInstallTimeout caps the per-invocation budget for the chromium +
// nuclei-templates installation step. Both are network-bound (template git
// clone, Chrome for Testing download) so we allow generous headroom; the
// marker write happens regardless of fix success so a flaky first run does
// not block every subsequent scan.
const coreDepInstallTimeout = 10 * time.Minute

// ensureCoreDeps guarantees the two native-scan dependencies — chromium and
// nuclei templates — are present before a scan-touching command runs. On the
// first invocation it shells out to the doctor's `--fix --only nuclei,chrome`
// path and stamps ~/.vigolium/initialized; on subsequent invocations the
// marker short-circuits the diagnostic to a single os.Stat.
//
// The marker is written even when one of the two installs fails — re-running
// the dep check on every command would punish users behind flaky networks or
// on hosts without internet access. The doctor's "Initialized" row + a
// printed warning here make the partial state visible, and the user can
// re-run `vigolium doctor --fix --only nuclei,chrome` to retry explicitly.
func ensureCoreDeps() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil // Silently fail; downstream command will surface the real issue.
	}
	vigoliumDir := filepath.Join(homeDir, ".vigolium")
	markerPath := filepath.Join(vigoliumDir, initMarkerFileName)
	if _, err := os.Stat(markerPath); err == nil {
		return nil
	}

	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}

	// DB intentionally omitted — neither the chromium nor nuclei-templates
	// check touches the database, and opening it here would either trigger
	// a redundant connection or surface a misleading "db unavailable" tip
	// inside the dep flow.
	//
	// diagnostics.Run sweeps the PATH for chromium/nuclei and friends, which
	// can take a couple of seconds on a cold first run — announce it so the
	// terminal doesn't look frozen while the sweep runs.
	fmt.Fprintf(os.Stderr, "%s %s\n",
		terminal.InfoSymbol(),
		"First-time scan detected — checking mandatory dependencies first...")
	report := diagnostics.Run(diagnostics.Deps{Settings: settings, ProbeBrowserLaunch: true})

	chromiumMissing := report.Tools["chromium"] == nil || report.Tools["chromium"].Status != diagnostics.StatusOK
	nucleiMissing := report.NucleiTemplates == nil || report.NucleiTemplates.Status != diagnostics.StatusOK

	if !chromiumMissing && !nucleiMissing {
		// Both already present — backfill the marker so subsequent runs
		// skip the diagnostic entirely. No need to invoke RunFixes.
		fmt.Fprintf(os.Stderr, "%s %s\n", terminal.SuccessSymbol(), terminal.Green("All mandatory dependencies present"))
		if err := writeInitMarker(vigoliumDir); err != nil {
			zap.L().Debug("Failed to write init marker", zap.Error(err))
		}
		return nil
	}

	fmt.Fprintf(os.Stderr, "%s %s\n",
		terminal.InfoSymbol(),
		terminal.BoldCyan("First-run setup: installing core scan dependencies (chromium, nuclei-templates)..."))

	ctx, cancel := context.WithTimeout(context.Background(), coreDepInstallTimeout)
	defer cancel()
	results := diagnostics.RunFixes(ctx, report, settings, []string{"nuclei", "chrome"})

	for _, r := range results {
		if r.Success {
			fmt.Fprintf(os.Stderr, "  %s %-30s %s\n", terminal.SuccessSymbol(), terminal.Green(r.Label), terminal.White(r.Message))
		} else {
			fmt.Fprintf(os.Stderr, "  %s %-30s %s\n", terminal.Red(terminal.SymbolError), terminal.Red(r.Label), terminal.White(r.Message))
		}
	}

	if err := writeInitMarker(vigoliumDir); err != nil {
		zap.L().Debug("Failed to write init marker after dep install", zap.Error(err))
	}
	return nil
}

// ensureInitMarkerIfDepsPresent stamps ~/.vigolium/initialized (best-effort,
// dir created if needed) ONLY when the two mandatory native-scan dependencies —
// chromium and nuclei-templates — are confirmed present in the supplied
// diagnostics report. Called by `vigolium doctor` so a run that observes a
// healthy toolchain backfills the marker, mirroring the ensureCoreDeps backfill
// (see ensureCoreDeps: both-present → writeInitMarker).
//
// The deps-present gate is the whole point: a read-only `vigolium doctor` on a
// machine that is MISSING chromium/nuclei must NOT stamp the marker, otherwise
// it would suppress the first-run auto-install that the next scan relies on. The
// existence guard preserves the original timestamp on repeat doctor runs.
func ensureInitMarkerIfDepsPresent(report *diagnostics.Report) {
	if report == nil {
		return
	}
	chromiumOK := report.Tools["chromium"] != nil && report.Tools["chromium"].Status == diagnostics.StatusOK
	nucleiOK := report.NucleiTemplates != nil && report.NucleiTemplates.Status == diagnostics.StatusOK
	if !chromiumOK || !nucleiOK {
		return // a dep is missing — leave the first-run install path armed for the next scan
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	vigoliumDir := filepath.Join(homeDir, ".vigolium")
	markerPath := filepath.Join(vigoliumDir, initMarkerFileName)
	if _, err := os.Stat(markerPath); err == nil {
		return // already stamped; preserve original timestamp
	}
	if err := os.MkdirAll(vigoliumDir, 0755); err != nil {
		zap.L().Debug("doctor: failed to create .vigolium dir for init marker", zap.Error(err))
		return
	}
	if err := writeInitMarker(vigoliumDir); err != nil {
		zap.L().Debug("doctor: failed to write init marker", zap.Error(err))
	}
}

// skipCoreDepCheck honors the --skip-dependency-check flag: it stamps
// ~/.vigolium/initialized immediately without probing for chromium or nuclei
// templates, so this run and every future scan fast-path past the first-run
// dependency check. Best-effort — a failed mkdir/write just means the check may
// run on a later invocation. Returns true when it actually wrote the marker.
func skipCoreDepCheck() bool {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	vigoliumDir := filepath.Join(homeDir, ".vigolium")
	markerPath := filepath.Join(vigoliumDir, initMarkerFileName)
	if _, err := os.Stat(markerPath); err == nil {
		return false // already stamped; nothing to do
	}
	if err := os.MkdirAll(vigoliumDir, 0755); err != nil {
		zap.L().Debug("skip-dependency-check: failed to create .vigolium dir", zap.Error(err))
		return false
	}
	if err := writeInitMarker(vigoliumDir); err != nil {
		zap.L().Debug("skip-dependency-check: failed to write init marker", zap.Error(err))
		return false
	}
	return true
}

// ensureInitialized checks if Vigolium is initialized and initializes if needed
// This is called before any command runs that shouldBootstrap admits.
func ensureInitialized() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil // Silently fail, command will continue
	}

	settingsPath := filepath.Join(homeDir, ".vigolium", settingsFileName)

	// Check if already initialized
	if _, err := os.Stat(settingsPath); err == nil {
		return nil
	}

	// Not initialized - run initialization. The default database is created
	// only when it is the store this invocation will use: a pinned --db (or a
	// VIGOLIUM_DB_PATH that applyDBPathEnv has already folded into globalDB)
	// means the default file would be created, seeded and never opened.
	//
	// --read-only deliberately does NOT suppress it. The spec called for that,
	// but with no --db the default file IS the store the read is about to open,
	// and openSQLiteReadOnly refuses a path that does not exist — so skipping
	// here would turn a cold-$HOME `vigolium --read-only finding` from "0
	// findings, exit 0" into "database file not readable". Creating an empty
	// store the read then reports as empty modifies nothing that existed.
	return initializeVigolium(strings.TrimSpace(globalDB) == "")
}

// bootstrapExemptCommands are the leaf command names that must not materialize
// ~/.vigolium as a side effect of running.
//
// Bootstrap writes a config, a database, and four directories of presets. That
// is the right thing to do before a scan and the wrong thing to do when the
// user asked what version this is, asked for help, or — worst of all — pressed
// tab. `__complete` runs on every shell completion, so a user who had never run
// vigolium could create a seeded database by typing `vigolium ` and hitting tab
// twice; `completion bash` is routinely run from a shell rc file, which made it
// happen at login.
//
// `init` is exempt because it does the initialization itself, with its own
// flags and its own reporting.
var bootstrapExemptCommands = map[string]bool{
	"init":                          true,
	"version":                       true,
	"help":                          true,
	cobra.ShellCompRequestCmd:       true, // __complete
	cobra.ShellCompNoDescRequestCmd: true, // __completeNoDesc
}

// shouldBootstrap reports whether this command may create ~/.vigolium.
//
// The root command with no subcommand only prints usage, and the `completion`
// subtree only writes a shell script to stdout — neither touches a database or
// a profile, and both are reached by users who have not yet decided to use
// vigolium at all.
func shouldBootstrap(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	if cmd.Root() == cmd {
		return false
	}
	if bootstrapExemptCommands[cmd.Name()] {
		return false
	}
	for c := cmd; c != nil; c = c.Parent() {
		if c.Name() == "completion" {
			return false
		}
	}
	return true
}
