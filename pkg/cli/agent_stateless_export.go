package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/internal/scratch"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// agentStatelessDefaultBase is the output base an agentic scan's -S/--stateless
// run falls back to when a file-producing --format was requested without
// -o/--output. It mirrors the audit driver's vigolium-result/ convention
// (defaultAuditStatelessReport): an agentic run is long (autopilot's default
// wall is 6h), so silently discarding its results because the operator forgot
// -o is a far worse outcome than picking a predictable path for them.
const agentStatelessDefaultBase = "vigolium-result/vigolium-autopilot"

// agentStatelessPlan is the resolved -S/--format state for one agentic-scan
// invocation: which formats to materialize and the output base to derive their
// paths from. A zero plan (active=false) means the run persists into the project
// DB as it always did.
type agentStatelessPlan struct {
	active  bool
	formats []string
	// output is the base path every format derives from. Empty means nothing is
	// written — either -S wasn't asked for, or the only format is console with no
	// -o (the documented throwaway case).
	output string
	// dbPath is the throwaway database this run writes into. Empty until
	// beginAgentStateless runs.
	dbPath string
}

// wantsFileOutput reports whether any requested format materializes a file or
// directory. console alone writes nothing on its own — the run already streamed
// to the terminal.
//
// Expressed as "anything that is not console" rather than as a list of file
// formats: a list has to be remembered for every new format and silently treats
// an unlisted one as writing nothing. Shared with scan-url's hasFileOutputFormat
// so the direct-path routing and the agentic -S validation cannot disagree.
func wantsFileOutput(formats []string) bool {
	for _, f := range formats {
		if !strings.EqualFold(f, "console") {
			return true
		}
	}
	return false
}

// planAgentStateless validates the --format/-o/-S combination for an agentic
// scan command and resolves the output base.
//
// Two asymmetries with the scan commands are deliberate. First, a file-producing
// --format is rejected WITHOUT -S rather than ignored: an agentic run has no live
// output writer to hang a file off, so the only honest answers are "run it
// stateless" or "query the project DB afterwards" — and silently accepting the
// flag (which is what a root-persistent --format did before) is how an operator
// discovers after a six-hour run that nothing was written. Second, -S with a
// file format and no -o defaults the base instead of erroring, because the run
// is expensive enough that a predictable path beats a rejected command.
func planAgentStateless(cmd *cobra.Command, cmdLabel string, stateless bool, output string) (agentStatelessPlan, error) {
	plan := agentStatelessPlan{active: stateless}

	// Same list, same aliases, same error as `vigolium scan -S` — the exporter
	// underneath is literally the same function (finishStatelessExport).
	plan.formats = parseFormats(globalFormat)
	if err := normalizeScanFormats(plan.formats); err != nil {
		return plan, err
	}

	output = strings.TrimSpace(output)
	wantsFiles := wantsFileOutput(plan.formats)
	// --format is a root-persistent flag defaulting to "console", so only an
	// explicit change can be a request for file output.
	formatRequested := cmd != nil && cmd.Flags().Changed("format")

	if !stateless {
		if formatRequested && wantsFiles {
			return plan, fmt.Errorf("--format %s requires -S/--stateless on %s: a persisted run writes into the project database, so export it afterwards instead — `vigolium export --format %s -o <path>`",
				strings.Join(plan.formats, ","), cmdLabel, strings.Join(plan.formats, ","))
		}
		if output != "" {
			fmt.Fprintf(os.Stderr, "%s -o/--output only applies with --stateless/-S; ignoring\n",
				terminal.WarningSymbol())
		}
		return plan, nil
	}

	// -S is a write-into-a-throwaway-DB flag, so an explicit --db (a database the
	// operator named and expects to keep) cannot also be the destination.
	if strings.TrimSpace(globalDB) != "" {
		return plan, fmt.Errorf("--stateless/-S cannot be combined with --db: -S runs into a throwaway temporary database, so the --db you named would never be written")
	}
	// Ordered after the --db check above: a database the operator named by hand
	// stays a hard conflict, while --db-isolate's destination is implicit and
	// costs nothing to drop.
	dbIsolateYieldsToStateless(stateless)

	switch {
	case output != "":
		plan.output = output
	case wantsFiles:
		plan.output = agentStatelessDefaultBase
		fmt.Fprintf(os.Stderr, "%s --stateless with no -o/--output: writing %s to %s.*\n",
			terminal.InfoSymbol(), strings.Join(plan.formats, ","), terminal.Cyan(plan.output))
	default:
		fmt.Fprintf(os.Stderr, "%s --stateless with only --format console and no -o/--output: this run's database is discarded and nothing is written. Pass -o <base>, or --format html/sqlite/jsonl/fs, to keep results.\n",
			terminal.WarningSymbol())
	}
	return plan, nil
}

// beginAgentStateless creates the throwaway database an -S agentic run writes
// into and points every consumer at it:
//
//   - globalDB, because the CLI opens through clicommon.GetDB(globalConfig, globalDB)
//   - $VIGOLIUM_DB_PATH, because the operator agent has a bash tool and shells
//     out to `vigolium` — a child that opened the default project database would
//     both hide this run's findings from the agent and leak its writes past -S
//   - the schema, created eagerly so a reader that runs before the main
//     CreateSchema (the natural-language path queries records while parsing the
//     prompt) does not hit a table that does not exist yet
//
// The caller must defer removeAgentStatelessDB(path) BEFORE its
// closeDatabaseOnExit defer, so LIFO ordering deletes the file only once the
// connection is closed. Settings-based consumers still need
// applyAgentStatelessSettings once settings are loaded.
func beginAgentStateless(prefix string) (string, error) {
	tmpFile, err := scratch.CreateTemp(prefix + "*.sqlite")
	if err != nil {
		return "", fmt.Errorf("create temporary database: %w", err)
	}
	dbPath := tmpFile.Name()
	_ = tmpFile.Close()

	globalDB = dbPath
	if err := os.Setenv(dbPathEnvVar, dbPath); err != nil {
		// Non-fatal: the in-process run still uses the temp DB via globalDB. Only
		// `vigolium` subprocesses the agent shells out to would miss it.
		zap.L().Warn("failed to pin child processes to the stateless database",
			zap.String("env", dbPathEnvVar), zap.Error(err))
	}

	db, err := getDB()
	if err != nil {
		removeAgentStatelessDB(dbPath)
		return "", fmt.Errorf("open temporary database: %w", err)
	}
	if err := db.CreateSchema(context.Background()); err != nil {
		removeAgentStatelessDB(dbPath)
		return "", fmt.Errorf("create schema in temporary database: %w", err)
	}
	return dbPath, nil
}

// applyAgentStatelessSettings repoints a loaded Settings at the throwaway
// database. Needed alongside globalDB because the native scan paths the agent
// launches (runner.LaunchScan and the pre-scan) read settings.Database rather
// than the --db global. No-op when the run isn't stateless.
func applyAgentStatelessSettings(settings *config.Settings, dbPath string) {
	if settings == nil || dbPath == "" {
		return
	}
	settings.Database.Enabled = true
	settings.Database.Driver = "sqlite"
	settings.Database.SQLite.Path = dbPath
}

// removeAgentStatelessDB deletes the throwaway database and its WAL sidecars.
func removeAgentStatelessDB(dbPath string) {
	if dbPath == "" {
		return
	}
	removeWorkingDB(dbPath)
}

// emitAgentStatelessExport materializes every requested --format from the
// throwaway database, reusing the scan commands' exporter so an agentic run's
// -S output is identical in shape (and in its unified "Exports" summary) to
// `vigolium scan -S`. Must be called while the DB handle is still open.
//
// Returns the export's outcome so the agent command can fold it into its own
// result: per-format failures are printed to stderr and every other format is
// still written, but a caller that asked for a file and got none must not be
// told the run succeeded.
func emitAgentStatelessExport(plan agentStatelessPlan) error {
	if !plan.active || plan.output == "" {
		return nil
	}
	db, err := getDB()
	if err != nil || db == nil {
		fmt.Fprintf(os.Stderr, "%s --stateless: skipping export — database unavailable: %v\n",
			terminal.WarningSymbol(), err)
		return fmt.Errorf("stateless export: database unavailable: %w", err)
	}
	// Create the base's parent directory (the default base nests under
	// vigolium-result/). finishStatelessExport's writers open files directly and
	// do not create parents; a local path only — a gs:// base uploads through a
	// temp file and has no local dir to make.
	if dir := filepath.Dir(plan.output); dir != "" && dir != "." && !storage.IsGCSURI(plan.output) {
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			fmt.Fprintf(os.Stderr, "%s --stateless: cannot create output directory %s: %v\n",
				terminal.WarningSymbol(), dir, mkErr)
		}
	}
	opts := &types.Options{
		Stateless:     true,
		OutputFormats: plan.formats,
		Output:        plan.output,
	}
	return finishStatelessExport(db, opts, plan.output, false)
}
