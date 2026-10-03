package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

var dbCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Clean database records",
	Long: "Delete records from the database by host, scan UUID, age, status, or severity. " +
		"Supports --dry-run to preview and --orphans to remove orphaned findings; disk space is reclaimed " +
		"automatically with VACUUM after a delete. Use --all --force to delete every row from the data tables, " +
		"or `vigolium db reset --force` to delete and recreate the database file from scratch. " +
		"A bare `db clean` with no selector is rejected — it never wipes the database implicitly.",
	Args: cobra.NoArgs,
	RunE: runDBClean,
}

var dbResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Delete and recreate the database from scratch (SQLite only)",
	Long: "Remove the SQLite database file (and its WAL/SHM companions) and recreate it with a fresh, empty " +
		"schema. This is destructive and irreversible: all scans, HTTP records, and findings are lost. " +
		"Requires --force, or confirm interactively when run on a TTY.",
	Args: cobra.NoArgs,
	RunE: runDBReset,
}

var (
	cleanAll      bool
	cleanHost     string
	cleanScanUUID string
	cleanBefore   string
	cleanStatus   []int
	cleanSeverity string
	cleanDryRun   bool
	cleanOrphans  bool
	cleanFindings bool
	cleanTable    string
)

func init() {
	dbCmd.AddCommand(dbCleanCmd)
	dbCmd.AddCommand(dbResetCmd)

	dbCleanCmd.Flags().BoolVar(&cleanAll, "all", false, "Delete every row from all data tables (requires --force)")
	dbCleanCmd.Flags().StringVar(&cleanHost, "host", "", "Delete records matching the specified hostname")
	dbCleanCmd.Flags().StringVar(&cleanScanUUID, "scan-uuid", "", "Delete records belonging to the specified scan UUID")
	dbCleanCmd.Flags().StringVar(&cleanBefore, "before", "", fmt.Sprintf("Delete records created strictly before this time — %s (the named day itself is kept)", clicommon.TimeFilterSyntax))
	dbCleanCmd.Flags().IntSliceVar(&cleanStatus, "status", nil, "Delete records with matching HTTP status codes")
	dbCleanCmd.Flags().StringVar(&cleanSeverity, "severity", "", "Delete findings matching the specified severity level")

	dbCleanCmd.Flags().BoolVar(&cleanDryRun, "dry-run", false, "Show what would be deleted without deleting")

	dbCleanCmd.Flags().BoolVar(&cleanOrphans, "orphans", false, "Delete findings with no matching HTTP record")

	dbCleanCmd.Flags().BoolVar(&cleanFindings, "findings-only", false, "Delete findings only, keep HTTP records")
	dbCleanCmd.Flags().StringVar(&cleanTable, "table", "", "Delete all rows from a specific table (e.g., http_records, findings, scans)")
}

func runDBReset(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	if !globalForce {
		fmt.Fprintf(os.Stderr, "%s %s\n", terminal.WarningSymbol(),
			terminal.Yellow("This will DELETE and recreate the entire database. All scans, HTTP records, and findings will be lost."))
	}
	if done, err := handleConfirmation("deleting and recreating the entire database"); done {
		return err
	}
	return resetDatabase()
}
func runDBClean(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	// A bare `db clean` with no selector must never implicitly wipe the database.
	// --all --force deletes every row; `db reset --force` recreates the DB file.
	noSelector := !cleanAll && cleanHost == "" && cleanScanUUID == "" && cleanBefore == "" &&
		len(cleanStatus) == 0 && cleanSeverity == "" && !cleanOrphans && !cleanFindings &&
		cleanTable == "" && dbSearch == ""
	if noSelector {
		return usageErrorf("no clean selector provided; narrow the delete with a filter " +
			"(--host, --scan-uuid, --before, --status, --severity, --search, --orphans, --findings-only, --table), " +
			"use `--all --force` to delete all records, " +
			"or use `vigolium db reset --force` to delete and recreate the database")
	}

	// Project resolution and combination validation both happen before getDB, so
	// a rejected command line never opens a writable connection. The old order
	// branched into a delete handler first and validated inside it, which is how
	// --findings-only reached a store-wide DELETE with a --host on the command
	// line that nothing ever read.
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}
	sel, err := resolveCleanSelection(projectUUID)
	if err != nil {
		return err
	}

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	ctx := context.Background()
	if sel.Mode == cleanModeAll {
		return cleanAllTables(ctx, db, sel)
	}
	return runScopedClean(ctx, db, sel)
}

// applySelection performs the selection, or counts it without deleting when
// dryRun is set. Count and delete go through ONE switch so a mode added later
// cannot be wired into the preview and forgotten in the delete — which is the
// class of divergence this whole file exists to prevent.
func applySelection(ctx context.Context, del *database.DeleteBuilder, sel *cleanSelection, dryRun bool) (int64, error) {
	switch sel.Mode {
	case cleanModeOrphans:
		return del.DeleteOrphans(ctx, dryRun)
	case cleanModeFindings:
		return del.DeleteFindings(ctx, dryRun)
	case cleanModeTable:
		return del.DeleteTable(ctx, sel.Table, dryRun)
	default:
		return del.DeleteRecords(ctx, dryRun)
	}
}

// runScopedClean is the single count -> preview -> confirm -> delete path shared
// by every mode except --all, which reports per-table counts and has its own
// renderer.
func runScopedClean(ctx context.Context, db *database.DB, sel *cleanSelection) error {
	del := database.NewDeleteBuilder(db, sel.Filters)

	count, err := applySelection(ctx, del, sel, true)
	if err != nil {
		return fmt.Errorf("failed to count rows to delete: %w", err)
	}

	if count == 0 {
		fmt.Fprintf(os.Stderr, "%s No rows match the selection (%s).\n",
			terminal.InfoSymbol(), sel.describeScope())
		return nil
	}

	printCleanPreview(sel, count)

	if cleanDryRun {
		fmt.Fprintf(os.Stderr, "\n%s Dry-run: nothing was deleted.\n", terminal.InfoSymbol())
		return nil
	}

	if done, err := handleConfirmation(sel.describeAction(count)); done {
		return err
	}

	deleted, err := applySelection(ctx, del, sel, false)
	if err != nil {
		return fmt.Errorf("failed to delete: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.SuccessSymbol(),
		terminal.Green(fmt.Sprintf("Deleted %d row(s).", deleted)))

	// Orphan cleanup removes rows the file had already stopped indexing; a
	// VACUUM there rewrites the whole database for very little reclaimed space,
	// so it stays opt-out-by-default as it was.
	if sel.Mode != cleanModeOrphans {
		runVacuum(ctx, db)
	}
	return nil
}

// printCleanPreview states what will be deleted and, crucially, the scope it
// will be deleted from. The scope line is unconditional: a store-wide mode that
// looks narrow on the command line is exactly the case this command got wrong.
func printCleanPreview(sel *cleanSelection, count int64) {
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.WarningSymbol(),
		terminal.Yellow(fmt.Sprintf("This will delete %d row(s) from %s.", count, sel.describeScope())))

	switch sel.Mode {
	case cleanModeRecords:
		fmt.Fprintf(os.Stderr, "  %s HTTP records and their associated findings.\n", terminal.InfoSymbol())
	case cleanModeFindings:
		fmt.Fprintf(os.Stderr, "  %s Findings only; HTTP records are kept.\n", terminal.InfoSymbol())
	case cleanModeOrphans:
		fmt.Fprintf(os.Stderr, "  %s Findings whose HTTP records no longer exist.\n", terminal.InfoSymbol())
	case cleanModeTable:
		fmt.Fprintf(os.Stderr, "  %s Every row of table %q, for every project.\n",
			terminal.InfoSymbol(), sel.Table)
	}

	if active := describeActiveFilters(sel); active != "" {
		fmt.Fprintf(os.Stderr, "  %s Filters: %s\n", terminal.InfoSymbol(), active)
	}
}

// describeActiveFilters renders the filters that were actually applied, so the
// preview can be checked against the command line rather than trusted. It uses
// the shared filterSummary so the echo quotes and formats values exactly the way
// `finding` and `traffic` do.
func describeActiveFilters(sel *cleanSelection) string {
	f := sel.Filters
	var fs filterSummary
	fs.add("host", f.HostPattern)
	fs.add("scan-uuid", f.ScanUUID)
	if f.DateTo != nil {
		fs.add("before", f.DateTo.Format(time.RFC3339))
	}
	fs.addSeverities("severity", f.Severity)
	fs.addInts("status", f.StatusCodes)
	fs.addQuoted("search", f.SearchTerm)
	return fs.String()
}

// cleanAllTables truncates every data table. It reports per-table counts, so it
// keeps its own renderer rather than folding into runScopedClean.
func cleanAllTables(ctx context.Context, db *database.DB, sel *cleanSelection) error {
	del := database.NewDeleteBuilder(db, database.QueryFilters{})
	counts, err := del.DeleteAllTables(ctx, true)
	if err != nil {
		return fmt.Errorf("failed to count records: %w", err)
	}

	var total int64
	for _, c := range counts {
		total += c
	}

	if total == 0 {
		fmt.Fprintf(os.Stderr, "%s All data tables are already empty.\n", terminal.InfoSymbol())
		return nil
	}

	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.WarningSymbol(),
		terminal.Yellow(fmt.Sprintf("This will delete ALL data from %s:", sel.describeScope())))
	for _, tbl := range database.AllTablesDeleteOrder() {
		if c := counts[tbl]; c > 0 {
			fmt.Fprintf(os.Stderr, "  - %-24s %d row(s)\n", tbl, c)
		}
	}
	fmt.Fprintf(os.Stderr, "  %s Total: %d row(s)\n", terminal.InfoSymbol(), total)

	if cleanDryRun {
		fmt.Fprintf(os.Stderr, "\n%s Dry-run: nothing was deleted.\n", terminal.InfoSymbol())
		return nil
	}

	// resolveCleanSelection already required --force for --all, so this cannot
	// prompt; the call is kept so every delete path goes through one gate.
	if done, err := handleConfirmation(sel.describeAction(total)); done {
		return err
	}

	if _, err := del.DeleteAllTables(ctx, false); err != nil {
		return fmt.Errorf("failed to delete all records: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.SuccessSymbol(),
		terminal.Green(fmt.Sprintf("Deleted %d row(s) from all data tables.", total)))

	runVacuum(ctx, db)
	return nil
}

// runVacuum reclaims disk space after deletion. Only applies to SQLite.
func runVacuum(ctx context.Context, db *database.DB) {
	if db.Driver() != "sqlite" {
		return
	}
	fmt.Printf("%s Running VACUUM to reclaim disk space...\n", terminal.InfoSymbol())
	if _, err := db.ExecContext(ctx, "VACUUM"); err != nil {
		zap.L().Warn("VACUUM failed", zap.Error(err))
		return
	}
	fmt.Printf("%s %s\n", terminal.SuccessSymbol(), terminal.Green("VACUUM completed."))
}

// resetDatabase deletes the SQLite database file and recreates it with a fresh schema.
func resetDatabase() error {
	// config.LoadSettings directly, and ANY error refuses — not the clicommon
	// helper, which degrades a merely-discovered broken config to defaults.
	//
	// This function deletes a database file. The config is what names which one,
	// so falling back to defaults here does not mean "run with default settings",
	// it means "delete ~/.vigolium/database-vgnm.sqlite instead of the file you
	// configured". There is no reading of a broken config that justifies guessing
	// at that.
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		return fmt.Errorf("cannot determine which database to reset: %w", err)
	}

	if !settings.Database.Enabled && settings.Database.Driver == "" {
		settings.Database.Enabled = true
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = "~/.vigolium/database-vgnm.sqlite"
	}
	if globalDB != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = globalDB
	}

	if settings.Database.Driver != "sqlite" {
		return fmt.Errorf("database reset is only supported for SQLite (current driver: %s)", settings.Database.Driver)
	}

	dbPath := config.ExpandPath(settings.Database.SQLite.Path)

	// Close existing connection if open
	clicommon.ResetDBCache()

	// Remove the database file and its WAL/SHM companions
	removed := 0
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := dbPath + suffix
		if _, err := os.Stat(p); err == nil {
			if err := os.Remove(p); err != nil {
				return fmt.Errorf("failed to remove %s: %w", p, err)
			}
			removed++
		}
	}

	if removed == 0 {
		fmt.Printf("%s No database file found at %s\n", terminal.InfoSymbol(), terminal.Cyan(dbPath))
	} else {
		fmt.Printf("%s Deleted database file: %s\n", terminal.SuccessSymbol(), terminal.Cyan(dbPath))
	}

	// Recreate with fresh schema
	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return fmt.Errorf("failed to create new database: %w", err)
	}
	clicommon.SetDBCache(db)

	if err := db.CreateSchema(context.Background()); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	fmt.Printf("%s %s %s\n", terminal.SuccessSymbol(), terminal.Green("Database recreated at"), terminal.Cyan(dbPath))
	return nil
}
