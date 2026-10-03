// Package clicommon holds shared, leaf-level helpers used across the vigolium
// CLI command tree: the database-connection cache, project resolution, the
// --watch loop, logger flushing, and display formatting. It is intentionally
// dependency-light (no imports back into pkg/cli) so command groups can be
// split into their own subpackages and still share this common ground.
package clicommon

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// dbConn is the process-wide cached database connection shared by every command.
var dbConn *database.DB

// GetDB returns the cached database connection, opening it on first use.
// configPath is the --config path (may be empty) and dbPath is the --db SQLite
// override (may be empty). When the database is not explicitly enabled it
// defaults to SQLite at the standard location.
// ReadOnlyRequested is set by the CLI before the first GetDB call when the
// command must not modify its source (--read-only). It is a package var rather
// than a GetDB parameter because GetDB is called from ~30 sites that would all
// have to thread a value none of them decides.
var ReadOnlyRequested bool

// RequireExistingSource holds the expanded path of an explicitly pinned SQLite
// source that a pure read command must NOT create. Empty means no such
// requirement — the built-in default database is still made on first use.
//
// Set by the CLI (applySourceMustExist) for the same reason ReadOnlyRequested is
// a package var: GetDB is reached from ~30 call sites, none of which decides
// this. Enforced here rather than at those call sites so a read path added later
// inherits the guarantee instead of having to remember it.
var RequireExistingSource string

// SourceMissingError reports a pinned database path that is not there.
//
// It is a type rather than a wrapped sentinel so the message can say the useful
// thing once. Unwrapping to fs.ErrNotExist keeps the CLI's error classifier
// mapping it to source_missing by identity rather than by message text, while
// Error() stays free of the stdlib's "file does not exist" tail and of an OS
// strerror string, which is neither locale- nor platform-stable.
type SourceMissingError struct{ Path string }

func (e *SourceMissingError) Error() string {
	return fmt.Sprintf("database %q does not exist. This is a read command, so it will not "+
		"create one — check the path, or run a scan/ingest against it first", e.Path)
}

func (e *SourceMissingError) Unwrap() error { return fs.ErrNotExist }

// SourceIncompatibleError reports a file that opens as SQLite but is not a
// vigolium store.
//
// Refusing it is the other half of the missing-path fix. A pinned path that
// exists is not necessarily the right file, and opening one that is not brings
// vigolium's ~17 tables into existence INSIDE another tool's database — then
// reports `total: 0`, exit 0, which reads as "nothing has been scanned here".
// Two opposite facts, one answer, and the wrong one silently modifies a file
// that belonged to something else.
//
// The distinction is the presence of the core table, not the presence of rows:
// a scanned target with no matching records and a foreign database both look
// empty from the outside.
type SourceIncompatibleError struct{ Path string }

func (e *SourceIncompatibleError) Error() string {
	return fmt.Sprintf("database %q is not a vigolium store: it opens as SQLite but has none of "+
		"vigolium's tables. This is a read command, so it will not create them — check the path, "+
		"or run a scan/ingest against it to initialize it", e.Path)
}

func GetDB(configPath, dbPath string) (*database.DB, error) {
	if dbConn != nil {
		return dbConn, nil
	}

	// Before any open, because opening is what creates the file.
	if err := checkSourceExists(); err != nil {
		return nil, err
	}

	// LoadSettings, not config.LoadSettings: a broken --config decides which
	// DATABASE this opens, so falling back to defaults here silently pointed the
	// command at ~/.vigolium/database-vgnm.sqlite — creating it if absent — while
	// the operator believed they were working in the store their config names.
	// A discovered-but-unreadable config still degrades to defaults, with a
	// warning; that is the helper's job, not this function's.
	settings, err := LoadSettings(configPath)
	if err != nil {
		return nil, err
	}

	// If database is not explicitly enabled, default to SQLite
	if !settings.Database.Enabled && settings.Database.Driver == "" {
		settings.Database.Enabled = true
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = "~/.vigolium/database-vgnm.sqlite"
	}

	// Override SQLite path if --db flag is set
	if dbPath != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = dbPath
	}

	// Only meaningful for SQLite; Postgres read-only is a server-side grant.
	if ReadOnlyRequested && settings.Database.Driver == "sqlite" {
		settings.Database.SQLite.ReadOnly = true
	}

	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// A pure read against a pinned source must not bring vigolium's tables into
	// being inside a file that never had them. Checked before the migration
	// below, which is exactly what would create them.
	if RequireExistingSource != "" && !db.HasVigoliumSchema(context.Background()) {
		_ = db.Close()
		return nil, &SourceIncompatibleError{Path: RequireExistingSource}
	}

	// Bring the schema up to date on EVERY open, not only on the write commands
	// that used to call CreateSchema themselves.
	//
	// Without this, a database written by an older vigolium fails its first read
	// with a raw `no such column: r.surface_score` — the read commands
	// (traffic/finding/db ls/export) never migrated, so any column added since
	// that file was last written simply was not there. Opening is exactly when a
	// store should be made current, and the read path is the one most likely to
	// meet an old file.
	//
	// EnsureSchemaCurrent, not CreateSchema: it checks for staleness with
	// READ-only queries and issues DDL only when something is actually missing.
	// CreateSchema unconditionally would take SQLite's write lock on every open,
	// making any read command queue behind a concurrent scan for up to
	// busy_timeout (measured: 22s for a `traffic` listing).
	if schemaErr := db.EnsureSchemaCurrent(context.Background()); schemaErr != nil {
		// An outdated schema on a read-only handle is fatal: it cannot be
		// migrated, and every query that follows would fail on a missing column
		// with an error that names no remedy. Any other migration failure is
		// best-effort — the schema may already be usable — so it only warns.
		if errors.Is(schemaErr, database.ErrSchemaOutdated) {
			// Close before returning: the handle never reaches dbConn on this
			// path, so nothing downstream can close it, and a long-lived process
			// that retries the open would leak a connection pool (and, on a
			// writable handle, a WAL checkpointer goroutine) per attempt.
			_ = db.Close()
			return nil, schemaErr
		}
		zap.L().Warn("Failed to bring database schema up to date", zap.Error(schemaErr))
	}

	dbConn = db
	openedDBDriver = settings.Database.Driver
	openedDBPath = config.ExpandPath(settings.Database.SQLite.Path)
	if settings.Database.Driver != "sqlite" {
		openedDBPath = settings.Database.Driver
	}
	return db, nil
}

// checkSourceExists refuses to open a pinned source that is absent, or that is a
// directory standing where a database file should be. A nil return means the
// path is there — not that it is a vigolium store, which the schema check and
// the source_incompatible code downstream still decide.
func checkSourceExists() error {
	if RequireExistingSource == "" {
		return nil
	}
	info, err := os.Stat(RequireExistingSource)
	if err != nil {
		if os.IsNotExist(err) {
			return &SourceMissingError{Path: RequireExistingSource}
		}
		return fmt.Errorf("cannot read database %q: %w", RequireExistingSource, err)
	}
	if info.IsDir() {
		return fmt.Errorf("database %q is a directory, not a file", RequireExistingSource)
	}
	return nil
}

// openedDBPath records which database the cached connection actually opened.
//
// The open order is --db → $VIGOLIUM_DB_PATH → config → the built-in default,
// and that last rung is ONE SHARED FILE under a single default project — so a
// command that falls through to it is reading every target that ever landed
// there. That is a cross-engagement mixing hazard a consumer cannot detect from
// the outside, which is why the resolved path is reported in every -j envelope
// (and in scan.started): a driver can then assert the store it read rather than
// trusting that its pin survived a subprocess chain.
var openedDBPath string

// openedDBDriver records which driver backed that open, because OpenedDBPath
// alone cannot be told apart: for PostgreSQL it returns the literal "postgres",
// which is also a perfectly legal relative filename. Anything deciding whether
// the opened store can be named on a command line — a `--db` in a follow-up
// query — has to ask the driver, not pattern-match the path.
var openedDBDriver string

// OpenedDBPath returns the resolved path of the database currently open, or ""
// before any open. For a non-SQLite driver it returns the driver name, since
// there is no single file to name.
func OpenedDBPath() string { return openedDBPath }

// OpenedDBDriver returns the driver that backed the current open ("sqlite",
// "postgres", …), or "" before any open.
func OpenedDBDriver() string { return openedDBDriver }

// SetOpenedDBPath overrides the recorded path. For tests that exercise what is
// reported about a read without opening a database to produce it.
func SetOpenedDBPath(path string) { openedDBPath = path }

// SetOpenedDBDriver overrides the recorded driver, for the same reason.
func SetOpenedDBDriver(driver string) { openedDBDriver = driver }

// CloseDatabaseOnExit closes the cached connection if open. Safe to defer.
func CloseDatabaseOnExit() {
	if dbConn != nil {
		_ = dbConn.Close()
	}
}

// ResetDBCache closes and clears the cached connection. Used by `db clean`
// before deleting the underlying SQLite file.
func ResetDBCache() {
	if dbConn != nil {
		_ = dbConn.Close()
		dbConn = nil
	}
}

// SetDBCache replaces the cached connection. Used by `db clean` after it
// recreates the database with a fresh schema.
func SetDBCache(db *database.DB) {
	dbConn = db
}
