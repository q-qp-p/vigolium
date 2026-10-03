package cli

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

// settleAsArchive puts a fixture into the shape a finished engagement file is
// in: journal_mode=delete, no -wal sidecar, nothing left to recover. That is the
// state a writable open would visibly damage — setting journal_mode=WAL rewrites
// the header — so it is the state worth hashing.
func settleAsArchive(t *testing.T, path string) {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open fixture for settling: %v", err)
	}
	if _, err := raw.Exec("PRAGMA journal_mode=DELETE"); err != nil {
		t.Fatalf("settle journal mode: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close settling handle: %v", err)
	}
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// assertUntouched fails if path's bytes changed or a journal sidecar appeared.
func assertUntouched(t *testing.T, path, before string) {
	t.Helper()
	if after := fileDigest(t, path); after != before {
		t.Errorf("source file was modified by a read: %s -> %s", before[:12], after[:12])
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(path + suffix); err == nil {
			t.Errorf("a read left a %s sidecar beside the source", suffix)
		}
	}
}

// A --glob-db source is evidence someone collected, and browsing it is a read.
// A writable open rewrites it without anyone asking: journal_mode=WAL changes
// the header, the startup wal_checkpoint(TRUNCATE) rewrites the main file and
// its sidecar, and Close writes sqlite_stat1 via PRAGMA optimize.
func TestOpenGlobSourceFileDoesNotModifyTheSource(t *testing.T) {
	dir := t.TempDir()
	path := writeGlobSQLiteFixture(t, dir, "a.example", 3)
	settleAsArchive(t, path)
	before := fileDigest(t, path)

	ctx := context.Background()
	db, closeDB, err := openGlobSourceFile(ctx, path)
	if err != nil {
		t.Fatalf("openGlobSourceFile: %v", err)
	}
	var records []*database.HTTPRecord
	if err := db.NewSelect().Model(&records).Scan(ctx); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("read %d records, want 3", len(records))
	}
	closeDB()

	assertUntouched(t, path, before)
}

// Read-only is enforced by the driver, not by convention: a write through the
// handle must fail rather than reach the file.
func TestOpenGlobSourceFileRefusesWrites(t *testing.T) {
	dir := t.TempDir()
	path := writeGlobSQLiteFixture(t, dir, "a.example", 1)

	ctx := context.Background()
	db, closeDB, err := openGlobSourceFile(ctx, path)
	if err != nil {
		t.Fatalf("openGlobSourceFile: %v", err)
	}
	defer closeDB()

	_, err = db.NewDelete().Model((*database.HTTPRecord)(nil)).Where("1=1").Exec(ctx)
	if err == nil {
		t.Fatal("a write through a glob source handle must be refused")
	}
}

// A missing file must stay missing. The writable path calls os.MkdirAll and
// would create an empty database for a mistyped name, turning a typo into a
// silent zero-result read.
func TestOpenGlobSourceFileDoesNotCreateMissingFiles(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.sqlite")

	if _, _, err := openGlobSourceFile(context.Background(), missing); err == nil {
		t.Fatal("opening a nonexistent source must fail")
	}
	if _, err := os.Stat(missing); err == nil {
		t.Fatal("a failed open created the file it was asked to read")
	}
}

// The merge attaches its sources; a plain-filename ATTACH opens them read-write.
func TestMergeDoesNotModifyItsSource(t *testing.T) {
	dir := t.TempDir()
	src := writeGlobSQLiteFixture(t, dir, "a.example", 4)
	settleAsArchive(t, src)
	before := fileDigest(t, src)

	ctx := context.Background()
	dest, destDir, err := newTempDB("merge-ro")
	if err != nil {
		t.Fatalf("newTempDB: %v", err)
	}
	defer func() {
		_ = dest.Close()
		_ = os.RemoveAll(destDir)
	}()
	if err := dest.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	if _, err := database.MergeSQLiteFile(ctx, dest, src); err != nil {
		t.Fatalf("MergeSQLiteFile: %v", err)
	}

	n, err := dest.NewSelect().Model((*database.HTTPRecord)(nil)).Count(ctx)
	if err != nil {
		t.Fatalf("count merged: %v", err)
	}
	if n != 4 {
		t.Fatalf("merged %d records, want 4", n)
	}

	assertUntouched(t, src, before)
}

// The driver parses every ATTACH filename as a URI, so a directory named with a
// metacharacter decides whether the right file is addressed at all. Getting it
// wrong does not raise an error — it attaches a different, empty database and
// the merge reports success having copied nothing.
//
// Immutability is asserted for each shape, not just the plain one: the point of
// the URI spelling is `mode=ro`, and a guarantee that lapses on a path with a
// space or a '#' in it is one no caller can rely on.
func TestMergeAttachesPathsWithURIMetacharacters(t *testing.T) {
	for _, dirName := range []string{"scan-plain", "scan #1", "scan 2024", "pct%25dir"} {
		t.Run(dirName, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), dirName)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			src := writeGlobSQLiteFixture(t, dir, "a.example", 2)
			settleAsArchive(t, src)
			before := fileDigest(t, src)

			ctx := context.Background()
			dest, destDir, err := newTempDB("merge-uri")
			if err != nil {
				t.Fatalf("newTempDB: %v", err)
			}
			defer func() {
				_ = dest.Close()
				_ = os.RemoveAll(destDir)
			}()
			if err := dest.CreateSchema(ctx); err != nil {
				t.Fatalf("CreateSchema: %v", err)
			}
			if _, err := database.MergeSQLiteFile(ctx, dest, src); err != nil {
				t.Fatalf("MergeSQLiteFile: %v", err)
			}
			n, err := dest.NewSelect().Model((*database.HTTPRecord)(nil)).Count(ctx)
			if err != nil {
				t.Fatalf("count merged: %v", err)
			}
			if n != 2 {
				t.Fatalf("merged %d records, want 2 — the wrong database was attached", n)
			}
			assertUntouched(t, src, before)
		})
	}
}

// A '?' in the path cannot be addressed: encoded it fails to open, and raw it
// silently loses `mode=ro`. Reporting that beats either alternative — the
// pre-existing behavior was a merge that succeeded having copied nothing.
func TestMergeRejectsPathsNoSpellingCanAddress(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "scan?draft")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// The fixture is BUILT in an addressable directory and then moved into the
	// '?' one: NewDB now refuses such a path for the same reason attachSpec does,
	// so writing the source in place is no longer possible. Moving it afterwards
	// is also the realistic shape — the file exists, the operator renamed a
	// folder, and only now does vigolium have to say something.
	staged := writeGlobSQLiteFixture(t, root, "a.example", 2)
	src := filepath.Join(dir, filepath.Base(staged))
	if err := os.Rename(staged, src); err != nil {
		t.Fatalf("stage fixture into %q: %v", dir, err)
	}

	ctx := context.Background()
	dest, destDir, err := newTempDB("merge-uri-bad")
	if err != nil {
		t.Fatalf("newTempDB: %v", err)
	}
	defer func() {
		_ = dest.Close()
		_ = os.RemoveAll(destDir)
	}()
	if err := dest.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	if _, err := database.MergeSQLiteFile(ctx, dest, src); err == nil {
		t.Fatal("a path the driver cannot address must be an error, not an empty merge")
	}
}
