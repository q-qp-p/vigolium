package database

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
)

// TestSQLitePathEncodingRoundTrip drives a real open → write → close → reopen
// read-only → read cycle for each awkward directory name.
//
// The assertion that matters most is the directory listing: an unencoded '#'
// made the driver open a DIFFERENT file (everything after the '#' became a URI
// fragment), which looked like a working empty database and left the real one
// untouched. A round trip that only checked "no error" passed for that.
func TestSQLitePathEncodingRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		dir  string
	}{
		{"question-mark", "a?b"},
		{"hash", "a#b"},
		{"percent-hex", "a%41b"},
		{"percent-invalid", "a%zz"},
		{"space", "a b"},
		{"unicode", "é"},
		{"plus", "a+b"},
		{"ampersand", "a&b"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.dir == "a?b" && runtime.GOOS == "windows" {
				t.Skip("'?' is not a legal path character on Windows")
			}
			root := t.TempDir()
			dir := filepath.Join(root, tc.dir)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("mkdir %q: %v", dir, err)
			}
			dbPath := filepath.Join(dir, "run.sqlite")

			cfg := config.DefaultDatabaseConfig()
			cfg.Driver = "sqlite"
			cfg.SQLite.Path = dbPath

			db, err := NewDB(cfg)
			if err != nil {
				if tc.dir == "a?b" {
					// Documented: the driver cannot address a '?' path in any
					// spelling, so an error is the contract. Silently opening an
					// empty database — the old behaviour — is what this replaces.
					if !strings.Contains(err.Error(), "'?'") {
						t.Fatalf("a '?' path should be refused explicitly, got: %v", err)
					}
					return
				}
				t.Fatalf("NewDB(%q): %v", dbPath, err)
			}
			if tc.dir == "a?b" {
				_ = db.Close()
				t.Fatal("a '?' path opened; the driver cannot address it, so this is the silent-empty-database bug")
			}

			ctx := context.Background()
			if err := db.CreateSchema(ctx); err != nil {
				t.Fatalf("CreateSchema: %v", err)
			}
			marker := &Scan{
				UUID:        "marker-" + tc.name,
				ProjectUUID: DefaultProjectUUID,
				Name:        "encoding marker",
				CreatedAt:   time.Now(),
			}
			if _, err := db.NewInsert().Model(marker).Exec(ctx); err != nil {
				t.Fatalf("insert marker: %v", err)
			}
			if err := db.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}

			// The write landed in the file we named, not in a neighbour the URI
			// parser invented.
			if _, err := os.Stat(dbPath); err != nil {
				t.Fatalf("the database was not created at %s: %v", dbPath, err)
			}

			roCfg := config.DefaultDatabaseConfig()
			roCfg.Driver = "sqlite"
			roCfg.SQLite.Path = dbPath
			roCfg.SQLite.ReadOnly = true
			roDB, err := NewDB(roCfg)
			if err != nil {
				t.Fatalf("NewDB read-only(%q): %v", dbPath, err)
			}
			var got Scan
			if err := roDB.NewSelect().Model(&got).Where("uuid = ?", marker.UUID).Scan(ctx); err != nil {
				_ = roDB.Close()
				t.Fatalf("read marker back read-only: %v", err)
			}
			if got.Name != "encoding marker" {
				_ = roDB.Close()
				t.Fatalf("marker name = %q, want %q", got.Name, "encoding marker")
			}
			if err := roDB.Close(); err != nil {
				t.Fatalf("close read-only: %v", err)
			}

			// Exactly one file in the directory. A stray sibling means the URI
			// resolved somewhere else; a leftover -wal/-shm means the read-only
			// path stopped reclaiming its sidecars.
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			sort.Strings(names)
			if len(names) != 1 || names[0] != "run.sqlite" {
				t.Errorf("directory %q holds %v, want [run.sqlite]", tc.dir, names)
			}
		})
	}
}

// sqliteDSNFilename must leave an ordinary path byte-identical: the encoding fix
// is for the handful of paths that were broken, not for every DSN in every
// existing deployment.
func TestSQLiteDSNFilenamePassesThroughOrdinaryPaths(t *testing.T) {
	for _, path := range []string{
		":memory:",
		"/var/data/run.sqlite",
		"relative/run.sqlite",
		"/path/with spaces/run.sqlite",
		"/path/with-é/run.sqlite",
	} {
		got, err := sqliteDSNFilename(path)
		if err != nil {
			t.Errorf("sqliteDSNFilename(%q): %v", path, err)
			continue
		}
		if got != path {
			t.Errorf("sqliteDSNFilename(%q) = %q, want it unchanged", path, got)
		}
	}
}

// …and must promote exactly the paths the driver would misparse.
func TestSQLiteDSNFilenamePromotesAmbiguousPaths(t *testing.T) {
	for _, path := range []string{"/tmp/a#b/run.sqlite", "/tmp/a%41b/run.sqlite"} {
		got, err := sqliteDSNFilename(path)
		if err != nil {
			t.Fatalf("sqliteDSNFilename(%q): %v", path, err)
		}
		if !strings.HasPrefix(got, "file:/") {
			t.Errorf("sqliteDSNFilename(%q) = %q, want a file: URI", path, got)
		}
		if strings.ContainsAny(strings.TrimPrefix(got, "file:"), "#") {
			t.Errorf("sqliteDSNFilename(%q) = %q, '#' is still literal", path, got)
		}
	}
	if _, err := sqliteDSNFilename("/tmp/a?b/run.sqlite"); err == nil {
		t.Error("a '?' path should be refused rather than silently misparsed")
	}
}

// attachSpec shares the encoder, so a path that opens also attaches.
func TestAttachSpecUsesSharedEncoder(t *testing.T) {
	spec, err := attachSpec(filepath.Join(t.TempDir(), "a#b", "src.sqlite"))
	if err != nil {
		t.Fatalf("attachSpec: %v", err)
	}
	if !strings.HasPrefix(spec, "file:/") || !strings.HasSuffix(spec, "?mode=ro") {
		t.Errorf("attachSpec = %q, want a file: URI ending in ?mode=ro", spec)
	}
	if strings.Contains(strings.TrimSuffix(spec, "?mode=ro"), "#") {
		t.Errorf("attachSpec = %q, '#' is still literal", spec)
	}
	if _, err := attachSpec("/tmp/a?b/src.sqlite"); err == nil {
		t.Error("attachSpec should still refuse a '?' path")
	}
}
