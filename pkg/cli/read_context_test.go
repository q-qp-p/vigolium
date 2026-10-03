package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

func resetReadContext(t *testing.T) {
	t.Helper()
	swapGlobal(t, &globalGlobDB, "")
	swapGlobal(t, &globalStateless, false)
	swapGlobal(t, &globalReadOnly, false)
	swapGlobal(t, &globalProjectUUID, "")
	swapGlobal(t, &globalProjectName, "")
	swapGlobal(t, &globalConfig, "")
	swapGlobal(t, &globalDB, "")
	swapGlobal(t, &dbPathEnvAutoStateless, false)

	// The clicommon side has no addressable global to swap, so it is cleared on
	// the way in and on the way out. Clearing the resolution memo is load-bearing:
	// without it, row two of a table test silently asserts row one's answer.
	clearOpened := func() {
		clicommon.SetOpenedDBPath("")
		clicommon.SetOpenedDBDriver("")
		clicommon.ResetProjectResolutionForTest()
	}
	clearOpened()
	t.Cleanup(clearOpened)
}

// Finding IDs are per-database autoincrement integers, so a follow-up that omits
// the database resolves the same id in a DIFFERENT store. Every generated query
// omitted it.
func TestFollowUpQueryCarriesTheDatabase(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBPath("/engagements/acme.sqlite")

	got := followUpQuery("finding", "--id", "5", "--json")
	if !strings.Contains(got, "--db /engagements/acme.sqlite") {
		t.Errorf("follow-up must pin the store it was read from, got: %s", got)
	}
}

func TestFollowUpQueryCarriesScope(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBPath("/tmp/x.sqlite")
	globalStateless = true

	got := followUpQuery("finding", "--id", "5")
	if !strings.Contains(got, "--stateless") {
		t.Errorf("a project-unscoped read must stay unscoped on the follow-up, got: %s", got)
	}

	resetReadContext(t)
	clicommon.SetOpenedDBPath("/tmp/x.sqlite")
	globalProjectUUID = "proj-b"
	got = followUpQuery("finding", "--id", "5")
	// Carried explicitly rather than left to the active-project file, which is
	// global state a parallel caller may have changed between the two reads.
	if !strings.Contains(got, "--project-uuid proj-b") {
		t.Errorf("the selected project must be pinned explicitly, got: %s", got)
	}
	if strings.Contains(got, "--stateless") {
		t.Errorf("a scoped read must not advertise itself as unscoped, got: %s", got)
	}
}

func TestFollowUpQueryQuotesPathsWithSpaces(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBPath("/tmp/db with space.sqlite")

	got := followUpQuery("finding", "--id", "5")
	if !strings.Contains(got, "'/tmp/db with space.sqlite'") {
		t.Errorf("a path with a space must be quoted, got: %s", got)
	}
}

// A glob merge reads through a temporary database that is removed when the
// process exits. No argument list reopens it, so the honest answer is no
// follow-up rather than one that silently resolves the id somewhere else.
func TestFollowUpQuerySuppressedForAGlobMerge(t *testing.T) {
	resetReadContext(t)
	globalGlobDB = "/scans/*.sqlite"
	clicommon.SetOpenedDBPath("/tmp/scratch-9271.sqlite")

	if got := followUpQuery("finding", "--id", "5"); got != "" {
		t.Errorf("a merged read cannot be reproduced; follow-up must be empty, got: %s", got)
	}
	if _, ok := readContextArgs(); ok {
		t.Error("readContextArgs must report that the read is not reproducible")
	}
}

func TestFollowUpQueryCarriesReadOnlyAndConfig(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBPath("/tmp/x.sqlite")
	globalReadOnly = true
	globalConfig = "/etc/vigolium.yaml"

	got := followUpQuery("traffic", "--uuid", "abc")
	for _, want := range []string{"--read-only", "--config /etc/vigolium.yaml"} {
		if !strings.Contains(got, want) {
			t.Errorf("follow-up missing %q, got: %s", want, got)
		}
	}
}

func TestFollowUpQueryStartsWithTheBinaryName(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBPath("/tmp/x.sqlite")

	got := followUpQuery("finding", "--id", "5")
	if !strings.HasPrefix(got, "vigolium ") {
		t.Errorf("follow-up must be runnable as written, got: %s", got)
	}
}

// A follow-up may be run from a different working directory than the read that
// produced it, where a relative --db names a different file — or no file.
func TestFollowUpQueryMakesTheDatabaseAbsolute(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBDriver("sqlite")
	clicommon.SetOpenedDBPath("./run.sqlite")

	abs, err := filepath.Abs("./run.sqlite")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	got := followUpQuery("finding", "--id", "5")
	if !strings.Contains(got, "--db "+abs) {
		t.Errorf("follow-up must carry an absolute --db (%s), got: %s", abs, got)
	}
}

func TestFollowUpQueryMakesTheConfigAbsolute(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBPath("/tmp/x.sqlite")
	globalConfig = "./vigolium-configs.yaml"

	abs, err := filepath.Abs("./vigolium-configs.yaml")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if got := followUpQuery("finding", "--id", "5"); !strings.Contains(got, "--config "+abs) {
		t.Errorf("follow-up must carry an absolute --config (%s), got: %s", abs, got)
	}
}

// A stateless read's store is the SOURCE the operator named, not the scratch
// database the CLI loaded it into — that one is deleted when the process exits.
func TestFollowUpQueryUsesTheStatelessSource(t *testing.T) {
	resetReadContext(t)
	globalStateless = true
	globalDB = "x.jsonl"
	clicommon.SetOpenedDBPath("/tmp/scratch-1234.sqlite")

	abs, err := filepath.Abs("x.jsonl")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	got := followUpQuery("finding", "--id", "5")
	if !strings.Contains(got, "--db "+abs) {
		t.Errorf("a stateless follow-up must name the source (%s), got: %s", abs, got)
	}
	if strings.Contains(got, "scratch-1234") {
		t.Errorf("the scratch database does not survive the process, got: %s", got)
	}
}

// "--db postgres" means "a file called postgres in the cwd". A non-SQLite
// driver's connection details live in the config, so the flag is omitted.
func TestFollowUpQueryOmitsTheDatabaseForANonFileDriver(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBDriver("postgres")
	clicommon.SetOpenedDBPath("postgres")

	if got := followUpQuery("finding", "--id", "5"); strings.Contains(got, "--db") {
		t.Errorf("a postgres read has no path to pin, got: %s", got)
	}
}

// The resolved UUID beats --project-name: a name is looked up at run time in
// whichever store the follow-up opens, and the active-project file can change
// between the two commands.
func TestFollowUpQueryPinsTheResolvedProjectUUID(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBPath("/tmp/x.sqlite")
	globalProjectName = "acme"
	clicommon.PinProjectUUID("resolved-uuid-7")

	got := followUpQuery("finding", "--id", "5")
	if !strings.Contains(got, "--project-uuid resolved-uuid-7") {
		t.Errorf("follow-up must pin the resolved uuid, got: %s", got)
	}
	if strings.Contains(got, "--project-name") {
		t.Errorf("a name re-resolves in the next process; the uuid does not, got: %s", got)
	}
}

// A stateless read is unscoped by default — the file carries whatever
// project_uuid it was exported under — so a scope flag only appears when the
// operator asked for one.
func TestFollowUpQueryScopesAStatelessReadOnlyWhenAsked(t *testing.T) {
	resetReadContext(t)
	globalStateless = true
	globalDB = "/exports/merged.jsonl"
	clicommon.PinProjectUUID("active-project-uuid")

	if got := followUpQuery("finding", "--id", "5"); strings.Contains(got, "--project-uuid") {
		t.Errorf("an unscoped stateless read must stay unscoped, got: %s", got)
	}

	resetReadContext(t)
	globalStateless = true
	globalDB = "/exports/merged.jsonl"
	globalProjectUUID = "chosen"
	clicommon.PinProjectUUID("chosen")
	if got := followUpQuery("finding", "--id", "5"); !strings.Contains(got, "--project-uuid chosen") {
		t.Errorf("an explicitly scoped stateless read must carry the scope, got: %s", got)
	}
}

// The argv form and the display string must describe the same command, and must
// be absent together — a consumer finding one but not the other has to guess.
func TestFollowUpArgvMatchesTheQueryString(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBPath("/tmp/x.sqlite")

	argv := followUpArgv("finding", "--id", "5", "--json")
	if len(argv) == 0 || argv[0] != "vigolium" {
		t.Fatalf("argv must start with the binary name, got: %v", argv)
	}
	if got, want := strings.Join(argv, " "), followUpQuery("finding", "--id", "5", "--json"); got != want {
		t.Errorf("argv %q and query %q describe different commands", got, want)
	}

	resetReadContext(t)
	globalGlobDB = "/scans/*.sqlite"
	if argv := followUpArgv("finding", "--id", "5"); argv != nil {
		t.Errorf("an unreproducible read must yield no argv, got: %v", argv)
	}
}
