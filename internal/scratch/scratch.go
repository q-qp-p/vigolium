// Package scratch owns vigolium's per-run temporary storage: where it is
// allocated, when this process's own is released, and when what an earlier run
// abandoned is collected.
//
// Many subsystems need scratch on disk for the life of a scan - a dedup DiskSet
// per module that dedups, deparos' request cache and discovery dedup, the
// sitemap store, jstangle job directories, stateless mode's temporary SQLite
// database. Each owner removes its own on the clean path, but a SIGKILL, a
// panic, an OOM kill or a CI job torn down mid-scan skips every deferred
// cleanup, and nothing ever collected what those runs left behind.
//
// Allocating directly in os.TempDir() made that leak expensive twice over. It
// is permanent and compounds - the workstation this was found on had 71,614
// leftover diskset directories and 108 GB - and it sits directly in the path of
// the startup sweeps that fastdialer/hmap and nuclei each run over the WHOLE
// temp directory, lstat'ing every entry whose name contains the executable
// name. vigolium's own litter was making vigolium slower to start, in
// proportion to how much of it there was.
//
// So everything lands under one root, and inside it under one directory per
// process:
//
//	$TMPDIR/vgl-scratch/p<pid>-<random>/...
//
// That shape is what makes cleanup total rather than best-effort. Releasing
// this process's scratch is a single RemoveAll of its own directory, so an
// owner that forgets - or never gets the chance - costs nothing beyond the run.
// Collecting an abandoned run's is a read of a directory holding only
// vigolium's own process directories, not a walk of a shared temp directory
// with six figures in it.
//
// Liveness is a lease, not an age. Each process directory holds a `.lease` file
// this process flocks for its lifetime, so the sweeper can ask the kernel
// whether an owner is still running — and get the right answer even after a
// SIGKILL, since the lock dies with the open file description.
//
// mtime alone was never the liveness proxy it was described as: a directory's
// mtime changes when an entry is created or removed in it, NOT when files
// already inside it are written. A long scan that allocated its disksets up
// front and then wrote gigabytes into them for eight hours had a directory
// mtime fixed at its first minute, so DefaultMaxAge made its scratch a
// collection candidate while it was still in use. Age remains the backstop for
// directories with no lease (an older version's, or Windows).
package scratch

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// rootName is the scratch root's name inside os.TempDir().
//
// It deliberately does NOT contain "vigolium". hmap expires stale temp
// databases by removing any directory whose name contains the running
// executable's name, and nuclei still enables that sweep through its own
// fastdialer - so a root named for the program could be handed to someone
// else's RemoveAll. Staying out of that match is free; being caught by it
// would take a live scan's scratch with it.
const rootName = "vgl-scratch"

// DefaultMaxAge is how long a process directory must have gone untouched before
// it counts as abandoned. Generous on purpose: mtime is a liveness proxy, and
// scratch belonging to a very long scan must never be collected out from under
// it. The leak is permanent, so a slow collector still fixes it.
const DefaultMaxAge = 6 * time.Hour

// sweepBudget bounds how long the automatic collection pass may run. It happens
// at teardown, after results are already reported, but an operator watching a
// scan finish must not be left waiting on housekeeping.
const sweepBudget = 100 * time.Millisecond

// LegacyPrefixes are the names older vigolium versions allocated directly in
// os.TempDir(), before scratch had a root.
//
// They are NOT part of the automatic sweep. Draining them is a one-time
// migration of a backlog that can run to six figures, and dripping it into
// every scan's teardown was measurably the wrong shape: it charged each run the
// full sweep budget and still needed a hundred-odd runs to finish. SweepLegacy
// does it in one pass, from `vigolium kit tmp-clean`.
//
// Prefix match, not substring: every name here is a temp pattern plus the
// random suffix os.MkdirTemp appends, so matching loosely could only ever widen
// this to files vigolium did not create.
// Every prefix an allocator used BEFORE it was routed through this package
// belongs here. Note "vigolium-stateless-" does not cover
// "vigolium-audit-stateless-": these are prefixes, not substrings, so each
// variant has to be listed.
var LegacyPrefixes = []string{
	"vigolium-diskset-",
	"vigolium-stateless-",
	"vigolium-audit-stateless-",
	"vigolium-autopilot-stateless-",
	"vigolium-isolate-",
	"vigolium-scratch-",
	"vigolium-parallel-",
	"vigolium-browserprobe-",
	"vigolium-extract-",
	"vigolium-pdf-",
	"deparos-dedup-",
	"reqcache-",
	"sitemap-",
	"jstangle-job-",
}

// mu guards dirPath and holders. Allocation and release are reference-counted
// so overlapping users of the scratch directory - concurrent scans in server
// mode, a server that outlives any single scan runner, sequential tests whose
// background work overlaps - cannot delete it out from under one another. The
// directory is created on the first Acquire and removed only when the last
// holder releases, mirroring how pkg/core/network refcounts the shared dialer.
var (
	mu      sync.Mutex
	dirPath string
	holders int

	// leaseFile holds this process's lease on dirPath for as long as the
	// directory is ours. Nil when the lease could not be taken (an exotic
	// filesystem, Windows), which costs the sweeper its liveness check and
	// nothing else.
	leaseFile *os.File

	sweepOnce sync.Once
)

// Root is the scratch root shared by every vigolium process on the machine. It
// is a path, not a promise the directory exists: the sweeps only read it, and
// a root that is absent has nothing to collect.
func Root() string {
	return filepath.Join(os.TempDir(), rootName)
}

// Acquire registers one holder of the scratch directory, creating it if this is
// the first. Every successful Acquire must be paired with exactly one Release.
//
// pkg/cli.Execute acquires once for the whole process, so every command gets
// the cleanup and a server does not tear the directory down between scans. The
// subsystems that allocate scratch just call MkdirTemp/CreateTemp.
func Acquire() error {
	mu.Lock()
	defer mu.Unlock()
	holders++
	_, err := ensureLocked()
	return err
}

// ensureLocked returns the scratch directory, creating one if there is none or
// if TMPDIR has moved since the last. The caller must hold mu.
//
// The TMPDIR check is not hypothetical: os.TempDir() re-reads the environment on
// every call, so a path cached from the old location would send this run's
// scratch somewhere the operator is no longer looking. A directory it replaces
// is left to the sweep rather than removed, since holders may still be writing
// into it.
func ensureLocked() (string, error) {
	root := Root()
	if dirPath != "" && filepath.Dir(dirPath) == root {
		return dirPath, nil
	}
	// pid alone is not unique enough: pids are recycled, so a stale directory
	// from a dead process with the same pid would be adopted rather than
	// collected. It also has to stay distinct across a release/re-acquire
	// within one process.
	path := filepath.Join(root, fmt.Sprintf("p%d-%08x", os.Getpid(), rand.Uint32()))
	if err := os.MkdirAll(path, 0o700); err != nil {
		return "", err
	}
	// Best-effort: a directory with no lease is still usable, it just falls back
	// to the pid and age checks when another process sweeps.
	leaseFile, _ = acquireLease(path)
	dirPath = path
	return dirPath, nil
}

// releaseLeaseLocked drops this process's lease. The caller must hold mu.
//
// Closing before the RemoveAll, not after: on the unixes removing an open file
// is legal and the lock would survive on the now-unlinked inode, which is
// harmless but makes the invariant "a lease exists iff a live owner has the
// directory" false for as long as the handle lives.
func releaseLeaseLocked() {
	if leaseFile != nil {
		_ = leaseFile.Close()
		leaseFile = nil
	}
}

// processDir returns the scratch directory, creating it if no holder has yet.
//
// On failure it returns "" and the error; callers pass that empty string
// straight to os.MkdirTemp/os.CreateTemp, which fall back to os.TempDir().
// Losing the directory costs tidiness, never the scan.
func processDir() (string, error) {
	mu.Lock()
	defer mu.Unlock()
	return ensureLocked()
}

// reprovision abandons the current scratch directory and creates a fresh one,
// keeping the reference count.
//
// Nothing guarantees the directory survives the run: a system temp cleaner, an
// operator clearing /tmp, or another vigolium's legacy sweep can all take it.
// Without this, the first such removal turned every later allocation in the
// process into a hard error.
func reprovision() (string, error) {
	mu.Lock()
	defer mu.Unlock()
	// The old lease belongs to a directory we are abandoning, and holding it
	// would keep another sweeper from collecting that directory forever.
	releaseLeaseLocked()
	dirPath = ""
	return ensureLocked()
}

// MkdirTemp allocates a scratch directory for this process, with the same
// contract as os.MkdirTemp(dir, pattern).
//
// The caller should still remove it when done - scratch released early is disk
// the rest of the scan gets back - but it no longer has to: Release takes the
// whole process directory.
func MkdirTemp(pattern string) (string, error) {
	d, _ := processDir()
	path, err := os.MkdirTemp(d, pattern)
	if err == nil || d == "" || !errors.Is(err, fs.ErrNotExist) {
		return path, err
	}
	d, _ = reprovision()
	return os.MkdirTemp(d, pattern)
}

// CreateTemp allocates a scratch file for this process, with the same contract
// as os.CreateTemp(dir, pattern).
func CreateTemp(pattern string) (*os.File, error) {
	d, _ := processDir()
	f, err := os.CreateTemp(d, pattern)
	if err == nil || d == "" || !errors.Is(err, fs.ErrNotExist) {
		return f, err
	}
	d, _ = reprovision()
	return os.CreateTemp(d, pattern)
}

// Release drops one reference. On the last one it removes everything allocated
// through MkdirTemp and CreateTemp since the first Acquire, and reports whether
// it did so.
//
// That removal is the backstop that makes cleanup total: it does not matter
// which owner forgot its own deferred cleanup, or which of them never got the
// chance, because the whole directory goes. Extra Releases (more than
// Acquires) are ignored rather than deleting scratch still in use - in server
// mode two scans share the directory, and the first to finish must not take the
// second's with it.
func Release() bool {
	mu.Lock()
	defer mu.Unlock()

	if holders > 0 {
		holders--
	}
	if holders > 0 || dirPath == "" {
		return false
	}
	releaseLeaseLocked()
	err := os.RemoveAll(dirPath)
	dirPath = ""
	return err == nil
}

// SweepOnce collects scratch abandoned by earlier runs, at most once per
// process, and reports how many entries it removed.
//
// It covers both the process directories under the root and the loose names
// older versions left directly in os.TempDir(). The second pass is why this
// runs at teardown rather than startup: a temp directory that has accumulated
// six figures of entries takes real time just to read, and that is time an
// operator waiting for scan results should not pay.
func SweepOnce(maxAge time.Duration) int {
	removed := 0
	sweepOnce.Do(func() {
		removed, _ = sweepDir(Root(), maxAge, time.Now().Add(sweepBudget), nil)
	})
	return removed
}

// SweepLegacy removes the loose scratch that versions before the scratch root
// left directly in os.TempDir(), and reports how many entries it took.
//
// Unbounded by design: this is the one-time migration `vigolium kit tmp-clean`
// drives, where the operator has asked for it and is watching it run. The
// automatic per-scan sweep deliberately does not do this - see LegacyPrefixes.
func SweepLegacy(maxAge time.Duration) (int, error) {
	// Legacy litter sits alongside every other program's temp files, so here -
	// and only here - entries are filtered by name.
	removed, err := sweepDir(os.TempDir(), maxAge, time.Time{}, LegacyPrefixes)

	// rod's default browser profile cache is a separate directory it owns
	// outright, so everything in it is a candidate and no name filter applies.
	// Profiles now live under the scratch directory; the ones already here are
	// nobody else's, and they are the bulk of the backlog.
	profiles := filepath.Join(os.TempDir(), "rod", "user-data")
	if n, perr := sweepDir(profiles, maxAge, time.Time{}, nil); perr == nil {
		removed += n
	} else if err == nil && !errors.Is(perr, fs.ErrNotExist) {
		err = perr
	}
	return removed, err
}

// SweepRoot removes abandoned process directories under the scratch root,
// unbounded, and reports how many it took.
func SweepRoot(maxAge time.Duration) (int, error) {
	return sweepDir(Root(), maxAge, time.Time{}, nil)
}

// processDirName matches a scratch process directory: p<pid>-<8 hex>.
//
// Used to decide which entries are eligible for the liveness checks. Loose
// matching would be worse than none: the legacy prefixes sweep runs over the
// whole of os.TempDir(), and reading an arbitrary name's digits as a pid would
// have the sweeper spare someone else's file because an unrelated number in it
// happened to be live.
var processDirName = regexp.MustCompile(`^p(\d+)-[0-9a-f]{8}$`)

// sweepDir removes entries in dir older than maxAge, stopping at the deadline.
// A zero deadline means no limit. A nil prefixes means every entry is a
// candidate, which is safe only under a directory vigolium owns outright.
//
// For a process directory under the scratch root, age is the LAST question
// asked, not the only one. See the package doc for why mtime was never the
// liveness proxy it was described as.
func sweepDir(dir string, maxAge time.Duration, deadline time.Time, prefixes []string) (int, error) {
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().Add(-maxAge)
	// Read once, outside the loop: a directory that appears mid-sweep is young
	// and fails the age check anyway, so re-reading it per entry only bought a
	// mutex round-trip for every one of the six figures of entries this walks.
	live := currentDir()
	removed := 0
	for i, entry := range entries {
		// Checking the clock every entry would cost more than the work; every
		// 64 is often enough to honour the budget.
		if !deadline.IsZero() && i%64 == 0 && time.Now().After(deadline) {
			break
		}
		if prefixes != nil && !hasAnyPrefix(entry.Name(), prefixes) && !isHmapTempDir(entry.Name()) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		// Never collect the live scratch directory, however the clock looks.
		if path == live {
			continue
		}
		if ownerIsAlive(path, entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			// Raced with another sweeper or with the owner's own cleanup.
			// Either way it is gone or going; nothing to do.
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		// Re-checked immediately before the removal, not only every 64 entries:
		// RemoveAll of a diskset directory with six figures of files in it is the
		// expensive operation here, so a budget enforced only at the loop head can
		// be overrun by one whole removal — minutes, on the backlog this exists to
		// drain.
		if !deadline.IsZero() && time.Now().After(deadline) {
			break
		}
		if err := os.RemoveAll(path); err == nil {
			removed++
		}
	}
	return removed, nil
}

// ownerIsAlive reports whether a live process still owns the scratch directory
// at path.
//
// Only process directories (p<pid>-<rand>) are asked: everything else under the
// root, and everything the legacy sweep matches, carries no owner identity to
// check. For those it answers false and the age check decides, which is the
// behavior that was always there.
func ownerIsAlive(path, name string) bool {
	m := processDirName.FindStringSubmatch(name)
	if m == nil {
		return false
	}
	if held, known := leaseHeld(path); known {
		// A lease answers definitively in both directions: held means a live
		// owner, and not-held means the owner is gone even if the pid has since
		// been recycled onto an unrelated process.
		return held
	}
	// No lease to ask (an older version's directory, or Windows). The pid is the
	// next best thing. It is wrong in one direction — a recycled pid keeps a dead
	// run's scratch — but that direction only delays collection, while the other
	// deletes a running scan's working set.
	pid, err := strconv.Atoi(m[1])
	if err != nil {
		return false
	}
	return pidAlive(pid)
}

// currentDir reads the live scratch directory under the lock, so the sweep
// cannot race an Acquire or Release while deciding what is safe to remove.
func currentDir() string {
	mu.Lock()
	defer mu.Unlock()
	return dirPath
}

// isHmapTempDir reports whether name is one of hmap's own temp databases.
//
// hmap names them os.MkdirTemp("", fileutil.ExecutableName()), which for this
// program is "vigolium" followed by the random digits MkdirTemp appends. They
// come from fastdialer's dialer history, which vigolium no longer enables (see
// pkg/core/network.NewDialer) - but nuclei still does, and every older release
// left one per run.
//
// Matched exactly rather than by a bare "vigolium" prefix: the temp directory is
// somewhere people also park files of their own, and a report someone named
// vigolium-something is not ours to delete.
func isHmapTempDir(name string) bool {
	rest, ok := strings.CutPrefix(name, "vigolium")
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func hasAnyPrefix(name string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
