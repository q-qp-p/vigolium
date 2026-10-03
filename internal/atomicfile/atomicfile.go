// Package atomicfile writes files atomically: content is streamed into a temp
// file in the destination directory and renamed into place only on success, so a
// failed or partial write never replaces or half-writes the destination.
//
// Three concerns are deliberately separated, because conflating them is how a
// "safe" write ends up either world-readable or owner-only by accident:
//
//   - atomicity — the temp-and-rename, which every entry point does;
//   - permissions — the caller's business, named once per entry point and
//     applied at creation time so the process umask is honoured the way an
//     ordinary open(2) would honour it;
//   - durability — the file is fsynced before the rename and the parent
//     directory after it, so a crash cannot leave the destination name pointing
//     at bytes that never reached storage, nor the rename itself unrecorded.
//
// The staging file has to live in the destination directory for the rename to
// be atomic, so a process killed between creating one and renaming it leaves a
// dot-prefixed ".tmp" file behind — strictly better than the truncated
// destination the non-atomic write left, but still litter. SweepStale, called
// on the way in by every entry point here, collects it the next time something
// writes to the same destination.
package atomicfile

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// Write atomically writes path's contents via write, leaving the temp file's
// 0600 in place. Use it for a file whose permissions the caller has no opinion
// about; WriteFile is the entry point that names a mode.
//
// It creates a temp file in path's directory, hands write a buffered writer,
// then flushes, fsyncs and renames the temp file over path on success. If write
// returns an error (or any I/O step fails) path is left untouched and the temp
// file is removed.
//
// write receives a *bufio.Writer so callers needing WriteByte/WriteString (e.g.
// incremental JSON array framing) can use them directly; it satisfies io.Writer
// for the common case.
func Write(path string, write func(w *bufio.Writer) error) error {
	return writeAtomic(path, 0, write)
}

// WriteFile atomically writes path's contents via write, creating the staging
// file with perm so the process umask applies exactly as it would to
// os.OpenFile — 0o666 reproduces os.Create, 0o644 the mode the CLI's named
// artifacts carry.
//
// Applying the mode at creation rather than with a later Chmod is the whole
// point: a Chmod overrides the umask, so an operator who runs with umask 077
// because their results are sensitive got a world-readable export anyway.
func WriteFile(path string, perm os.FileMode, write func(w *bufio.Writer) error) error {
	return writeAtomic(path, perm, write)
}

// WriteBytes atomically writes data to path at 0644 (subject to umask), the mode
// every other artifact the CLI emits carries.
func WriteBytes(path string, data []byte) error {
	return WriteFile(path, 0o644, func(w *bufio.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// createTempAttempts bounds the retry loop for a staging name that already
// exists, for a staged file and a staged directory alike. The names carry 32
// bits of randomness, so a collision needs a concurrent writer that guessed it;
// ten attempts is far past the point where that is a real race rather than a
// directory we cannot write into.
const createTempAttempts = 10

// StagingDirGlob is the SweepStale pattern matching MkdirStaging's names for a
// root called name. Exported with MkdirStaging so a caller cannot sweep for one
// shape while staging under another.
func StagingDirGlob(name string) string { return "." + name + ".staging-*" }

// MkdirStaging creates a staging DIRECTORY beside a destination, for a caller
// publishing a whole generation rather than a single file. The name, the
// randomness and the retry budget are this package's, so a staged tree and a
// staged file share one scheme and one sweep pattern instead of two that have to
// be kept in step by comment.
//
// perm goes through the umask exactly as os.Mkdir applies it — deliberately not
// os.MkdirTemp, which creates at 0700: the staging directory IS the published
// root after the rename, so a tree would come out owner-only while the
// directories inside it kept the mode they were created with.
func MkdirStaging(parent, name string, perm os.FileMode) (string, error) {
	var lastErr error
	for range createTempAttempts {
		suffix, err := RandomSuffix()
		if err != nil {
			return "", err
		}
		dir := filepath.Join(parent, "."+name+".staging-"+suffix)
		err = os.Mkdir(dir, perm)
		if err == nil {
			return dir, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
		lastErr = err
	}
	return "", lastErr
}

// StaleAge is how long an abandoned staging entry must have gone untouched
// before SweepStale will collect it. Generous on purpose: the only way to tell
// a corpse from a staging entry another process is still filling is that the
// live one was written recently, and deleting a live one turns someone else's
// successful export into a failed rename. A day is far past any real export.
const StaleAge = 24 * time.Hour

// SweepStale removes entries matching the glob pattern inside dir whose
// modification time is older than StaleAge, and reports how many it removed.
// Best effort throughout: a directory it cannot read, or an entry it cannot
// remove, is left alone rather than failing the caller's write — litter is a
// nuisance, a refused export is an outage.
//
// pattern must be specific enough to name only this package's own staging
// shapes (see writeAtomic and pkg/cli's fs-export generations); it is applied
// to names within dir, never recursively.
func SweepStale(dir, pattern string) int {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return 0
	}
	cutoff := time.Now().Add(-StaleAge)
	removed := 0
	for _, m := range matches {
		info, err := os.Lstat(m)
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		if err := os.RemoveAll(m); err == nil {
			removed++
		}
	}
	return removed
}

// sweptDestinations records the (dir, pattern) pairs writeAtomic has already
// swept in this process. Bounded by the number of distinct destinations a
// process writes to.
var sweptDestinations sync.Map

// sweepOncePerDestination runs SweepStale the first time this process writes to
// a given destination shape, and skips it thereafter. Exposed as a helper rather
// than folded into SweepStale because the explicit callers (pkg/cli's fs-export
// generations) sweep a destination they are about to replace wholesale and want
// the readdir every time they stage.
func sweepOncePerDestination(dir, pattern string) {
	if _, seen := sweptDestinations.LoadOrStore(dir+"\x00"+pattern, struct{}{}); seen {
		return
	}
	SweepStale(dir, pattern)
}

// writeAtomic is the shared body. perm 0 means "whatever a temp file gets"
// (os.CreateTemp's 0600).
func writeAtomic(path string, perm os.FileMode, write func(w *bufio.Writer) error) error {
	dir := filepath.Dir(path)
	// Collect anything a previous kill -9 left staged for this same
	// destination. Scoped to this base name so a directory full of unrelated
	// dotfiles is untouched.
	//
	// Once per destination per process, not once per write: the sweep is a
	// filepath.Glob, i.e. a full readdir of a directory that grows as the caller
	// fills it, and a caller writing N artifacts into one directory (kit beautify
	// does, one file per recovered module) paid N of them to collect litter only
	// another process could have left. A corpse that appears mid-process is one
	// StaleAge old by definition, so a second look cannot find anything the first
	// one could not.
	sweepOncePerDestination(dir, "."+filepath.Base(path)+".*.tmp")
	tmp, err := createStaging(dir, filepath.Base(path), perm)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	bw := bufio.NewWriter(tmp)
	if err := write(bw); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	// Flushed to disk before the rename, so a crash cannot leave the destination
	// name pointing at a file whose contents never reached storage. Without it
	// "atomic" covers only the rename, not the bytes.
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true
	// The rename is only durable once the directory entry itself is on disk.
	// Best-effort: a destination directory that cannot be opened for reading
	// still holds a complete, correctly-named file, and failing a successful
	// export over an unsyncable directory would be the worse answer.
	syncDir(dir)
	return nil
}

// createStaging opens a staging file next to base. perm 0 delegates to
// os.CreateTemp; otherwise the file is created with O_EXCL at perm, so the umask
// applies at creation.
func createStaging(dir, base string, perm os.FileMode) (*os.File, error) {
	if perm == 0 {
		return os.CreateTemp(dir, "."+base+".*.tmp")
	}
	var lastErr error
	for range createTempAttempts {
		suffix, err := RandomSuffix()
		if err != nil {
			return nil, err
		}
		name := filepath.Join(dir, "."+base+"."+suffix+".tmp")
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// RandomSuffix returns 32 bits of randomness as hex, the name fragment this
// package uses to make a staging name collision-proof. Exported so callers
// publishing a whole directory generation (pkg/cli's fs export) name their
// staging and retired trees the same way rather than inventing a second scheme.
func RandomSuffix() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// syncDir fsyncs dir so a completed rename survives a crash. A no-op on
// Windows, where a directory cannot be opened as a file at all.
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
