//go:build unix

package scratch

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// leaseName is the lock file inside a process scratch directory.
//
// The dot prefix keeps it out of a casual `ls` of a directory an operator is
// inspecting, and it is a plain regular file rather than the directory itself
// because flock on a directory fd is not portable across the unixes.
const leaseName = ".lease"

// acquireLease takes an exclusive, non-blocking flock on dir's lease file and
// returns the open file. The lock lives on the open file description, so it is
// released by closing the returned file — or by the process dying, including on
// SIGKILL, which is exactly the liveness signal the age-based sweep lacks.
//
// Best-effort by contract: the caller keeps working on an error, because a
// missing lease only costs the sweeper its liveness check.
func acquireLease(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, leaseName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// leaseHeld reports whether another live process holds dir's lease.
//
// known is false when there is no lease file to ask about — an older version's
// directory, or one whose creation lost the race. The caller falls back to the
// pid check for those rather than treating "no lease" as "not running".
//
// A held lease is detected by trying to take it: flock locks belong to the open
// file description, so this process's own second open conflicts with a lease it
// already holds, which is what makes the check work in-process as well as
// across processes.
func leaseHeld(dir string) (held, known bool) {
	path := filepath.Join(dir, leaseName)
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return false, false
	}
	defer func() { _ = f.Close() }()

	fd := int(f.Fd())
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return true, true
		}
		// Some other failure (EOPNOTSUPP on an exotic filesystem, say). We cannot
		// tell, so say so and let the pid check decide.
		return false, false
	}
	// We got it, so nobody held it. Release immediately — holding it would make
	// the sweeper itself look like a live owner to the next sweeper.
	_ = syscall.Flock(fd, syscall.LOCK_UN)
	return false, true
}

// pidAlive reports whether pid names a running process.
//
// Signal 0 performs the permission and existence checks without delivering
// anything. EPERM means the process exists and belongs to someone else, which
// for this purpose is still alive — a shared machine's /tmp holds other users'
// scratch, and removing theirs because we cannot signal it would be worse than
// leaving it for its own owner's sweep.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
