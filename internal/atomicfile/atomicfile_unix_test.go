//go:build unix

package atomicfile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The mode WriteBytes names is a request, not a command: it is applied at
// creation so the umask subtracts from it. An operator who runs with umask 077
// because scan results are sensitive must not get a world-readable export, and
// the force-chmod this replaced handed them one.
//
// Not parallel, and the umask is restored in cleanup: it is process-global
// state, so a leaked value would silently change the modes every later test in
// this package asserts.
func TestWriteBytesHonorsUmask(t *testing.T) {
	cases := []struct {
		umask int
		want  os.FileMode
	}{
		{umask: 0o077, want: 0o600},
		{umask: 0o022, want: 0o644},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		dest := filepath.Join(dir, "export.jsonl")

		prev := syscall.Umask(tc.umask)
		err := WriteBytes(dest, []byte("{}\n"))
		syscall.Umask(prev)
		if err != nil {
			t.Fatalf("umask %o: WriteBytes: %v", tc.umask, err)
		}

		info, serr := os.Stat(dest)
		if serr != nil {
			t.Fatal(serr)
		}
		if perm := info.Mode().Perm(); perm != tc.want {
			t.Errorf("umask %o: mode = %o, want %o", tc.umask, perm, tc.want)
		}
	}
}
