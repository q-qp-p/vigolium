package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestManagedPackagePreventsSelfUpdate(t *testing.T) {
	for _, manager := range []string{"aur", "pacman", "deb", "rpm", "scoop", "winget", "nix", "snap"} {
		t.Run(manager, func(t *testing.T) {
			t.Setenv(packageManagerEnv, manager)
			t.Setenv(envAutoUpdate, "1")
			t.Setenv(envDisableUpdateCheck, "")
			if !updateCheckHardDisabled(&cobra.Command{Use: "doctor"}, "v1.0.0") {
				t.Fatal("managed installation would contact npm or auto-update")
			}
			// Guard must precede invoking curl/bash, even on explicit update.
			err := runInstallScript(context.Background(), io.Discard)
			if err == nil || !strings.Contains(err.Error(), packageManagerUpgrade(manager)) || !strings.Contains(err.Error(), "--skip-binary") {
				t.Fatalf("expected package upgrade and template-only instructions, got %v", err)
			}
		})
	}
}

func TestPackageManagerMarker(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "vigolium")
	if err := os.WriteFile(exe, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := packageManagerForExecutable(exe); got != "" {
		t.Fatalf("standalone executable detected as %q", got)
	}
	marker := filepath.Join(dir, ".vigolium-package-manager")
	for _, value := range []string{"deb\n", "unknown\n"} {
		if err := os.WriteFile(marker, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
		want := strings.TrimSpace(value)
		if want == "unknown" {
			want = ""
		}
		if got := packageManagerForExecutable(exe); got != want {
			t.Fatalf("marker %q: got %q, want %q", value, got, want)
		}
	}
	if err := os.WriteFile(marker, []byte("aur\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "vigolium")
	if err := os.Symlink(exe, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if got := packageManagerForExecutable(link); got != "aur" {
		t.Fatalf("symlink did not resolve package marker: %q", got)
	}
}

func TestWinGetPackagePath(t *testing.T) {
	for _, path := range []string{
		`C:\Users\user\AppData\Local\Microsoft\WinGet\Packages\Vigolium.Vigolium_Microsoft.Winget.Source_8wekyb3d8bbwe\vigolium.exe`,
		`C:\Program Files\WinGet\Packages\Vigolium.Vigolium_Microsoft.Winget.Source_8wekyb3d8bbwe\vigolium.exe`,
	} {
		if got := packageManagerForExecutable(path); got != "winget" {
			t.Fatalf("WinGet path detected as %q", got)
		}
	}
	if got := packageManagerForExecutable(`C:\tools\vigolium.exe`); got != "" {
		t.Fatalf("standalone Windows binary detected as %q", got)
	}
}
