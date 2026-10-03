package cli

import (
	"os"
	"path/filepath"
	"strings"
)

// Package recipes install a marker beside the real executable (not its symlink).
// Wrappers such as Nix and Snap can instead set VIGOLIUM_PACKAGE_MANAGER.
// This leaves standalone, npm, and existing Homebrew distributions unchanged.
const packageManagerEnv = "VIGOLIUM_PACKAGE_MANAGER"

func packageManagerUpgrade(manager string) string {
	switch manager {
	case "aur":
		return "upgrade vigolium-bin with your AUR helper"
	case "pacman":
		return "run: sudo pacman -Syu vigolium"
	case "deb":
		return "install the newer Vigolium .deb with apt, or upgrade through your configured APT repository"
	case "rpm":
		return "install the newer Vigolium .rpm with dnf, or upgrade through your configured DNF repository"
	case "scoop":
		return "run: scoop update vigolium"
	case "winget":
		return "run: winget upgrade --id Vigolium.Vigolium --exact"
	case "nix":
		return "update your Vigolium flake input and rebuild, or upgrade its Nix profile entry"
	case "snap":
		return "run: sudo snap refresh vigolium"
	default:
		return ""
	}
}

func managedPackageManager() string {
	if manager := strings.TrimSpace(os.Getenv(packageManagerEnv)); packageManagerUpgrade(manager) != "" {
		return manager
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return packageManagerForExecutable(exe)
}

func packageManagerForExecutable(exe string) string {
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if data, err := os.ReadFile(filepath.Join(filepath.Dir(exe), ".vigolium-package-manager")); err == nil {
		manager := strings.TrimSpace(string(data))
		if packageManagerUpgrade(manager) != "" {
			return manager
		}
	}
	// WinGet installs the original ZIP, which cannot carry a channel-specific
	// marker. Recognize its package directory for both user and machine scope.
	path := strings.ToLower(strings.ReplaceAll(exe, "\\", "/"))
	if strings.Contains(path, "/winget/packages/vigolium.vigolium_") {
		return "winget"
	}
	return ""
}
