package browser

import (
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"go.uber.org/zap"
)

// applySecurityFlags sets exactly the Chromium flags the compat exceptions ask
// for and removes the rest, so a launcher built for one posture can never carry
// another's exception. Pure (no host probing) — the forced-sandbox decision is
// made by the caller and arrives here as c.NoSandbox — so it is unit-testable
// with launcher.Has, like applyProxy.
//
// reduce-security-for-testing is tied to DisableWebSecurity: it only weakens
// checks the same-origin policy already enforces, so it means nothing with web
// security on and must not ride along by default.
func applySecurityFlags(l *launcher.Launcher, c config.BrowserCompat) *launcher.Launcher {
	l = l.NoSandbox(c.NoSandbox)
	set := func(on bool, flag flags.Flag) {
		if on {
			l = l.Set(flag)
		} else {
			l = l.Delete(flag)
		}
	}
	set(c.IgnoreTLSErrors, "ignore-certificate-errors")
	set(c.AllowInsecureContent, "allow-running-insecure-content")
	set(c.DisableWebSecurity, "disable-web-security")
	set(c.DisableWebSecurity, "reduce-security-for-testing")
	return l
}

// sandboxHost is the slice of the host the sandbox decision reads, injected so
// every branch is testable on any OS.
type sandboxHost struct {
	goos     string
	euid     int
	readFile func(string) ([]byte, error)
	exists   func(string) bool
	getenv   func(string) string
}

func currentSandboxHost() sandboxHost {
	return sandboxHost{
		goos:     runtime.GOOS,
		euid:     os.Geteuid(),
		readFile: os.ReadFile,
		exists: func(p string) bool {
			_, err := os.Stat(p)
			return err == nil
		},
		getenv: os.Getenv,
	}
}

// inContainer mirrors rod's own container test (lib/utils.InContainer), plus
// podman's /run/.containerenv, so this decision and rod's launcher default
// never disagree about where the sandbox is unavailable.
func (h sandboxHost) inContainer() bool {
	return h.exists("/.dockerenv") || h.exists("/.containerenv") || h.exists("/run/.containerenv") ||
		h.getenv("KUBERNETES_SERVICE_HOST") != ""
}

// sysctlIs reports whether the /proc/sys file at path holds exactly want.
func (h sandboxHost) sysctlIs(path, want string) bool {
	b, err := h.readFile(path)
	return err == nil && strings.TrimSpace(string(b)) == want
}

// sandboxUnavailableOn reports whether the host cannot give Chromium a sandbox,
// and why. Only Linux is probed: there the sandbox needs either unprivileged
// user namespaces or a setuid helper, and Chromium refuses to start as root
// with it on. Other platforms provide one unconditionally.
func sandboxUnavailableOn(h sandboxHost) (bool, string) {
	if h.goos != "linux" {
		return false, ""
	}
	switch {
	case h.euid == 0:
		return true, "running as root"
	case h.inContainer():
		return true, "running in a container"
	case h.sysctlIs("/proc/sys/user/max_user_namespaces", "0"):
		return true, "user namespaces disabled (user.max_user_namespaces=0)"
	case h.sysctlIs("/proc/sys/kernel/unprivileged_userns_clone", "0"):
		return true, "unprivileged user namespaces disabled (kernel.unprivileged_userns_clone=0)"
	}
	return false, ""
}

// sandboxRetryReason explains why a sandboxed Linux launch failed for the warn
// that accompanies the unsandboxed retry. Ubuntu 23.10+ restricts unprivileged
// user namespaces through AppArmor, which is the common cause for a browser with
// no AppArmor profile of its own (Chrome for Testing, a rod download).
func sandboxRetryReason(h sandboxHost, launchErr string) string {
	reason := "sandboxed launch failed: " + launchErr
	if h.sysctlIs("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "1") {
		reason += " (kernel.apparmor_restrict_unprivileged_userns=1 — AppArmor blocks the sandbox's user namespace)"
	}
	return reason
}

// sandboxState is the process-wide sandbox decision. The host does not change
// during a run, so both the forced-off detection and a learned launch fallback
// are made once: later launches (every ProbeURL starts a browser) skip straight
// to the working posture, and the operator sees one warning, not one per launch.
var sandboxState struct {
	mu       sync.Mutex
	detected bool
	forced   bool
	reason   string
	warned   bool
}

// SandboxDisabledReason reports whether launches in this process run without
// the sandbox although the configuration asked for one, and the named reason.
// The forced-off detection runs on first call; a Linux launch fallback recorded
// later (sandbox failed, unsandboxed worked) is reported once it has happened.
func SandboxDisabledReason() (bool, string) {
	sandboxState.mu.Lock()
	defer sandboxState.mu.Unlock()
	detectSandboxLocked()
	return sandboxState.forced, sandboxState.reason
}

func detectSandboxLocked() {
	if sandboxState.detected {
		return
	}
	sandboxState.detected = true
	if off, why := sandboxUnavailableOn(currentSandboxHost()); off {
		sandboxState.forced, sandboxState.reason = true, why
	}
}

// effectiveNoSandbox resolves whether this launch runs unsandboxed: the
// operator's exception, or the process-wide forced/learned state — the latter
// announced with exactly one warn per process.
func effectiveNoSandbox(c config.BrowserCompat) bool {
	if c.NoSandbox {
		return true
	}
	sandboxState.mu.Lock()
	defer sandboxState.mu.Unlock()
	detectSandboxLocked()
	if !sandboxState.forced {
		return false
	}
	if !sandboxState.warned {
		sandboxState.warned = true
		zap.L().Warn("Browser sandbox disabled: the host cannot provide one",
			zap.String("reason", sandboxState.reason))
	}
	return true
}

// recordSandboxFallback remembers that a sandboxed launch failed and an
// unsandboxed one worked, so the rest of the run launches unsandboxed directly.
func recordSandboxFallback(reason string) {
	sandboxState.mu.Lock()
	defer sandboxState.mu.Unlock()
	sandboxState.detected = true
	sandboxState.forced = true
	sandboxState.reason = reason
	if !sandboxState.warned {
		sandboxState.warned = true
		zap.L().Warn("Browser sandbox disabled: retried the launch without it",
			zap.String("reason", reason))
	}
}
