// Package browserprobe smoke-tests a browser binary by actually launching it
// headless, rather than trusting a `--version` string.
//
// A `--version` check (or a bare PATH lookup) only proves the file exists and
// can print a banner. It does NOT prove the browser can render: some distro
// Chromium builds print a version but then SIGTRAP during real headless
// startup (observed with Debian's Chromium 150 on a KVM guest), and a
// downloaded Chrome can be missing a runtime shared library. Those failures
// only surface when a scan tries to spider, long after `doctor` reported the
// browser green. Launchable() closes that gap by performing the same
// remote-debugging handshake the spider relies on.
package browserprobe

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/scratch"

	"github.com/go-rod/rod/lib/launcher"
)

// DefaultTimeout bounds a single launch probe. A healthy browser exposes its
// DevTools endpoint in ~1-2s; a broken one dies almost immediately. The cap
// only matters for a binary that hangs without ever crashing or serving.
const DefaultTimeout = 30 * time.Second

// Launchable reports whether the browser binary at binPath can actually start
// headless and expose a DevTools endpoint. It returns nil when the browser came
// up, or a trimmed error describing why it did not. It launches a throwaway
// headless instance in an isolated, self-cleaning user-data dir with the same
// critical flags the spider uses (--no-sandbox, --disable-dev-shm-usage), waits
// for the DevTools URL, then kills the process. Bounded by DefaultTimeout.
//
// The remote-debugging handshake — not `--dump-dom` or `--version` — is the
// reliable discriminator: a working Chrome for Testing can hang on --dump-dom in
// a minimal VM (blocked on dbus/UPower) while still serving DevTools instantly,
// whereas a genuinely broken Chromium never serves at all.
func Launchable(binPath string) error {
	if strings.TrimSpace(binPath) == "" {
		return fmt.Errorf("empty browser path")
	}

	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	// A liveness probe, not a crawl: it always runs unsandboxed so the answer
	// is about the binary, not the host's sandbox support. The crawl launcher's
	// security posture is spitolas's config.BrowserCompat (sandbox on unless the
	// host cannot provide one), applied in browser.applySecurityFlags.
	l := launcher.New().
		Context(ctx).
		Bin(binPath).
		Headless(true).
		NoSandbox(true).
		Set("disable-gpu").
		Set("disable-dev-shm-usage").
		Set("no-first-run")

	// Own the user-data dir so it is removed deterministically regardless of how
	// the launch ends. go-rod's Cleanup() blocks on the process-exit channel,
	// which never closes if the binary fails to even start — so we do not rely
	// on it here.
	if dir, err := scratch.MkdirTemp("browserprobe-*"); err == nil {
		defer func() { _ = os.RemoveAll(dir) }()
		l.Set("user-data-dir", dir)
	}

	u, err := l.Launch()
	if err != nil {
		// launcher.Launch already kills the process on failure (and a failed
		// start leaves none); a second Kill would only burn its built-in ~1s
		// sleep. Only a *successful* launch leaves a live process to reap.
		return fmt.Errorf("browser did not start: %s", FirstLine(err.Error()))
	}
	l.Kill()

	if strings.TrimSpace(u) == "" {
		return fmt.Errorf("browser started but exposed no debug endpoint")
	}
	return nil
}

// FirstLine returns the first non-empty line of s, trimmed. go-rod's launch
// error embeds the browser's multi-line stderr (often led by benign crashpad
// cpufreq noise); the first line — "[launcher] Failed to get the debug url: ..."
// — is the actionable part and keeps doctor/log output readable.
func FirstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return strings.TrimSpace(s)
}
