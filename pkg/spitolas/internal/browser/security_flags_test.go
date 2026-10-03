package browser

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

var securityFlagNames = []flags.Flag{
	flags.NoSandbox,
	"ignore-certificate-errors",
	"allow-running-insecure-content",
	"disable-web-security",
	"reduce-security-for-testing",
}

func setSecurityFlags(l *launcher.Launcher) map[flags.Flag]bool {
	got := map[flags.Flag]bool{}
	for _, f := range securityFlagNames {
		if l.Has(f) {
			got[f] = true
		}
	}
	return got
}

func TestApplySecurityFlags_NoExceptions(t *testing.T) {
	// Start from a launcher carrying every flag, so the test also proves the
	// function removes what it was not asked for (rod's own launcher.New adds
	// no-sandbox inside a container).
	l := launcher.New()
	for _, f := range securityFlagNames {
		l = l.Set(f)
	}
	if got := setSecurityFlags(applySecurityFlags(l, config.BrowserCompat{})); len(got) != 0 {
		t.Errorf("no exceptions requested, but flags set: %v", got)
	}
}

func TestApplySecurityFlags_EachExceptionSetsOnlyItsFlag(t *testing.T) {
	cases := []struct {
		name   string
		compat config.BrowserCompat
		want   []flags.Flag
	}{
		{"no_sandbox", config.BrowserCompat{NoSandbox: true}, []flags.Flag{flags.NoSandbox}},
		{"ignore_tls", config.BrowserCompat{IgnoreTLSErrors: true}, []flags.Flag{"ignore-certificate-errors"}},
		{"insecure_content", config.BrowserCompat{AllowInsecureContent: true}, []flags.Flag{"allow-running-insecure-content"}},
		// reduce-security-for-testing rides only with disable-web-security.
		{"disable_web_security", config.BrowserCompat{DisableWebSecurity: true}, []flags.Flag{"disable-web-security", "reduce-security-for-testing"}},
	}
	for _, c := range cases {
		got := setSecurityFlags(applySecurityFlags(launcher.New().Delete(flags.NoSandbox), c.compat))
		if len(got) != len(c.want) {
			t.Errorf("%s: flags set = %v, want exactly %v", c.name, got, c.want)
			continue
		}
		for _, f := range c.want {
			if !got[f] {
				t.Errorf("%s: missing %s (got %v)", c.name, f, got)
			}
		}
	}
}

func TestApplySecurityFlags_DefaultPosture(t *testing.T) {
	got := setSecurityFlags(applySecurityFlags(launcher.New().Delete(flags.NoSandbox), config.DefaultBrowserCompat()))
	if len(got) != 1 || !got["ignore-certificate-errors"] {
		t.Errorf("default posture flags = %v, want only ignore-certificate-errors", got)
	}
}

// fakeHost builds a sandboxHost from literal facts.
func fakeHost(goos string, euid int, files map[string]string, env map[string]string) sandboxHost {
	return sandboxHost{
		goos: goos,
		euid: euid,
		readFile: func(p string) ([]byte, error) {
			if v, ok := files[p]; ok {
				return []byte(v), nil
			}
			return nil, errors.New("not found")
		},
		exists: func(p string) bool {
			_, ok := files[p]
			return ok
		},
		getenv: func(k string) string { return env[k] },
	}
}

func TestSandboxUnavailableOn(t *testing.T) {
	cases := []struct {
		name       string
		host       sandboxHost
		wantOff    bool
		wantReason string
	}{
		{"darwin root is fine", fakeHost("darwin", 0, nil, nil), false, ""},
		{"linux ordinary user", fakeHost("linux", 1000, map[string]string{"/proc/sys/user/max_user_namespaces": "63000\n"}, nil), false, ""},
		{"linux root", fakeHost("linux", 0, nil, nil), true, "root"},
		{"docker", fakeHost("linux", 1000, map[string]string{"/.dockerenv": ""}, nil), true, "container"},
		{"podman", fakeHost("linux", 1000, map[string]string{"/run/.containerenv": ""}, nil), true, "container"},
		{"kubernetes", fakeHost("linux", 1000, nil, map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"}), true, "container"},
		{"userns off", fakeHost("linux", 1000, map[string]string{"/proc/sys/user/max_user_namespaces": "0\n"}, nil), true, "max_user_namespaces=0"},
		{"unpriv clone off", fakeHost("linux", 1000, map[string]string{"/proc/sys/kernel/unprivileged_userns_clone": "0"}, nil), true, "unprivileged_userns_clone=0"},
	}
	for _, c := range cases {
		off, why := sandboxUnavailableOn(c.host)
		if off != c.wantOff {
			t.Errorf("%s: off = %v, want %v (reason %q)", c.name, off, c.wantOff, why)
		}
		if c.wantOff && (why == "" || !strings.Contains(why, c.wantReason)) {
			t.Errorf("%s: reason %q must name %q", c.name, why, c.wantReason)
		}
		if !c.wantOff && why != "" {
			t.Errorf("%s: no reason expected, got %q", c.name, why)
		}
	}
}

func TestSandboxRetryReason_NamesAppArmor(t *testing.T) {
	h := fakeHost("linux", 1000, map[string]string{"/proc/sys/kernel/apparmor_restrict_unprivileged_userns": "1\n"}, nil)
	got := sandboxRetryReason(h, "No usable sandbox!")
	if !strings.Contains(got, "No usable sandbox!") || !strings.Contains(got, "AppArmor") {
		t.Errorf("reason %q must carry the launch error and name AppArmor", got)
	}
	if got := sandboxRetryReason(fakeHost("linux", 1000, nil, nil), "boom"); strings.Contains(got, "AppArmor") {
		t.Errorf("AppArmor named without the restriction set: %q", got)
	}
}

// TestSandboxState_ForcedAndLearned exercises the process-wide memo: a learned
// fallback is reported, and from then on every launch runs unsandboxed.
func TestSandboxState_ForcedAndLearned(t *testing.T) {
	sandboxState.mu.Lock()
	detected, forced, reason, warned := sandboxState.detected, sandboxState.forced, sandboxState.reason, sandboxState.warned
	sandboxState.detected, sandboxState.forced, sandboxState.reason, sandboxState.warned = true, false, "", false
	sandboxState.mu.Unlock()
	t.Cleanup(func() {
		sandboxState.mu.Lock()
		sandboxState.detected, sandboxState.forced, sandboxState.reason, sandboxState.warned = detected, forced, reason, warned
		sandboxState.mu.Unlock()
	})

	if effectiveNoSandbox(config.BrowserCompat{}) {
		t.Fatal("sandbox must stay on with no forced state")
	}
	if !effectiveNoSandbox(config.BrowserCompat{NoSandbox: true}) {
		t.Fatal("an explicit NoSandbox must always win")
	}
	recordSandboxFallback("sandboxed launch failed: No usable sandbox!")
	if !effectiveNoSandbox(config.BrowserCompat{}) {
		t.Error("after a learned fallback every launch must run unsandboxed")
	}
	if off, why := SandboxDisabledReason(); !off || !strings.Contains(why, "No usable sandbox") {
		t.Errorf("SandboxDisabledReason = (%v, %q), want the learned reason", off, why)
	}
}
