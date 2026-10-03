package cli

import (
	"strings"
	"testing"
)

// TestBrowsersFlagStatesClamp: --browsers advertised parallel browsers that the
// single-threaded crawler clamps to one; the help must say so, so the doc fix
// cannot silently regress. Same for --require-auth existing on the scan
// commands that spider.
func TestBrowsersFlagStatesClamp(t *testing.T) {
	for _, cmd := range []struct {
		name  string
		usage func(string) string
	}{
		{"scan", func(n string) string {
			if f := scanCmd.Flags().Lookup(n); f != nil {
				return f.Usage
			}
			return ""
		}},
		{"run", func(n string) string {
			if f := runCmd.Flags().Lookup(n); f != nil {
				return f.Usage
			}
			return ""
		}},
	} {
		usage := cmd.usage("browsers")
		if usage == "" {
			t.Errorf("%s: --browsers not registered", cmd.name)
			continue
		}
		if !strings.Contains(usage, "clamped to 1") {
			t.Errorf("%s --browsers help %q does not state the clamp", cmd.name, usage)
		}
		if cmd.usage("require-auth") == "" {
			t.Errorf("%s: --require-auth not registered", cmd.name)
		}
	}
}
