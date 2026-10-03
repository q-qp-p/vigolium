package cli

import (
	"fmt"
	"os"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
)

func init() {
	// Route clicommon's configuration diagnostics through the CLI's own output
	// policy. They are advice about a file the operator wrote, so they belong on
	// stderr — never stdout, which belongs to the machine document — and they
	// stay quiet under --silent, where the caller asked for nothing at all.
	//
	// Deliberately NOT gated on machineOutputMode(): -j and --ci-output-format
	// own stdout, which this never touches, and a JSON caller whose --config is
	// broken is exactly the caller who needs to be told.
	clicommon.ConfigWarn = func(msg string) {
		if globalSilent {
			return
		}
		fmt.Fprintf(os.Stderr, "%s %s\n", terminal.WarningSymbol(), msg)
	}
}

// settingsOrDefaults loads configuration for the handful of call sites with no
// error to return — a *config.Settings accessor, an enabled-modules lookup, a
// sessions-dir resolver.
//
// Those cannot fail the command, so the failure is at least made visible once
// instead of becoming an invisible switch to defaults. Every such site sits
// inside a command that also opens the database, and clicommon.GetDB DOES fail
// on the same broken config, so in practice the command still exits non-zero —
// this exists so the reason is on screen when it does.
func settingsOrDefaults() *config.Settings {
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		clicommon.WarnConfigOnce(fmt.Sprintf("%v; continuing with built-in defaults", err))
		return config.DefaultSettings()
	}
	return settings
}
