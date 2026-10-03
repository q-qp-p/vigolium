package cli

import "github.com/spf13/cobra"

// flagOn reports whether cmd was given this boolean flag with a true value.
//
// `Changed` alone means "the operator typed it", which is not the same thing:
// pflag records `--stateless=false` as Changed, so every site that read Changed
// as "enabled" turned the flag ON when the operator had explicitly turned it
// off. Three of those had teeth — `scan --stateless=false` with
// VIGOLIUM_DB_PATH set dropped the pin and wrote to the default database,
// `ingest -S=false` enabled scan-on-receive, and `--read-only
// --save-to-vigolium-db=false` was rejected as a conflict that did not exist.
//
// A non-boolean flag is reported as on when it was set at all: for those,
// "typed" is the only meaning available, and Value.String() carries the value
// rather than a truth. Callers that need a value read it themselves.
func flagOn(cmd *cobra.Command, name string) bool {
	if cmd == nil {
		return false
	}
	f := cmd.Flags().Lookup(name)
	if f == nil || !f.Changed {
		return false
	}
	if f.Value.Type() == "bool" {
		return f.Value.String() == "true"
	}
	return true
}
