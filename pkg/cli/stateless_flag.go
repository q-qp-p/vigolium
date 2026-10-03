package cli

import (
	"fmt"
	"os"
	"slices"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// -S used to mean two different things depending on which command you typed it
// after: --stateless on scan/export/finding/replay/agent-audit, and
// --scan-on-receive on server/ingest. A third group (log, and traffic's
// --save-to-vigolium-db path) rejected it outright with "unknown shorthand
// flag" — a non-zero exit and no output, which is the worst of the three: a
// driver passing -S for safety got a control that looked live and could only
// ever report zero rows.
//
// Two changes retire the trap:
//
//  1. On server/ingest the shorthand is deprecated. --scan-on-receive keeps
//     working and is now the spelling in the help text; -S still sets it for one
//     minor version, with a warning naming the replacement, so no existing
//     command line breaks today.
//  2. --stateless is accepted everywhere as a persistent root flag. On a command
//     where it is meaningless it is a documented no-op — a flag that is harmless
//     everywhere is one a driver never has to keep a per-command acceptance
//     table for.
//
// The root flag is deliberately LONG-ONLY. Giving it the -S shorthand at root
// level would collide with the local -S the read commands and the deprecated
// scan-on-receive alias still register, and pflag resolves that by panicking at
// startup rather than by picking one.

// deprecatedScanOnReceiveShorthand backs the retiring -S on server/ingest. It is
// a separate variable from globalScanOnReceive so PreRun can tell "the operator
// typed the deprecated shorthand" from "the operator typed the long flag".
var deprecatedScanOnReceiveShorthand bool

// registerScanOnReceiveFlags declares --scan-on-receive plus its deprecated -S
// shorthand on a server/ingest flagset.
func registerScanOnReceiveFlags(flags *pflag.FlagSet, usage string) {
	flags.BoolVar(&globalScanOnReceive, "scan-on-receive", false, usage)
	// A hidden second flag rather than a shorthand on the first: pflag binds a
	// shorthand to one flag, and the whole point is to tell the two spellings
	// apart so only the old one warns.
	flags.BoolVarP(&deprecatedScanOnReceiveShorthand, "scan-on-receive-shorthand", "S", false,
		"Deprecated alias for --scan-on-receive")
	_ = flags.MarkHidden("scan-on-receive-shorthand")
}

// applyDeprecatedScanOnReceive folds the deprecated -S into the real flag and
// warns once. Called from the root PersistentPreRunE so every command that
// registered the alias is covered without repeating the check.
// The value matters, not just the spelling: `ingest -S=false` is an operator
// saying "do not scan what you receive", and folding it in on Changed alone
// turned ingestion into a scanner against an explicit instruction.
func applyDeprecatedScanOnReceive(cmd *cobra.Command) {
	if !flagOn(cmd, "scan-on-receive-shorthand") {
		return
	}
	globalScanOnReceive = true
	if machineOutputMode() {
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s on %s is deprecated and will be removed — use %s. "+
		"(%s now means %s everywhere else, and this is the last command where it did not.)\n",
		terminal.WarnPrefix(),
		terminal.BoldCyan("-S"),
		terminal.BoldCyan(cmd.Name()),
		terminal.BoldCyan("--scan-on-receive"),
		terminal.BoldCyan("-S"),
		terminal.BoldCyan("--stateless"))
}

// registerStatelessRootFlag declares the persistent, long-only --stateless so it
// parses on every command. Commands that give it real meaning register their own
// local -S/--stateless, which shadows this one; everywhere else it lands here and
// does nothing beyond being accepted.
func registerStatelessRootFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&globalStateless, "stateless", false,
		"Read from --db (a .jsonl export or standalone .sqlite) with project scoping off, "+
			"or scan into a throwaway database. Accepted (and ignored) on commands where neither applies.")
	// Hidden at root so `vigolium --help` doesn't advertise a flag that is inert
	// for most subcommands; the commands where it means something document it in
	// their own help.
	_ = cmd.PersistentFlags().MarkHidden("stateless")
}

// addStatelessShorthand gives cmd and every subcommand a local -S/--stateless
// when they have none, so the letter means one thing everywhere.
//
// Not the root persistent flag, which is long-only: a shorthand there would
// collide with the commands that still bind -S themselves, and pflag resolves
// that by panicking at startup rather than by shadowing. Registering per command
// is what lets those keep theirs while every other command accepts the letter.
//
// Two structural guards, no exemption list. `server`/`ingest` still bind -S to
// the retiring --scan-on-receive alias — but by the time this runs (from
// Execute, after every init) that shorthand is already registered, so the
// ShorthandLookup guard skips them on its own and self-heals when the alias is
// finally removed. A name-keyed exemption list would rot in both directions:
// rename a command and it silently stops matching; add a third -S owner and the
// two mechanisms disagree about which is authoritative.
//
// On a read command -S is meaningful (read --db with project scoping off);
// elsewhere it is a documented no-op. Both beat "unknown shorthand flag", which
// exits non-zero with no output — a control that looks live and can only ever
// report nothing.
func addStatelessShorthand(c *cobra.Command) {
	for _, sub := range c.Commands() {
		addStatelessShorthand(sub)
	}
	if f := c.Flags().Lookup("stateless"); f != nil {
		return // already has its own, shorthand and all
	}
	if c.Flags().ShorthandLookup("S") != nil {
		return // the letter is taken on this command (the deprecated alias)
	}
	c.Flags().BoolVarP(&globalStateless, "stateless", "S", false,
		"Read from --db (a .jsonl export or standalone .sqlite) with project scoping off; ignored where it does not apply")
	_ = c.Flags().MarkHidden("stateless")
	statelessInjected[c] = true
}

// statelessInjected records the commands addStatelessShorthand gave an injected
// -S to. They are exactly the commands where the letter is accepted because it
// is accepted everywhere, not because the command does anything with it — and
// so exactly the set where it may be a no-op.
//
// Recorded at registration rather than listed by name: the injection has two
// structural guards and no exemption table, so a hand-written list of "commands
// without real -S" would be a second, drifting copy of a decision already made
// here.
var statelessInjected = map[*cobra.Command]bool{}

// statelessReaderCommands are the injected-'-S' commands where the flag still
// means something, as command paths without the root name.
//
// These reach a read path that consults statelessReadRequested even though they
// never registered -S themselves, so the injected flag is live on them.
var statelessReaderCommands = []string{
	"log", "log ls", "fuzz", "db list",
}

// warnNoOpStateless tells the operator when -S/--stateless was accepted and
// ignored.
//
// The flag parses on every command so that a driver passing it for safety never
// gets "unknown shorthand flag" — a non-zero exit with no output. But silence
// has its own failure mode: `-S` reads as "do not touch my project database",
// and on a command that writes, it does not mean that. One line naming the
// command is the difference between a wrong belief and a corrected one.
//
// Not in a machine-output mode, and not for the commands that genuinely honor
// it. Rejecting instead of warning is deferred: it would break command lines
// that work today.
func warnNoOpStateless(cmd *cobra.Command) {
	if !globalStateless || machineOutputMode() {
		return
	}
	if !statelessInjected[cmd] {
		return // the command registered its own -S, so it means something here
	}
	path := commandPathWithoutRoot(cmd)
	if slices.Contains(statelessReaderCommands, path) {
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s has no effect on %q and is ignored\n",
		terminal.WarnPrefix(), terminal.BoldCyan("-S/--stateless"), path)
}
