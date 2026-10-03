package tool

// RegisterBuiltins populates a Registry with every tool olium ships by default.
// approve is used only for the bash tool's rm -rf guard; other tools run
// without gating per the M2 permission policy.
func RegisterBuiltins(r *Registry, approve ApprovalFn) {
	// The mutating tools, then the read-only set (registry is name-keyed, so
	// order isn't load-bearing). Keeping the read-only list in one place means
	// a new read-only builtin only has to be added once.
	r.Register(NewBash(approve))
	r.Register(NewWriteFile())
	r.Register(NewEditFile())
	RegisterReadOnlyBuiltins(r)
	// The full web_fetch (any method, browser mode) replaces the read-only
	// variant RegisterReadOnlyBuiltins installed under the same name.
	r.Register(NewWebFetch())
}

// RegisterReadOnlyBuiltins populates r with only the builtins that can neither
// mutate the filesystem nor execute arbitrary commands: read_file, ls, grep,
// glob, web_fetch, and browser_probe. It deliberately omits bash, write_file,
// and edit_file, and its web_fetch is the read-only variant (GET/HEAD, no
// browser mode). Use it for strictly read-only contexts — e.g. the candidate
// verifier, which investigates evidence but must never touch the source tree
// or shell out.
func RegisterReadOnlyBuiltins(r *Registry) {
	r.Register(NewReadFile())
	r.Register(NewLs())
	r.Register(NewGrep())
	r.Register(NewGlob())
	r.Register(NewWebFetchReadOnly())
	r.Register(NewBrowserProbe())
}
