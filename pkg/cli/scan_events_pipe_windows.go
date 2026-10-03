//go:build windows

package cli

// guardEventStreamPipe is a no-op on Windows: there is no SIGPIPE, and a write
// to a closed pipe already fails with an error rather than a signal, which is
// the behaviour the unix build has to arrange for explicitly.
func guardEventStreamPipe() func() { return func() {} }
