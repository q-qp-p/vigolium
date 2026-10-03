//go:build !windows

package cli

import (
	"os"
	"os/signal"
	"syscall"
)

// guardEventStreamPipe neutralises SIGPIPE for the duration of the event
// stream, returning the function that restores the default.
//
// Go's runtime raises SIGPIPE to the default handler — which kills the process
// — when a write to fd 1 or 2 hits a closed pipe. That rule exists so an
// ordinary program piped into `head` dies the way every other unix program
// does. For a scanner it is the wrong trade: `vigolium scan --events ndjson |
// head -5` killed a running scan mid-request, leaving no scan row, no findings
// and no explanation, because a consumer had read as much as it wanted.
//
// signal.Notify on SIGPIPE changes that: the write returns EPIPE instead, the
// emitter latches shut (and records the error for Err), and the scan runs to
// completion. The goroutine drains the channel so a repeat cannot block.
func guardEventStreamPipe() func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGPIPE)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
			case <-done:
				return
			}
		}
	}()
	var stopped bool
	return func() {
		if stopped {
			return
		}
		stopped = true
		signal.Stop(ch)
		close(done)
	}
}
