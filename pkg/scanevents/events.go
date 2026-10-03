// Package scanevents is the machine-readable event stream a scan emits on
// stdout, alongside (never instead of) the human console render on stderr.
//
// The contract has one job: let a program that spawned `vigolium scan` learn
// what the scan is doing while it runs, without reading anything that was
// formatted for a terminal. Every consumer fact — which phase, how far, whether
// the edge started filtering, what was found — is a field on a line here, so
// nothing downstream has to regex a rendered log to recover it.
//
// Four rules make the stream usable and must not regress:
//
//   - Stdout only, and only when --events is passed. The stderr console is
//     byte-for-byte unchanged whether or not a stream is attached, so an
//     interactive operator sees no difference and a driver gets clean NDJSON out
//     of `2>/dev/null`.
//   - Every event carries ScanUUID. One sweep is several `vigolium scan`
//     invocations; an event a consumer cannot attribute to an invocation is an
//     event it cannot use.
//   - One line, one flush. A consumer polling a pipe must see phase.progress
//     while the phase runs. Buffering to exit would turn the stream back into a
//     post-mortem log, which is the thing it exists to replace.
//   - A terminal event on every exit path we can reach, including SIGINT/SIGTERM
//     (status "interrupted"). SIGKILL cannot be caught, which is fine: the
//     ABSENCE of a terminal event is itself the signal, and only stays that way
//     if every reachable path emits one.
package scanevents

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// SchemaVersion is the event-schema version carried on every line as "v".
// Bump it on any breaking field change so consumers can gate on it.
const SchemaVersion = 1

// Event types. These are the string values of the "type" field; a consumer
// switches on them, so they are part of the contract and only ever added to.
const (
	TypeScanStarted = "scan.started"
	// TypeScanInterrupting says a shutdown signal arrived and the graceful stop
	// has begun. NONTERMINAL: the scan is still finalizing, and the terminal
	// scan.finished still follows. It exists because graceful shutdown can take
	// seconds, during which a consumer could not tell a slow phase from a scan
	// that was already on its way out — and an operator who sends a second
	// signal in that window gets a hard exit with no explanation on the stream.
	TypeScanInterrupting = "scan.interrupting"
	TypeScanFinished     = "scan.finished"
	TypePhaseStarted     = "phase.started"
	TypePhaseProgress    = "phase.progress"
	TypePhaseFinished    = "phase.finished"
	TypeWAFBlock         = "waf.block"
	TypeWAFPacing        = "waf.pacing"
	TypeFindingNew       = "finding.new"
	TypeImportSummary    = "import.summary"
	TypeError            = "error"
)

// Terminal scan statuses.
const (
	StatusCompleted   = "completed"
	StatusInterrupted = "interrupted"
	StatusFailed      = "failed"
	StatusCurtailed   = "curtailed"
)

// Event is one line of the stream. Field order in the struct is the field order
// on the wire, which keeps a hand-read line legible: identity first, payload
// after. Everything past Type is omitempty so a line carries only what its type
// actually means.
type Event struct {
	V  int    `json:"v"`
	TS string `json:"ts"`
	// Seq is this emitter's 1-based write counter, stamped under the same lock
	// that serialises the write, so it is the stream's own total order. ts alone
	// could not be: it has millisecond precision and a busy scan emits several
	// events per millisecond, so a consumer sorting by timestamp reorders them.
	// A gap means a line was lost in transit — which a consumer otherwise had no
	// way to detect at all.
	Seq      uint64 `json:"seq"`
	ScanUUID string `json:"scan_uuid"`
	Type     string `json:"type"`

	// Scan identity / lifecycle.
	Target   string   `json:"target,omitempty"`
	Targets  int      `json:"targets,omitempty"`
	Strategy string   `json:"strategy,omitempty"`
	Phases   []string `json:"phases,omitempty"`
	DBPath   string   `json:"db_path,omitempty"`
	Project  string   `json:"project_uuid,omitempty"`
	Pace     *Pace    `json:"pace,omitempty"`
	// PhasePace is the resolved per-phase pace table, present on scan.started
	// whenever any phase resolves to something other than the global values.
	// Keyed by canonical phase id.
	PhasePace map[string]Pace `json:"phase_pace,omitempty"`

	// Phase lifecycle.
	Phase      string `json:"phase,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	Status     string `json:"status,omitempty"`

	// Why a phase or a scan did not cover everything. Reasons are defects or
	// curtailments ("phase_deadline", "targets_failed", …); Limits are configured
	// bounds that were reached, which is designed behaviour and is reported
	// separately so a consumer never reads a correctly time-boxed target as a
	// degraded one. StopReason is the scan-level roll-up on scan.finished. All
	// three are additive: a "completed" status still means what it did, and a
	// consumer that ignores them sees the stream it saw before.
	Reasons    []string `json:"reasons,omitempty"`
	Limits     []string `json:"limits,omitempty"`
	StopReason string   `json:"stop_reason,omitempty"`

	// Progress counters. Pointers so a zero is reported as a zero rather than
	// dropped by omitempty — "0 requests sent" is a meaningful reading.
	RequestsSent   *int64 `json:"requests_sent,omitempty"`
	Findings       *int64 `json:"findings,omitempty"`
	Total          *int64 `json:"total,omitempty"`
	RecordsWritten *int64 `json:"records_written,omitempty"`

	// WAF / edge.
	Host            string `json:"host,omitempty"`
	Vendor          string `json:"vendor,omitempty"`
	StatusCode      int    `json:"status_code,omitempty"`
	Detail          string `json:"detail,omitempty"`
	ConcurrencyFrom int    `json:"concurrency_from,omitempty"`
	ConcurrencyTo   int    `json:"concurrency_to,omitempty"`

	// Findings.
	Severity   string `json:"severity,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	ModuleID   string `json:"module_id,omitempty"`
	URL        string `json:"url,omitempty"`

	FindingsBySeverity map[string]int `json:"findings_by_severity,omitempty"`

	// Message carries an error's text. An `error` event is by construction NON-
	// fatal: a failure that ends the run rides on scan.finished{status:"failed"}
	// instead, so a consumer never has to guess which kind it is holding. (A
	// `fatal` field lived here briefly, hardcoded false and dropped by omitempty
	// — it could never appear on the wire, which is a worse contract than not
	// having it.)
	Message string `json:"message,omitempty"`

	// Import summaries (bridge pulls). Carried here so a consumer never has to
	// re-query the database to learn what an import is about to write. Total is
	// what will cross; Matched is what the listener holds before the -n budget.
	Source  string `json:"source,omitempty"`
	Matched int64  `json:"matched,omitempty"`
}

// Pace is the effective speed of a scan or of one phase within it. It rides on
// scan.started so a consumer can assert what actually applied instead of
// inferring it from the flags it passed — the flags and the resolved values are
// not the same thing (an unset --rate-limit resolves to the documented default,
// a phase override replaces it, and a strategy can narrow both).
type Pace struct {
	RateLimit   int `json:"rate_limit"`
	Concurrency int `json:"concurrency"`
	MaxPerHost  int `json:"max_per_host"`
}

// Emitter writes events. The nil Emitter is a valid no-op emitter, so every call
// site can hold a possibly-nil *Emitter and call methods on it unguarded — the
// stream being off is the common case and must not need an `if` at each site.
type Emitter struct {
	mu       sync.Mutex
	w        io.Writer
	enc      *json.Encoder
	scanUUID string
	closed   bool
	seq      uint64
	// err keeps the FIRST write failure. The emitter latches shut on one (a
	// consumer that went away must not cost a syscall per event for the rest of
	// the run) and never propagates it, so without this the failure left no
	// trace anywhere — a scan whose entire stream went to a closed pipe looked,
	// from the outside, exactly like a scan that emitted nothing.
	err error
	// terminalOnce guards the single terminal scan.finished, which several paths
	// race to write: the normal return, the signal handler, and a panic recovery
	// can all reach it. A stream with two terminal events is worse than one with
	// none — a consumer that stops at the first is fine, but one that tallies
	// them reports a scan that finished twice.
	//
	// Per EMITTER, not per process: a process can run several scans (the -P 1
	// multi-target loop calls executeNativeScan once per line, and the server
	// runs one per request), and a package-level latch would let only the first
	// of them ever emit a terminal event.
	terminalOnce sync.Once
}

// Format names accepted by --events. Only NDJSON exists today; the flag takes a
// value rather than being a bare bool so a second encoding can be added without
// a second flag.
const FormatNDJSON = "ndjson"

// ParseFormat validates an --events value. An empty value means "no stream".
func ParseFormat(value string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	switch v {
	case "":
		return "", nil
	case FormatNDJSON, "jsonl", "json":
		return FormatNDJSON, nil
	default:
		return "", fmt.Errorf("invalid --events %q (want: %s)", value, FormatNDJSON)
	}
}

// New returns an Emitter writing NDJSON to w. Pass a nil writer (or use the nil
// *Emitter) for a disabled stream.
func New(w io.Writer, scanUUID string) *Emitter {
	if w == nil {
		return nil
	}
	enc := json.NewEncoder(w)
	// Payloads carry URLs and evidence full of &, < and >; Go's default HTML
	// escaping would mangle them into & and make the stream harder to read
	// and to diff against what the scan actually sent.
	enc.SetEscapeHTML(false)
	return &Emitter{w: w, enc: enc, scanUUID: scanUUID}
}

// NewStdout returns an Emitter on os.Stdout, the only destination the flag
// offers: the human render owns stderr, so the machine stream owns stdout.
func NewStdout(scanUUID string) *Emitter { return New(os.Stdout, scanUUID) }

// Enabled reports whether events are actually being written.
func (e *Emitter) Enabled() bool { return e != nil && e.w != nil }

// ScanUUID returns the uuid stamped on every event this emitter writes. Fixed at
// construction: the scan uuid is pinned before the stream is opened, so there is
// nothing to backfill.
func (e *Emitter) ScanUUID() string {
	if !e.Enabled() {
		return ""
	}
	return e.scanUUID
}

// Finish emits the terminal scan.finished event exactly once for this emitter,
// then latches it shut. Subsequent calls are dropped.
func (e *Emitter) Finish(ev Event) {
	if !e.Enabled() {
		return
	}
	e.terminalOnce.Do(func() {
		ev.Type = TypeScanFinished
		e.Emit(ev)
		e.Close()
	})
}

// Emit writes one event. The caller supplies the type and payload; v, ts and
// scan_uuid are stamped here so no call site can forget them.
func (e *Emitter) Emit(ev Event) {
	if !e.Enabled() {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	ev.V = SchemaVersion
	ev.TS = time.Now().UTC().Format(TimestampLayout)
	e.seq++
	ev.Seq = e.seq
	if ev.ScanUUID == "" {
		ev.ScanUUID = e.scanUUID
	}
	// A write failure is a closed pipe in practice (the consumer went away).
	// Latch closed so the rest of the scan does not spend a syscall per event
	// discovering the same thing, and never propagate it: a scan does not fail
	// because nobody was listening.
	// One Encode is one Write, and os.Stdout is unbuffered — so "one line, one
	// flush" holds without any explicit flush. It used to call Sync() here, which
	// on darwin is F_FULLFSYNC: a full storage barrier per finding and per
	// progress tick, taken while holding this mutex, on a stream whose whole
	// point is to be cheap enough to emit continuously.
	if err := e.enc.Encode(&ev); err != nil {
		e.closed = true
		if e.err == nil {
			e.err = err
		}
	}
}

// Err returns the first write failure, or nil. A non-nil result means the
// stream is incomplete: everything from that event on was dropped. The scan
// itself is unaffected — nobody listening is not a scanning failure — so this is
// for the caller that wants to SAY so rather than for one that wants to fail.
func (e *Emitter) Err() error {
	if !e.Enabled() {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

// Close latches the emitter shut. Idempotent; safe on a nil Emitter.
func (e *Emitter) Close() {
	if !e.Enabled() {
		return
	}
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
}

// TimestampLayout is the wire format for every timestamp vigolium emits in
// machine-readable output: RFC3339 with exactly three fractional digits.
//
// Three, not Go's default variable count, because a consumer comparing a
// vigolium timestamp against a millisecond-precision clock (JS toISOString) does
// it lexically, and "…785113Z" sorts BEFORE "…785Z". Microsecond precision is
// not extra information to such a consumer, it is a broken comparison. See
// scanevents.FormatTime, which is the one place this is applied.
const TimestampLayout = "2006-01-02T15:04:05.000Z"

// FormatTime renders t in the wire format. Always UTC: a machine stream that
// mixes offsets forces every consumer to parse before it can compare.
func FormatTime(t time.Time) string { return t.UTC().Format(TimestampLayout) }

// EpochMillis renders t as epoch milliseconds — the numeric sibling of
// FormatTime, for consumers that would rather compare integers than strings.
func EpochMillis(t time.Time) int64 { return t.UTC().UnixMilli() }

// Int64 is a helper for the *int64 progress counters, so a call site can write
// scanevents.Int64(n) instead of taking the address of a temporary.
func Int64(v int64) *int64 { return &v }
