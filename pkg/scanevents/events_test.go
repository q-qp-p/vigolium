package scanevents

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEmitStampsVersionTimestampAndUUID(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, "scan-1")
	e.Emit(Event{Type: TypePhaseStarted, Phase: "discovery"})

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("emitted line is not JSON: %v (%q)", err, buf.String())
	}
	if got["v"] != float64(SchemaVersion) {
		t.Errorf("v = %v, want %d", got["v"], SchemaVersion)
	}
	if got["scan_uuid"] != "scan-1" {
		t.Errorf("scan_uuid = %v, want scan-1", got["scan_uuid"])
	}
	// Every event must be attributable to its invocation; a sweep is several
	// `vigolium scan` calls and an unattributed event is unusable.
	if got["ts"] == nil {
		t.Error("ts missing")
	}
}

func TestEmitWritesOneLinePerEvent(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, "scan-1")
	e.Emit(Event{Type: TypePhaseStarted, Phase: "a"})
	e.Emit(Event{Type: TypePhaseFinished, Phase: "a"})

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), buf.String())
	}
	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Errorf("line %d is not valid JSON: %q", i, line)
		}
	}
}

func TestNilEmitterIsSafe(t *testing.T) {
	// Every call site holds a possibly-nil emitter and calls methods unguarded;
	// the stream being off is the common case and must not need an `if`.
	var e *Emitter
	e.Emit(Event{Type: TypeScanStarted})
	e.Finish(Event{Status: StatusCompleted})
	e.Close()
	if e.Enabled() {
		t.Error("nil emitter reports enabled")
	}
	if got := e.ScanUUID(); got != "" {
		t.Errorf("nil emitter ScanUUID = %q", got)
	}
}

func TestZeroProgressCountersSurvive(t *testing.T) {
	// "0 requests sent" is a meaningful reading — a phase that has started and
	// sent nothing — so the counters are pointers and must not be dropped by
	// omitempty.
	var buf bytes.Buffer
	New(&buf, "s").Emit(Event{
		Type:         TypePhaseProgress,
		Phase:        "discovery",
		RequestsSent: Int64(0),
	})
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["requests_sent"]; !ok {
		t.Errorf("requests_sent dropped when zero: %s", buf.String())
	}
}

func TestParseFormat(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"ndjson", FormatNDJSON, false},
		{"NDJSON", FormatNDJSON, false},
		{" jsonl ", FormatNDJSON, false},
		{"yaml", "", true},
	} {
		got, err := ParseFormat(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseFormat(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
		}
		if got != tc.want {
			t.Errorf("ParseFormat(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFormatTimeHasExactlyThreeFractionalDigits(t *testing.T) {
	// A consumer compares vigolium's timestamps against a millisecond clock
	// LEXICALLY, and "…785113Z" sorts before "…785Z". Microsecond precision is a
	// broken comparison, not extra information.
	ts := FormatTime(time.Date(2026, 9, 4, 10, 11, 12, 345678901, time.UTC))
	if ts != "2026-09-04T10:11:12.345Z" {
		t.Errorf("FormatTime = %q, want 2026-09-04T10:11:12.345Z", ts)
	}
	frac := ts[strings.IndexByte(ts, '.')+1 : len(ts)-1]
	if len(frac) != 3 {
		t.Errorf("fractional digits = %d, want 3 (%q)", len(frac), ts)
	}
}

func TestFormatTimeNormalizesToUTC(t *testing.T) {
	// A stream mixing offsets forces every consumer to parse before it can
	// compare, which defeats the lexical comparison the fixed precision exists
	// to enable.
	loc := time.FixedZone("test", 5*3600)
	ts := FormatTime(time.Date(2026, 9, 4, 15, 0, 0, 0, loc))
	if !strings.HasSuffix(ts, "Z") || !strings.HasPrefix(ts, "2026-09-04T10:00:00") {
		t.Errorf("FormatTime = %q, want the UTC instant with a Z suffix", ts)
	}
}

func TestFinishEmitsExactlyOncePerEmitter(t *testing.T) {
	// A stream with two terminal events is worse than one with none: a consumer
	// that stops at the first is fine, but one that tallies them reports a scan
	// that finished twice. The normal return, the signal handler and a panic
	// recovery all race to write it.
	var buf bytes.Buffer
	e := New(&buf, "s")
	e.Finish(Event{Status: StatusCompleted})
	e.Finish(Event{Status: StatusInterrupted})
	if n := strings.Count(buf.String(), TypeScanFinished); n != 1 {
		t.Errorf("scan.finished appeared %d times, want 1", n)
	}
}

func TestFinishLatchIsPerEmitterNotPerProcess(t *testing.T) {
	// One process can run several scans — the -P 1 multi-target loop calls the
	// scan path once per line, and the server once per request. A package-level
	// latch would let only the first of them emit a terminal event.
	var first, second bytes.Buffer
	New(&first, "scan-1").Finish(Event{Status: StatusCompleted})
	New(&second, "scan-2").Finish(Event{Status: StatusCompleted})
	for name, buf := range map[string]*bytes.Buffer{"first": &first, "second": &second} {
		if !strings.Contains(buf.String(), TypeScanFinished) {
			t.Errorf("%s emitter produced no terminal event", name)
		}
	}
}

func TestCloseStopsFurtherEmission(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, "s")
	e.Emit(Event{Type: TypeScanStarted})
	e.Close()
	before := buf.Len()
	e.Emit(Event{Type: TypeFindingNew})
	if buf.Len() != before {
		t.Error("emitted after Close")
	}
}

func TestEmitDoesNotEscapeHTML(t *testing.T) {
	// URLs and payload evidence are full of & < >; escaping them costs tokens and
	// makes a hand-read line harder to compare against what was actually sent.
	var buf bytes.Buffer
	New(&buf, "s").Emit(Event{Type: TypeFindingNew, URL: "https://x/?a=1&b=<2>"})
	for _, escape := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if strings.Contains(buf.String(), escape) {
			t.Errorf("HTML-escaped output contains %s: %s", escape, buf.String())
		}
	}
}

// syncWriter serialises concurrent writes the way os.Stdout does not, so the
// only ordering under test is the emitter's own.
type syncWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// TestEmitterSeqMonotonic: seq is the stream's own total order. ts has
// millisecond precision and a busy scan emits several events per millisecond,
// so a consumer that sorts by timestamp reorders them; a gap in seq is the only
// way to detect a line lost in transit.
func TestEmitterSeqMonotonic(t *testing.T) {
	w := &syncWriter{}
	e := New(w, "scan-seq")

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				e.Emit(Event{Type: TypePhaseProgress, Phase: "discovery"})
			}
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(w.buf.String()), "\n")
	if len(lines) != 3200 {
		t.Fatalf("got %d lines, want 3200", len(lines))
	}
	seen := make(map[uint64]bool, len(lines))
	prev := uint64(0)
	for i, line := range lines {
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line %d is not JSON: %v", i, err)
		}
		if ev.Seq <= prev {
			t.Fatalf("line %d has seq %d after %d — seq must increase in output order", i, ev.Seq, prev)
		}
		if seen[ev.Seq] {
			t.Fatalf("seq %d emitted twice", ev.Seq)
		}
		seen[ev.Seq] = true
		prev = ev.Seq
	}
	if prev != 3200 {
		t.Errorf("last seq is %d, want 3200 (seq starts at 1 and never skips)", prev)
	}
}

// failingWriter fails every write after the first n bytes.
type failingWriter struct {
	budget int
	err    error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.budget <= 0 {
		return 0, w.err
	}
	w.budget -= len(p)
	return len(p), nil
}

// TestEmitterErrRecorded: the emitter swallows write failures by design — a
// scan does not fail because nobody was listening — but swallowing them without
// a trace meant a run whose whole stream went to a closed pipe looked exactly
// like a run that emitted nothing.
func TestEmitterErrRecorded(t *testing.T) {
	want := errors.New("broken pipe")
	w := &failingWriter{budget: 10, err: want}
	e := New(w, "scan-err")

	if e.Err() != nil {
		t.Fatal("a fresh emitter has no error")
	}
	e.Emit(Event{Type: TypeScanStarted}) // consumes the budget
	e.Emit(Event{Type: TypePhaseStarted, Phase: "discovery"})

	if !errors.Is(e.Err(), want) {
		t.Fatalf("Err() = %v, want %v", e.Err(), want)
	}
	// Latched: the rest of the scan must not spend a syscall per event
	// rediscovering the same thing.
	e.Emit(Event{Type: TypePhaseFinished, Phase: "discovery"})
	if !errors.Is(e.Err(), want) {
		t.Error("the FIRST error is the one kept")
	}
}

// A disabled emitter is the common case; Err must be callable on it.
func TestEmitterErrOnDisabledEmitter(t *testing.T) {
	var e *Emitter
	if e.Err() != nil {
		t.Error("a nil emitter has no error")
	}
	if New(nil, "x").Err() != nil {
		t.Error("a disabled emitter has no error")
	}
}

// scan.interrupting is NONTERMINAL: it says a shutdown began, and the terminal
// scan.finished still follows. Finish must remain the only latch.
func TestInterruptingIsNotTerminal(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, "scan-int")
	e.Emit(Event{Type: TypeScanInterrupting, Message: "interrupt"})
	e.Finish(Event{Status: StatusInterrupted})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2:\n%s", len(lines), buf.String())
	}
	var last Event
	if err := json.Unmarshal([]byte(lines[1]), &last); err != nil {
		t.Fatalf("terminal line is not JSON: %v", err)
	}
	if last.Type != TypeScanFinished {
		t.Errorf("last line is %q, want %q — scan.interrupting must not latch the emitter",
			last.Type, TypeScanFinished)
	}
}
