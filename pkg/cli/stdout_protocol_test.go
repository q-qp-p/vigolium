package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// withStdoutProtocolGlobals clears the print-mode globals validateStdoutProtocol
// reads, and restores them afterwards. pflag owns them for the process.
func withStdoutProtocolGlobals(t *testing.T) {
	t.Helper()
	prevFinding, prevTraffic, prevTree := scanPrintFinding, scanPrintTraffic, scanPrintTrafficTree
	prevJSON, prevCI := globalJSON, globalCIOutput
	t.Cleanup(func() {
		scanPrintFinding, scanPrintTraffic, scanPrintTrafficTree = prevFinding, prevTraffic, prevTree
		globalJSON, globalCIOutput = prevJSON, prevCI
	})
	scanPrintFinding, scanPrintTraffic, scanPrintTrafficTree = false, false, false
	globalJSON, globalCIOutput = false, false
}

// --events owns stdout. Every other writer listed here would interleave with it
// into a stream that is not what either contract describes, and nothing used to
// detect the combination: the output was corrupt and the exit code was 0.
func TestValidateStdoutProtocol(t *testing.T) {
	withStdoutProtocolGlobals(t)

	eventsOpts := func() *types.Options {
		o := types.DefaultOptions()
		o.Events = "ndjson"
		return o
	}

	t.Run("no events is always fine", func(t *testing.T) {
		o := types.DefaultOptions()
		o.CIOutput = true
		o.OutputFormats = []string{"jsonl"}
		scanPrintFinding = true
		t.Cleanup(func() { scanPrintFinding = false })
		assert.NoError(t, validateStdoutProtocol(o),
			"the rule is one-way: these combinations are only a conflict once --events is asked for")
	})

	t.Run("events alone is fine", func(t *testing.T) {
		assert.NoError(t, validateStdoutProtocol(eventsOpts()))
	})

	t.Run("events + ci-output is a usage error", func(t *testing.T) {
		o := eventsOpts()
		o.CIOutput = true
		err := validateStdoutProtocol(o)
		require.Error(t, err)
		assert.Equal(t, ExitUsageError, classifyExitCode(err), "a rejected combination is exit 2")
		assert.Contains(t, err.Error(), "--ci-output-format", "the message must name the conflict")
	})

	t.Run("events + stdout jsonl is a usage error", func(t *testing.T) {
		o := eventsOpts()
		o.OutputFormats = []string{"jsonl"}
		err := validateStdoutProtocol(o)
		require.Error(t, err)
		assert.Equal(t, ExitUsageError, classifyExitCode(err))
		assert.Contains(t, err.Error(), "-o", "the message must name the fix")
	})

	t.Run("events + jsonl with -o is fine", func(t *testing.T) {
		o := eventsOpts()
		o.OutputFormats = []string{"jsonl"}
		o.Output = "run.jsonl"
		assert.NoError(t, validateStdoutProtocol(o),
			"jsonl with a destination goes to the file, so there is no collision")
	})

	for name, set := range map[string]func(){
		"--print-finding":      func() { scanPrintFinding = true },
		"--print-traffic":      func() { scanPrintTraffic = true },
		"--print-traffic-tree": func() { scanPrintTrafficTree = true },
	} {
		t.Run("events + "+name+" is a usage error", func(t *testing.T) {
			withStdoutProtocolGlobals(t)
			set()
			err := validateStdoutProtocol(eventsOpts())
			require.Error(t, err)
			assert.Equal(t, ExitUsageError, classifyExitCode(err))
			assert.Contains(t, err.Error(), name)
		})
	}

	t.Run("nil options", func(t *testing.T) {
		assert.NoError(t, validateStdoutProtocol(nil))
	})
}

// --json on the scan path becomes jsonl via reconcileOutputFormats, which is
// what makes `scan --events --json` the same collision as the explicit form.
// Checking before that mapping would miss it, so the call site order matters.
func TestValidateStdoutProtocolCatchesJSONMappedToJSONL(t *testing.T) {
	withStdoutProtocolGlobals(t)

	o := types.DefaultOptions()
	o.Events = "ndjson"
	// What `vigolium scan -j --events ndjson` arrives with: the default console
	// format and nothing else.
	o.OutputFormats = []string{"console"}
	globalJSON = true
	require.NoError(t, reconcileOutputFormats(o))
	require.True(t, o.HasFormat("jsonl"), "reconcileOutputFormats maps --json to jsonl")

	err := validateStdoutProtocol(o)
	require.Error(t, err, "--events --json streams two different object shapes to stdout")
	assert.Equal(t, ExitUsageError, classifyExitCode(err))
}

// --events must reach the Runner, which is the only thing that emits it.
func TestBuildPhaseOptionsCopiesEvents(t *testing.T) {
	resetLightweightIOGlobals()
	t.Cleanup(resetLightweightIOGlobals)

	scanOpts.Events = "ndjson"
	opts, err := buildPhaseOptions("http://events.example/")
	require.NoError(t, err)
	assert.Equal(t, "ndjson", opts.Events,
		"the flag parsed, validated, and then described nothing because the Runner got an empty Events path")
}

// A Ctrl-C partway through a multi-target run used to leave the caller with
// results for the targets that finished and no statement at all about the rest,
// which reads identically to a run that scanned them and found nothing.
func TestScanInputsStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inputs := []scanInput{
		{target: "http://a.example/", method: "GET"},
		{target: "http://b.example/", method: "GET"},
		{target: "http://c.example/", method: "GET"},
	}

	var calls atomic.Int64
	results, notScanned, err := scanInputs(ctx, inputs, func(_ context.Context, in scanInput) (*scanResult, error) {
		calls.Add(1)
		cancel() // the operator's Ctrl-C lands during the first target
		return &scanResult{Target: in.target}, nil
	})

	assert.NoError(t, err)
	require.EqualValues(t, 1, calls.Load(), "dispatch must stop, not merely mark the rest")
	require.Len(t, results, 1)
	assert.Equal(t, "http://a.example/", results[0].Target)
	assert.Equal(t, []string{"http://b.example/", "http://c.example/"}, notScanned,
		"the targets that were never scanned must be named, not silently absent")
}

// A per-input error does not stop the batch: the remaining targets are
// independent, and the caller asked for all of them.
func TestScanInputsContinuesPastAFailure(t *testing.T) {
	inputs := []scanInput{{target: "a"}, {target: "b"}}
	boom := errors.New("executor failed")

	results, notScanned, err := scanInputs(context.Background(), inputs,
		func(_ context.Context, in scanInput) (*scanResult, error) {
			if in.target == "a" {
				return nil, boom
			}
			return &scanResult{Target: in.target}, nil
		})

	require.ErrorIs(t, err, boom, "the failure must still reach the exit code")
	require.Len(t, results, 1, "the target that did scan must still be reported")
	assert.Equal(t, "b", results[0].Target)
	assert.Empty(t, notScanned)
}

// Several direct-path results must leave stdout holding ONE document. Two
// top-level objects are a stream json.Unmarshal rejects, and the documented
// contract does not allow it.
func TestDirectMultiInputSingleDocument(t *testing.T) {
	withMachineDocumentState(t)
	globalJSON = true

	cmd := &cobra.Command{Use: "scan-url"}
	root := &cobra.Command{Use: "vigolium"}
	root.AddCommand(cmd)

	results := []*scanResult{
		{Target: "http://a.example/", Method: "GET", Persisted: true},
		{Target: "http://b.example/", Method: "GET"},
	}

	var writeErr error
	out := captureStdout(t, func() {
		writeErr = writeDirectScanBatch(commandPathWithoutRoot(cmd), results, []string{"http://c.example/"})
	})
	require.NoError(t, writeErr)

	dec := json.NewDecoder(strings.NewReader(out))
	var env map[string]any
	require.NoError(t, dec.Decode(&env), "the batch document is not valid JSON:\n%s", out)

	var trailing map[string]any
	require.ErrorIs(t, dec.Decode(&trailing), io.EOF,
		"stdout carries more than one top-level document:\n%s", out)

	assert.Equal(t, "scan-url", env["command"])
	assert.EqualValues(t, 2, env["total"])
	items, ok := env["items"].([]any)
	require.True(t, ok, "items missing: %v", env)
	require.Len(t, items, 2)
	assert.Equal(t, []any{"http://c.example/"}, env["targets_not_scanned"])
}

// The key is an array even when nothing was skipped, so a consumer reading it to
// decide whether to re-run the remainder never has to special-case null.
func TestDirectMultiInputNotScannedIsAlwaysAnArray(t *testing.T) {
	withMachineDocumentState(t)
	globalJSON = true

	out := captureStdout(t, func() {
		require.NoError(t, writeDirectScanBatch("scan-url", []*scanResult{{Target: "a"}}, nil))
	})
	var env map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &env))
	assert.Equal(t, []any{}, env["targets_not_scanned"])
}

// directBatchJSON decides when the aggregation applies. The Runner path writes
// its own output and --ci-output-format is a line protocol, so neither qualifies.
func TestDirectBatchJSON(t *testing.T) {
	resetLightweightIOGlobals()
	t.Cleanup(resetLightweightIOGlobals)
	prevJSON, prevCI := globalJSON, globalCIOutput
	t.Cleanup(func() { globalJSON, globalCIOutput = prevJSON, prevCI })

	two := []scanInput{{target: "a"}, {target: "b"}}
	one := []scanInput{{target: "a"}}

	globalJSON, globalCIOutput = true, false
	assert.True(t, directBatchJSON(two))
	assert.False(t, directBatchJSON(one), "a single input keeps its existing document shape")

	globalCIOutput = true
	assert.False(t, directBatchJSON(two), "--ci-output-format is one finding per line, by design")
	globalCIOutput = false

	globalJSON = false
	assert.False(t, directBatchJSON(two), "the human renderer prints per target")

	globalJSON = true
	scanOpts.Output = "out.jsonl" // routes to the Runner
	assert.False(t, directBatchJSON(two), "the Runner path writes its own output")
}

// dispatchScanInputs must notice the interrupt between inputs: both the direct
// and the Runner path go through it, and only the direct path's executor sees
// the context itself.
func TestDispatchScanInputsStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Nothing is dispatched at all, so no network or database is touched: an
	// already-cancelled context means the operator stopped before this started.
	err := dispatchScanInputs(ctx, []scanInput{{rr: &httpmsg.HttpRequestResponse{}, target: "a"}})
	assert.NoError(t, err)
}
