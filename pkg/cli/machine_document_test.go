package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// The --json contract is "exactly one document on stdout". The tests here cover
// the three ways an invocation used to break it: a failed -o write that latched
// before publishing and so suppressed the error envelope; a --watch stream that
// ended with no line saying why; and an import that printed its success object
// before the report and the upload it was still going to attempt.

// withMachineDocumentState saves every package global these tests reach for.
// pflag owns them for the process, so a test that left one set would change a
// later test's output contract.
func withMachineDocumentState(t *testing.T) {
	t.Helper()
	prevPath, prevJSON, prevWatch := jsonOutputPath, globalJSON, globalWatchRaw
	prevEmitted, prevStream, prevFramed := jsonResultEmitted, jsonStreamMode, jsonStreamFramed
	prevSoftFail, prevGlob, prevDB := globalSoftFail, globalGlobDB, globalDB
	t.Cleanup(func() {
		jsonOutputPath, globalJSON, globalWatchRaw = prevPath, prevJSON, prevWatch
		jsonResultEmitted, jsonStreamMode, jsonStreamFramed = prevEmitted, prevStream, prevFramed
		globalSoftFail, globalGlobDB, globalDB = prevSoftFail, prevGlob, prevDB
	})
	jsonOutputPath, globalJSON, globalWatchRaw = "", false, ""
	jsonResultEmitted, jsonStreamMode, jsonStreamFramed = false, false, false
	globalSoftFail, globalGlobDB, globalDB = false, "", ""
}

// decodeStdoutDocuments splits captured stdout into top-level JSON documents,
// which is the only honest way to assert "exactly one": a byte comparison would
// pass for a stream of two objects, and a single Unmarshal would silently ignore
// trailing data.
func decodeStdoutDocuments(t *testing.T, out string) []map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(out))
	var docs []map[string]any
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return docs
		}
		require.NoErrorf(t, err, "stdout is not a sequence of JSON documents: %q", out)
		docs = append(docs, doc)
	}
}

func TestWriteAgentJSONFileFailureLeavesErrorEnvelope(t *testing.T) {
	withMachineDocumentState(t)
	// A directory that does not exist: atomicfile cannot create its temp file
	// there, so the write fails before anything reaches stdout.
	jsonOutputPath = filepath.Join(t.TempDir(), "absent", "result.json")
	globalJSON = true

	env := newAgentEnvelope("traffic", "records", []map[string]any{{"uuid": "a"}}, 1, 0, 100)

	var writeErr error
	out := captureStdout(t, func() { writeErr = writeAgentJSON(env) })

	require.Error(t, writeErr, "an unwritable -o destination must fail the command")
	require.Empty(t, out, "nothing was published, so stdout must be free for the error envelope")
	require.False(t, jsonResultEmitted,
		"the latch must only close after publication; closing it early suppressed the error envelope")

	// The root handler's job, done here explicitly: one error document on stdout.
	cmd := &cobra.Command{Use: "traffic"}
	root := &cobra.Command{Use: "vigolium"}
	root.AddCommand(cmd)
	errOut := captureStdout(t, func() { emitJSONError(writeErr, 1, cmd) })

	docs := decodeStdoutDocuments(t, errOut)
	require.Len(t, docs, 1)
	require.Equal(t, false, docs[0]["ok"])
	errObj, ok := docs[0]["error"].(map[string]any)
	require.True(t, ok, "error envelope has no error object: %v", docs[0])
	require.Equal(t, errCodeExportFailed, errObj["code"],
		"a failed -o write is a failed requested artifact, not a missing source")
	require.Contains(t, errObj["message"], "write ")
	require.Contains(t, errObj["message"], jsonOutputPath,
		"the message must name the destination that could not be written")
}

func TestWatchErrorFrameIsOneLine(t *testing.T) {
	withMachineDocumentState(t)
	globalJSON = true
	globalWatchRaw = "10ms"

	// First tick publishes a document; the second fails, which is what ends the
	// watch loop.
	calls := 0
	fnErr := errors.New("read broke mid-stream")
	var runErr error
	out := captureStdout(t, func() {
		runErr = runWithWatch(func() error {
			calls++
			if calls > 1 {
				return fnErr
			}
			return writeAgentJSONToStdout(newAgentEnvelope("db ls", "scans", []map[string]any{{"uuid": "a"}}, 1, 0, 100))
		})
		// The root handler runs after the loop has returned, with jsonStreamMode
		// already reset — jsonStreamFramed is what tells it the frame is NDJSON.
		emitJSONError(runErr, 1, nil)
	})

	require.Error(t, runErr)
	require.GreaterOrEqual(t, calls, 2, "the watch loop never re-ran")

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 2, "a watch stream is one compact document per line, got:\n%s", out)
	for i, line := range lines {
		require.Truef(t, json.Valid([]byte(line)), "line %d is not valid JSON: %q", i+1, line)
	}

	var last map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &last))
	require.Equal(t, false, last["ok"], "the stream must end with a line saying why it stopped")
	require.False(t, jsonStreamMode, "stream mode must not leak past the watch loop")
}

// A non-streamed invocation keeps the old rule: once a result is on stdout, the
// error is carried by the exit code alone.
func TestNonStreamedErrorStillSuppressedAfterResult(t *testing.T) {
	withMachineDocumentState(t)
	globalJSON = true

	out := captureStdout(t, func() {
		_ = writeAgentJSONToStdout(newAgentEnvelope("finding", "findings", []map[string]any{}, 0, 0, 100))
		emitJSONError(errors.New("gate tripped"), ExitFailOnGate, nil)
	})

	require.Len(t, decodeStdoutDocuments(t, out), 1,
		"a second top-level object turns a parseable document into an unreadable stream")
}

// newImportTestCmd builds a command carrying exactly the flags runImport reads
// through cmd.Flags(). Reusing the real importCmd would share pflag state with
// every other test in the package.
func newImportTestCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "import"}
	cmd.Flags().Bool("upload", false, "")
	cmd.Flags().String("upload-key", "", "")
	cmd.Flags().String("format", "", "")
	cmd.Flags().StringP("output", "o", "", "")
	cmd.Flags().String("report-title", "", "")
	cmd.Flags().String("report-target", "", "")
	cmd.Flags().String("report-duration", "", "")
	cmd.Flags().String("report-generated-at", "", "")
	cmd.Flags().String("report-url", "", "")
	cmd.Flags().String("severity", "", "")
	root := &cobra.Command{Use: "vigolium"}
	root.AddCommand(cmd)
	return cmd
}

// writeImportJSONL writes a one-finding JSONL source, the smallest input that
// produces a non-trivial import summary.
func writeImportJSONL(t *testing.T, dir string) string {
	t.Helper()
	src := filepath.Join(dir, "source.jsonl")
	line := `{"type":"finding","data":{"module_id":"mod-a","module_name":"Module A","severity":"high",` +
		`"confidence":"firm","finding_hash":"hash-a","url":"http://a.example/","hostname":"a.example"}}` + "\n"
	require.NoError(t, os.WriteFile(src, []byte(line), 0o600))
	return src
}

func TestImportJSONEmitsSingleDocumentAfterReport(t *testing.T) {
	withMachineDocumentState(t)
	withImportUploader := func(fn func(context.Context, string, string) (string, error)) {
		prev := uploadImportSource
		t.Cleanup(func() { uploadImportSource = prev })
		uploadImportSource = fn
	}

	dir := t.TempDir()
	src := writeImportJSONL(t, dir)
	globalJSON = true
	globalDB = filepath.Join(dir, "import.sqlite")
	resetDBCacheForTest()
	t.Cleanup(resetDBCacheForTest)

	t.Run("upload failure leaves no result document", func(t *testing.T) {
		jsonResultEmitted = false
		withImportUploader(func(context.Context, string, string) (string, error) {
			return "", errors.New("storage unavailable")
		})
		cmd := newImportTestCmd(t)
		require.NoError(t, cmd.Flags().Set("upload", "true"))

		var runErr error
		out := captureStdout(t, func() { runErr = runImport(cmd, []string{src}) })

		require.Error(t, runErr, "--upload failed, so the command failed")
		require.Empty(t, decodeStdoutDocuments(t, out),
			"the success object was printed before the upload it was still going to attempt")
		require.False(t, jsonResultEmitted, "the root handler must still be free to frame the failure")
	})

	t.Run("success carries report_path and uploaded_to", func(t *testing.T) {
		jsonResultEmitted = false
		resetDBCacheForTest()
		withImportUploader(func(_ context.Context, srcPath, _ string) (string, error) {
			return "gs://proj/imports/" + filepath.Base(srcPath), nil
		})
		cmd := newImportTestCmd(t)
		require.NoError(t, cmd.Flags().Set("upload", "true"))
		require.NoError(t, cmd.Flags().Set("format", "markdown"))
		report := filepath.Join(dir, "report.md")
		require.NoError(t, cmd.Flags().Set("output", report))

		var runErr error
		out := captureStdout(t, func() { runErr = runImport(cmd, []string{src}) })
		require.NoError(t, runErr)

		docs := decodeStdoutDocuments(t, out)
		require.Len(t, docs, 1, "import must emit exactly one document under -j")
		require.Equal(t, report, docs[0]["report_path"],
			"report_path must name the file the caller can open")
		uploaded, ok := docs[0]["uploaded_to"].([]any)
		require.True(t, ok, "uploaded_to missing: %v", docs[0])
		require.Len(t, uploaded, 1)
		require.Equal(t, "gs://proj/imports/source.jsonl", uploaded[0])
		// The import summary itself is still there — the new keys are additive.
		require.Contains(t, docs[0], "findings_total")

		_, statErr := os.Stat(report)
		require.NoError(t, statErr, "report_path names a file that was not written")
	})
}
