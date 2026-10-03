package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

// A failed -j command used to print `✖ Error: …` to stderr and nothing at all to
// stdout. For a machine consumer that is two failures for the price of one: the
// read failed, and then the JSON parse failed for an unrelated reason, leaving
// the actual cause to be scraped out of human prose. A parseable error object is
// still an error — the exit code carries that — but it is one the caller can act
// on instead of guess at.
//
// The shape deliberately mirrors agentEnvelope's spine (schema_version, command,
// generated_at) so one parser reads both, with `error` present only on failure.
type agentErrorEnvelope struct {
	SchemaVersion int        `json:"schema_version"`
	Command       string     `json:"command"`
	OK            bool       `json:"ok"`
	Error         agentError `json:"error"`
	DBPath        string     `json:"db_path,omitempty"`
	// SoftFail states that --soft-fail suppressed the exit code. Without it a
	// consumer reading exit_code: 2 alongside a process that exited 0 has no way
	// to tell which number is the truth. Both are: exit_code is what the command
	// concluded, the process status is what the caller asked to be told.
	SoftFail      bool   `json:"soft_fail,omitempty"`
	GeneratedAt   string `json:"generated_at"`
	GeneratedAtMS int64  `json:"generated_at_ms"`
}

type agentError struct {
	// Code is the stable, machine-branchable classification. Message is for a
	// human reading the log; never branch on it.
	Code     string `json:"code"`
	Message  string `json:"message"`
	ExitCode int    `json:"exit_code"`
}

// Stable error codes. These are a closed set: add to it rather than re-wording
// an existing value, because a consumer branches on these strings.
const (
	errCodeUsage = "usage_error"
	// errCodeSourceMissing: the path does not exist.
	errCodeSourceMissing = "source_missing"
	// errCodeSourceUnreadable: the file exists but is not openable as a database
	// — not SQLite at all, or corrupt.
	errCodeSourceUnreadable = "source_unreadable"
	// errCodeSourceIncompatible: a perfectly good SQLite file that is not a
	// vigolium store. It opens, it passes an integrity check, and every read
	// against it fails on a missing table.
	//
	// It has its own code because the three states it used to share with
	// errCodeFailed are decisions a caller makes differently: an empty store
	// ("nothing scanned this yet") means go scan; a zero-byte or foreign file
	// means the path is wrong; a genuine query failure means the read itself
	// broke. Collapsing them is how a scratch database that was never a vigolium
	// store gets reported as a target with no traffic.
	errCodeSourceIncompatible = "source_incompatible"
	errCodeGateTripped        = "gate_tripped"
	errCodeFailed             = "failed"

	// Single-message extraction (traffic body / traffic headers). These name the
	// states that `db export --format fs` used to collapse into an empty file or a
	// generic failure — which is how a mistyped UUID, a request stored without a
	// response, and a genuinely empty body all became the same answer.
	//
	// errCodeRecordNotFound: no record carries the given UUID.
	errCodeRecordNotFound = "record_not_found"
	// errCodeBodyUnavailable: the record exists, but the requested side was never
	// captured. Distinct from a captured body of zero length, which SUCCEEDS and
	// reports empty: true.
	errCodeBodyUnavailable = "body_unavailable"
	// errCodeBodyDecodeFailed: the body announces an encoding that could not be
	// undone. Never silently downgraded to the stored bytes: a caller who asked
	// for `decoded` and received compressed bytes writes a broken artifact.
	errCodeBodyDecodeFailed = "body_decode_failed"
	// errCodeBodyIncomplete: only a prefix of the body is available (the decoder
	// hit its ceiling). Requires --allow-incomplete to extract anyway.
	errCodeBodyIncomplete = "body_incomplete"
	// errCodeExportFailed: the work ran, but a requested artifact was not written
	// — an unwritable destination, a failed query mid-stream, a VACUUM that could
	// not complete. Distinct from a failure of the scan itself: the findings may
	// well exist, they just did not reach the file the caller asked for, and a
	// driver's correct response is to retry the export rather than the scan.
	errCodeExportFailed = "export_failed"
	// errCodeIngestIncomplete: the ingest ran, but not every record it read
	// reached the database — a write the store refused, or a request with no
	// response to store. Distinct from a generic failure because the caller's
	// remedy is about the records, not the command: re-ingest the capture, or
	// check that the origins it replays against are still reachable. It exists
	// because the alternative was the shape it replaces — "30 records ingested",
	// exit 0, zero rows in the table.
	errCodeIngestIncomplete = "ingest_incomplete"
	// errCodeOutputTooLarge: --max-output-bytes is smaller than the result
	// document's fixed parts, so not even a zero-item page fits. Distinct from
	// a usage error because the flag value is well formed and the command ran
	// — the caller's remedy is a larger budget or a narrower projection, not a
	// corrected command line.
	errCodeOutputTooLarge = "output_too_large"
)

// codedError carries a stable error code alongside its message, for conditions
// the classifier cannot infer from an exit code or a wrapped sentinel.
//
// The alternative was matching on message text, which this file already rejects
// for OS and Postgres strings and should reject for its own: a code a consumer
// branches on must not depend on how the sentence around it is worded.
type codedError struct {
	code string
	err  error
}

func (c codedError) Error() string { return c.err.Error() }
func (c codedError) Unwrap() error { return c.err }
func (c codedError) Code() string  { return c.code }

// codedErrorf builds an error that reports the given stable code.
func codedErrorf(code, format string, args ...any) error {
	return codedError{code: code, err: fmt.Errorf(format, args...)}
}

// classifyErrorCode maps an error to its stable code. The source cases are
// matched on message content because the database layer wraps driver errors as
// plain text; a miss degrades to errCodeFailed, never to a wrong success.
func classifyErrorCode(err error, exitCode int) string {
	switch exitCode {
	case ExitUsageError:
		return errCodeUsage
	case ExitFailOnGate:
		return errCodeGateTripped
	}
	// An explicitly coded error outranks every inference below: the call site
	// knew exactly which condition this was.
	var coded codedError
	if errors.As(err, &coded) {
		return coded.Code()
	}
	// The shared opener's refusals are typed for the same reason, and are matched
	// by identity rather than by the "no such table" text below — it never reaches
	// the query layer, because the open is what was refused.
	var incompatible *clicommon.SourceIncompatibleError
	if errors.As(err, &incompatible) {
		return errCodeSourceIncompatible
	}
	// exitCode already came from classifyExitCode, which owns the usageError
	// classification — re-deriving it here would be a second copy of that rule.
	//
	// The missing-source case uses the stdlib sentinel rather than a substring:
	// every path that produces it wraps with %w (openSQLiteReadOnly wraps
	// os.Stat, statelessSourceError and clicommon.GetDB wrap onward), and
	// "no such file or directory" is an OS strerror string that is neither
	// locale- nor platform-stable.
	if errors.Is(err, os.ErrNotExist) {
		return errCodeSourceMissing
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "failed to connect to database"),
		strings.Contains(msg, "not a database"),
		strings.Contains(msg, "readonly database"):
		return errCodeSourceUnreadable
	// A missing table is matched on message text for the same reason the cases
	// above are, but with a firmer guarantee: unlike an OS strerror string, "no
	// such table" is SQLite's OWN error text, fixed in its source and identical
	// on every platform and locale.
	//
	// Postgres is matched on its SQLSTATE (42P01 = undefined_table), which
	// pgdriver renders into the error string. Deliberately NOT on the prose:
	// Postgres message text is translated per `lc_messages`, so matching
	// "relation … does not exist" would be exactly the locale-unstable string the
	// paragraph above rejects — a closed code set with a branch that silently
	// stops firing on a non-English server.
	case strings.Contains(msg, "no such table"),
		strings.Contains(msg, "42p01"):
		return errCodeSourceIncompatible
	}
	return errCodeFailed
}

// emitJSONError writes the structured error to stdout when the caller asked for
// JSON. It is a no-op otherwise, so the human path is byte-for-byte unchanged.
func emitJSONError(err error, exitCode int, cmd *cobra.Command) {
	if !globalJSON || err == nil {
		return
	}
	// One document per invocation. A gate trip, a --fail-on-match hit, or a
	// failure partway through a write all arrive here with a complete result
	// already on stdout; appending a second top-level object to it produces a
	// stream no single json.Unmarshal can read. The exit code reports the
	// outcome in those cases.
	//
	// The exception is --watch, where stdout is already NDJSON (jsonStreamFramed):
	// one more line is the frame, not a violation of it, and a stream that ends
	// because the read broke should say why on the stream. Encode compactly so
	// the error occupies exactly one line like every tick before it.
	if jsonResultEmitted && !jsonStreamFramed {
		return
	}
	if jsonStreamFramed {
		prev := jsonStreamMode
		jsonStreamMode = true
		defer func() { jsonStreamMode = prev }()
	}
	name := "vigolium"
	if cmd != nil {
		name = commandPathWithoutRoot(cmd)
	}
	now := time.Now()
	env := agentErrorEnvelope{
		SchemaVersion: AgentSchemaVersion,
		Command:       name,
		OK:            false,
		Error: agentError{
			Code:     classifyErrorCode(err, exitCode),
			Message:  err.Error(),
			ExitCode: exitCode,
		},
		DBPath:        resolvedReadDBPath(),
		SoftFail:      globalSoftFail,
		GeneratedAt:   agentTimestamp(now),
		GeneratedAtMS: scanevents.EpochMillis(now),
	}
	// Straight to stdout, deliberately NOT through writeAgentJSON: -o/--output
	// redirects the RESULT document, and an error is not one. Routing it there
	// would write the failure into the file the caller expected results in, and
	// leave stdout carrying a receipt for it.
	_ = writeAgentJSONToStdout(env)
}
