package cli

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

func marshalEnvelope(t *testing.T, env *agentEnvelope) map[string]any {
	t.Helper()
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, raw)
	}
	return got
}

func TestEnvelopeCarriesSchemaVersionAndItems(t *testing.T) {
	// The whole point: one parser for every -j command. `items` is canonical and
	// `schema_version` is the number a consumer gates on.
	got := marshalEnvelope(t, newAgentEnvelope("traffic", "records", []string{"a"}, 1, 0, 100))
	if got["schema_version"] != float64(AgentSchemaVersion) {
		t.Errorf("schema_version = %v", got["schema_version"])
	}
	if got["command"] != "traffic" {
		t.Errorf("command = %v", got["command"])
	}
	if _, ok := got["items"]; !ok {
		t.Error("items missing")
	}
}

// withLegacyKeys turns the deprecated row alias on for one test, and pins the
// env var off so an operator's exported VIGOLIUM_JSON_LEGACY_KEYS cannot decide
// what these assertions see.
func withLegacyKeys(t *testing.T, on bool) {
	t.Helper()
	t.Setenv(jsonLegacyKeysEnv, "")
	prev := globalJSONLegacyKeys
	globalJSONLegacyKeys = on
	t.Cleanup(func() { globalJSONLegacyKeys = prev })
}

func TestEnvelopeOmitsLegacyKeyByDefault(t *testing.T) {
	// `items` is the contract. The pre-envelope alias costs a second copy of
	// every row on the wire, so it is off unless a migrating caller asks.
	withLegacyKeys(t, false)
	got := marshalEnvelope(t, newAgentEnvelope("traffic", "records", []string{"a"}, 1, 0, 100))
	if _, ok := got["items"]; !ok {
		t.Error("items missing")
	}
	if _, ok := got["records"]; ok {
		t.Error("legacy alias `records` emitted by default")
	}
}

func TestEnvelopeKeepsLegacyKeyAsAliasWhenRequested(t *testing.T) {
	// The migration window: --json-legacy-keys restores the old name, pointing at
	// the same content.
	withLegacyKeys(t, true)
	got := marshalEnvelope(t, newAgentEnvelope("traffic", "records", []string{"a"}, 1, 0, 100))
	items, _ := json.Marshal(got["items"])
	legacy, _ := json.Marshal(got["records"])
	if string(items) != string(legacy) {
		t.Errorf("legacy alias diverges: items=%s records=%s", items, legacy)
	}
}

func TestJSONLegacyKeysEnvOptsIn(t *testing.T) {
	// A wrapper that cannot edit its argv gets the same switch, resolved once as
	// the flag's default. An unparseable value reads as off rather than failing
	// the command over the spelling of a deprecation switch.
	for _, tc := range []struct {
		raw  string
		want bool
	}{{"", false}, {"1", true}, {"true", true}, {"0", false}, {"nonsense", false}} {
		t.Setenv(jsonLegacyKeysEnv, tc.raw)
		if got := envBool(jsonLegacyKeysEnv); got != tc.want {
			t.Errorf("%s=%q: envBool = %v, want %v", jsonLegacyKeysEnv, tc.raw, got, tc.want)
		}
	}
}

func TestEnvelopeStructFieldsWinOverExtra(t *testing.T) {
	// An alias that shadowed `items` or `total` would reintroduce exactly the
	// ambiguity the envelope removes.
	env := newAgentEnvelope("finding", "findings", []string{"real"}, 7, 0, 10)
	env.With("total", 999).With("items", []string{"fake"})
	got := marshalEnvelope(t, env)
	if got["total"] != float64(7) {
		t.Errorf("total = %v, want 7 (struct field must win)", got["total"])
	}
	items, _ := json.Marshal(got["items"])
	if string(items) != `["real"]` {
		t.Errorf("items = %s, want the struct value", items)
	}
}

func TestEnvelopeZeroTotalIsPresent(t *testing.T) {
	// "0 results" and "the field is missing" are different facts; a consumer
	// distinguishing an empty match from a broken query needs the former.
	got := marshalEnvelope(t, newAgentEnvelope("finding", "findings", []string{}, 0, 0, 100))
	if _, ok := got["total"]; !ok {
		t.Error("total dropped when zero")
	}
}

func TestEnvelopeTimestampPrecision(t *testing.T) {
	got := marshalEnvelope(t, newAgentEnvelope("traffic", "records", nil, 0, 0, 0))
	ts, _ := got["generated_at"].(string)
	if ts == "" {
		t.Fatal("generated_at missing")
	}
	dot := strings.IndexByte(ts, '.')
	if dot < 0 || len(ts)-dot-2 != 3 {
		t.Errorf("generated_at = %q, want exactly 3 fractional digits", ts)
	}
	if got["generated_at_ms"] == nil {
		t.Error("generated_at_ms missing — the numeric sibling is always present")
	}
}

func TestAgentTimestampZeroTimeIsEmpty(t *testing.T) {
	// A zero time is "not set", not 1970; emitting the epoch would make a missing
	// value look like a real one from 56 years ago.
	if got := agentTimestamp(time.Time{}); got != "" {
		t.Errorf("agentTimestamp(zero) = %q, want empty", got)
	}
}

func TestEnvelopeEncodesRowsOnce(t *testing.T) {
	// The default payload carries each row exactly once. It used to carry them
	// twice — `items` plus the deprecated alias — which on a measured 20-record
	// compact traffic read was 19,983 bytes against 7,884 of actual rows, paid on
	// every call by the token-metered consumer this contract exists for.
	withLegacyKeys(t, false)
	rows := []string{"aaaaaaaaaa", "bbbbbbbbbb"}
	raw, err := json.Marshal(newAgentEnvelope("traffic", "records", rows, 2, 0, 100))
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(raw, []byte("aaaaaaaaaa")); n != 1 {
		t.Errorf("row appears %d times, want 1 (items only): %s", n, raw)
	}

	// Opting back in is what costs the second copy, and it must cost only that.
	withLegacyKeys(t, true)
	rawLegacy, err := json.Marshal(newAgentEnvelope("traffic", "records", rows, 2, 0, 100))
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(rawLegacy, []byte("aaaaaaaaaa")); n != 2 {
		t.Errorf("with --json-legacy-keys row appears %d times, want 2", n)
	}
}

func TestAgentTimestampMatchesEventStream(t *testing.T) {
	// The -j envelope and the --events stream must render the same instant
	// identically, or a consumer correlating the two has to parse both.
	when := time.Date(2026, 9, 4, 1, 2, 3, 456789000, time.UTC)
	if agentTimestamp(when) != "2026-09-04T01:02:03.456Z" {
		t.Errorf("agentTimestamp = %q", agentTimestamp(when))
	}
}

func TestEnvelopeQueryIsOmittedWhenEmpty(t *testing.T) {
	got := marshalEnvelope(t, newAgentEnvelope("traffic", "records", nil, 0, 0, 0))
	if _, ok := got["query"]; ok {
		t.Error("query present but empty — omitempty should drop it")
	}
	// WithQuery takes argv, not a hand-written string: the read context
	// (--db/--stateless/--project) is prepended for us. With no context set,
	// that leaves just the command.
	resetReadContext(t)
	env := newAgentEnvelope("traffic", "records", nil, 0, 0, 0).WithQuery("replay", "-u", "x")
	if marshalEnvelope(t, env)["query"] != "vigolium replay -u x" {
		t.Errorf("query not carried, got %v", marshalEnvelope(t, env)["query"])
	}
}

func TestEnvelopeDoesNotEscapeHTML(t *testing.T) {
	env := newAgentEnvelope("traffic", "records", []string{"https://x/?a=1&b=<2>"}, 1, 0, 1)
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	for _, escape := range []string{`&`, `<`, `>`} {
		if strings.Contains(string(raw), escape) {
			t.Errorf("escaped %s: %s", escape, raw)
		}
	}
}

// query is shell-quoted for a human to read; query_argv is the same command as
// a vector, so a consumer that wants to RUN it does not have to re-split a
// string whose quoting was the point.
func TestEnvelopeQueryArgv(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBPath("/engagements/db with space.sqlite")

	env := newAgentEnvelope("finding", "findings", []any{}, 0, 0, 10)
	env.WithQuery("finding", "--id", "5", "--json")
	got := marshalEnvelope(t, env)

	rawArgv, ok := got["query_argv"].([]any)
	if !ok {
		t.Fatalf("query_argv missing or not an array: %#v", got["query_argv"])
	}
	argv := make([]string, len(rawArgv))
	for i, v := range rawArgv {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("query_argv[%d] is not a string: %#v", i, v)
		}
		argv[i] = s
	}
	if argv[0] != "vigolium" {
		t.Errorf("query_argv must start with the binary name, got %v", argv)
	}
	// The unquoted path is what exec needs; the display string quotes it.
	if !slices.Contains(argv, "/engagements/db with space.sqlite") {
		t.Errorf("query_argv must carry the raw path, got %v", argv)
	}
	query, _ := got["query"].(string)
	if !strings.Contains(query, "'/engagements/db with space.sqlite'") {
		t.Errorf("query must stay shell-quoted, got %q", query)
	}
	if got, want := strings.Join(argv, " "), followUpQuery("finding", "--id", "5", "--json"); want == got {
		t.Errorf("the two forms must differ in quoting for a path with a space: %q", got)
	}
}

// Both forms are absent together: a consumer finding one but not the other has
// to guess whether the read is reproducible.
func TestEnvelopeQueryArgvAbsentWithQuery(t *testing.T) {
	resetReadContext(t)
	globalGlobDB = "/scans/*.sqlite"

	env := newAgentEnvelope("finding", "findings", []any{}, 0, 0, 10)
	env.WithQuery("finding", "--id", "5")
	got := marshalEnvelope(t, env)

	if _, ok := got["query"]; ok {
		t.Error("an unreproducible read must omit query")
	}
	if _, ok := got["query_argv"]; ok {
		t.Error("an unreproducible read must omit query_argv")
	}
}
