package cli

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"time"

	"github.com/vigolium/vigolium/pkg/scanevents"
)

// AgentSchemaVersion is the contract version of every -j/--json envelope. A
// consumer gates on it; it is bumped on any breaking field change.
//
// Its absence was the real problem. A driver could not write one parser, because
// different commands (and different vigolium versions) named the same thing
// differently — the row array was `data` or `records` or `traffic` or `results`
// or `http_records` depending on where you asked, and drift was discovered as a
// parse failure in production rather than as a version check at startup. There
// is now one shape, one canonical name per field, and a number to check.
const AgentSchemaVersion = 1

// agentEnvelope is the single JSON shape every -j command emits.
//
// `items` is canonical and is the only row array rendered by default. Each
// command still DECLARES its historical key (see legacyKey), but that alias is
// rendered only under --json-legacy-keys / $VIGOLIUM_JSON_LEGACY_KEYS — it
// duplicates the rows on the wire, which is the single largest avoidable cost in
// the read path. See json_legacy_keys.go.
type agentEnvelope struct {
	SchemaVersion int    `json:"schema_version"`
	Command       string `json:"command"`
	ProjectUUID   string `json:"project_uuid,omitempty"`
	// DBPath names the database this command actually opened. A consumer that
	// pins $VIGOLIUM_DB_PATH and passes --db can then ASSERT the store it read
	// rather than trusting that the pin survived a subprocess chain — the default
	// database is one shared file, so a silent fall-through to it reads every
	// target that ever landed there.
	DBPath string `json:"db_path,omitempty"`

	Total  int64 `json:"total"`
	Offset int   `json:"offset"`
	Limit  int   `json:"limit"`

	Items any `json:"items"`

	// Query is a ready-to-run follow-up command for the obvious next step. It is
	// the cheapest documentation in the surface: a paragraph of consumer guidance
	// that cannot go stale, because it is generated from the same values the
	// envelope reports.
	Query string `json:"query,omitempty"`

	// QueryArgv is the same follow-up as an argv vector. The string form is for
	// a human to read and is shell-quoted; a consumer that wants to RUN it had
	// to either shell out (inheriting the quoting rules of whatever shell it
	// found) or re-split a quoted string, which is where the quoting that made
	// the string safe becomes the thing that breaks the parse. The vector goes
	// straight into exec.
	QueryArgv []string `json:"query_argv,omitempty"`

	// GeneratedAt is stamped in the wire timestamp format (RFC3339, exactly three
	// fractional digits) with an epoch-millisecond sibling. See
	// agentTimestamp for why the precision is fixed.
	GeneratedAt   string `json:"generated_at,omitempty"`
	GeneratedAtMS int64  `json:"generated_at_ms,omitempty"`

	// extra carries command-specific fields. Marshaled by MarshalJSON into the
	// same object.
	extra map[string]any
	// legacyKey is the pre-envelope name this command used for its row array
	// ("records", "findings", …). Rendering it means encoding the rows a second
	// time into the same object, which doubles every -j payload — on a
	// `traffic -j -n 10000` that is tens of MB, and on any agent-driven read it is
	// a doubled token bill for a field deprecated on arrival. So it is emitted
	// only when jsonLegacyKeysEnabled() says a caller is still migrating.
	legacyKey string
}

// newAgentEnvelope builds the standard envelope. legacyKey is the pre-envelope
// name this command used for its row array ("records", "findings", "scans", …);
// pass "" for a command that had none.
func newAgentEnvelope(command, legacyKey string, items any, total int64, offset, limit int) *agentEnvelope {
	now := time.Now()
	env := &agentEnvelope{
		SchemaVersion: AgentSchemaVersion,
		Command:       command,
		Total:         total,
		Offset:        offset,
		Limit:         limit,
		Items:         items,
		// One clock read for both: they are two representations of the SAME
		// instant, and a schema whose selling point is that a consumer can compare
		// them must not ship a pair sampled a millisecond apart.
		GeneratedAt:   agentTimestamp(now),
		GeneratedAtMS: scanevents.EpochMillis(now),
		extra:         map[string]any{},
	}
	env.legacyKey = legacyKey
	return env
}

// WithProjectScope records the project filter that was ACTUALLY applied.
//
// The envelope used to fill project_uuid from resolveProjectUUID() regardless of
// the read mode, so a `-S` read — where scoping is off and the result spans
// every project in the file — still named one project. A consumer reading that
// field to confirm which engagement it was looking at was being told something
// untrue, which is the opposite of the assertion the envelope exists to support.
// project_scoped states whether a filter was applied at all, so "no project
// filter" is explicit rather than inferred from an absent field.
func (e *agentEnvelope) WithProjectScope(projectUUID string) *agentEnvelope {
	e.ProjectUUID = projectUUID
	return e.With("project_scoped", projectUUID != "")
}

// With attaches a command-specific field to the envelope.
func (e *agentEnvelope) With(key string, value any) *agentEnvelope {
	if e.extra == nil {
		e.extra = map[string]any{}
	}
	e.extra[key] = value
	return e
}

// WithQuery attaches the follow-up command, pinned to the read context.
//
// tail is the command and its own flags — WithQuery("finding", "--id", "5") —
// and followUpQuery prepends the --db/--stateless/--project flags that make the
// result reachable. It takes argv rather than a finished string on purpose: the
// old string form let a caller hand-write "vigolium finding --id 5 --json",
// which resolves that per-database autoincrement id in whatever store the next
// process happens to open. Every call site had that bug, and three survived the
// first sweep. With this signature they cannot.
//
// A read that cannot be reproduced (a --glob-db merge reads through a temporary
// database) yields "", and the field is omitted rather than pointing somewhere
// it does not lead.
func (e *agentEnvelope) WithQuery(tail ...string) *agentEnvelope {
	e.Query = followUpQuery(tail...)
	e.QueryArgv = followUpArgv(tail...)
	return e
}

// envelopeItemSlice reports whether v is a row-list envelope, and hands back the
// `items` slice by reflection.
//
// Reflection rather than a type switch over the two shapes the read commands
// happen to use today: the scan views are typed slices ([]scanRowView and
// friends), and a switch missing them called every paged scan listing complete.
// Anything that is not a slice (db stats emits an object) has no record
// boundary, which is the question both callers are really asking — resultIsPaged
// to describe a page, applyOutputBudget to find somewhere to cut. One rule, so
// the two cannot disagree about what counts as a row list.
func envelopeItemSlice(v any) (*agentEnvelope, reflect.Value, bool) {
	env, ok := v.(*agentEnvelope)
	if !ok {
		return nil, reflect.Value{}, false
	}
	items := reflect.ValueOf(env.Items)
	if !items.IsValid() || items.Kind() != reflect.Slice {
		return env, reflect.Value{}, false
	}
	return env, items, true
}

// envelopeFields is the struct's own JSON key set. Extra keys colliding with one
// are dropped: `items` and `total` are the contract, and an alias shadowing one
// would reintroduce exactly the ambiguity the envelope removes.
var envelopeFields = map[string]bool{
	"schema_version": true, "command": true, "project_uuid": true, "db_path": true,
	"total": true, "offset": true, "limit": true, "items": true, "query": true,
	"query_argv": true, "generated_at": true, "generated_at_ms": true,
}

// MarshalJSON merges the struct fields with extra (and the legacy row alias)
// into one flat object. Written by hand because the alias key is dynamic — it
// differs per command — and Go's struct tags cannot express that.
//
// It appends to the encoded struct rather than round-tripping through a
// map[string]any. That round trip decoded the whole result set — request and
// response bodies included — into a generic tree costing several times the
// JSON's size in live heap, purely to answer a key-collision question the fixed
// field set above already answers.
func (e *agentEnvelope) MarshalJSON() ([]byte, error) {
	type alias agentEnvelope
	base, err := jsonMarshalNoEscape((*alias)(e))
	if err != nil {
		return nil, err
	}
	renderLegacy := e.legacyKey != "" && jsonLegacyKeysEnabled()
	if len(e.extra) == 0 && !renderLegacy {
		return base, nil
	}

	out := bytes.TrimSuffix(bytes.TrimSpace(base), []byte("}"))
	appendField := func(key string, raw []byte) {
		if envelopeFields[key] {
			return
		}
		out = append(out, ',')
		keyJSON, _ := json.Marshal(key)
		out = append(out, keyJSON...)
		out = append(out, ':')
		out = append(out, raw...)
	}

	if renderLegacy {
		itemsJSON, err := jsonMarshalNoEscape(e.Items)
		if err != nil {
			return nil, err
		}
		appendField(e.legacyKey, itemsJSON)
	}
	for _, key := range sortedExtraKeys(e.extra) {
		raw, err := jsonMarshalNoEscape(e.extra[key])
		if err != nil {
			return nil, err
		}
		appendField(key, raw)
	}
	return append(out, '}'), nil
}

// sortedExtraKeys keeps the appended fields in a stable order — map iteration is
// random, and a payload whose key order changes run to run defeats diffing.
func sortedExtraKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// agentTimestamp renders t for JSON output: RFC3339 UTC with exactly three
// fractional digits.
//
// Go's default renders a variable number of fractional digits, so vigolium
// emitted microseconds (…785113Z) while a consumer comparing against a
// JavaScript toISOString() has milliseconds (…785Z) — and lexically "…785113Z"
// sorts BEFORE "…785Z". The extra precision is not extra information to such a
// consumer, it is a broken comparison that silently drops same-instant rows. The
// epoch-millisecond sibling exists for consumers that would rather compare
// integers than strings; either is correct, and both are always present.
func agentTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return scanevents.FormatTime(t)
}

// jsonMarshalNoEscape keeps HTML escaping off throughout the envelope's own
// marshaling. Payload evidence is full of &, < and >; the
// standard encoder would turn each into a \u00XX escape, which costs tokens and
// makes a hand-read line harder to compare against what the scanner sent.
func jsonMarshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encode appends a newline; the caller is assembling a value, not a stream.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
