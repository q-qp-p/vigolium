package crawler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

func TestGraphOutputPathFor(t *testing.T) {
	if got := GraphOutputPathFor("", "app.test", "run1", "001"); got != "" {
		t.Errorf("no directory should disable the dump, got %q", got)
	}
	if got := GraphOutputPathFor("/out", "app.test", "run1", "001"); got != filepath.Join("/out", "crawl-graph-app.test-run1-001.json") {
		t.Errorf("path = %q", got)
	}
	if got := GraphOutputPathFor("/out", "", "run1", "001"); got != filepath.Join("/out", "crawl-graph-run1-001.json") {
		t.Errorf("unknown host should drop the component, got %q", got)
	}
	// Two hosts, two seeds on one host, and two runs: no two may share a file.
	seen := map[string]bool{}
	for _, p := range []string{
		GraphOutputPathFor("/out", "a.test", "run1", "001"),
		GraphOutputPathFor("/out", "b.test", "run1", "002"),
		GraphOutputPathFor("/out", "a.test", "run1", "003"),
		GraphOutputPathFor("/out", "a.test", "run2", "001"),
	} {
		if seen[p] {
			t.Errorf("graph paths collided: %q", p)
		}
		seen[p] = true
	}
	// Components are reduced to file-name-safe characters.
	if got := GraphOutputPathFor("/out", "::1", "../../etc", "001"); filepath.Dir(got) != "/out" {
		t.Errorf("unsafe components escaped the directory: %q", got)
	}
}

func TestGraphDumpEdgeFromCarriesSelectorAndInputs(t *testing.T) {
	e := &action.Eventable{
		ID:            7,
		EventType:     action.EventTypeClick,
		SourceStateID: "src",
		TargetStateID: "dst",
		RelatedFrame:  "frame[0]",
		Identification: &action.Identification{
			How:   action.HowXPath,
			Value: "//button[@id='go']",
		},
		Element: &action.Element{
			Tag:        "button",
			Text:       "Go",
			Attributes: map[string]string{"id": "go"},
		},
		RelatedFormInputs: []*action.FormInput{
			{
				Type:           action.InputTypeText,
				Identification: &action.Identification{How: action.HowName, Value: "q"},
				InputValues:    []action.InputValue{{Value: "widgets"}},
			},
		},
	}

	got := graphDumpEdgeFrom(e)

	if got.ID != 7 || got.From != "src" || got.To != "dst" {
		t.Errorf("edge identity not carried: %+v", got)
	}
	// The selector is what makes the transition replayable — without it the dump
	// is a list of state ids rather than a route.
	if got.Selector.Value != "//button[@id='go']" || got.Selector.How != string(action.HowXPath) {
		t.Errorf("selector not carried: %+v", got.Selector)
	}
	if got.Frame != "frame[0]" || got.Tag != "button" || got.Text != "Go" {
		t.Errorf("element context not carried: %+v", got)
	}
	if len(got.FormInputs) != 1 {
		t.Fatalf("form inputs not carried: %+v", got.FormInputs)
	}
	// The submitted value matters as much as the field name: a transition that
	// only happens for a particular input cannot be reproduced without it.
	if got.FormInputs[0].Value != "q" || len(got.FormInputs[0].Inputs) != 1 || got.FormInputs[0].Inputs[0] != "widgets" {
		t.Errorf("form input value not carried: %+v", got.FormInputs[0])
	}
}

func TestGraphDumpEdgeFromToleratesSparseEventable(t *testing.T) {
	// Reload edges carry no element or identification; serializing must not panic.
	got := graphDumpEdgeFrom(&action.Eventable{ID: 1, EventType: action.EventTypeClick})
	if got.ID != 1 || got.Selector.Value != "" || got.FormInputs != nil {
		t.Errorf("sparse eventable mishandled: %+v", got)
	}
}

func TestWriteGraphDumpProducesReadableJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "graph.json")

	cfg, err := config.New("https://app.test")
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}

	g := state.NewGraph()
	index := state.New("https://app.test/", "<html></html>", "html", 0)
	next := state.New("https://app.test/admin", "<html>admin</html>", "html-admin", 1)
	g.AddState(index)
	g.AddState(next)
	g.AddEdge(index.ID, next.ID, action.NewEventable(
		action.NewIdentification(action.HowXPath, "//a[@id='admin']"), action.EventTypeClick))

	c := &Crawler{config: cfg, graph: g}
	c.stats.FormsSubmitted, c.stats.FormSubmitsPrevented, c.stats.FormSubmitsUncertain = 3, 2, 1
	m := GraphManifest{
		RunID:    "scan-uuid",
		Seed:     "001",
		Policy:   map[string]any{"submit_forms": true},
		Security: map[string]any{"sandbox": "on"},
		Capture:  map[string]any{"persisted": 12, "drain_complete": true},
	}
	if werr := c.WriteGraphDump(path, m, false); werr != nil {
		t.Fatalf("WriteGraphDump: %v", werr)
	}

	data, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("graph file not written (the directory should be created): %v", rerr)
	}

	var dump GraphDump
	if jerr := json.Unmarshal(data, &dump); jerr != nil {
		t.Fatalf("graph file is not valid JSON: %v", jerr)
	}
	if dump.Version != graphDumpVersion || dump.Target != "https://app.test" {
		t.Errorf("dump header wrong: version=%d target=%q", dump.Version, dump.Target)
	}
	if dump.Stats.States != 2 || len(dump.States) != 2 {
		t.Errorf("expected 2 states, got %d (%d in stats)", len(dump.States), dump.Stats.States)
	}
	if dump.Version != 2 {
		t.Errorf("version = %d, want 2 (forms_submitted changed meaning)", dump.Version)
	}
	if dump.Stats.FormsSubmitted != 3 || dump.Stats.FormSubmitsPrevented != 2 || dump.Stats.FormSubmitsUncertain != 1 {
		t.Errorf("submission counters not carried: %+v", dump.Stats)
	}
	if dump.Stats.Edges != 1 || len(dump.Edges) != 1 {
		t.Errorf("expected 1 edge, got %d (%d in stats)", len(dump.Edges), dump.Stats.Edges)
	}
	if dump.Edges[0].Selector.Value != "//a[@id='admin']" {
		t.Errorf("edge selector lost through serialization: %+v", dump.Edges[0])
	}
	// The manifest says which run this is, what it was allowed to do, and what
	// its capture kept.
	if dump.RunID != "scan-uuid" || dump.Seed != "001" || !dump.Redacted ||
		dump.Policy["submit_forms"] != true || dump.Security["sandbox"] != "on" || dump.Capture == nil {
		t.Errorf("manifest not carried: run=%q seed=%q redacted=%v policy=%v security=%v capture=%v",
			dump.RunID, dump.Seed, dump.Redacted, dump.Policy, dump.Security, dump.Capture)
	}
	info, serr := os.Stat(path)
	if serr != nil {
		t.Fatal(serr)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("graph mode = %o, want 600", perm)
	}
	// The DOM is deliberately excluded — it is large and already represented by
	// the captured responses.
	if len(data) > 64*1024 {
		t.Errorf("dump is unexpectedly large (%d bytes); is the DOM leaking in?", len(data))
	}
}

func TestWriteGraphDumpNoOpWithoutPath(t *testing.T) {
	cfg, err := config.New("https://app.test")
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	c := &Crawler{config: cfg, graph: state.NewGraph()}
	if err := c.WriteGraphDump("", GraphManifest{}, false); err != nil { // no output requested
		t.Errorf("WriteGraphDump with no path = %v", err)
	}
}

// TestWriteGraphDumpFailureKeepsPreviousGraph: the write is temp-and-rename, so
// a serialization failure leaves an earlier good graph exactly as it was.
func TestWriteGraphDumpFailureKeepsPreviousGraph(t *testing.T) {
	path := filepath.Join(t.TempDir(), "graph.json")
	if err := os.WriteFile(path, []byte(`{"previous":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.New("https://app.test")
	c := &Crawler{config: cfg, graph: state.NewGraph()}
	// A channel cannot be marshalled.
	if err := c.WriteGraphDump(path, GraphManifest{Capture: make(chan int)}, false); err == nil {
		t.Fatal("expected the unmarshallable manifest to fail the write")
	}
	if data, _ := os.ReadFile(path); string(data) != `{"previous":true}` {
		t.Errorf("previous graph damaged: %q", data)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temp file left behind: %d entries", len(entries))
	}
}
