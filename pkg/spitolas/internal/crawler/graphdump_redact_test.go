package crawler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

const graphCanary = "SECRETCANARY42"

// canaryCrawler builds a graph carrying the canary everywhere a credential can
// hide: a password field's value, a hidden token field, an element's value and
// data-* attributes, a URL attribute's query, a state URL's query and the
// target's userinfo.
func canaryCrawler(t *testing.T) *Crawler {
	t.Helper()
	cfg, err := config.New("https://admin:" + graphCanary + "@app.test/")
	if err != nil {
		t.Fatal(err)
	}
	g := state.NewGraph()
	index := state.New("https://app.test/", "<html></html>", "html", 0)
	next := state.New("https://app.test/cb?code="+graphCanary+"&page=2", "<html>x</html>", "html-x", 1)
	g.AddState(index)
	g.AddState(next)
	e := action.NewEventable(action.NewIdentification(action.HowXPath, "//button[1]"), action.EventTypeClick)
	e.Element = &action.Element{Tag: "button", Text: "Sign in", Attributes: map[string]string{
		"id":         "login",
		"value":      graphCanary,
		"data-state": graphCanary,
		"formaction": "/login?api_key=" + graphCanary,
	}}
	e.RelatedFormInputs = []*action.FormInput{
		{Type: action.InputTypePassword, Identification: action.NewIdentification(action.HowXPath, "/html/body/form/input[2]"),
			InputValues: []action.InputValue{{Value: graphCanary}}},
		{Type: action.InputTypeHidden, Identification: action.NewIdentification(action.HowXPath, "/html/body/form/input[3]"),
			InputValues: []action.InputValue{{Value: graphCanary}}},
		{Type: action.InputTypeText, Identification: action.NewIdentification(action.HowName, "api_token"),
			InputValues: []action.InputValue{{Value: graphCanary}}},
		{Type: action.InputTypeText, Identification: action.NewIdentification(action.HowName, "q"),
			InputValues: []action.InputValue{{Value: "widgets"}}},
	}
	g.AddEdge(index.ID, next.ID, e)
	return &Crawler{config: cfg, graph: g}
}

func TestGraphDumpRedactsByDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "graph.json")
	if err := canaryCrawler(t).WriteGraphDump(path, GraphManifest{RunID: "r"}, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), graphCanary) {
		t.Errorf("canary survived redaction:\n%s", data)
	}
	// What a replay needs is kept: the non-sensitive value, the selector, the
	// non-sensitive query parameter and the field names.
	for _, keep := range []string{`"widgets"`, `//button[1]`, `page=2`, `"api_token"`, `"redacted": true`} {
		if !strings.Contains(string(data), keep) {
			t.Errorf("redaction removed %s", keep)
		}
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestGraphDumpIncludeValuesOptsOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "graph.json")
	if err := canaryCrawler(t).WriteGraphDump(path, GraphManifest{}, true); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), graphCanary) {
		t.Error("graph_include_values must keep the values")
	}
	if !strings.Contains(string(data), `"redacted": false`) {
		t.Error("an unredacted graph must say so")
	}
}

// TestGraphDumpRedactionLeavesLiveEdgeIntact: redaction works on the dump's
// copy, never on the crawler's live graph.
func TestGraphDumpRedactionLeavesLiveEdgeIntact(t *testing.T) {
	c := canaryCrawler(t)
	if err := c.WriteGraphDump(filepath.Join(t.TempDir(), "g.json"), GraphManifest{}, false); err != nil {
		t.Fatal(err)
	}
	for _, e := range c.graph.AllEdges() {
		if e.Element.Attributes["value"] != graphCanary || e.RelatedFormInputs[0].InputValues[0].Value != graphCanary {
			t.Fatal("redaction mutated the live graph")
		}
	}
}
