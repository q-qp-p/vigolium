package crawler

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"go.uber.org/zap"
)

// GraphDump is the serialized form of a finished crawl: the locations the
// crawler reached and, for each transition between them, the action that was
// taken and how to find that element again.
//
// The captured traffic already says what was requested. What it cannot say is
// how the crawler got there — which click on which page, with which form values,
// produced a given request. That is the difference between a list of URLs and a
// reproducible route, and it is what makes a state re-reachable later without
// rediscovering the whole path to it.
//
// The manifest fields (RunID, Seed, Policy, Security, Capture, Redacted) say
// which run the graph belongs to, what the crawl was permitted to change, the
// browser's security posture and what its capture retained — the context a
// reader needs before trusting or sharing the file.
type GraphDump struct {
	Version   int       `json:"version"`
	RunID     string    `json:"run_id,omitempty"`
	Seed      string    `json:"seed,omitempty"`
	Target    string    `json:"target"`
	CreatedAt time.Time `json:"created_at"`
	// Redacted is true when credential-bearing values were scrubbed (the
	// default); false only under spidering.graph_include_values.
	Redacted bool           `json:"redacted"`
	Policy   map[string]any `json:"policy,omitempty"`
	Security map[string]any `json:"security,omitempty"`
	// Capture is the run's capture receipt (spitolas.CaptureReceipt), carried
	// as written by the caller.
	Capture any              `json:"capture,omitempty"`
	Stats   GraphDumpStats   `json:"stats"`
	States  []GraphDumpState `json:"states"`
	Edges   []GraphDumpEdge  `json:"edges"`
}

// GraphManifest is the run context a caller supplies with WriteGraphDump.
type GraphManifest struct {
	RunID    string
	Seed     string
	Policy   map[string]any
	Security map[string]any
	Capture  any
}

// GraphDumpStats summarises the run the graph came from.
type GraphDumpStats struct {
	States               int `json:"states"`
	Edges                int `json:"edges"`
	ActionsExecuted      int `json:"actions_executed"`
	ActionsFailed        int `json:"actions_failed"`
	FormsSubmitted       int `json:"forms_submitted"`
	FormSubmitsPrevented int `json:"form_submits_prevented"`
	FormSubmitsUncertain int `json:"form_submits_uncertain"`
	WaitConditionsFailed int `json:"wait_conditions_failed,omitempty"`
}

// GraphDumpState is one reached location. The DOM itself is deliberately not
// included: it is large, it is already represented by the captured responses,
// and the identity hash is what a later run needs in order to recognise the
// same location again.
type GraphDumpState struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	URL             string    `json:"url"`
	Depth           int       `json:"depth"`
	CreatedAt       time.Time `json:"created_at"`
	OnURL           bool      `json:"on_url"`
	IsNearDuplicate bool      `json:"is_near_duplicate,omitempty"`
	NearestStateID  string    `json:"nearest_state_id,omitempty"`
}

// GraphDumpEdge is one transition, recorded so it can be replayed.
type GraphDumpEdge struct {
	ID         int64             `json:"id"`
	From       string            `json:"from"`
	To         string            `json:"to"`
	EventType  string            `json:"event_type"`
	Selector   GraphDumpSelector `json:"selector"`
	Frame      string            `json:"frame,omitempty"`
	Tag        string            `json:"tag,omitempty"`
	Text       string            `json:"text,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	FormInputs []GraphDumpInput  `json:"form_inputs,omitempty"`
}

// GraphDumpSelector is how the element was addressed — the method (xpath, css,
// id, …) and the expression.
type GraphDumpSelector struct {
	How   string `json:"how"`
	Value string `json:"value"`
}

// GraphDumpInput is a form field the transition carried, with the value that was
// submitted. Recording the value matters as much as the field: a transition that
// only happens for a particular input is not reproducible without it.
type GraphDumpInput struct {
	Type   string   `json:"type"`
	How    string   `json:"how"`
	Value  string   `json:"value"`
	Inputs []string `json:"inputs,omitempty"`
}

// graphDumpVersion is bumped when the shape or the meaning of a field changes.
// 2: forms_submitted counts every submission mechanism (v1 counted only Enter
// actions, so it was structurally 0); form_submits_prevented/_uncertain added;
// the run manifest (run_id, seed, policy, security, capture, redacted) added;
// credential-bearing values redacted by default. A v1 file may hold unredacted
// values.
const graphDumpVersion = 2

// WriteGraphDump serializes the finished graph to path, owner-only (0600) and
// atomically — a temp file in the same directory renamed into place — so an
// interrupted write never truncates an earlier good graph. Credential-bearing
// values are redacted unless includeValues is set (see redactGraphDump).
//
// The caller decides what a failure costs: a crawl that produced traffic is a
// successful crawl whether or not the map of it could be written.
func (c *Crawler) WriteGraphDump(path string, m GraphManifest, includeValues bool) error {
	if path == "" || c.graph == nil {
		return nil
	}

	dump := c.buildGraphDump()
	dump.RunID, dump.Seed = m.RunID, m.Seed
	dump.Policy, dump.Security, dump.Capture = m.Policy, m.Security, m.Capture
	dump.Redacted = !includeValues
	if dump.Redacted {
		redactGraphDump(&dump)
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create crawl-graph directory: %w", err)
		}
	}
	// atomicfile.Write leaves the temp file's 0600 in place.
	err := atomicfile.Write(path, func(w *bufio.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(dump)
	})
	if err != nil {
		return fmt.Errorf("write crawl graph: %w", err)
	}
	zap.L().Info("Spidering: wrote crawl graph",
		zap.String("path", path),
		zap.Bool("redacted", dump.Redacted),
		zap.Int("states", dump.Stats.States),
		zap.Int("edges", dump.Stats.Edges))
	return nil
}

// buildGraphDump converts the live graph into its serializable form. States and
// edges are emitted in a stable order (name, then edge id) so two runs over an
// unchanged application produce diffable output.
func (c *Crawler) buildGraphDump() GraphDump {
	target := ""
	if c.config.URL != nil {
		target = c.config.URL.String()
	}

	states := c.graph.AllStates()
	edges := c.graph.AllEdges()

	dumpStates := make([]GraphDumpState, 0, len(states))
	for _, s := range states {
		if s == nil {
			continue
		}
		dumpStates = append(dumpStates, GraphDumpState{
			ID:              s.ID,
			Name:            s.Name,
			URL:             s.URL,
			Depth:           s.Depth,
			CreatedAt:       s.CreatedAt,
			OnURL:           s.OnURL,
			IsNearDuplicate: s.IsNearDuplicate,
			NearestStateID:  s.NearestStateID,
		})
	}
	sort.Slice(dumpStates, func(i, j int) bool { return dumpStates[i].Name < dumpStates[j].Name })

	dumpEdges := make([]GraphDumpEdge, 0, len(edges))
	for _, e := range edges {
		if e == nil {
			continue
		}
		dumpEdges = append(dumpEdges, graphDumpEdgeFrom(e))
	}
	sort.Slice(dumpEdges, func(i, j int) bool { return dumpEdges[i].ID < dumpEdges[j].ID })

	c.mu.Lock()
	stats := GraphDumpStats{
		States:          len(dumpStates),
		Edges:           len(dumpEdges),
		ActionsExecuted: c.stats.ActionsExecuted,
		ActionsFailed:   c.stats.ActionsFailed,
		FormsSubmitted:  c.stats.FormsSubmitted,

		FormSubmitsPrevented: c.stats.FormSubmitsPrevented,
		FormSubmitsUncertain: c.stats.FormSubmitsUncertain,
		WaitConditionsFailed: c.stats.WaitConditionsFailed,
	}
	c.mu.Unlock()

	return GraphDump{
		Version:   graphDumpVersion,
		Target:    target,
		CreatedAt: time.Now().UTC(),
		Stats:     stats,
		States:    dumpStates,
		Edges:     dumpEdges,
	}
}

// graphDumpEdgeFrom converts one live edge into its serializable form.
func graphDumpEdgeFrom(e *action.Eventable) GraphDumpEdge {
	out := GraphDumpEdge{
		ID:        e.ID,
		From:      e.SourceStateID,
		To:        e.TargetStateID,
		EventType: string(e.EventType),
		Frame:     e.RelatedFrame,
	}
	if e.Identification != nil {
		out.Selector = GraphDumpSelector{
			How:   string(e.Identification.How),
			Value: e.Identification.Value,
		}
	}
	if e.Element != nil {
		out.Tag = e.Element.Tag
		out.Text = e.Element.Text
		if len(e.Element.Attributes) > 0 {
			out.Attributes = e.Element.Attributes
		}
	}
	for _, fi := range e.RelatedFormInputs {
		if fi == nil {
			continue
		}
		in := GraphDumpInput{Type: string(fi.Type)}
		if fi.Identification != nil {
			in.How = string(fi.Identification.How)
			in.Value = fi.Identification.Value
		}
		for _, v := range fi.InputValues {
			in.Inputs = append(in.Inputs, v.Value)
		}
		out.FormInputs = append(out.FormInputs, in)
	}
	return out
}

// GraphOutputPathFor names one graph file in dir:
// crawl-graph-<host>-<runID>-<seq>.json. The run id keeps repeat runs apart and
// seq keeps same-host seeds of one run apart, so no graph overwrites another.
// Empty host or runID components are left out; every component is reduced to
// filename-safe characters.
func GraphOutputPathFor(dir, host, runID, seq string) string {
	if dir == "" {
		return ""
	}
	name := "crawl-graph"
	for _, part := range []string{host, runID, seq} {
		if p := fileNameSafe(part); p != "" {
			name += "-" + p
		}
	}
	return filepath.Join(dir, name+".json")
}

// fileNameSafe keeps [A-Za-z0-9._-] and replaces anything else (an IPv6
// host's colons, a path separator in an operator-supplied run id) with "_".
func fileNameSafe(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, strings.Trim(s, "."))
}
