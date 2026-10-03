package crawler

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/form"
)

func formInput(name, formKey string) *form.DetectedInput {
	d := form.NewDetectedInputWithType(action.InputTypeText, action.NewIdentification(action.HowName, name))
	d.Name = name
	d.FormKey = formKey
	return d
}

func inputNames(in []*form.DetectedInput) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		out = append(out, d.Name)
	}
	return out
}

// TestMergeActionInputs: an action inside form f1 fills only f1's controls;
// an action outside any form keeps the whole-page merge (SPA flows built from
// orphan inputs depend on it).
func TestMergeActionInputs(t *testing.T) {
	c := &Crawler{}
	dom := func() []*form.DetectedInput {
		return []*form.DetectedInput{
			formInput("user", "f1"),
			formInput("pass", "f1"),
			formInput("q", "f2"),
			formInput("orphan", ""),
		}
	}

	tests := []struct {
		name         string
		related      []*form.DetectedInput
		actionForm   string
		wantNames    []string
		wantExcluded int
	}{
		{"action in f1", nil, "f1", []string{"user", "pass"}, 2},
		{"action in f2", nil, "f2", []string{"q"}, 3},
		{"action outside any form", nil, "", []string{"user", "pass", "q", "orphan"}, 0},
		{"related kept, duplicate not re-added", []*form.DetectedInput{formInput("user", "")}, "f1", []string{"user", "pass"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, excluded := c.mergeActionInputs(tt.related, dom(), tt.actionForm)
			names := inputNames(got)
			if len(names) != len(tt.wantNames) {
				t.Fatalf("merged %v, want %v", names, tt.wantNames)
			}
			for i := range names {
				if names[i] != tt.wantNames[i] {
					t.Fatalf("merged %v, want %v", names, tt.wantNames)
				}
			}
			if excluded != tt.wantExcluded {
				t.Errorf("excluded = %d, want %d", excluded, tt.wantExcluded)
			}
		})
	}
}
