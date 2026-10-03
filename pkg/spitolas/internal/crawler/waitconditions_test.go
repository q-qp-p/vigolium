package crawler

import (
	"fmt"
	"slices"
	"testing"
)

// TestRecordWaitConditionFailure: every timed-out readiness condition is
// counted, and up to maxWaitConditionFailures distinct selectors are kept for
// the summary.
func TestRecordWaitConditionFailure(t *testing.T) {
	c := &Crawler{}
	c.recordWaitConditionFailure("#app")
	c.recordWaitConditionFailure("#app")
	for i := range 8 {
		c.recordWaitConditionFailure(fmt.Sprintf("#w%d", i))
	}
	st := c.GetStats()
	if st.WaitConditionsFailed != 10 {
		t.Errorf("WaitConditionsFailed = %d, want 10", st.WaitConditionsFailed)
	}
	want := []string{"#app", "#w0", "#w1", "#w2", "#w3"}
	if !slices.Equal(st.WaitConditionFailures, want) {
		t.Errorf("WaitConditionFailures = %v, want %v", st.WaitConditionFailures, want)
	}
}
