package tool

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// recordingSink keeps every record handed to it.
type recordingSink struct {
	mu      sync.Mutex
	records []*httpmsg.HttpRequestResponse
}

func (s *recordingSink) SaveRecord(_ context.Context, rr *httpmsg.HttpRequestResponse, _, _ string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rr)
	return "rec-1", nil
}

func (s *recordingSink) SaveRecordBatch(_ context.Context, rrs []*httpmsg.HttpRequestResponse, _, _ string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rrs...)
	return make([]string, len(rrs)), nil
}

// TestWebFetchRedirectPairing: the stored request is the one that produced the
// stored response — the last hop — and the chain is reported.
func TestWebFetchRedirectPairing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			http.Redirect(w, r, "/b?x=1", http.StatusFound)
		case "/b":
			_, _ = w.Write([]byte("final-body"))
		case "/keep":
			http.Redirect(w, r, "/echo", http.StatusTemporaryRedirect)
		case "/echo":
			_, _ = w.Write([]byte("echoed"))
		}
	}))
	defer srv.Close()

	sink := &recordingSink{}
	res, err := NewWebFetchWithCapture(sink, "proj").Execute(context.Background(), map[string]any{"url": srv.URL + "/a"}, nil)
	if err != nil || res.IsError {
		t.Fatalf("Execute: %v %s", err, res.Content)
	}
	if len(sink.records) != 1 {
		t.Fatalf("records = %d, want 1", len(sink.records))
	}
	raw := string(sink.records[0].Request().Raw())
	if !strings.HasPrefix(raw, "GET /b?x=1 HTTP/1.1\r\n") {
		t.Errorf("stored request line = %q, want the final hop GET /b?x=1", strings.SplitN(raw, "\r\n", 2)[0])
	}
	chain, ok := res.Details["redirect_chain"].(map[string]any)
	if !ok || chain["hops"] != 1 || chain["original_url"] != srv.URL+"/a" || chain["final_url"] != srv.URL+"/b?x=1" {
		t.Errorf("redirect_chain = %v", res.Details["redirect_chain"])
	}

	// A 307 re-sends the body; the stored request must carry it.
	sink.records = nil
	res, _ = NewWebFetchWithCapture(sink, "proj").Execute(context.Background(), map[string]any{
		"url": srv.URL + "/keep", "method": "POST", "body": "q=canary",
	}, nil)
	raw = string(sink.records[0].Request().Raw())
	if !strings.HasPrefix(raw, "POST /echo HTTP/1.1\r\n") || !strings.HasSuffix(raw, "q=canary") {
		t.Errorf("307 hop stored as %q, want POST /echo with its body", raw)
	}
	if _, omitted := res.Details["body_omitted"]; omitted {
		t.Error("a re-readable body must not be reported omitted")
	}

	// No redirect: no chain reported.
	res, _ = NewWebFetchWithCapture(&recordingSink{}, "proj").Execute(context.Background(), map[string]any{"url": srv.URL + "/b"}, nil)
	if _, ok := res.Details["redirect_chain"]; ok {
		t.Errorf("redirect_chain reported without a redirect: %v", res.Details)
	}
}
