//go:build integration

package spitolas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// TestProbeURLCapturesAlert serves a page that calls alert() and asserts
// the probe records the dialog event.
func TestProbeURLCapturesAlert(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>probe-target</title></head>
<body><script>alert("vig-probe-canary-123")</script></body></html>`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := ProbeURL(ctx, ProbeConfig{
		URL:        srv.URL,
		WaitExtra:  500 * time.Millisecond,
		NavTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("ProbeURL: %v", err)
	}
	if len(res.Dialogs) == 0 {
		t.Fatalf("expected at least one dialog, got none")
	}
	found := false
	for _, d := range res.Dialogs {
		if d.Type == "alert" && strings.Contains(d.Message, "vig-probe-canary-123") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("dialog with canary not captured; got %+v", res.Dialogs)
	}
}

// TestProbeURLNoAlert ensures a benign page reports zero dialogs.
func TestProbeURLNoAlert(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><p>nothing happens here</p></body></html>`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := ProbeURL(ctx, ProbeConfig{URL: srv.URL, WaitExtra: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("ProbeURL: %v", err)
	}
	if len(res.Dialogs) != 0 {
		t.Fatalf("expected no dialogs, got %+v", res.Dialogs)
	}
}

// memSink is an in-memory CaptureSink counting what it was asked to store.
type memSink struct {
	mu      sync.Mutex
	records []*httpmsg.HttpRequestResponse
}

func (m *memSink) SaveRecord(_ context.Context, rr *httpmsg.HttpRequestResponse, _, _ string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, rr)
	return "id", nil
}

func (m *memSink) SaveRecordBatch(_ context.Context, rrs []*httpmsg.HttpRequestResponse, _, _ string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, len(rrs))
	for i := range ids {
		ids[i] = "id"
	}
	m.records = append(m.records, rrs...)
	return ids, nil
}

// TestProbeURLCaptureReceipt: the receipt reports what the sink actually
// stored, after the writer drained, and whether bodies were kept.
func TestProbeURLCaptureReceipt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/data" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"probe":"body-canary"}`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><script>fetch('/api/data')</script></body></html>`))
	}))
	defer srv.Close()

	for _, bodies := range []bool{false, true} {
		sink := &memSink{}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		res, err := ProbeURL(ctx, ProbeConfig{
			URL: srv.URL, WaitExtra: 800 * time.Millisecond, NavTimeout: 30 * time.Second,
			CaptureSink: sink, CaptureProjectUUID: "proj", CaptureBodies: bodies,
		})
		cancel()
		if err != nil {
			t.Fatalf("ProbeURL(bodies=%v): %v", bodies, err)
		}
		rc := res.Capture
		sink.mu.Lock()
		stored := len(sink.records)
		withBody := false
		for _, rr := range sink.records {
			if rr.Response() != nil && strings.Contains(string(rr.Response().Body()), "body-canary") {
				withBody = true
			}
		}
		sink.mu.Unlock()
		if !rc.Enabled || !rc.Clean() || rc.Persisted == 0 || rc.Persisted != stored {
			t.Errorf("bodies=%v: receipt %+v, sink stored %d", bodies, rc, stored)
		}
		if rc.BodiesRetained != bodies || withBody != bodies {
			t.Errorf("bodies=%v: receipt says bodies_retained=%v, sink saw a body=%v", bodies, rc.BodiesRetained, withBody)
		}
	}
}
