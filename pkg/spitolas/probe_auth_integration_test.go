//go:build integration

package spitolas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestProbeURLSessionContext: seeded cookies and headers reach the target, a
// cookie scoped to another domain does not, and the readiness of a selector
// that never appears is reported (with RequireSelector, as an error).
func TestProbeURLSessionContext(t *testing.T) {
	var mu sync.Mutex
	var cookie, apiKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			mu.Lock()
			cookie, apiKey = r.Header.Get("Cookie"), r.Header.Get("X-Api-Key")
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><p id="here">ok</p></body></html>`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	res, err := ProbeURL(ctx, ProbeConfig{
		URL:        srv.URL + "/",
		NavTimeout: 30 * time.Second,
		Cookies: []*http.Cookie{
			{Name: "sid", Value: "abc"},
			{Name: "other", Value: "x", Domain: "elsewhere.test"},
		},
		Headers:      map[string]string{"X-Api-Key": "k-123"},
		WaitSelector: "#here",
	})
	if err != nil {
		t.Fatalf("ProbeURL: %v", err)
	}
	mu.Lock()
	gotCookie, gotKey := cookie, apiKey
	mu.Unlock()
	if gotCookie != "sid=abc" {
		t.Errorf("Cookie = %q, want only the host-only session cookie", gotCookie)
	}
	if gotKey != "k-123" {
		t.Errorf("X-Api-Key = %q, want k-123", gotKey)
	}
	if res.Readiness != ReadinessReady || res.ReadinessFailed {
		t.Errorf("readiness = %q failed=%v, want ready", res.Readiness, res.ReadinessFailed)
	}

	res, err = ProbeURL(ctx, ProbeConfig{
		URL:             srv.URL + "/",
		NavTimeout:      2 * time.Second,
		WaitSelector:    "#never",
		RequireSelector: true,
	})
	if err == nil || res == nil || res.Readiness != ReadinessTimeout {
		t.Fatalf("missing selector: res=%+v err=%v, want a timeout readiness and an error", res, err)
	}
}
