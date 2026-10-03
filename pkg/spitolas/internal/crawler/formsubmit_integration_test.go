//go:build integration

package crawler

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/testutil"
)

// jsDrivenPostFormIndex reproduces the GinJuiceShop stock-check pattern: a POST form
// whose submit is intercepted by JS that posts an application/xml body built from the
// form fields (the endpoint that carries XXE / body+cookie SQLi), plus a second POST
// form with NO JS handler (exercised by the synthesized-fetch fallback).
const jsDrivenPostFormIndex = `<!doctype html><html><head><title>shop</title></head><body>
<h1>Product</h1>
<form id="stockCheckForm" action="/stock" method="POST">
  <input type="hidden" name="productId" value="1">
  <select name="storeId"><option value="7">Store 7</option></select>
  <button type="submit">Check stock</button>
</form>
<form id="plainForm" action="/plain" method="POST">
  <input type="text" name="q" value="x">
  <button type="submit">Go</button>
</form>
<script>
window.contentType = 'application/xml';
function payload(data){
  var xml = '<?xml version="1.0"?><stockCheck>';
  for (var p of data.entries()) { xml += '<' + p[0] + '>' + p[1] + '</' + p[0] + '>'; }
  return xml + '</stockCheck>';
}
document.getElementById('stockCheckForm').addEventListener('submit', function(e){
  e.preventDefault();
  fetch(this.getAttribute('action'), {
    method: this.getAttribute('method'),
    headers: { 'Content-Type': window.contentType },
    body: payload(new FormData(this))
  });
});
</script>
</body></html>`

// TestSubmitPostFormsReachesJSDrivenEndpoint verifies the deterministic POST-form
// submission recovers a JS-driven endpoint (application/xml stock check) that the
// GET-form path and the opportunistic interaction crawl both miss, and that the
// plain (no-handler) POST form is covered by the synthesized-fetch fallback.
func TestSubmitPostFormsReachesJSDrivenEndpoint(t *testing.T) {
	var stockHits, plainHits int32
	var gotXML atomic.Bool
	var gotProductID atomic.Bool

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, jsDrivenPostFormIndex)
	})
	mux.HandleFunc("/stock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			atomic.AddInt32(&stockHits, 1)
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "xml") {
				gotXML.Store(true)
			}
			if strings.Contains(string(body), "<productId>1</productId>") {
				gotProductID.Store(true)
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "42")
	})
	mux.HandleFunc("/plain", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			atomic.AddInt32(&plainHits, 1)
		}
		_, _ = io.WriteString(w, "ok")
	})

	server := testutil.NewTestServerWithHandler(mux)
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxStates = 3
	cfg.MaxDepth = 2
	cfg.MaxDuration = 45 * time.Second

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("new crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if _, err := crawler.Run(ctx); err != nil {
		t.Fatalf("crawl: %v", err)
	}

	if atomic.LoadInt32(&stockHits) == 0 {
		t.Fatalf("JS-driven POST form was never submitted: /stock got 0 POSTs")
	}
	if !gotXML.Load() {
		t.Errorf("/stock was hit but never with an XML content-type — the page's JS submit handler did not fire (XXE would stay unreachable)")
	}
	if !gotProductID.Load() {
		t.Errorf("/stock XML body did not carry the form's productId field")
	}
	if atomic.LoadInt32(&plainHits) == 0 {
		t.Errorf("plain (no-handler) POST form was never submitted: /plain got 0 POSTs (fallback fetch missing)")
	}
}

// attributionIndex has three POST forms whose handlers stress the outcome
// decision: one posts to its own action only after a delay, one posts somewhere
// other than its action, and one has no handler at all.
const attributionIndex = `<!doctype html><html><body>
<form id="late" action="/late" method="POST"><input name="a" value="1"><button>Go</button></form>
<form id="elsewhere" action="/elsewhere-action" method="POST"><input name="b" value="1"><button>Go</button></form>
<form id="plain" action="/plain" method="POST"><input name="c" value="1"><button>Go</button></form>
<script>
document.getElementById('late').addEventListener('submit', function (e) {
  e.preventDefault();
  setTimeout(function () { fetch('/late', { method: 'POST', body: 'a=1' }); }, 300);
});
document.getElementById('elsewhere').addEventListener('submit', function (e) {
  e.preventDefault();
  fetch('/api/other', { method: 'POST', body: 'b=1' });
});
</script>
</body></html>`

// pollIndex is a handler-less POST form on a page that polls in the background:
// an unattributable request lands in the form's window, so the outcome is
// uncertain and no fallback may be sent.
const pollIndex = `<!doctype html><html><body>
<form id="plain" action="/plain" method="POST"><input name="c" value="1"><button>Go</button></form>
<script>setInterval(function () { fetch('/poll'); }, 100);</script>
</body></html>`

// TestSubmitPostFormsAttribution drives submitPostForms against a live page and
// counts what reached the server: a delayed handler is attributed (one POST, no
// fallback), a handler posting elsewhere and a polled page are uncertain (no
// fallback POST to the action), a handler-less form gets exactly one fallback.
func TestSubmitPostFormsAttribution(t *testing.T) {
	var mu sync.Mutex
	posts := map[string]int{}
	mux := http.NewServeMux()
	serve := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, body)
		}
	}
	mux.HandleFunc("/", serve(attributionIndex))
	mux.HandleFunc("/polled", serve(pollIndex))
	for _, p := range []string{"/late", "/elsewhere-action", "/api/other", "/plain"} {
		path := p
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				mu.Lock()
				posts[path]++
				mu.Unlock()
			}
			_, _ = io.WriteString(w, "ok")
		})
	}
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "{}") })
	server := testutil.NewTestServerWithHandler(mux)
	defer server.Close()

	run := func(t *testing.T, path string) *Crawler {
		t.Helper()
		cfg, err := config.New(server.URL())
		if err != nil {
			t.Fatal(err)
		}
		cfg.Headless = true
		b, err := browser.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { b.Close() })
		page, err := b.NewPage()
		if err != nil {
			t.Fatal(err)
		}
		if err := page.Navigate(server.URL() + path); err != nil {
			t.Fatal(err)
		}
		c := &Crawler{config: cfg}
		c.submitPostForms(context.Background(), page, true)
		time.Sleep(500 * time.Millisecond) // let a late handler request land
		return c
	}
	count := func(p string) int {
		mu.Lock()
		defer mu.Unlock()
		return posts[p]
	}

	t.Run("handlers", func(t *testing.T) {
		c := run(t, "/")
		if got := count("/late"); got != 1 {
			t.Errorf("/late POSTs = %d, want 1 (the delayed handler, attributed — no fallback)", got)
		}
		if got := count("/elsewhere-action"); got != 0 {
			t.Errorf("/elsewhere-action POSTs = %d, want 0 (uncertain: no fallback)", got)
		}
		if got := count("/api/other"); got != 1 {
			t.Errorf("/api/other POSTs = %d, want 1 (the page's own handler)", got)
		}
		if got := count("/plain"); got != 1 {
			t.Errorf("/plain POSTs = %d, want 1 (fallback for a handler-less form)", got)
		}
		if c.stats.FormsSubmitted != 2 || c.stats.FormSubmitsUncertain != 1 {
			t.Errorf("submitted=%d uncertain=%d, want 2 and 1", c.stats.FormsSubmitted, c.stats.FormSubmitsUncertain)
		}
	})

	t.Run("background poll", func(t *testing.T) {
		before := count("/plain")
		c := run(t, "/polled")
		if got := count("/plain") - before; got != 0 {
			t.Errorf("/plain POSTs = %d, want 0 (a poll in the window makes the outcome uncertain)", got)
		}
		if c.stats.FormSubmitsUncertain != 1 || c.stats.FormsSubmitted != 0 {
			t.Errorf("submitted=%d uncertain=%d, want 0 and 1", c.stats.FormsSubmitted, c.stats.FormSubmitsUncertain)
		}
	})
}
