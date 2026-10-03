//go:build integration

package browser

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// TestSubmitGuardBlocksScriptedSubmission drives a page whose ordinary <div>
// submits a form from script — the case the dispatch gates cannot see. With
// submits denied the POST never reaches the server; AllowAuthorizedSubmit lets
// an authorized submission through.
func TestSubmitGuardBlocksScriptedSubmission(t *testing.T) {
	var posts atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
<form id="f" method="post" action="/submit"><input name="q" value="x"></form>
<div id="go" onclick="document.getElementById('f').submit()">go</div>
<button id="btn" form="f">send</button>
</body></html>`))
	})
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
		}
		_, _ = w.Write([]byte("<html><body>done</body></html>"))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	newPage := func(t *testing.T, submit bool) *Page {
		cfg, err := config.New(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Headless = true
		cfg.Policy.SubmitForms = submit
		b, err := New(cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { b.Close() })
		page, err := b.NewPage()
		if err != nil {
			t.Fatalf("NewPage: %v", err)
		}
		if err := page.Navigate(server.URL + "/"); err != nil {
			t.Fatalf("Navigate: %v", err)
		}
		return page
	}
	clickAll := func(t *testing.T, page *Page) {
		for _, sel := range []string{"#go", "#btn"} {
			el, err := page.Element(sel)
			if err != nil {
				t.Fatalf("Element(%s): %v", sel, err)
			}
			_ = el.Click()
			time.Sleep(300 * time.Millisecond)
		}
	}

	t.Run("denied", func(t *testing.T) {
		posts.Store(0)
		page := newPage(t, false)
		clickAll(t, page)
		if n := posts.Load(); n != 0 {
			t.Errorf("submits denied, but the server saw %d POST(s)", n)
		}
	})

	t.Run("authorized", func(t *testing.T) {
		posts.Store(0)
		page := newPage(t, false)
		page.AllowAuthorizedSubmit()
		el, err := page.Element("#go")
		if err != nil {
			t.Fatal(err)
		}
		_ = el.Click()
		time.Sleep(500 * time.Millisecond)
		if n := posts.Load(); n != 1 {
			t.Errorf("authorized submission: server saw %d POST(s), want 1", n)
		}
	})

	t.Run("permitted", func(t *testing.T) {
		posts.Store(0)
		page := newPage(t, true)
		el, err := page.Element("#go")
		if err != nil {
			t.Fatal(err)
		}
		_ = el.Click()
		time.Sleep(500 * time.Millisecond)
		if n := posts.Load(); n != 1 {
			t.Errorf("submits permitted: server saw %d POST(s), want 1", n)
		}
	})
}
