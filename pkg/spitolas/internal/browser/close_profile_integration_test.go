//go:build integration && (linux || darwin)

package browser

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// TestCloseRemovesProfileAfterExit: Close must leave no profile directory
// behind. Browser.close is acknowledged before Chromium exits, and the exiting
// process flushes its profile (Default/Cache, Network Persistent State...), so a
// profile removed straight after the acknowledgement was re-created and
// stranded — one directory per closed browser, for the life of the process.
func TestCloseRemovesProfileAfterExit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	b := newHeadlessBrowser(t, srv.URL)
	profile := b.profileDir
	if profile == "" {
		t.Fatal("a launched browser should own a profile directory")
	}

	// Give the profile something to flush on exit, as a crawl would.
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}
	if err := page.Navigate(srv.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Checked again after a pause: the leak was the exiting process writing the
	// profile back after Close had already removed it.
	for _, wait := range []time.Duration{0, time.Second} {
		time.Sleep(wait)
		if _, err := os.Stat(profile); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("profile directory %s still present %v after Close (stat: %v)", profile, wait, err)
		}
	}
}
