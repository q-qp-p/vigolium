//go:build integration

package form

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

const formKeyPage = `<!doctype html><html><body>
<form id="login" action="/login"><input name="user"><input name="pass" type="password">
  <button id="login-btn">Log in</button></form>
<form action="/search"><input name="q"><input name="action" value="shadowing"></form>
<input name="remote" form="login">
<input name="loose"><button id="loose-btn">Go</button>
<a id="nav" href="/about">About</a>
</body></html>`

// TestDetectInputsForAction checks the owning-form keys against a live DOM:
// the form= attribute counts, a control named "action" does not change the
// key, and an element outside any form resolves to "".
func TestDetectInputsForAction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(formKeyPage))
	}))
	defer srv.Close()

	b := setupFormBrowser(t, srv.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatal(err)
	}
	if err := page.Navigate(srv.URL); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(&config.Config{})

	inputs, loginKey, err := h.DetectInputsForAction(page, "/HTML[1]/BODY[1]/FORM[1]/BUTTON[1]")
	if err != nil {
		t.Fatal(err)
	}
	if loginKey == "" {
		t.Fatal("the login button's form key is empty")
	}
	keys := map[string]string{}
	for _, in := range inputs {
		keys[in.Name] = in.FormKey
	}
	if keys["user"] != loginKey || keys["pass"] != loginKey || keys["remote"] != loginKey {
		t.Errorf("login controls (incl. form=login) must share the button's key %q: %v", loginKey, keys)
	}
	if keys["q"] == "" || keys["q"] == loginKey || keys["action"] != keys["q"] {
		t.Errorf("search controls must share a distinct key: %v", keys)
	}
	if keys["loose"] != "" {
		t.Errorf("orphan input key = %q, want empty", keys["loose"])
	}

	for _, xp := range []string{"/HTML[1]/BODY[1]/BUTTON[1]", "/HTML[1]/BODY[1]/A[1]", "", "/HTML[1]/BODY[1]/NOPE[9]"} {
		if _, key, err := h.DetectInputsForAction(page, xp); err != nil || key != "" {
			t.Errorf("action %q: key=%q err=%v, want empty and no error", xp, key, err)
		}
	}
}
