package browser

import (
	"net/http"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"
)

// TestCookieParams pins how a net/http cookie becomes a CDP cookie: the
// attributes that decide where it is sent survive, and URL and Domain are
// never both set.
func TestCookieParams(t *testing.T) {
	const target = "https://app.example.com/login"
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		name string
		in   http.Cookie
		want proto.NetworkCookieParam
	}{
		{"host-only", http.Cookie{Name: "a", Value: "1"},
			proto.NetworkCookieParam{Name: "a", Value: "1", URL: target, SameSite: proto.NetworkCookieSameSiteLax}},
		{"host-only with path", http.Cookie{Name: "a", Value: "1", Path: "/api"},
			proto.NetworkCookieParam{Name: "a", Value: "1", URL: target, Path: "/api", SameSite: proto.NetworkCookieSameSiteLax}},
		{"domain", http.Cookie{Name: "a", Value: "1", Domain: "example.com"},
			proto.NetworkCookieParam{Name: "a", Value: "1", Domain: "example.com", Path: "/", SameSite: proto.NetworkCookieSameSiteLax}},
		{"dot domain and path", http.Cookie{Name: "a", Value: "1", Domain: ".example.com", Path: "/app"},
			proto.NetworkCookieParam{Name: "a", Value: "1", Domain: ".example.com", Path: "/app", SameSite: proto.NetworkCookieSameSiteLax}},
		{"expiry", http.Cookie{Name: "a", Value: "1", Expires: exp},
			proto.NetworkCookieParam{Name: "a", Value: "1", URL: target, Expires: proto.TimeSinceEpoch(exp.Unix()), SameSite: proto.NetworkCookieSameSiteLax}},
		{"secure httpOnly", http.Cookie{Name: "a", Value: "1", Secure: true, HttpOnly: true},
			proto.NetworkCookieParam{Name: "a", Value: "1", URL: target, Secure: true, HTTPOnly: true, SameSite: proto.NetworkCookieSameSiteLax}},
		{"samesite strict", http.Cookie{Name: "a", Value: "1", SameSite: http.SameSiteStrictMode},
			proto.NetworkCookieParam{Name: "a", Value: "1", URL: target, SameSite: proto.NetworkCookieSameSiteStrict}},
		{"samesite none", http.Cookie{Name: "a", Value: "1", SameSite: http.SameSiteNoneMode, Secure: true},
			proto.NetworkCookieParam{Name: "a", Value: "1", URL: target, Secure: true, SameSite: proto.NetworkCookieSameSiteNone}},
		{"samesite lax", http.Cookie{Name: "a", Value: "1", SameSite: http.SameSiteLaxMode},
			proto.NetworkCookieParam{Name: "a", Value: "1", URL: target, SameSite: proto.NetworkCookieSameSiteLax}},
		{"samesite default", http.Cookie{Name: "a", Value: "1", SameSite: http.SameSiteDefaultMode},
			proto.NetworkCookieParam{Name: "a", Value: "1", URL: target, SameSite: proto.NetworkCookieSameSiteLax}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cookieParams([]*http.Cookie{&tc.in}, target)
			if len(got) != 1 {
				t.Fatalf("got %d params, want 1", len(got))
			}
			if *got[0] != tc.want {
				t.Fatalf("param = %+v\n want   %+v", *got[0], tc.want)
			}
			if got[0].URL != "" && got[0].Domain != "" {
				t.Fatal("URL and Domain are both set")
			}
		})
	}
	if got := cookieParams([]*http.Cookie{nil}, target); len(got) != 0 {
		t.Fatalf("nil cookie produced %d params", len(got))
	}
}
