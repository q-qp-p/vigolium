package browser

import (
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"
)

// TestCdpCookieToHTTP pins the conversion the cookie carry depends on. It is
// pure, so it runs without a browser.
func TestCdpCookieToHTTP(t *testing.T) {
	expiry := time.Date(2030, 6, 1, 12, 0, 0, 0, time.UTC)

	t.Run("host-only keeps its bare domain", func(t *testing.T) {
		// The leading dot (or its absence) is the ONLY record of whether a
		// cookie is host-only; stripping it here would silently widen every
		// host-only cookie to the whole domain downstream.
		got := cdpCookieToHTTP(&proto.NetworkCookie{
			Name: "sid", Value: "s", Domain: "app.test", Path: "/", Session: true,
		})
		if got == nil {
			t.Fatal("expected a cookie")
		}
		if got.Domain != "app.test" {
			t.Errorf("Domain = %q, want the bare host", got.Domain)
		}
		if !got.Expires.IsZero() {
			t.Errorf("Expires = %v, want zero for a session cookie", got.Expires)
		}
	})

	t.Run("domain cookie keeps its leading dot", func(t *testing.T) {
		got := cdpCookieToHTTP(&proto.NetworkCookie{
			Name: "tracker", Value: "t", Domain: ".app.test", Path: "/", Session: true,
		})
		if got.Domain != ".app.test" {
			t.Errorf("Domain = %q, want the leading dot preserved", got.Domain)
		}
	})

	t.Run("persistent cookie carries its expiry", func(t *testing.T) {
		got := cdpCookieToHTTP(&proto.NetworkCookie{
			Name:    "remember",
			Value:   "r",
			Domain:  "app.test",
			Path:    "/",
			Expires: proto.TimeSinceEpoch(float64(expiry.Unix())),
		})
		if got.Expires.IsZero() {
			t.Fatal("Expires is zero; a persistent cookie's expiry was dropped")
		}
		if got.Expires.Unix() != expiry.Unix() {
			t.Errorf("Expires = %v, want %v", got.Expires.UTC(), expiry)
		}
	})

	t.Run("a session cookie with an expiry still reads as a session cookie", func(t *testing.T) {
		got := cdpCookieToHTTP(&proto.NetworkCookie{
			Name: "s", Domain: "app.test", Session: true,
			Expires: proto.TimeSinceEpoch(float64(expiry.Unix())),
		})
		if !got.Expires.IsZero() {
			t.Errorf("Expires = %v, want zero: CDP says Session", got.Expires)
		}
	})

	t.Run("CDP's -1 no-expiry sentinel is not a 1969 expiry", func(t *testing.T) {
		got := cdpCookieToHTTP(&proto.NetworkCookie{
			Name: "s", Domain: "app.test", Expires: -1,
		})
		if !got.Expires.IsZero() {
			t.Errorf("Expires = %v, want zero; a negative epoch is 'no expiry', not an expired cookie",
				got.Expires)
		}
	})

	t.Run("flags are carried", func(t *testing.T) {
		got := cdpCookieToHTTP(&proto.NetworkCookie{
			Name: "x", Domain: "app.test", Path: "/admin", Secure: true, HTTPOnly: true, Session: true,
		})
		if !got.Secure || !got.HttpOnly {
			t.Errorf("flags lost: Secure=%v HttpOnly=%v", got.Secure, got.HttpOnly)
		}
		if got.Path != "/admin" {
			t.Errorf("Path = %q, want /admin", got.Path)
		}
	})

	t.Run("nil and nameless are skipped", func(t *testing.T) {
		if cdpCookieToHTTP(nil) != nil {
			t.Error("nil cookie must convert to nil")
		}
		if cdpCookieToHTTP(&proto.NetworkCookie{Value: "v", Domain: "app.test"}) != nil {
			t.Error("a nameless cookie must convert to nil")
		}
	})
}
