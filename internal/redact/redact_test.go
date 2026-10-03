package redact

import (
	"strings"
	"testing"
)

func TestIsSensitiveName(t *testing.T) {
	for _, n := range []string{
		"password", "user_password", "Passwd", "api_key", "X-Api-Key", "authorization",
		"access_token", "csrf_token", "_csrf", "sessionid", "otp_code", "card_number",
		"cvv", "client_secret", "code", "PIN", "jwt", "oauth_cred_json",
	} {
		if !IsSensitiveName(n) {
			t.Errorf("%q should be sensitive", n)
		}
	}
	for _, n := range []string{"", "q", "search", "email", "username", "zipcode", "page", "category", "id"} {
		if IsSensitiveName(n) {
			t.Errorf("%q should not be sensitive", n)
		}
	}
	// Every entry of the exact tables is matched.
	for k := range JSONFields {
		if !IsSensitiveName(k) {
			t.Errorf("JSONFields entry %q not matched", k)
		}
	}
	for k := range HeaderNames {
		if !IsSensitiveName(k) {
			t.Errorf("HeaderNames entry %q not matched", k)
		}
	}
}

func TestURL(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://app.test/a?q=1", "https://app.test/a?q=1"},
		{"https://admin:hunter2@app.test/", "https://app.test/"},
		{"https://app.test/cb?code=abc&state=xyz", "https://app.test/cb?code=%3Credacted%3E&state=xyz"},
		{"https://app.test/#access_token=tok&expires_in=3600", "https://app.test/#access_token=%3Credacted%3E&expires_in=3600"},
		{"https://app.test/#/route", "https://app.test/#/route"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := URL(tt.in); got != tt.want {
			t.Errorf("URL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	if got := URL("https://u:p@app.test/?api_key=SECRETCANARY"); strings.Contains(got, "SECRETCANARY") || strings.Contains(got, "u:p") {
		t.Errorf("canary survived: %q", got)
	}
}
