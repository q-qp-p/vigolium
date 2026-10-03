package database

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/authentication"
)

// TestAuthenticationHostname_LoginFlowSurvivesTheDatabase is the real F07
// round trip: through bun and back out of SQLite, not just through the pure
// converters. Two separate defects made a persisted login session unusable by
// the next scan, and both are only visible with a database in the loop:
//
//   - extract_rules is a Go string mapped to a `jsonb` column, so bun's write
//     side JSON-encodes it and its read side returns the raw text. Every stored
//     flow was double-encoded and restored with ZERO extract rules.
//   - the row carries the login flow AND the headers that flow produced, and a
//     Session may name only one credential source.
//
// Either one made Session.Validate fail, which failed session initialization
// for the whole scan — so a scan could persist a session that no later scan
// could load.
func TestAuthenticationHostname_LoginFlowSurvivesTheDatabase(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	const project = "proj-auth-roundtrip"
	const hostname = "app.test"

	// Exactly what a scan persists: a hydrated session whose login flow
	// produced an Authorization header.
	hydrated := &authentication.Session{
		Name: "admin",
		Role: authentication.RolePrimary,
		Headers: map[string]string{
			"Authorization": "Bearer from-the-previous-scan",
		},
		Login: &authentication.LoginFlow{
			URL:         "https://app.test/login",
			Method:      "POST",
			ContentType: "application/json",
			Body:        `{"u":"a","p":"b"}`,
			Extract: []authentication.ExtractRule{
				{Source: authentication.ExtractJSON, Path: "$.token", ApplyAs: "Authorization: Bearer {value}"},
			},
		},
	}

	rows := SessionsToAuthenticationHostnames([]*authentication.Session{hydrated}, project, hostname)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row to persist, got %d", len(rows))
	}
	if err := repo.SaveAuthenticationHostnames(ctx, rows); err != nil {
		t.Fatalf("SaveAuthenticationHostnames: %v", err)
	}

	stored, err := repo.GetAuthenticationHostnamesByHostname(ctx, project, hostname)
	if err != nil {
		t.Fatalf("GetAuthenticationHostnamesByHostname: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("read back %d rows, want 1", len(stored))
	}

	restored := AuthenticationHostnameToSession(stored[0])
	if restored == nil {
		t.Fatal("expected a restored session")
	}

	// The extract rule survived the double encoding.
	if restored.Login == nil {
		t.Fatal("expected a restored login flow")
	}
	if len(restored.Login.Extract) != 1 {
		t.Fatalf("restored %d extract rules, want 1 (extract_rules did not survive the round trip)",
			len(restored.Login.Extract))
	}
	rule := restored.Login.Extract[0]
	if rule.Source != authentication.ExtractJSON || rule.Path != "$.token" ||
		rule.ApplyAs != "Authorization: Bearer {value}" {
		t.Errorf("restored rule = %+v, want the json/$.token/Bearer rule", rule)
	}
	if restored.Login.Body != `{"u":"a","p":"b"}` {
		t.Errorf("restored body = %q", restored.Login.Body)
	}

	// The session is usable: it validates, and it is NOT hydrated, so the login
	// re-runs rather than the scan reusing last run's token.
	if err := restored.Validate(); err != nil {
		t.Errorf("restored session does not validate: %v", err)
	}
	if restored.IsHydrated() {
		t.Error("a restored login session must not read as hydrated")
	}

	// And it gets all the way through the manager, which is where the whole
	// scan used to die.
	if _, err := authentication.NewManager([]*authentication.Session{restored}); err != nil {
		t.Errorf("NewManager rejected the restored session: %v", err)
	}
}

// A static-header session persisted and reloaded keeps its headers and needs no
// login — the other half of the round trip.
func TestAuthenticationHostname_StaticSessionSurvivesTheDatabase(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	const project = "proj-auth-static"
	const hostname = "api.test"

	static := &authentication.Session{
		Name:    "api-key",
		Role:    authentication.RolePrimary,
		Headers: map[string]string{"X-API-Key": "k123"},
	}
	rows := SessionsToAuthenticationHostnames([]*authentication.Session{static}, project, hostname)
	if err := repo.SaveAuthenticationHostnames(ctx, rows); err != nil {
		t.Fatalf("SaveAuthenticationHostnames: %v", err)
	}
	stored, err := repo.GetAuthenticationHostnamesByHostname(ctx, project, hostname)
	if err != nil {
		t.Fatalf("GetAuthenticationHostnamesByHostname: %v", err)
	}
	restored := AuthenticationHostnameToSession(stored[0])
	if restored.Headers["X-API-Key"] != "k123" {
		t.Errorf("restored Headers = %v, want the static key", restored.Headers)
	}
	if restored.Login != nil {
		t.Error("a static session must restore with no login flow")
	}
	if !restored.IsHydrated() {
		t.Error("a static session is hydrated by definition")
	}
	if err := restored.Validate(); err != nil {
		t.Errorf("restored session does not validate: %v", err)
	}
}

// TestDecodeExtractRules covers both stored encodings plus the junk cases,
// since the column holds whatever every past binary wrote.
func TestDecodeExtractRules(t *testing.T) {
	const plain = `[{"source":"json","path":"$.token","apply_as":"Authorization: Bearer {value}"}]`
	const doubled = `"[{\"source\":\"json\",\"path\":\"$.token\",\"apply_as\":\"Authorization: Bearer {value}\"}]"`

	for _, tc := range []struct {
		name  string
		raw   string
		rules int
	}{
		{"plain array", plain, 1},
		{"double-encoded, as bun writes it", doubled, 1},
		{"empty", "", 0},
		{"whitespace", "   ", 0},
		{"not json", "{nope", 0},
		{"a json string that is not an array", `"hello"`, 0},
		{"json null", "null", 0},
		{"empty array", "[]", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeExtractRules(tc.raw)
			if len(got) != tc.rules {
				t.Fatalf("decodeExtractRules(%q) = %d rules, want %d", tc.raw, len(got), tc.rules)
			}
			if tc.rules > 0 && got[0].Path != "$.token" {
				t.Errorf("rule Path = %q, want $.token", got[0].Path)
			}
		})
	}
}
