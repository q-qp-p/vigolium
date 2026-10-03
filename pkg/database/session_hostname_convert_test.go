package database

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/authentication"
)

func TestAuthenticationHostnameToSession_StaticHeaders(t *testing.T) {
	sh := &AuthenticationHostname{
		SessionName: "api-key",
		SessionRole: "primary",
		Headers:     map[string]string{"X-API-Key": "secret123"},
	}

	s := AuthenticationHostnameToSession(sh)
	if s == nil {
		t.Fatal("expected non-nil session")
	}
	if s.Name != "api-key" {
		t.Errorf("expected name=api-key, got %q", s.Name)
	}
	if s.Role != authentication.RolePrimary {
		t.Errorf("expected role=primary, got %q", s.Role)
	}
	if s.Headers["X-API-Key"] != "secret123" {
		t.Errorf("expected X-API-Key header, got %v", s.Headers)
	}
	if s.Login != nil {
		t.Error("expected nil Login for static-header session")
	}
}

func TestAuthenticationHostnameToSession_LoginFlow(t *testing.T) {
	sh := &AuthenticationHostname{
		SessionName:      "admin",
		SessionRole:      "primary",
		LoginURL:         "https://example.com/login",
		LoginMethod:      "POST",
		LoginContentType: "application/json",
		LoginBody:        `{"user":"admin","pass":"admin"}`,
		ExtractRules:     `[{"source":"cookie","name":"session_id"},{"source":"json","path":"$.token","apply_as":"Authorization: Bearer {value}"}]`,
	}

	s := AuthenticationHostnameToSession(sh)
	if s == nil {
		t.Fatal("expected non-nil session")
	}
	if s.Login == nil {
		t.Fatal("expected non-nil Login")
	}
	if s.Login.URL != "https://example.com/login" {
		t.Errorf("unexpected login URL: %q", s.Login.URL)
	}
	if s.Login.Method != "POST" {
		t.Errorf("unexpected method: %q", s.Login.Method)
	}
	if s.Login.ContentType != "application/json" {
		t.Errorf("unexpected content type: %q", s.Login.ContentType)
	}
	if len(s.Login.Extract) != 2 {
		t.Fatalf("expected 2 extract rules, got %d", len(s.Login.Extract))
	}
	if s.Login.Extract[0].Source != authentication.ExtractCookie {
		t.Errorf("expected cookie source, got %q", s.Login.Extract[0].Source)
	}
	if s.Login.Extract[0].Name != "session_id" {
		t.Errorf("expected name=session_id, got %q", s.Login.Extract[0].Name)
	}
	if s.Login.Extract[1].ApplyAs != "Authorization: Bearer {value}" {
		t.Errorf("unexpected apply_as: %q", s.Login.Extract[1].ApplyAs)
	}
}

func TestAuthenticationHostnameToSession_Nil(t *testing.T) {
	s := AuthenticationHostnameToSession(nil)
	if s != nil {
		t.Error("expected nil for nil input")
	}
}

func TestAuthenticationHostnamesToSessionConfig(t *testing.T) {
	rows := []*AuthenticationHostname{
		{SessionName: "admin", SessionRole: "primary", Headers: map[string]string{"Authorization": "Bearer tok1"}},
		{SessionName: "user", SessionRole: "compare", Headers: map[string]string{"Authorization": "Bearer tok2"}},
	}

	cfg := AuthenticationHostnamesToSessionConfig(rows)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.Sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(cfg.Sessions))
	}
	if cfg.Sessions[0].Name != "admin" {
		t.Errorf("expected first session=admin, got %q", cfg.Sessions[0].Name)
	}
	if cfg.Sessions[1].Role != authentication.RoleCompare {
		t.Errorf("expected second role=compare, got %q", cfg.Sessions[1].Role)
	}
}

func TestAuthenticationHostnamesToSessionConfig_Empty(t *testing.T) {
	cfg := AuthenticationHostnamesToSessionConfig(nil)
	if cfg != nil {
		t.Error("expected nil for empty input")
	}
}

func TestSessionToAuthenticationHostname_StaticHeaders(t *testing.T) {
	s := &authentication.Session{
		Name:    "admin",
		Role:    authentication.RolePrimary,
		Headers: map[string]string{"Authorization": "Bearer tok1"},
	}

	sh := SessionToAuthenticationHostname(s, 0)
	if sh == nil {
		t.Fatal("expected non-nil row")
	}
	if sh.SessionName != "admin" {
		t.Errorf("expected session_name=admin, got %q", sh.SessionName)
	}
	if sh.SessionRole != "primary" {
		t.Errorf("expected role=primary, got %q", sh.SessionRole)
	}
	if sh.Headers["Authorization"] != "Bearer tok1" {
		t.Errorf("expected Authorization header, got %v", sh.Headers)
	}
	if sh.Source != "cli" {
		t.Errorf("expected source=cli, got %q", sh.Source)
	}
	if sh.Position != 0 {
		t.Errorf("expected position=0, got %d", sh.Position)
	}
}

func TestSessionToAuthenticationHostname_LoginFlow(t *testing.T) {
	s := &authentication.Session{
		Name: "user",
		Role: authentication.RoleCompare,
		Login: &authentication.LoginFlow{
			URL:         "https://example.com/login",
			Method:      "POST",
			ContentType: "application/json",
			Body:        `{"user":"test","pass":"test"}`,
			Extract: []authentication.ExtractRule{
				{Source: authentication.ExtractCookie, Name: "sid"},
			},
		},
	}

	sh := SessionToAuthenticationHostname(s, 1)
	if sh == nil {
		t.Fatal("expected non-nil row")
	}
	if sh.LoginURL != "https://example.com/login" {
		t.Errorf("unexpected login_url: %q", sh.LoginURL)
	}
	if sh.LoginMethod != "POST" {
		t.Errorf("unexpected login_method: %q", sh.LoginMethod)
	}
	if sh.ExtractRules == "" {
		t.Error("expected non-empty extract_rules")
	}
	if sh.Position != 1 {
		t.Errorf("expected position=1, got %d", sh.Position)
	}
}

func TestSessionToAuthenticationHostname_Nil(t *testing.T) {
	sh := SessionToAuthenticationHostname(nil, 0)
	if sh != nil {
		t.Error("expected nil for nil input")
	}
}

func TestSessionsToAuthenticationHostnames(t *testing.T) {
	sessions := []*authentication.Session{
		{Name: "admin", Role: authentication.RolePrimary, Headers: map[string]string{"Cookie": "s=1"}},
		{Name: "user", Role: authentication.RoleCompare, Headers: map[string]string{"Cookie": "s=2"}},
	}

	rows := SessionsToAuthenticationHostnames(sessions, "proj-1", "example.com")
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	for _, row := range rows {
		if row.ProjectUUID != "proj-1" {
			t.Errorf("expected project_uuid=proj-1, got %q", row.ProjectUUID)
		}
		if row.Hostname != "example.com" {
			t.Errorf("expected hostname=example.com, got %q", row.Hostname)
		}
	}
	if rows[0].SessionName != "admin" || rows[1].SessionName != "user" {
		t.Errorf("unexpected session names: %q, %q", rows[0].SessionName, rows[1].SessionName)
	}
}

func TestSessionToAuthenticationHostname_Roundtrip(t *testing.T) {
	original := &authentication.Session{
		Name:    "roundtrip",
		Role:    authentication.RolePrimary,
		Headers: map[string]string{"Authorization": "Bearer xyz"},
		Login: &authentication.LoginFlow{
			URL:         "https://app.com/api/login",
			Method:      "POST",
			ContentType: "application/json",
			Body:        `{"u":"a","p":"b"}`,
			Extract: []authentication.ExtractRule{
				{Source: authentication.ExtractJSON, Path: "$.token", ApplyAs: "Authorization: Bearer {value}"},
			},
		},
	}

	sh := SessionToAuthenticationHostname(original, 0)
	restored := AuthenticationHostnameToSession(sh)

	if restored.Name != original.Name {
		t.Errorf("name mismatch: %q vs %q", restored.Name, original.Name)
	}
	if restored.Role != original.Role {
		t.Errorf("role mismatch: %q vs %q", restored.Role, original.Role)
	}
	if restored.Login == nil {
		t.Fatal("expected non-nil Login after roundtrip")
	}
	if restored.Login.URL != original.Login.URL {
		t.Errorf("login URL mismatch: %q vs %q", restored.Login.URL, original.Login.URL)
	}
	if len(restored.Login.Extract) != 1 {
		t.Fatalf("expected 1 extract rule, got %d", len(restored.Login.Extract))
	}
	if restored.Login.Extract[0].ApplyAs != original.Login.Extract[0].ApplyAs {
		t.Errorf("apply_as mismatch: %q vs %q", restored.Login.Extract[0].ApplyAs, original.Login.Extract[0].ApplyAs)
	}

	// The two facts that make a DB login session usable at all. The row carries
	// BOTH the login flow and the headers that flow produced; a Session may name
	// only one credential source, so the restored session must drop the stored
	// headers:
	//   - with both, Validate rejects the session and initSessions fails for the
	//     WHOLE scan, so a DB-sourced login session never worked.
	//   - with headers alone, IsHydrated is true and the login never re-runs, so
	//     the scan reuses a token from an earlier run and collects 401s.
	if err := restored.Validate(); err != nil {
		t.Errorf("restored session does not validate: %v", err)
	}
	if restored.IsHydrated() {
		t.Error("a restored login session must NOT read as hydrated, or the login will not re-run")
	}
	if len(restored.Headers) != 0 {
		t.Errorf("restored Headers = %v, want none alongside a login flow", restored.Headers)
	}
	// The row itself still carries the headers — they are what `vigolium session`
	// shows the operator, and dropping them on write would lose that.
	if sh.Headers["Authorization"] != "Bearer xyz" {
		t.Errorf("row Headers = %v, want the last hydrated token preserved", sh.Headers)
	}
}

// A row that carries a raw login request alongside stored headers restores with
// the raw request and no headers, for the same single-source reason.
func TestAuthenticationHostnameToSession_RawLoginDropsStoredHeaders(t *testing.T) {
	sh := &AuthenticationHostname{
		SessionName:  "raw",
		SessionRole:  "primary",
		LoginRequest: "POST /login HTTP/1.1\r\nHost: app.test\r\n\r\nu=a&p=b",
		Headers:      map[string]string{"Authorization": "Bearer stale"},
	}
	s := AuthenticationHostnameToSession(sh)
	if s == nil {
		t.Fatal("expected non-nil session")
	}
	if s.LoginRequest == "" {
		t.Error("expected the raw login request to be restored")
	}
	if len(s.Headers) != 0 {
		t.Errorf("Headers = %v, want none alongside a raw login request", s.Headers)
	}
	if err := s.Validate(); err != nil {
		t.Errorf("restored session does not validate: %v", err)
	}
}

// A row with a login flow AND a raw login request restores with the flow only:
// the flow is the executable form (HydrateSessions runs Session.Login and
// nothing else), the raw request is provenance, and naming both fails Validate.
func TestAuthenticationHostnameToSession_LoginFlowOutranksRawRequest(t *testing.T) {
	sh := &AuthenticationHostname{
		SessionName:  "both",
		SessionRole:  "primary",
		LoginURL:     "https://app.test/login",
		LoginMethod:  "POST",
		LoginBody:    `{"u":"a"}`,
		ExtractRules: `[{"source":"json","path":"$.token","apply_as":"Authorization: Bearer {value}"}]`,
		LoginRequest: "POST /login HTTP/1.1\r\nHost: app.test\r\n\r\n{\"u\":\"a\"}",
		Headers:      map[string]string{"Authorization": "Bearer stale"},
	}
	s := AuthenticationHostnameToSession(sh)
	if s == nil || s.Login == nil {
		t.Fatal("expected a restored session with a login flow")
	}
	if s.LoginRequest != "" {
		t.Error("the raw request must not be carried alongside the login flow")
	}
	if len(s.Headers) != 0 {
		t.Errorf("Headers = %v, want none", s.Headers)
	}
	if err := s.Validate(); err != nil {
		t.Errorf("restored session does not validate: %v", err)
	}
}

// A static-header row (no login flow at all) keeps its headers and reads as
// hydrated — there is nothing to re-run.
func TestAuthenticationHostnameToSession_StaticHeadersStayHydrated(t *testing.T) {
	sh := &AuthenticationHostname{
		SessionName: "static",
		SessionRole: "primary",
		Headers:     map[string]string{"X-API-Key": "k"},
	}
	s := AuthenticationHostnameToSession(sh)
	if s == nil {
		t.Fatal("expected non-nil session")
	}
	if s.Headers["X-API-Key"] != "k" {
		t.Errorf("Headers = %v, want the static header kept", s.Headers)
	}
	if !s.IsHydrated() {
		t.Error("a static-header session is hydrated by definition")
	}
	if err := s.Validate(); err != nil {
		t.Errorf("restored session does not validate: %v", err)
	}
}

// TestSessionToAuthenticationHostname_TokenPathShorthand verifies that a
// LoginFlow using the type/token_path shorthand (without an explicit Extract
// array) is normalized into concrete extract rules at write time. The DB
// schema has no columns for the shorthand fields, so without normalization
// the row would round-trip with an empty extract_rules JSON and the restored
// session would silently fail to hydrate at login time. Mirrors the
// agent-side regression guard in pkg/agent/swarm_hydrate_test.go.
func TestSessionToAuthenticationHostname_TokenPathShorthand(t *testing.T) {
	original := &authentication.Session{
		Name: "admin",
		Role: authentication.RolePrimary,
		Login: &authentication.LoginFlow{
			URL:         "https://app.com/rest/user/login",
			Method:      "POST",
			ContentType: "application/json",
			Body:        `{"email":"admin@app.com","password":"pw"}`,
			// Shorthand: no Extract array, just type + token_path.
			Type:      authentication.LoginTypeBearer,
			TokenPath: ".authentication.token",
		},
	}

	sh := SessionToAuthenticationHostname(original, 0)
	if sh == nil {
		t.Fatal("expected non-nil row")
	}
	if sh.ExtractRules == "" {
		t.Fatal("expected extract_rules to be populated by normalization, got empty")
	}

	restored := AuthenticationHostnameToSession(sh)
	if restored == nil || restored.Login == nil {
		t.Fatal("expected non-nil restored session and login")
	}
	if len(restored.Login.Extract) != 1 {
		t.Fatalf("expected 1 expanded extract rule, got %d", len(restored.Login.Extract))
	}
	rule := restored.Login.Extract[0]
	if rule.Source != authentication.ExtractJSON {
		t.Errorf("expected source=%q, got %q", authentication.ExtractJSON, rule.Source)
	}
	if rule.Path != ".authentication.token" {
		t.Errorf("expected path=.authentication.token, got %q", rule.Path)
	}
	if rule.ApplyAs != "Authorization: Bearer {value}" {
		t.Errorf("expected ApplyAs bearer template, got %q", rule.ApplyAs)
	}
}
