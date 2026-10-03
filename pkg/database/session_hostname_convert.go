package database

import (
	"encoding/json"
	"strings"

	"github.com/vigolium/vigolium/pkg/authentication"
)

// extractPrimaryToken extracts the primary session token value from a headers map.
// It checks Authorization (Bearer/token) first, then Cookie, then falls back to
// the first header value. Returns empty string if no headers.
func ExtractPrimaryToken(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}

	// Prefer Authorization header — strip "Bearer " / "Token " prefix.
	for k, v := range headers {
		lower := strings.ToLower(k)
		if lower == "authorization" {
			v = strings.TrimSpace(v)
			for _, prefix := range []string{"Bearer ", "bearer ", "Token ", "token "} {
				if strings.HasPrefix(v, prefix) {
					return strings.TrimPrefix(v, prefix)
				}
			}
			return v
		}
	}

	// Fall back to Cookie header value.
	for k, v := range headers {
		if strings.ToLower(k) == "cookie" {
			return v
		}
	}

	// Last resort: first header value.
	for _, v := range headers {
		return v
	}
	return ""
}

// AuthenticationHostnameToSession converts a DB AuthenticationHostname row to a native authentication.Session.
//
// A row commonly carries BOTH a login flow and the headers that flow produced
// last time (SessionToAuthenticationHostname writes both, and the stored headers
// are what `vigolium session` shows the operator). A Session may name only ONE
// credential source, though — Session.Validate rejects more, and
// Session.IsHydrated treats stored headers as "already logged in" — so exactly
// one is restored, in this order:
//
//	login flow (login_url) → raw login request → static headers
//
// A row with a login flow therefore restores with NIL headers, which is what
// makes the login RE-RUN: the stored token is from an earlier scan and is very
// likely expired, and the scan that reused it spent its whole run getting 401s.
// Carrying both instead made NewManager reject the session outright and failed
// session initialization for the entire scan, so a DB-sourced login session
// never worked at all.
//
// Note: the DB schema does not carry the type/token_path shorthand fields —
// only the expanded ExtractRules. SessionToAuthenticationHostname normalizes
// shorthand into explicit rules on write so they round-trip correctly.
func AuthenticationHostnameToSession(sh *AuthenticationHostname) *authentication.Session {
	if sh == nil {
		return nil
	}

	s := &authentication.Session{
		Name: sh.SessionName,
		Role: authentication.Role(sh.SessionRole),
	}

	// Map flat login fields to LoginFlow if login_url is set.
	switch {
	case sh.LoginURL != "":
		lf := &authentication.LoginFlow{
			URL:         sh.LoginURL,
			Method:      sh.LoginMethod,
			ContentType: sh.LoginContentType,
			Body:        sh.LoginBody,
		}
		lf.Extract = decodeExtractRules(sh.ExtractRules)
		s.Login = lf
	case sh.LoginRequest != "":
		s.LoginRequest = sh.LoginRequest
	default:
		s.Headers = sh.Headers
	}

	return s
}

// decodeExtractRules parses the extract_rules column into typed rules, nil when
// there are none or the stored value is unreadable.
//
// It accepts TWO encodings because the column holds both. The field is a Go
// string mapped to a `jsonb` column, and bun's write side JSON-encodes the
// string — so the array `[{...}]` lands as the JSON *string* `"[{...}]"` —
// while its read side hands back the raw column text, quotes and escapes
// included. Every stored login flow is therefore double-encoded, and the single
// `json.Unmarshal` this used to do failed on all of them: the restored flow had
// zero extract rules, Validate rejected it ("login.extract requires at least
// one rule"), and session initialization failed for the WHOLE scan. That is why
// a session persisted by one scan could not be reused by the next.
//
// Unwrapping on read fixes every existing row without a migration and without
// changing what is written (a single-encoded write would not survive bun's own
// read path). A plain array is accepted too, so a row written by any other
// producer also works.
func decodeExtractRules(raw string) []authentication.ExtractRule {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var rules []authentication.ExtractRule
	if err := json.Unmarshal([]byte(raw), &rules); err == nil {
		return rules
	}
	// Double-encoded: a JSON string whose contents are the array.
	var inner string
	if err := json.Unmarshal([]byte(raw), &inner); err != nil {
		return nil
	}
	if err := json.Unmarshal([]byte(inner), &rules); err != nil {
		return nil
	}
	return rules
}

// AuthenticationHostnamesToSessionConfig converts a slice of DB rows (typically for one hostname)
// into a authentication.SessionConfig with ordered sessions.
func AuthenticationHostnamesToSessionConfig(rows []*AuthenticationHostname) *authentication.SessionConfig {
	if len(rows) == 0 {
		return nil
	}
	cfg := &authentication.SessionConfig{
		Sessions: make([]authentication.Session, 0, len(rows)),
	}
	for _, sh := range rows {
		s := AuthenticationHostnameToSession(sh)
		if s != nil {
			cfg.Sessions = append(cfg.Sessions, *s)
		}
	}
	return cfg
}

// SessionToAuthenticationHostname converts a native authentication.Session to a DB AuthenticationHostname row.
// The caller must set ProjectUUID, Hostname, and optionally ScanUUID on the returned row.
func SessionToAuthenticationHostname(s *authentication.Session, position int) *AuthenticationHostname {
	if s == nil {
		return nil
	}

	sh := &AuthenticationHostname{
		SessionName:  s.Name,
		SessionRole:  string(s.Role),
		Position:     position,
		SessionToken: ExtractPrimaryToken(s.Headers),
		Headers:      s.Headers,
		Source:       "cli",
	}

	if s.Login != nil {
		// Expand the type/token_path shorthand into explicit Extract rules
		// before serializing — the DB schema has no columns for those
		// shorthand fields (see AuthenticationHostname in models.go), so a
		// shorthand-only LoginFlow would round-trip with zero extract rules
		// and silently fail to hydrate. NormalizeLoginFlow is a no-op when
		// Extract is already populated.
		authentication.NormalizeLoginFlow(s.Login)

		sh.LoginURL = s.Login.URL
		sh.LoginMethod = s.Login.Method
		sh.LoginContentType = s.Login.ContentType
		sh.LoginBody = s.Login.Body

		if len(s.Login.Extract) > 0 {
			if data, err := json.Marshal(s.Login.Extract); err == nil {
				sh.ExtractRules = string(data)
			}
		}
	}

	if s.LoginRequest != "" {
		sh.LoginRequest = s.LoginRequest
	}

	return sh
}

// SessionsToAuthenticationHostnames converts a slice of authentication.Session objects to DB rows
// for a given hostname. Sets ProjectUUID and Hostname on each row.
func SessionsToAuthenticationHostnames(sessions []*authentication.Session, projectUUID, hostname string) []*AuthenticationHostname {
	if len(sessions) == 0 {
		return nil
	}

	rows := make([]*AuthenticationHostname, 0, len(sessions))
	for i, s := range sessions {
		sh := SessionToAuthenticationHostname(s, i)
		if sh == nil {
			continue
		}
		sh.ProjectUUID = projectUUID
		sh.Hostname = hostname
		rows = append(rows, sh)
	}
	return rows
}
