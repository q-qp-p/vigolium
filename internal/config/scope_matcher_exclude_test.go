package config

import "testing"

// TestExplicitlyExcluded covers the ONE scope question that is safe to answer
// before a request leaves: did the operator name this and say no. Everything else
// about the scope — includes, origin mode, static-file filtering, the dynamic
// allow-set — must not influence it, because enforcing those pre-send would
// narrow discovery in ways nobody asked for (triage C12).
func TestExplicitlyExcluded(t *testing.T) {
	tests := []struct {
		name     string
		cfg      ScopeConfig
		host     string
		path     string
		excluded bool
	}{
		{
			name: "default pass-all config excludes nothing",
			cfg:  *DefaultScopeConfig(),
			host: "example.com", path: "/admin",
		},
		{
			name: "include-only config excludes nothing",
			cfg: ScopeConfig{
				Host: ScopeRule{Include: []string{"*.example.com"}},
				Path: ScopeRule{Include: []string{"/api/*"}},
			},
			host: "other.com", path: "/admin",
		},
		{
			name: "host exclude matches exactly",
			cfg: ScopeConfig{
				Host: ScopeRule{Include: []string{"*"}, Exclude: []string{"logout.example.com"}},
			},
			host: "logout.example.com", path: "/", excluded: true,
		},
		{
			name: "host exclude glob matches a subdomain",
			cfg: ScopeConfig{
				Host: ScopeRule{Exclude: []string{"*.cdn.example.com"}},
			},
			host: "assets.cdn.example.com", path: "/x", excluded: true,
		},
		{
			name: "host exclude glob does not match the apex",
			cfg: ScopeConfig{
				Host: ScopeRule{Exclude: []string{"*.cdn.example.com"}},
			},
			host: "cdn.example.com", path: "/x",
		},
		{
			name: "host exclude is case-insensitive",
			cfg: ScopeConfig{
				Host: ScopeRule{Exclude: []string{"Logout.Example.COM"}},
			},
			host: "logout.example.com", path: "/", excluded: true,
		},
		{
			name: "path exclude matches",
			cfg: ScopeConfig{
				Path: ScopeRule{Exclude: []string{"/admin/*"}},
			},
			host: "example.com", path: "/admin/users", excluded: true,
		},
		{
			name: "path exclude does not match a sibling prefix",
			cfg: ScopeConfig{
				Path: ScopeRule{Exclude: []string{"/admin/*"}},
			},
			host: "example.com", path: "/administrator",
		},
		{
			name: "either rule is enough",
			cfg: ScopeConfig{
				Host: ScopeRule{Exclude: []string{"never.example.com"}},
				Path: ScopeRule{Exclude: []string{"/logout"}},
			},
			host: "example.com", path: "/logout", excluded: true,
		},
		{
			name: "a non-excluded request under exclusion rules passes",
			cfg: ScopeConfig{
				Host: ScopeRule{Exclude: []string{"never.example.com"}},
				Path: ScopeRule{Exclude: []string{"/logout"}},
			},
			host: "example.com", path: "/orders",
		},
		{
			name:     "status/content-type excludes are not consulted",
			cfg:      ScopeConfig{StatusCode: ScopeRule{Exclude: []string{"404"}}},
			host:     "example.com",
			path:     "/missing",
			excluded: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewScopeMatcher(tt.cfg)
			if got := m.ExplicitlyExcluded(tt.host, tt.path); got != tt.excluded {
				t.Errorf("ExplicitlyExcluded(%q, %q) = %v, want %v", tt.host, tt.path, got, tt.excluded)
			}
		})
	}
}

func TestExplicitlyExcluded_NilMatcher(t *testing.T) {
	var m *ScopeMatcher
	if m.ExplicitlyExcluded("example.com", "/admin") {
		t.Fatal("a nil matcher must exclude nothing")
	}
}

// TestExplicitlyExcluded_IgnoresOriginMode pins that the origin-mode narrowing —
// which legitimately pushes a host out of InScope — is NOT an explicit denial.
// If it were, discovery would stop crawling hosts an operator deliberately
// reached through --follow-subdomains or a seed list.
func TestExplicitlyExcluded_IgnoresOriginMode(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "strict"
	m := NewScopeMatcher(cfg, "https://example.com")

	if m.HostInScope("other.example.com") {
		t.Fatal("precondition: strict origin mode should reject a sibling host")
	}
	if m.ExplicitlyExcluded("other.example.com", "/") {
		t.Fatal("origin mode must not read as an explicit exclusion")
	}
}
