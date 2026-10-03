package vigtool

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/vigolium/vigolium/pkg/database"
)

// stubAuthStore records saves and serves a fixed set of existing rows.
type stubAuthStore struct {
	mu       sync.Mutex
	existing []*database.AuthenticationHostname
	saved    []*database.AuthenticationHostname
}

func (s *stubAuthStore) GetAuthenticationHostnamesByHostname(_ context.Context, _, hostname string) ([]*database.AuthenticationHostname, error) {
	var out []*database.AuthenticationHostname
	for _, r := range s.existing {
		if r.Hostname == hostname {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *stubAuthStore) SaveAuthenticationHostname(_ context.Context, sh *database.AuthenticationHostname) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saved = append(s.saved, sh)
	return nil
}

// stubAdapter answers agent-browser invocations without a subprocess.
type stubAdapter struct {
	mu      sync.Mutex
	version string
	cookies string
	failOn  string // step subcommand that fails ("click", "wait", ...)
	calls   [][]string
}

func (a *stubAdapter) run(_ context.Context, _ string, _ time.Duration, args ...string) ([]byte, error) {
	a.mu.Lock()
	a.calls = append(a.calls, append([]string(nil), args...))
	a.mu.Unlock()
	if slices.Equal(args, []string{"--version"}) {
		return []byte(a.version + "\n"), nil
	}
	sub := ""
	if len(args) > 2 {
		sub = args[2] // after --session-name <name>
	}
	switch sub {
	case a.failOn:
		return nil, errors.New("exit status 1")
	case "get":
		return []byte("https://app.example.com/home\n"), nil
	case "cookies":
		return []byte(a.cookies), nil
	}
	return []byte("ok\n"), nil
}

// stepCalls returns the recorded invocations other than the version preflight,
// with the leading --session-name pair removed.
func (a *stubAdapter) stepCalls() [][]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out [][]string
	for _, c := range a.calls {
		if len(c) > 2 && c[0] == "--session-name" {
			out = append(out, c[2:])
		}
	}
	return out
}

func (a *stubAdapter) versionCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, c := range a.calls {
		if slices.Equal(c, []string{"--version"}) {
			n++
		}
	}
	return n
}

func newStubBrowserAuth(store *stubAuthStore, adapter *stubAdapter, headed bool) *browserAuthTool {
	if adapter.version == "" {
		adapter.version = "agent-browser 0.26.0"
	}
	return &browserAuthTool{
		repo:        store,
		projectUUID: "proj",
		bin:         "agent-browser",
		headed:      headed,
		run:         adapter.run,
	}
}

func steps(items ...map[string]any) []any {
	out := make([]any, len(items))
	for i, it := range items {
		out[i] = it
	}
	return out
}

const appCookies = `[{"name":"sid","value":"abc","domain":"app.example.com","path":"/"}]`

// TestBrowserAuthArgv pins each step kind to the 0.26.0 command surface; in
// particular wait takes a positional selector or millisecond count (the CLI
// has no --selector / --ms).
func TestBrowserAuthArgv(t *testing.T) {
	cases := []struct {
		name string
		step map[string]any
		want []string
	}{
		{"open", map[string]any{"action": "open", "url": "https://app.example.com/login"}, []string{"open", "https://app.example.com/login"}},
		{"snapshot", map[string]any{"action": "snapshot"}, []string{"snapshot", "-i", "--json"}},
		{"snapshot scoped", map[string]any{"action": "snapshot", "scope": "#login"}, []string{"snapshot", "-i", "--json", "-s", "#login"}},
		{"fill", map[string]any{"action": "fill", "ref": "@e3", "value": "alice"}, []string{"fill", "@e3", "alice"}},
		{"click", map[string]any{"action": "click", "ref": "@e4"}, []string{"click", "@e4"}},
		{"press", map[string]any{"action": "press", "key": "Enter"}, []string{"press", "Enter"}},
		{"wait selector", map[string]any{"action": "wait", "wait_selector": "#dashboard"}, []string{"wait", "#dashboard"}},
		{"wait ms", map[string]any{"action": "wait", "wait_ms": float64(1500)}, []string{"wait", "1500"}},
		{"wait url", map[string]any{"action": "wait", "wait_url": "**/dashboard"}, []string{"wait", "--url", "**/dashboard"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &stubAdapter{}
			ba := newStubBrowserAuth(&stubAuthStore{}, adapter, false)
			res, err := ba.Execute(context.Background(), map[string]any{"steps": steps(tc.step)}, nil)
			if err != nil || res.IsError {
				t.Fatalf("Execute: err=%v result=%s", err, res.Content)
			}
			calls := adapter.stepCalls()
			if len(calls) != 1 || !reflect.DeepEqual(calls[0], tc.want) {
				t.Fatalf("argv = %q, want %q", calls, tc.want)
			}
			for _, a := range calls[0] {
				if a == "--selector" || a == "--ms" {
					t.Fatalf("argv %q carries a flag 0.26.0 does not accept", calls[0])
				}
			}
		})
	}
}

// TestBrowserAuthHeaded: the headed flag rides on open steps only.
func TestBrowserAuthHeaded(t *testing.T) {
	adapter := &stubAdapter{}
	ba := newStubBrowserAuth(&stubAuthStore{}, adapter, true)
	_, err := ba.Execute(context.Background(), map[string]any{"steps": steps(
		map[string]any{"action": "open", "url": "https://app.example.com"},
		map[string]any{"action": "snapshot"},
		map[string]any{"action": "click", "ref": "@e1"},
	)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	calls := adapter.stepCalls()
	if len(calls) != 3 {
		t.Fatalf("calls = %q", calls)
	}
	if !slices.Contains(calls[0], "--headed") {
		t.Errorf("open argv %q lacks --headed", calls[0])
	}
	for _, c := range calls[1:] {
		if slices.Contains(c, "--headed") {
			t.Errorf("non-open argv %q carries --headed", c)
		}
	}
}

// TestBrowserAuthFailedStepSkipsSave: a failed batch is an error result and
// never writes the session unless forced.
func TestBrowserAuthFailedStepSkipsSave(t *testing.T) {
	failing := steps(
		map[string]any{"action": "open", "url": "https://app.example.com/login"},
		map[string]any{"action": "click", "ref": "@e9"},
		map[string]any{"action": "snapshot"},
	)
	t.Run("no force", func(t *testing.T) {
		store := &stubAuthStore{}
		adapter := &stubAdapter{failOn: "click", cookies: appCookies}
		ba := newStubBrowserAuth(store, adapter, false)
		res, err := ba.Execute(context.Background(), map[string]any{
			"steps":   failing,
			"save_as": map[string]any{"hostname": "app.example.com", "session_name": "user"},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatal("a failed step must make the result an error")
		}
		if len(store.saved) != 0 {
			t.Fatalf("failed batch wrote %d session row(s)", len(store.saved))
		}
		if saved, _ := res.Details["saved"].(bool); saved {
			t.Error("details.saved = true for a skipped save")
		}
		sf, _ := res.Details["step_failed"].(map[string]any)
		if sf["index"] != 1 || sf["action"] != "click" {
			t.Errorf("step_failed = %v, want index 1 / click", sf)
		}
		if n := len(adapter.stepCalls()); n != 2 {
			t.Errorf("batch ran %d step(s) after the failure; want it stopped at the failing step", n)
		}
		if !strings.Contains(res.Content, "save_as skipped") {
			t.Errorf("content does not explain the skipped save: %s", res.Content)
		}
	})
	t.Run("existing session preserved", func(t *testing.T) {
		store := &stubAuthStore{existing: []*database.AuthenticationHostname{{
			Hostname: "app.example.com", SessionName: "user", Headers: map[string]string{"Cookie": "sid=good"},
		}}}
		ba := newStubBrowserAuth(store, &stubAdapter{failOn: "click", cookies: appCookies}, false)
		res, _ := ba.Execute(context.Background(), map[string]any{
			"steps":   failing,
			"save_as": map[string]any{"session_name": "user"}, // hostname from the page URL
		}, nil)
		if len(store.saved) != 0 {
			t.Fatal("failed batch replaced an existing session")
		}
		if preserved, _ := res.Details["existing_session_preserved"].(bool); !preserved {
			t.Errorf("existing_session_preserved missing: %v", res.Details)
		}
		if !strings.Contains(res.Content, "preserved") {
			t.Errorf("content does not report the preserved session: %s", res.Content)
		}
	})
	t.Run("force", func(t *testing.T) {
		store := &stubAuthStore{}
		ba := newStubBrowserAuth(store, &stubAdapter{failOn: "click", cookies: appCookies}, false)
		res, err := ba.Execute(context.Background(), map[string]any{
			"steps":   failing,
			"save_as": map[string]any{"hostname": "app.example.com", "force": true},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(store.saved) != 1 {
			t.Fatalf("forced save wrote %d row(s), want 1", len(store.saved))
		}
		if !res.IsError {
			t.Error("a forced save does not make a failed batch a success")
		}
		if saved, _ := res.Details["saved"].(bool); !saved {
			t.Error("details.saved = false after a forced save")
		}
	})
}

// TestBrowserAuthSaveFailureIsError: a save that cannot complete is an error.
func TestBrowserAuthSaveFailureIsError(t *testing.T) {
	store := &stubAuthStore{}
	ba := newStubBrowserAuth(store, &stubAdapter{cookies: `[{"name":"x","value":"1","domain":"other.test"}]`}, false)
	res, err := ba.Execute(context.Background(), map[string]any{
		"save_as": map[string]any{"hostname": "app.example.com"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || len(store.saved) != 0 {
		t.Fatalf("IsError=%v saved=%d, want an error and no write", res.IsError, len(store.saved))
	}
	if !strings.Contains(res.Content, "save_as failed") {
		t.Errorf("content = %s", res.Content)
	}
}

// TestBrowserAuthCleanSave: the clean path saves and is not an error.
func TestBrowserAuthCleanSave(t *testing.T) {
	store := &stubAuthStore{}
	ba := newStubBrowserAuth(store, &stubAdapter{cookies: appCookies}, false)
	res, err := ba.Execute(context.Background(), map[string]any{
		"steps":   steps(map[string]any{"action": "snapshot"}),
		"save_as": map[string]any{"hostname": "app.example.com", "session_name": "user"},
	}, nil)
	if err != nil || res.IsError {
		t.Fatalf("err=%v result=%s", err, res.Content)
	}
	if len(store.saved) != 1 || store.saved[0].Headers["Cookie"] != "sid=abc" {
		t.Fatalf("saved = %+v", store.saved)
	}
	if res.Details["adapter_version"] != "0.26.0" {
		t.Errorf("adapter_version = %v", res.Details["adapter_version"])
	}
}

// TestBrowserAuthVersionPreflight: a release outside the supported range is
// refused before any step runs, and the check runs once per tool.
func TestBrowserAuthVersionPreflight(t *testing.T) {
	cases := []struct {
		out    string
		wantOK bool
	}{
		{"agent-browser 0.26.0", true},
		{"agent-browser 0.27.3", true},
		{"v0.26.1", true},
		{"agent-browser 0.9.0", false},
		{"agent-browser 0.25.9", false},
		{"agent-browser 1.0.0", false},
		{"agent-browser (dev build)", false},
	}
	for _, tc := range cases {
		t.Run(tc.out, func(t *testing.T) {
			adapter := &stubAdapter{version: tc.out}
			ba := newStubBrowserAuth(&stubAuthStore{}, adapter, false)
			args := map[string]any{"steps": steps(map[string]any{"action": "snapshot"})}
			res, err := ba.Execute(context.Background(), args, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantOK {
				if res.IsError {
					t.Fatalf("supported version refused: %s", res.Content)
				}
			} else {
				if !res.IsError || !strings.Contains(res.Content, supportedAdapterRange) {
					t.Fatalf("want an error naming %q, got IsError=%v %s", supportedAdapterRange, res.IsError, res.Content)
				}
				if n := len(adapter.stepCalls()); n != 0 {
					t.Fatalf("%d step(s) ran against an unsupported adapter", n)
				}
			}
			_, _ = ba.Execute(context.Background(), args, nil)
			if n := adapter.versionCalls(); n != 1 {
				t.Errorf("--version ran %d times, want once", n)
			}
		})
	}
}

// TestNewBrowserAuthToolConfig: disabled ⇒ no tool; a configured binary path
// wins over PATH; PATH is the fallback.
func TestNewBrowserAuthToolConfig(t *testing.T) {
	repo := &database.Repository{}
	dir := t.TempDir()
	bin := filepath.Join(dir, "my-agent-browser")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho agent-browser 0.26.0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir()) // agent-browser is not on PATH

	if tl := NewBrowserAuthTool(repo, "proj", BrowserToolConfig{Enabled: false, BinaryPath: bin}); tl != nil {
		t.Error("disabled integration still produced a tool")
	}
	if tl := NewBrowserAuthTool(repo, "proj", BrowserToolConfig{Enabled: true}); tl != nil {
		t.Error("no binary on PATH and none configured still produced a tool")
	}
	tl := NewBrowserAuthTool(repo, "proj", BrowserToolConfig{Enabled: true, BinaryPath: bin, Headed: true})
	if tl == nil {
		t.Fatal("configured binary path was not honored")
	}
	ba := tl.(*browserAuthTool)
	if ba.bin != bin || !ba.headed {
		t.Errorf("bin=%q headed=%v, want %q / true", ba.bin, ba.headed, bin)
	}

	t.Setenv("PATH", dir)
	if err := os.Rename(bin, filepath.Join(dir, "agent-browser")); err != nil {
		t.Fatal(err)
	}
	if NewBrowserAuthTool(repo, "proj", BrowserToolConfig{Enabled: true}) == nil {
		t.Error("PATH fallback did not resolve agent-browser")
	}
}

// TestClipStepOutput: clipped output ends on a line (else rune) boundary and
// the transcript carrying it stays valid JSON with an explicit flag.
func TestClipStepOutput(t *testing.T) {
	lines := strings.Repeat(`{"ref":"@e1","role":"button","name":"Sign in"}`+"\n", 400)
	got, trunc := clipStepOutput(lines, maxStepOutput)
	if !trunc || len(got) > maxStepOutput || !strings.HasSuffix(got, "}") {
		t.Fatalf("line clip: truncated=%v len=%d tail=%q", trunc, len(got), got[max(0, len(got)-10):])
	}

	oneLine := strings.Repeat("é", maxStepOutput) // 2 bytes per rune, no newline
	got, trunc = clipStepOutput(oneLine, maxStepOutput+1)
	if !trunc || !utf8.ValidString(got) || len(got) > maxStepOutput+1 {
		t.Fatalf("rune clip: truncated=%v valid=%v len=%d", trunc, utf8.ValidString(got), len(got))
	}

	if s, trunc := clipStepOutput("short", maxStepOutput); trunc || s != "short" {
		t.Fatalf("short output altered: %q %v", s, trunc)
	}

	// Through the tool: the content is one JSON document with the flag set.
	adapter := &stubAdapter{}
	ba := newStubBrowserAuth(&stubAuthStore{}, adapter, false)
	ba.run = func(ctx context.Context, bin string, timeout time.Duration, args ...string) ([]byte, error) {
		if slices.Equal(args, []string{"--version"}) {
			return []byte("agent-browser 0.26.0"), nil
		}
		return []byte(lines), nil
	}
	res, err := ba.Execute(context.Background(), map[string]any{"steps": steps(map[string]any{"action": "snapshot"})}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Steps []browserAuthStepResult `json:"steps"`
	}
	if err := json.Unmarshal([]byte(res.Content), &out); err != nil {
		t.Fatalf("transcript is not valid JSON: %v", err)
	}
	if len(out.Steps) != 1 || !out.Steps[0].OutputTruncated {
		t.Fatalf("steps = %+v, want one step flagged output_truncated", out.Steps)
	}
	if strings.Contains(out.Steps[0].Output, "[truncated]") {
		t.Error("clipped output still carries an in-band marker")
	}
}

// TestBrowserAuthSaveLabelsLossyExport: what a flat Cookie header cannot carry
// is named, and the save is never presented as a verified login.
func TestBrowserAuthSaveLabelsLossyExport(t *testing.T) {
	store := &stubAuthStore{}
	cookies := `[{"name":"sid","value":"abc","domain":".example.com","path":"/app","expires":1924992000,"secure":true,"httpOnly":true},
		{"name":"pref","value":"x","domain":"app.example.com","path":"/","expires":-1}]`
	ba := newStubBrowserAuth(store, &stubAdapter{cookies: cookies}, false)
	res, err := ba.Execute(context.Background(), map[string]any{
		"save_as": map[string]any{"hostname": "app.example.com"},
	}, nil)
	if err != nil || res.IsError {
		t.Fatalf("err=%v result=%s", err, res.Content)
	}
	var out struct {
		Saved savedAuthSummary `json:"saved"`
		Hint  string           `json:"hint"`
	}
	if err := json.Unmarshal([]byte(res.Content), &out); err != nil {
		t.Fatal(err)
	}
	want := []string{"domain", "path", "expiry", "secure", "httpOnly"}
	if !out.Saved.Lossy || !slices.Equal(out.Saved.DroppedAttributes, want) {
		t.Fatalf("lossy=%v dropped=%v, want true %v", out.Saved.Lossy, out.Saved.DroppedAttributes, want)
	}
	if out.Saved.CookiesSaved != 2 || out.Saved.Verified {
		t.Fatalf("cookies_saved=%d verified=%v, want 2 / false", out.Saved.CookiesSaved, out.Saved.Verified)
	}
	if res.Details["verified"] != false || res.Details["cookies_saved"] != 2 || res.Details["lossy"] != true {
		t.Errorf("details = %v", res.Details)
	}
	if !strings.Contains(out.Hint, "not verified") {
		t.Errorf("hint does not say the session is unverified: %q", out.Hint)
	}
	if len(store.saved) != 1 || store.saved[0].Headers["Cookie"] != "sid=abc; pref=x" {
		t.Fatalf("what gets saved changed: %+v", store.saved)
	}

	// A host-only session cookie loses nothing.
	if got := droppedCookieAttributes([]browserCookie{{Name: "a", Value: "1", Domain: "app.example.com", Path: "/", Expires: -1}}, "app.example.com"); len(got) != 0 {
		t.Fatalf("host-only session cookie reported lossy: %v", got)
	}
}
