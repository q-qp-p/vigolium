package http

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/vigolium/vigolium/pkg/types"
)

// TestLoginTransport_FollowsTheProxyFlag: a login goes to the host the scan is
// about to attack, so it must follow --proxy like every other request to that
// host. It previously did not, so the proxy log showed an authenticated scan
// with no login in it.
func TestLoginTransport_FollowsTheProxyFlag(t *testing.T) {
	opts := types.DefaultOptions()
	opts.ProxyURL = "http://127.0.0.1:8080"

	tr, ok := LoginTransport(opts).(*http.Transport)
	if !ok {
		t.Fatalf("LoginTransport returned %T, want *http.Transport", LoginTransport(opts))
	}
	if tr.Proxy == nil {
		t.Fatal("no proxy configured from --proxy")
	}
	req, err := http.NewRequest(http.MethodGet, "https://target.test/login", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	proxied, err := tr.Proxy(req)
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	if proxied == nil || proxied.Host != "127.0.0.1:8080" {
		t.Errorf("proxy = %v, want 127.0.0.1:8080", proxied)
	}
}

// An explicit proxy URL, not ProxyFromEnvironment: Go's environment proxy
// bypasses localhost, and a localhost target behind a proxy is the common local
// pentest setup.
func TestLoginTransport_ProxiesLocalhostToo(t *testing.T) {
	opts := types.DefaultOptions()
	opts.ProxyURL = "http://127.0.0.1:8080"
	tr := LoginTransport(opts).(*http.Transport)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:3000/rest/user/login", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	proxied, err := tr.Proxy(req)
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	if proxied == nil {
		t.Error("a localhost login must still go through the proxy")
	}
}

// Target traffic accepts self-signed and expired certs, and a target that
// presents one on /admin presents it on /login too.
func TestLoginTransport_AcceptsTargetCerts(t *testing.T) {
	tr := LoginTransport(nil).(*http.Transport)
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("login TLS must match target-traffic policy (InsecureSkipVerify)")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS10 {
		t.Errorf("MinVersion = %x, want TLS 1.0 like target traffic", tr.TLSClientConfig.MinVersion)
	}
	if tr.Proxy != nil {
		// No --proxy and (in a clean test env) no proxy environment.
		if _, ok := proxyEnvSet(); !ok {
			t.Error("no proxy configured, want none")
		}
	}
}

// A --sni override applies to the login handshake too, since it is the same
// host.
func TestLoginTransport_HonoursSNI(t *testing.T) {
	opts := types.DefaultOptions()
	opts.SNI = "internal.target.test"
	tr := LoginTransport(opts).(*http.Transport)
	if tr.TLSClientConfig.ServerName != "internal.target.test" {
		t.Errorf("ServerName = %q, want the --sni override", tr.TLSClientConfig.ServerName)
	}
}

// An unparseable proxy is reported (logged) and left unset rather than failing
// the login outright — the same thing NewRequester does with a bad --proxy.
func TestLoginTransport_InvalidProxyIsIgnored(t *testing.T) {
	opts := types.DefaultOptions()
	opts.ProxyURL = "ht tp://nope"
	tr := LoginTransport(opts).(*http.Transport)
	if tr.Proxy != nil {
		t.Error("an unparseable proxy must not be installed")
	}
}

// And the transport actually carries a request end to end, so the policy above
// is not merely a struct full of fields.
func TestLoginTransport_RoundTrips(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := &http.Client{Transport: LoginTransport(types.DefaultOptions())}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
}

// proxyEnvSet reports whether the environment carries a proxy, so the
// no-proxy assertion above does not fail on a machine that has one.
func proxyEnvSet() (*url.URL, bool) {
	raw := getProxyURL("")
	if raw == "" {
		return nil, false
	}
	u, err := url.Parse(raw)
	return u, err == nil
}
