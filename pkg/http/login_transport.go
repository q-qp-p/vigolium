package http

import (
	"net/http"

	"github.com/vigolium/vigolium/pkg/types"
)

// LoginTransport returns the RoundTripper an authentication login flow should
// send over. A login request goes to the SAME host the scan is about to attack,
// so it is target traffic and must follow the same two policies target traffic
// follows — and nothing else:
//
//   - the proxy, through the same applyExplicitProxy NewRequester uses (--proxy,
//     else HTTP(S)_PROXY from the environment, as an explicit URL so a localhost
//     target is proxied too). Without this a login ran direct while every
//     subsequent request went through Burp, so the proxy log showed an
//     authenticated scan with no login in it — and a proxy-only route to the
//     target made the login fail outright.
//   - the target TLS stance, through the same targetTLSConfig: a target that
//     presents a self-signed or expired cert presents it on /login as well, and
//     a scanner that scans such a host happily but refuses to log into it is
//     refusing for no reason.
//
// Both are shared functions rather than copies, so this client cannot drift
// from the scan transport whose policy it is deliberately adopting.
//
// Everything else is left at Go's defaults: this transport sends a handful of
// requests at setup time, so none of NewRequester's pool sizing, keep-alive or
// response-header-timeout tuning is worth duplicating here. It is deliberately
// a separate, short-lived transport rather than the scan transport itself — the
// login must not share the scan's cookie jar or its clustering.
//
// Keep this the ONE place that answers "what does target-transport policy mean
// for an auxiliary client": the previous `&http.Client{Timeout: 30s}` literals
// in pkg/authentication silently answered "neither of the above".
//
// A nil opts is valid and yields the environment-proxy / insecure-TLS defaults.
func LoginTransport(opts *types.Options) http.RoundTripper {
	var cliProxy, sni string
	if opts != nil {
		cliProxy = opts.ProxyURL
		sni = opts.SNI
	}
	t := &http.Transport{TLSClientConfig: targetTLSConfig(sni)}
	applyExplicitProxy(t, cliProxy, "login")
	return t
}
