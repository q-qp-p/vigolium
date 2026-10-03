package crawler

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/authsig"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/form"
)

// maxLoginCredAttempts bounds how many credential pairs are submitted against a
// single login form. Kept small (a documented default list, never a wordlist)
// plus one reused identity, so the pass cannot brute-force or lock an account.
const maxLoginCredAttempts = 10

// loginCredSettleTimeout bounds the network-idle settle after a login submission
// before the result is evaluated.
const loginCredSettleTimeout = 4 * time.Second

// Negative-control credentials: an improbable pair that must be REJECTED. If a
// login form "accepts" these, its success heuristic is unreliable (it redirects
// or clears the password field regardless), so the real spray is abandoned to
// avoid a false "logged in".
const (
	negativeControlUser = "vgn0-nologin-8f3a2b"
	negativeControlPass = "vgn0-9c1d4e-rejectme"
)

// commonLoginMinimalCreds is the smallest documented default set, tried at
// balanced intensity against a username-style login form. The two most common
// vendor defaults only.
var commonLoginMinimalCreds = [][2]string{
	{"admin", "admin"},
	{"admin", "123456"},
}

// commonLoginUserCreds is the full documented default-credential list tried at
// deep intensity against a username-style login form. Vendor/app defaults only —
// never a brute-force wordlist — so the pass cannot lock accounts.
var commonLoginUserCreds = [][2]string{
	{"admin", "admin"},
	{"admin", "123456"},
	{"admin", "password"},
	{"admin", "admin123"},
	{"administrator", "administrator"},
	{"root", "root"},
	{"test", "test"},
	{"guest", "guest"},
	{"demo", "demo"},
	{"user", "user"},
}

// commonLoginEmailCreds is the full documented default list tried at deep
// intensity when the identity field is an email input (so "admin" alone would
// fail HTML5 validation).
var commonLoginEmailCreds = [][2]string{
	{"admin@admin.com", "admin"},
	{"admin@example.com", "admin"},
	{"test@test.com", "test"},
	{"demo@demo.com", "demo"},
	{"user@example.com", "user"},
}

// loginFormInfo is the result of probing a page for a local login form.
type loginFormInfo struct {
	Found    bool   `json:"found"`
	Reason   string `json:"reason"`
	Action   string `json:"action"`   // resolved absolute form action (or page URL)
	UserType string `json:"userType"` // type of the identity field (text/email/…)
}

// loginState is the post-submission page probe used to judge whether a
// credential pair authenticated.
type loginState struct {
	HasPassword bool   `json:"hasPassword"`
	HasLogout   bool   `json:"hasLogout"`
	URL         string `json:"url"`
}

// loginFormProbeScript confirms a page holds a single-password LOCAL login form
// (not a registration/change-password form, which carries two password fields or
// many identity inputs) and tags its identity field, password field, and submit
// control with data-vgo-login-* attributes for Go to fill. It returns a JSON
// loginFormInfo. No backticks: embedded as a Go raw string.
const loginFormProbeScript = `(() => {
  const isVisible = (el) => {
    try {
      if (el.disabled) return false;
      const r = el.getBoundingClientRect();
      if (r.width < 1 || r.height < 1) return false;
      const s = getComputedStyle(el);
      if (s.visibility === 'hidden' || s.display === 'none') return false;
      return true;
    } catch (e) { return false; }
  };
  const pwds = Array.from(document.querySelectorAll('input[type=password]')).filter(isVisible);
  if (pwds.length === 0) return JSON.stringify({found:false, reason:'no-password'});
  if (pwds.length > 1) return JSON.stringify({found:false, reason:'multi-password'});
  const pwd = pwds[0];
  const formEl = pwd.closest('form');
  const scope = formEl || document;
  const identityTypes = ['text','email','tel','search',''];
  const texts = Array.from(scope.querySelectorAll('input')).filter((i) => {
    const t = (i.getAttribute('type') || 'text').toLowerCase();
    return identityTypes.indexOf(t) !== -1 && isVisible(i);
  });
  if (texts.length === 0) return JSON.stringify({found:false, reason:'no-identity-field'});
  // Many visible identity inputs → registration/profile form, not a login.
  if (texts.length > 3) return JSON.stringify({found:false, reason:'too-many-fields'});
  // Identity = the last text input that appears before the password (the
  // username/email); fall back to the first.
  let user = null;
  for (const t of texts) {
    if (t === pwd) continue;
    if (t.compareDocumentPosition(pwd) & Node.DOCUMENT_POSITION_FOLLOWING) user = t;
  }
  if (!user) user = texts[0];
  let submit = scope.querySelector('button[type=submit], input[type=submit], button:not([type])');
  if (!submit) submit = scope.querySelector('button, [role=button], input[type=button]');
  let action = '';
  try { action = formEl ? (formEl.action || location.href) : location.href; } catch (e) { action = location.href; }
  try { user.setAttribute('data-vgo-login-user', '1'); } catch (e) {}
  try { pwd.setAttribute('data-vgo-login-pass', '1'); } catch (e) {}
  if (submit) { try { submit.setAttribute('data-vgo-login-submit', '1'); } catch (e) {} }
  return JSON.stringify({
    found: true,
    action: action,
    userType: (user.getAttribute('type') || 'text').toLowerCase()
  });
})()`

// loginStateProbeScript reports the page's post-submission auth state: whether a
// password field is still present, whether a logout affordance appeared, and the
// current URL. Returns JSON loginState. No backticks: Go raw string.
const loginStateProbeScript = `(() => {
  const hasPass = !!document.querySelector('input[type=password]');
  let bodyText = '';
  try { bodyText = (document.body && (document.body.innerText || document.body.textContent)) || ''; } catch (e) {}
  const hasLogout = /(log\s?out|sign\s?out|logout|signout)/i.test(bodyText);
  return JSON.stringify({hasPassword: hasPass, hasLogout: hasLogout, url: location.href});
})()`

// loginSubmitFallbackScript submits the tagged login form when no clickable
// submit control was found — it requests submit on the password field's form.
const loginSubmitFallbackScript = `(() => {
  const pwd = document.querySelector('[data-vgo-login-pass="1"]');
  if (!pwd) return 'no-pass';
  const f = pwd.closest('form');
  if (f) { try { if (f.requestSubmit) f.requestSubmit(); else f.submit(); return 'submitted'; } catch (e) { return 'err'; } }
  return 'no-form';
})()`

// attemptLoginCredentials tries a small list of common default credentials
// against a confirmed local login form so the crawl can proceed authenticated.
// It is a no-op unless the policy permits login attempts (by default at
// balanced and deep intensity), only ever runs against a
// confirmed single-password local login form, is single-flighted per host, and
// is negative-control gated. On success the browser session stays logged in
// (cookies persist) and the page is returned to the login URL so the crawl loop
// resumes from a known state. No finding is emitted — the attempts are captured
// as ordinary traffic.
func (c *Crawler) attemptLoginCredentials(ctx context.Context, page *browser.Page) {
	if page == nil || c.config == nil || !c.config.LoginCredentialAttempts {
		return
	}
	if ctx.Err() != nil {
		return
	}

	loginURL, _ := page.URL()
	host := hostOf(loginURL)
	if host == "" {
		host = c.config.URL.Hostname()
	}

	// Never spray a form on a host that is not the target itself. The
	// loginActionInScope check below cannot catch this case: it compares the
	// form's action against the *page's* host, so when the page IS a third-party
	// identity provider the action is same-host and passes. That gap turned an
	// SSO bounce into repeated credential POSTs against someone else's IdP —
	// traffic indistinguishable from credential stuffing, aimed at a host that
	// was never in the engagement.
	if !c.isTargetHost(host) {
		zap.L().Debug("Login-cred: page host is not the target, not spraying",
			zap.String("host", host), zap.String("login_url", loginURL))
		return
	}

	// Cheap short-circuit: a host already sprayed this crawl needs no re-probe.
	// The URL read above is far cheaper than the login-form probe Eval, so this
	// spares an Eval on every revisit to an already-handled login host. The
	// authoritative claim still happens after confirmation (below) to stay
	// gated on "this is really a login form".
	if c.loginCredHostDone(host) {
		return
	}

	// Confirm this really is a login form (and tag its fields) before doing
	// anything active.
	info, ok := c.probeLoginForm(page)
	if !ok {
		return
	}

	// Only ever spray a form that posts to an in-scope host — never an external
	// identity provider.
	if !c.loginActionInScope(info.Action, loginURL) {
		zap.L().Debug("Login-cred: form posts off-host, not spraying",
			zap.String("action", info.Action), zap.String("login_url", loginURL))
		return
	}

	// One spray per host for the whole crawl.
	if !c.claimLoginCredHost(host) {
		return
	}

	c.mu.Lock()
	c.stats.LoginCredsURL = loginURL
	c.mu.Unlock()

	zap.L().Info("Spidering: confirmed local login form — trying common credentials",
		zap.String("url", loginURL), zap.String("identity_type", info.UserType))

	// Negative control: a bogus pair must be rejected. The fields are already
	// tagged from the confirming probe above, so this attempt runs directly.
	if c.submitLoginAttempt(ctx, page, negativeControlUser, negativeControlPass, false) {
		zap.L().Info("Login-cred: negative control authenticated — success signal unreliable, abandoning spray",
			zap.String("url", loginURL))
		c.returnToURL(ctx, page, loginURL)
		return
	}

	creds := c.buildLoginCreds(strings.EqualFold(info.UserType, "email"), c.config.LoginCredentialFullList)

	success := false
	var matchedUser string
	for i, pair := range creds {
		if i >= maxLoginCredAttempts || ctx.Err() != nil {
			break
		}
		// Reload the login page and re-tag the fields for a clean attempt (the
		// previous submission navigated away).
		if !c.reloadAndProbe(ctx, page, loginURL) {
			break
		}
		if c.submitLoginAttempt(ctx, page, pair[0], pair[1], true) {
			success = true
			matchedUser = pair[0]
			break
		}
	}

	if success {
		c.mu.Lock()
		c.stats.LoginCredsSucceeded++
		c.mu.Unlock()
		// Harvest a token-based session credential (JWT in localStorage/sessionStorage)
		// so token-auth SPAs — which send Authorization: Bearer, not a cookie — are
		// scanned authenticated. Cookie-based apps carry via HarvestedCookies instead.
		c.harvestAuthToken(page)
		zap.L().Warn("Spidering: default credentials accepted — continuing crawl authenticated",
			zap.String("url", loginURL), zap.String("username", matchedUser))
	} else {
		zap.L().Debug("Login-cred: no common credential authenticated", zap.String("url", loginURL))
	}

	// Return to the login URL so the crawl loop resumes from a known state. On
	// success the session cookies persist across this navigation, so subsequent
	// crawling is authenticated.
	c.returnToURL(ctx, page, loginURL)
}

// probeLoginForm runs the login-form probe, tagging the identity/password/submit
// elements, and returns the parsed info. ok is false unless a confirmed
// single-password local login form (with a submit path) was found.
func (c *Crawler) probeLoginForm(page *browser.Page) (loginFormInfo, bool) {
	raw, err := page.Eval(loginFormProbeScript)
	if err != nil {
		return loginFormInfo{}, false
	}
	s, ok := raw.(string)
	if !ok || s == "" || s == "<nil>" {
		return loginFormInfo{}, false
	}
	var info loginFormInfo
	if jerr := json.Unmarshal([]byte(s), &info); jerr != nil {
		return loginFormInfo{}, false
	}
	if !info.Found {
		zap.L().Debug("Login-cred: not a login form", zap.String("reason", info.Reason))
		return info, false
	}
	return info, true
}

// reloadAndProbe navigates back to the login URL and re-tags its fields for a
// fresh attempt. Returns false on navigation/probe failure or context
// cancellation.
func (c *Crawler) reloadAndProbe(ctx context.Context, page *browser.Page, loginURL string) bool {
	if ctx.Err() != nil {
		return false
	}
	if err := page.Navigate(loginURL); err != nil {
		zap.L().Debug("Login-cred: reload failed", zap.String("url", loginURL), zap.Error(err))
		return false
	}
	_ = page.WaitStable(c.config.DOMStableTime)
	_, ok := c.probeLoginForm(page)
	return ok
}

// submitLoginAttempt fills the tagged identity/password fields, submits, waits
// for the page to settle, and reports whether it looks authenticated. count
// governs whether the attempt is added to the tried counter (the negative
// control passes false).
func (c *Crawler) submitLoginAttempt(ctx context.Context, page *browser.Page, user, pass string, count bool) bool {
	if ctx.Err() != nil {
		return false
	}
	userElem, err := page.ElementPiercing(`[data-vgo-login-user="1"]`)
	if err != nil || userElem == nil {
		return false
	}
	passElem, err := page.ElementPiercing(`[data-vgo-login-pass="1"]`)
	if err != nil || passElem == nil {
		return false
	}
	if ferr := form.FillText(userElem, user); ferr != nil {
		zap.L().Debug("Login-cred: identity fill failed", zap.Error(ferr))
	}
	if ferr := form.FillText(passElem, pass); ferr != nil {
		zap.L().Debug("Login-cred: password fill failed", zap.Error(ferr))
	}

	if count {
		c.mu.Lock()
		c.stats.LoginCredsTried++
		c.mu.Unlock()
	}

	urlBefore, _ := page.URL()

	// Credential attempts are authorized by their own policy category, so they
	// pass the page's submit guard even when ordinary submits are denied.
	page.AllowAuthorizedSubmit()
	c.countSubmitDispatched(submitMechLoginAttempt, 1)
	if submitElem, serr := page.ElementPiercing(`[data-vgo-login-submit="1"]`); serr == nil && submitElem != nil {
		if cerr := submitElem.Click(); cerr != nil {
			zap.L().Debug("Login-cred: submit click failed, trying form.submit()", zap.Error(cerr))
			_, _ = page.Eval(loginSubmitFallbackScript)
		}
	} else {
		_, _ = page.Eval(loginSubmitFallbackScript)
	}

	_ = page.WaitStable(c.config.DOMStableTime)
	page.WaitNetworkIdle(c.config.DOMStableTime, loginCredSettleTimeout)

	return c.loginLooksSucceeded(page, urlBefore)
}

// loginLooksSucceeded judges whether the page transitioned out of the login
// state after a submission: the top-level URL moved to a non-login page, or the
// password field disappeared and a logout affordance appeared. The authsig body
// check cross-guards against a page that merely re-rendered the login form.
func (c *Crawler) loginLooksSucceeded(page *browser.Page, urlBefore string) bool {
	raw, err := page.Eval(loginStateProbeScript)
	if err != nil {
		return false
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return false
	}
	var st loginState
	if jerr := json.Unmarshal([]byte(s), &st); jerr != nil {
		return false
	}

	// Left the login state entirely: navigated to a new URL that no longer holds
	// a password field. Only here is the (heavier) full-body authsig check worth
	// fetching, to rule out a re-rendered login form under a changed URL.
	if urlChanged := st.URL != "" && st.URL != urlBefore; urlChanged && !st.HasPassword {
		html, _ := page.HTML()
		if !authsig.BodyLooksLikeLogin([]byte(html)) {
			return true
		}
	}
	// Same page swapped to an authenticated view (password gone, logout present).
	if !st.HasPassword && st.HasLogout {
		return true
	}
	return false
}

// jwtShape validates that s is a three-segment base64url JWT, the shape a
// token-auth SPA stores after login. Guards the harvest against carrying an
// arbitrary storage value (a feature flag, a cart id) as a bearer credential.
var jwtShape = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

// harvestAuthToken reads a JWT-shaped session token from the page's local/session
// storage after a confirmed login and records it (bare, no "Bearer " prefix) for
// the runner to carry forward. Best-effort: any failure leaves harvestedAuth empty
// and the scan simply stays cookie-only. Only stores a value that passes the JWT
// shape check, so a non-token storage entry is never carried as a credential.
func (c *Crawler) harvestAuthToken(page *browser.Page) {
	raw, err := page.Eval(authTokenHarvestScript)
	if err != nil {
		zap.L().Debug("Login-cred: auth-token harvest eval failed", zap.Error(err))
		return
	}
	tok, _ := raw.(string)
	tok = strings.TrimSpace(tok)
	if tok == "" || !jwtShape.MatchString(tok) {
		return
	}
	c.mu.Lock()
	c.harvestedAuth = tok
	c.mu.Unlock()
	zap.L().Info("Spidering: harvested bearer session token for carry-forward")
}

// authTokenHarvestScript scans local/session storage for a JWT-shaped value,
// preferring token-named keys (token/jwt/access_token/authorization/bearer), and
// returns it with any leading "Bearer " stripped. Returns "" when none is found.
const authTokenHarvestScript = `(function(){
  try {
    var stores = [window.localStorage, window.sessionStorage];
    var jwt = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
    var pref = /(token|jwt|auth|bearer|access|session)/i;
    var best = "", bestPref = false;
    for (var s = 0; s < stores.length; s++) {
      var store = stores[s]; if (!store) continue;
      for (var i = 0; i < store.length; i++) {
        var k = store.key(i); var v = store.getItem(k);
        if (!v) continue;
        var val = String(v).replace(/^Bearer\s+/i, '').trim();
        if (!jwt.test(val)) continue;
        var p = pref.test(k);
        if (best === "" || (p && !bestPref)) { best = val; bestPref = p; }
      }
    }
    return best;
  } catch (e) { return ""; }
})()`

// buildLoginCreds assembles the ordered credential list: any identity registered
// earlier this crawl first (the best "log in and crawl deeper" shot, always
// tried), then the documented default list appropriate to the identity field
// type. fullList selects the full deep-intensity list versus the minimal
// balanced set (admin:admin, admin:123456). Duplicates are removed.
func (c *Crawler) buildLoginCreds(identityIsEmail, fullList bool) [][2]string {
	var creds [][2]string

	fc := c.formHandler.FillContext()
	if fc != nil {
		if pass, ok := fc.Recall(form.SemPassword); ok {
			user := ""
			if u, ok := fc.Recall(form.SemUsername); ok {
				user = u
			} else if e, ok := fc.Recall(form.SemEmail); ok {
				user = e
			}
			if user != "" {
				creds = append(creds, [2]string{user, pass})
			}
		}
	}

	if identityIsEmail {
		// Target-derived admin address is always the first default tried on an
		// email form (native-looking, and the minimal set has no email pair).
		if fc != nil {
			if d := fc.Domain(); d != "" {
				creds = append(creds, [2]string{"admin@" + d, "admin"})
				if !fullList {
					creds = append(creds, [2]string{"admin@" + d, "123456"})
				}
			}
		}
		if fullList {
			creds = append(creds, commonLoginEmailCreds...)
		} else {
			creds = append(creds, [2]string{"admin@admin.com", "admin"})
		}
	} else {
		if fullList {
			creds = append(creds, commonLoginUserCreds...)
		} else {
			creds = append(creds, commonLoginMinimalCreds...)
		}
	}

	return dedupeCreds(creds)
}

// dedupeCreds removes duplicate user:pass pairs, preserving order.
func dedupeCreds(in [][2]string) [][2]string {
	seen := make(map[string]bool, len(in))
	out := make([][2]string, 0, len(in))
	for _, p := range in {
		key := p[0] + "\x00" + p[1]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

// loginCredHostDone reports whether the login-cred pass has already run for a
// host, without claiming it — a cheap read used to skip the probe on revisits.
func (c *Crawler) loginCredHostDone(host string) bool {
	c.loginCredMu.Lock()
	defer c.loginCredMu.Unlock()
	return c.loginCredHosts[host]
}

// claimLoginCredHost returns true the first time it is called for a host and
// false thereafter, single-flighting the login-cred pass per host.
func (c *Crawler) claimLoginCredHost(host string) bool {
	c.loginCredMu.Lock()
	defer c.loginCredMu.Unlock()
	if c.loginCredHosts[host] {
		return false
	}
	c.loginCredHosts[host] = true
	return true
}

// loginActionInScope reports whether a login form's action targets an in-scope
// host (the page host, the configured target, or an adopted host). An empty or
// relative action resolves to the page host and is in scope; an external IdP is
// not.
func (c *Crawler) loginActionInScope(action, loginURL string) bool {
	ah := hostOf(action)
	if ah == "" {
		return true
	}
	if strings.EqualFold(ah, hostOf(loginURL)) {
		return true
	}
	if c.config.URL != nil && strings.EqualFold(ah, c.config.URL.Hostname()) {
		return true
	}
	if c.adoptedHost != "" && strings.EqualFold(ah, c.adoptedHost) {
		return true
	}
	return false
}

// returnToURL navigates the page back to target (the login URL) so the crawl
// resumes from a known state. Best-effort; auth cookies set during the spray
// persist across the navigation.
func (c *Crawler) returnToURL(ctx context.Context, page *browser.Page, target string) {
	if target == "" || ctx.Err() != nil {
		return
	}
	if cur, err := page.URL(); err == nil && cur == target {
		return
	}
	if err := page.Navigate(target); err != nil {
		zap.L().Debug("Login-cred: failed to return to login URL", zap.String("url", target), zap.Error(err))
		return
	}
	_ = page.WaitStable(c.config.DOMStableTime)
}

// hostOf returns the lowercase hostname of a URL string ("" when unparseable or
// relative).
func hostOf(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
