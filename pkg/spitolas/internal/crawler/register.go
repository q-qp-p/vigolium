package crawler

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/form"
)

// registerSettleTimeout bounds the network-idle settle after the signup
// submission before the outcome is judged. Longer than the login equivalent:
// account creation usually costs a write plus a redirect, sometimes a mail send.
const registerSettleTimeout = 8 * time.Second

// registerEntryScript looks for a way into the app's signup flow from the
// current page and returns the resolved URL, or "" when there is none.
//
// Both halves matter. An app that renders signup at a conventional path is found
// by the href pattern; one that routes to it from a button with no href is found
// by the label. Labels are matched against a short phrase list rather than the
// substring "register", because "registered trademark" and "register your
// interest" are not signup links. No backticks: embedded as a Go raw string.
const registerEntryScript = `(() => {
  const origin = location.origin;
  const HREF = /(^|\/)(register|signup|sign-up|sign_up|create-account|createaccount|join|new-account|users\/new|account\/create)(\/|\?|#|$)/i;
  const LABEL = /^(sign\s?up|signup|register|create (an )?account|create account|join( now| free)?|get started|new account|create profile)$/i;

  const resolve = (raw) => {
    if (!raw) return '';
    try {
      const u = new URL(raw, location.href);
      if (u.origin !== origin) return '';
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
      return u.href;
    } catch (e) { return ''; }
  };

  // A signup form already on this page beats navigating anywhere.
  try {
    const pwds = document.querySelectorAll('input[type=password]');
    if (pwds.length >= 2) return location.href;
    if (pwds.length === 1 && HREF.test(location.pathname)) return location.href;
  } catch (e) {}

  let anchors;
  try { anchors = document.querySelectorAll('a[href]'); } catch (e) { anchors = []; }
  for (const a of anchors) {
    const href = a.getAttribute('href');
    if (href && HREF.test(href)) { const r = resolve(href); if (r) return r; }
  }
  for (const a of anchors) {
    let t = ''; try { t = (a.innerText || a.textContent || '').trim(); } catch (e) {}
    if (t && t.length <= 32 && LABEL.test(t)) { const r = resolve(a.getAttribute('href')); if (r) return r; }
  }
  return '';
})()`

// registerFormProbeScript confirms the page holds a signup form and tags its
// submit control as data-vgo-register-submit.
//
// The shape test is what separates signup from the login form on the same site:
// a signup either carries two password fields (password + confirm) or one
// password alongside several identity inputs, whereas a login is one password
// and one identity field. A page reached by an explicit signup link is accepted
// on the weaker single-password shape, since the link already established
// intent. __VIA_LINK__ is substituted by the caller.
// Returns JSON registerFormInfo. No backticks: Go raw string.
const registerFormProbeScript = `(() => {
  const isVisible = (el) => {
    try {
      if (el.disabled) return false;
      const r = el.getBoundingClientRect();
      if (r.width < 1 || r.height < 1) return false;
      const s = getComputedStyle(el);
      return s.visibility !== 'hidden' && s.display !== 'none';
    } catch (e) { return false; }
  };
  const viaLink = __VIA_LINK__;
  const pwds = Array.from(document.querySelectorAll('input[type=password]')).filter(isVisible);
  if (pwds.length === 0) return JSON.stringify({found:false, reason:'no-password'});

  const formEl = pwds[0].closest('form');
  const scope = formEl || document;
  const identityTypes = ['text','email','tel','search',''];
  const identity = Array.from(scope.querySelectorAll('input')).filter((i) => {
    const t = (i.getAttribute('type') || 'text').toLowerCase();
    return identityTypes.indexOf(t) !== -1 && isVisible(i);
  });
  if (identity.length === 0) return JSON.stringify({found:false, reason:'no-identity-field'});

  const looksLikeSignup = pwds.length >= 2 || identity.length >= 2 || viaLink;
  if (!looksLikeSignup) return JSON.stringify({found:false, reason:'looks-like-login'});

  let submit = scope.querySelector('button[type=submit], input[type=submit], button:not([type])');
  if (!submit) submit = scope.querySelector('button, [role=button], input[type=button]');
  if (submit) { try { submit.setAttribute('data-vgo-register-submit', '1'); } catch (e) {} }

  let action = '';
  try { action = formEl ? (formEl.action || location.href) : location.href; } catch (e) { action = location.href; }

  return JSON.stringify({
    found: true,
    action: action,
    passwordFields: pwds.length,
    identityFields: identity.length
  });
})()`

// registerConsentScript ticks the unchecked, visible checkboxes inside the
// signup form. A terms-of-service or age-confirmation box is required for the
// submission to validate, and leaving it unticked makes every attempt fail for a
// reason that has nothing to do with the form being reachable. Marketing opt-ins
// get ticked along with them, which is the accepted cost of one crawl account.
// Returns the count ticked. No backticks: Go raw string.
const registerConsentScript = `(() => {
  const submit = document.querySelector('[data-vgo-register-submit="1"]');
  const scope = (submit && submit.closest('form')) ||
                (document.querySelector('input[type=password]') || {}).closest?.('form') ||
                document;
  let n = 0;
  let boxes; try { boxes = scope.querySelectorAll('input[type=checkbox]'); } catch (e) { boxes = []; }
  for (const b of boxes) {
    try {
      if (b.disabled || b.checked) continue;
      const r = b.getBoundingClientRect();
      const s = getComputedStyle(b);
      const hidden = (r.width < 1 || r.height < 1) && s.opacity === '0' && s.position !== 'absolute';
      if (hidden) continue;
      b.click();
      if (b.checked) n++;
    } catch (e) {}
  }
  return n;
})()`

// registerOutcomeScript reports the post-submission page: whether a password
// field survives, whether a logout affordance appeared, whether the page states
// the account was created, whether a validation error is showing, and the URL.
// Returns JSON registerOutcome. No backticks: Go raw string.
const registerOutcomeScript = `(() => {
  let bodyText = '';
  try { bodyText = (document.body && (document.body.innerText || document.body.textContent)) || ''; } catch (e) {}
  const t = bodyText.slice(0, 20000);
  const success = /(account (has been )?created|registration (was )?successful|successfully registered|thanks for (signing up|registering)|welcome aboard|check your (e-?mail|inbox)|verify your e-?mail|confirmation (e-?mail|link) (has been )?sent)/i.test(t);
  const failure = /(already (in use|taken|registered|exists)|is already|password (is )?too (short|weak)|invalid e-?mail|please (correct|fix|enter)|is required|does not match|passwords must match|captcha)/i.test(t);
  return JSON.stringify({
    hasPassword: !!document.querySelector('input[type=password]'),
    hasLogout: /(log\s?out|sign\s?out|logout|signout|my account|dashboard)/i.test(t),
    success: success,
    failure: failure,
    url: location.href
  });
})()`

// registerFormInfo is the result of probing a page for a signup form.
type registerFormInfo struct {
	Found          bool   `json:"found"`
	Reason         string `json:"reason"`
	Action         string `json:"action"`
	PasswordFields int    `json:"passwordFields"`
	IdentityFields int    `json:"identityFields"`
}

// registerOutcome is the post-submission page probe.
type registerOutcome struct {
	HasPassword bool   `json:"hasPassword"`
	HasLogout   bool   `json:"hasLogout"`
	Success     bool   `json:"success"`
	Failure     bool   `json:"failure"`
	URL         string `json:"url"`
}

// attemptSelfRegistration finds the app's public signup form, completes it with
// a generated identity, and submits it.
//
// On an application with open registration, everything behind the login is
// invisible to an unauthenticated crawl — which is usually most of the
// application, and nearly all of the part worth looking at. Creating one account
// converts that from unreachable to ordinary crawlable surface.
//
// It is off unless the operator opted in, runs at most once per host, and only
// ever submits to an in-scope host. The identity it creates is stored in the
// crawl's fill context, so the login pass reuses it automatically whether or not
// registration logged the browser in directly.
func (c *Crawler) attemptSelfRegistration(ctx context.Context, page *browser.Page) {
	if page == nil || c.config == nil || !c.config.SelfRegister || ctx.Err() != nil {
		return
	}

	startURL, _ := page.URL()
	host := hostOf(startURL)
	if host == "" && c.config.URL != nil {
		host = c.config.URL.Hostname()
	}
	if !c.claimSelfRegisterHost(host) {
		return
	}
	// Every exit below leaves the browser wherever the signup flow put it, so the
	// return is deferred once rather than repeated on each path. returnToURL
	// no-ops when the page never moved.
	defer c.returnToURL(ctx, page, startURL)

	entryURL, viaLink := c.findRegistrationEntry(page, startURL)
	if entryURL == "" {
		zap.L().Debug("Self-register: no signup entry point found")
		return
	}

	if entryURL != startURL {
		if err := page.NavigateCtx(ctx, entryURL); err != nil {
			zap.L().Debug("Self-register: navigation to signup page failed",
				zap.String("url", entryURL), zap.Error(err))
			return
		}
		c.settleSPA(ctx, page)
	}

	info, ok := c.probeRegisterForm(page, viaLink)
	if !ok {
		zap.L().Debug("Self-register: page is not a signup form",
			zap.String("url", entryURL), zap.String("reason", info.Reason))
		return
	}
	// Never submit an account to somebody else's identity service.
	if !c.loginActionInScope(info.Action, entryURL) {
		zap.L().Debug("Self-register: form posts off-host, skipping",
			zap.String("action", info.Action))
		return
	}

	zap.L().Info("Spidering: found signup form — registering a crawl account",
		zap.String("url", entryURL),
		zap.Int("password_fields", info.PasswordFields),
		zap.Int("identity_fields", info.IdentityFields))

	// Fill through the form handler so every value is chosen (and remembered) by
	// the same fill context the rest of the crawl uses. That is what makes the
	// identity reusable: the confirm-password field resolves to the same value as
	// the password field, and a later login form recalls both.
	c.fillFormsIfPresent(page, "")

	if raw, err := page.Eval(registerConsentScript); err == nil {
		if n, _ := raw.(float64); n > 0 {
			zap.L().Debug("Self-register: ticked required consent boxes", zap.Int("count", int(n)))
		}
	}

	identity := c.registeredIdentity()
	urlBefore, _ := page.URL()
	c.submitRegisterForm(ctx, page)

	outcome, ok := c.probeRegisterOutcome(page)
	if !ok {
		return
	}

	switch {
	case outcome.Failure && !outcome.Success:
		zap.L().Info("Self-register: the form rejected the submission",
			zap.String("url", entryURL))
		return
	case !outcome.Success && !c.loginLooksSucceeded(page, urlBefore):
		// No success text. Fall back to the shared "did we leave the auth screen"
		// judgement the credential pass uses, so both flows decide it one way.
		zap.L().Debug("Self-register: no confirmation that the account was created",
			zap.String("url", entryURL))
		return
	}

	c.mu.Lock()
	c.stats.SelfRegistered = true
	c.stats.SelfRegisterIdentity = identity
	c.mu.Unlock()

	// Some apps log the new account straight in; others hand back a "now sign in"
	// page or ask for email verification. Only harvest a bearer token when the
	// browser is genuinely authenticated — otherwise the identity alone is the
	// deliverable, and the login pass will use it.
	authenticated := !outcome.HasPassword && outcome.HasLogout
	if authenticated {
		c.harvestAuthToken(page)
		zap.L().Info("Spidering: registered account is signed in — continuing crawl authenticated",
			zap.String("identity", identity))
	} else {
		zap.L().Info("Spidering: registered an account; its identity will be reused at the login form",
			zap.String("identity", identity))
	}
}

// findRegistrationEntry locates the signup page. It returns the URL and whether
// it was reached through an explicit signup link — the probe relaxes its shape
// test in that case, because the link already established what the page is.
func (c *Crawler) findRegistrationEntry(page *browser.Page, currentURL string) (string, bool) {
	raw, err := page.Eval(registerEntryScript)
	if err != nil {
		return "", false
	}
	entry, _ := raw.(string)
	entry = strings.TrimSpace(entry)
	if entry == "" || entry == "<nil>" {
		return "", false
	}
	if c.config.CrawlScope != nil && !c.config.CrawlScope(entry) {
		return "", false
	}
	return entry, entry != currentURL
}

// probeRegisterForm confirms the page holds a signup form and tags its submit
// control. viaLink relaxes the shape test for a page reached by a signup link.
func (c *Crawler) probeRegisterForm(page *browser.Page, viaLink bool) (registerFormInfo, bool) {
	raw, err := page.Eval(fmtRegisterProbe(viaLink))
	if err != nil {
		return registerFormInfo{}, false
	}
	s, ok := raw.(string)
	if !ok || s == "" || s == "<nil>" {
		return registerFormInfo{}, false
	}
	var info registerFormInfo
	if jerr := json.Unmarshal([]byte(s), &info); jerr != nil {
		return registerFormInfo{}, false
	}
	return info, info.Found
}

// fmtRegisterProbe renders the probe script with its viaLink flag.
func fmtRegisterProbe(viaLink bool) string {
	return strings.ReplaceAll(registerFormProbeScript, "__VIA_LINK__", strconv.FormatBool(viaLink))
}

// submitRegisterForm clicks the tagged submit control (falling back to
// requesting submit on the form) and waits for the result to settle.
func (c *Crawler) submitRegisterForm(ctx context.Context, page *browser.Page) {
	if ctx.Err() != nil {
		return
	}
	// Registration is authorized by its own policy category, so it passes the
	// page's submit guard even when ordinary submits are denied.
	page.AllowAuthorizedSubmit()
	c.countSubmitDispatched(submitMechRegister, 1)
	submitted := false
	if elem, err := page.ElementPiercing(`[data-vgo-register-submit="1"]`); err == nil && elem != nil {
		if cerr := elem.Click(); cerr == nil {
			submitted = true
		} else {
			zap.L().Debug("Self-register: submit click failed, falling back to form submit", zap.Error(cerr))
		}
	}
	if !submitted {
		_, _ = page.Eval(registerSubmitFallbackScript)
	}
	_ = page.WaitStable(c.config.DOMStableTime)
	page.WaitNetworkIdle(c.config.DOMStableTime, registerSettleTimeout)
}

// registerSubmitFallbackScript requests submit on the signup form when no
// clickable submit control could be driven.
const registerSubmitFallbackScript = `(() => {
  const pwd = document.querySelector('input[type=password]');
  if (!pwd) return 'no-pass';
  const f = pwd.closest('form');
  if (!f) return 'no-form';
  try { if (f.requestSubmit) f.requestSubmit(); else f.submit(); return 'submitted'; } catch (e) { return 'err'; }
})()`

// probeRegisterOutcome reads the post-submission page state.
func (c *Crawler) probeRegisterOutcome(page *browser.Page) (registerOutcome, bool) {
	raw, err := page.Eval(registerOutcomeScript)
	if err != nil {
		return registerOutcome{}, false
	}
	s, ok := raw.(string)
	if !ok || s == "" || s == "<nil>" {
		return registerOutcome{}, false
	}
	var out registerOutcome
	if jerr := json.Unmarshal([]byte(s), &out); jerr != nil {
		return registerOutcome{}, false
	}
	return out, true
}

// registeredIdentity reports the identity the fill context settled on, for
// logging and for the run's stats. Prefers the username, falling back to the
// email address.
func (c *Crawler) registeredIdentity() string {
	fc := c.formHandler.FillContext()
	if fc == nil {
		return ""
	}
	if u, ok := fc.Recall(form.SemUsername); ok && u != "" {
		return u
	}
	if e, ok := fc.Recall(form.SemEmail); ok {
		return e
	}
	return ""
}

// claimSelfRegisterHost returns true the first time it is called for a host and
// false thereafter, so at most one account is ever created per host per crawl.
func (c *Crawler) claimSelfRegisterHost(host string) bool {
	c.selfRegisterMu.Lock()
	defer c.selfRegisterMu.Unlock()
	if c.selfRegisterHosts[host] {
		return false
	}
	c.selfRegisterHosts[host] = true
	return true
}
