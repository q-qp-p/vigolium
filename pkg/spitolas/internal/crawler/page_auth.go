package crawler

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"go.uber.org/zap"
)

// Authentication states (Stats.AuthState). There is deliberately no
// "verified": applying credentials says nothing about whether the application
// accepted them, and an identity check needs an operator-declared success
// condition this crawler does not have.
const (
	AuthNotRequested = "not-requested" // no cookies or headers were configured
	AuthConfigured   = "configured"    // configured, not yet applied to a page
	AuthApplied      = "applied"       // installed on the start page (and later pages)
	AuthFailed       = "failed"        // configured but not (fully) applied
)

// pageAuthOps are the two page calls that install credentials. Nil fields use
// the page's own methods; tests substitute them so the credential rules run
// without a browser.
type pageAuthOps struct {
	setCookies func(page *browser.Page, cookies []*http.Cookie) error
	setHeaders func(page *browser.Page, headers map[string]string) error
}

var errNoPage = errors.New("no page")

func (o pageAuthOps) cookies(page *browser.Page, cookies []*http.Cookie) error {
	if o.setCookies != nil {
		return o.setCookies(page, cookies)
	}
	if page == nil {
		return errNoPage
	}
	return page.SetCookies(cookies)
}

func (o pageAuthOps) headers(page *browser.Page, headers map[string]string) error {
	if o.setHeaders != nil {
		return o.setHeaders(page, headers)
	}
	if page == nil {
		return errNoPage
	}
	return page.SetExtraHeaders(headers)
}

// initialAuthState is the state before any page exists.
func (c *Crawler) initialAuthState() string {
	if len(c.config.InitialCookies) == 0 && len(c.config.ExtraHeaders) == 0 {
		return AuthNotRequested
	}
	return AuthConfigured
}

// credentialOriginAllowed reports whether operator credential headers may ride
// on a page at rawURL: anywhere the operator's scope admits, or — under the
// default host scope — the target host and its subdomains. An adopted
// relocation host is not included: the credentials were given for the target.
func (c *Crawler) credentialOriginAllowed(rawURL string) bool {
	if c.config.CrawlScope != nil {
		return c.config.CrawlScope(rawURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return sameOrSubdomain(strings.ToLower(u.Hostname()), strings.ToLower(c.config.URL.Hostname()))
}

// applyPageAuth seeds operator-supplied authentication onto a freshly created
// page before navigation: initial cookies (written into the browser's cookie
// jar, which scopes them by their own domain/path) and extra HTTP headers such
// as Authorization / X-Api-Key. Extra headers are page-wide in CDP — they ride
// on every request the page makes — so they are installed only when the
// target is inside the operator scope, and never again once the crawl has
// withdrawn them for leaving it (withdrawCredentialHeaders).
//
// The outcome is recorded in Stats.AuthState; a failure is sticky, so a run
// whose start page went out unauthenticated says so even if a later page got
// the credentials. The error is returned for RequireAuth to act on.
func (c *Crawler) applyPageAuth(page *browser.Page) error {
	if len(c.config.InitialCookies) == 0 && len(c.config.ExtraHeaders) == 0 {
		return nil
	}
	var errs []error
	if len(c.config.InitialCookies) > 0 {
		zap.L().Debug("Setting initial cookies", zap.Int("count", len(c.config.InitialCookies)))
		if err := c.authOps.cookies(page, c.config.InitialCookies); err != nil {
			errs = append(errs, fmt.Errorf("set cookies: %w", err))
		}
	}
	if len(c.config.ExtraHeaders) > 0 {
		c.mu.Lock()
		withdrawn := c.credentialHeadersWithdrawn
		c.mu.Unlock()
		target := c.config.URL.String()
		switch {
		case withdrawn:
			// Withdrawn when the crawl left the credential scope; a fresh page
			// (reset) does not bring them back.
		case !c.credentialOriginAllowed(target):
			c.denyCredentialHost(c.config.URL.Hostname())
			errs = append(errs, fmt.Errorf("extra headers withheld: the target %s is outside the operator scope", c.config.URL.Hostname()))
		default:
			zap.L().Debug("Setting extra headers", zap.Int("count", len(c.config.ExtraHeaders)))
			if err := c.authOps.headers(page, c.config.ExtraHeaders); err != nil {
				errs = append(errs, fmt.Errorf("set extra headers: %w", err))
			}
		}
	}
	err := errors.Join(errs...)
	c.mu.Lock()
	switch {
	case err != nil:
		c.stats.AuthState = AuthFailed
	case c.stats.AuthState != AuthFailed:
		c.stats.AuthState = AuthApplied
	}
	c.mu.Unlock()
	if err != nil {
		zap.L().Warn("Spidering: configured authentication could not be applied", zap.Error(err))
	}
	return err
}

// seedPageAuth applies configured authentication to the start page. The error
// is non-nil only when RequireAuth turns a failed application into a failed
// crawl; otherwise the crawl proceeds and Stats.AuthState says "failed".
func (c *Crawler) seedPageAuth(page *browser.Page) error {
	if err := c.applyPageAuth(page); err != nil && c.config.RequireAuth {
		return fmt.Errorf("authentication required but not applied: %w", err)
	}
	return nil
}

// withdrawCredentialHeaders stops sending the operator's extra headers once
// the crawl's page lands on a host the credential scope does not admit (an
// off-host start redirect: a relocated app being adopted, or a login wall).
// The headers are cleared on page and not installed on later pages; the host
// is recorded (never the header values). Cookies are untouched — the browser's
// jar already scopes them by domain. Without CDP request interception a
// header has necessarily ridden on the redirect hop that got here; this stops
// every request after it.
func (c *Crawler) withdrawCredentialHeaders(page *browser.Page, landingURL, host string) {
	if len(c.config.ExtraHeaders) == 0 || c.credentialOriginAllowed(landingURL) {
		return
	}
	c.mu.Lock()
	already := c.credentialHeadersWithdrawn
	c.credentialHeadersWithdrawn = true
	c.mu.Unlock()
	c.denyCredentialHost(host)
	if already {
		return
	}
	if err := c.authOps.headers(page, map[string]string{}); err != nil {
		zap.L().Warn("Spidering: could not clear credential headers after leaving the credential scope",
			zap.String("host", host), zap.Error(err))
		return
	}
	zap.L().Warn("Spidering: stopped sending configured credential headers — the crawl left the operator scope",
		zap.String("host", host))
}

// denyCredentialHost records a host credential headers were kept from.
func (c *Crawler) denyCredentialHost(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if host == "" || slices.Contains(c.stats.CredentialHostsDenied, host) {
		return
	}
	c.stats.CredentialOriginsDenied++
	c.stats.CredentialHostsDenied = append(c.stats.CredentialHostsDenied, host)
}
