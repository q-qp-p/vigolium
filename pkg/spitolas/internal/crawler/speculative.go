package crawler

import (
	"context"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"go.uber.org/zap"
)

// speculativeDiscoverScript scrapes URL-like strings out of the LIVE document —
// HTML comments and inline <script> content — and returns the same-origin ones
// as a JSON array.
//
// This reads the rendered document on purpose. Anything parsing the served HTML
// sees the pre-hydration shell; a single-page app writes its API base paths,
// route table, feature endpoints and environment config into inline script and
// injected markup that only exist after the framework has run. Commented-out
// markup is worth the same look: a disabled admin link or a staging endpoint
// left in a comment names a real location nothing links to any more.
//
// Two filters keep the yield usable rather than merely large. Strings must look
// like paths (a leading slash, or a same-origin absolute URL) — bare words from
// a bundle's string table are not candidates. And known static-asset extensions
// are dropped: the page already loaded the ones it needs, so re-fetching them
// costs requests and records nothing new.
//
// __MAX__ is substituted with the cap. Token substitution rather than
// Sprintf: the script itself contains %-signs (a URL-encoding character class,
// a format-specifier guard) that a format verb scan would misread.
// No backticks: embedded as a Go raw string.
const speculativeDiscoverScript = `(() => {
  const MAX = __MAX__;
  const origin = location.origin;
  const out = [];
  const seen = new Set();

  const SKIP_EXT = /\.(png|jpe?g|gif|svg|webp|avif|ico|bmp|css|woff2?|ttf|eot|otf|mp[34]|webm|ogg|wav|pdf|zip|gz|tgz|rar|7z|dmg|exe|map)(\?|#|$)/i;

  const add = (raw) => {
    if (!raw || out.length >= MAX) return;
    let s = String(raw).trim();
    if (!s || s.length > 512) return;
    // Template placeholders and format specifiers are not locations.
    if (/[{}<>\s"'` + "`" + `\\]/.test(s)) return;
    if (s.indexOf('${') !== -1 || s.indexOf('%s') !== -1) return;
    let u;
    try { u = new URL(s, origin); } catch (e) { return; }
    if (u.origin !== origin) return;
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
    if (SKIP_EXT.test(u.pathname)) return;
    if (u.pathname === '/' && !u.search) return;
    u.hash = '';
    const href = u.href;
    if (seen.has(href)) return;
    seen.add(href);
    out.push(href);
  };

  // Absolute same-origin URLs, and root-relative paths with at least one more
  // segment. The second segment requirement drops "/" and single characters
  // that a minifier's string table is full of.
  const ABS = new RegExp(origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\/[^\\s"\'` + "`" + `<>\\\\)]{1,256}', 'g');
  const REL = /["'` + "`" + `](\/[A-Za-z0-9_\-./]{2,200}(?:\?[A-Za-z0-9_\-.=&%]{0,120})?)["'` + "`" + `]/g;

  const scan = (text) => {
    if (!text || out.length >= MAX) return;
    let m;
    ABS.lastIndex = 0;
    while ((m = ABS.exec(text)) !== null && out.length < MAX) add(m[0]);
    REL.lastIndex = 0;
    while ((m = REL.exec(text)) !== null && out.length < MAX) add(m[1]);
  };

  // 1) HTML comments anywhere in the rendered tree.
  try {
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
    let n, comments = 0;
    while ((n = walker.nextNode()) !== null && comments < 500 && out.length < MAX) {
      comments++;
      scan(n.nodeValue);
    }
  } catch (e) {}

  // 2) Inline script content. External bundles are skipped — they are fetched
  //    and analysed on their own; re-scanning them here would only duplicate.
  try {
    let scripts = document.querySelectorAll('script:not([src])');
    let count = 0;
    for (const s of scripts) {
      if (++count > 60 || out.length >= MAX) break;
      scan(s.textContent);
    }
  } catch (e) {}

  return JSON.stringify(out);
})()`

// renderSpeculativeScript substitutes the crawl's link cap into the discovery
// script. The cap is fixed for the life of a crawl and the script is several KB,
// so this is done once at construction rather than rebuilding and re-shipping
// the same string on every state.
func renderSpeculativeScript(maxLinks int) string {
	return strings.ReplaceAll(speculativeDiscoverScript, "__MAX__", strconv.Itoa(maxLinks))
}

// filterInScope drops URLs outside the operator's boundary. The browser's
// same-origin rule is not the same question: a sitemap or a config blob
// legitimately names locations this scan was not asked to touch.
func (c *Crawler) filterInScope(urls []string) []string {
	if c.config.CrawlScope == nil {
		return urls
	}
	out := urls[:0]
	for _, u := range urls {
		if c.config.CrawlScope(u) {
			out = append(out, u)
		}
	}
	return out
}

// harvestSpeculativeLinks scrapes URL-like strings from the rendered document's
// comments and inline script and fetches the new, in-scope ones so the network
// capture records them.
//
// Best-effort and bounded: any failure is logged at debug and the crawl
// continues. Deduped against everything already primed this crawl, so a config
// blob repeated on every page is fetched once.
func (c *Crawler) harvestSpeculativeLinks(ctx context.Context, page *browser.Page) {
	if page == nil || c.config == nil || !c.config.SpeculativeLinks {
		return
	}
	if ctx.Err() != nil {
		return
	}

	// SpeculativeMaxLinks is this source's own crawl-wide allowance, spent down
	// across every state that contributes strings — the harvest runs on each new
	// state, so a per-call cap would let a long crawl fetch an unbounded total.
	//
	// Checked FIRST: everything below is expensive (a full-document eval, a JSON
	// parse, a url.Parse per candidate), and once the allowance is gone every
	// remaining state would pay all of it only to discover there is nothing left
	// to spend.
	c.mu.Lock()
	remaining := c.config.SpeculativeMaxLinks - c.stats.SpeculativeLinksFetched
	c.mu.Unlock()
	if remaining <= 0 {
		return
	}

	raw, err := page.Eval(c.speculativeScript)
	if err != nil {
		zap.L().Debug("Speculative link discovery failed", zap.Error(err))
		return
	}
	jsonStr, ok := raw.(string)
	if !ok || jsonStr == "" || jsonStr == "<nil>" {
		return
	}
	var discovered []string
	if err := parseJSONLinks(jsonStr, &discovered); err != nil || len(discovered) == 0 {
		return
	}

	// Early pruning only — fetchURLsInPage (admissibleFetchURLs) is the
	// enforcement point. Filtering here bounds the work before the budget maths
	// below, which depends on the in-scope length.
	inScope := c.filterInScope(discovered)
	if len(inScope) == 0 {
		return
	}

	// The primed set is shared with the anchor primer so a URL reachable both as a
	// link and as a scraped string is fetched once; the budget is not, so neither
	// source can consume the other's. MaxParamValueVariants keeps an id-indexed
	// string set from spending the whole allowance on one endpoint shape.
	toFetch := c.selectUnprimedLinksBudgeted(inScope, remaining, c.config.MaxParamValueVariants)
	if len(toFetch) == 0 {
		return
	}
	zap.L().Debug("Speculative links harvested from rendered document",
		zap.Int("candidates", len(inScope)), zap.Int("fetching", len(toFetch)))
	c.fetchURLsInPage(ctx, page, toFetch, "speculative")

	c.mu.Lock()
	c.stats.SpeculativeLinksFetched += len(toFetch)
	c.mu.Unlock()
}
