# Spitolas — Browser-Based Web Crawler

Spitolas is a state-machine-driven web crawler that drives a real Chromium browser to discover application states through user-like interactions (clicking, form filling, iframe traversal). All resulting HTTP traffic is captured at the CDP level and fed into vigolium's scanning pipeline.

## How It Works

```
RunSpider(config, recordSaver)
  │
  ▼
┌─────────────────────────────────────────────────┐
│  Browser Pool (Chromium via rod)                │
│  ├── CDP Network Capture (all tabs/iframes)     │
│  └── Auto dialog handler (alert/confirm/prompt) │
└────────────────────┬────────────────────────────┘
                     │ navigate to target URL
                     ▼
┌─────────────────────────────────────────────────┐
│  Capture Index State (DOM snapshot + SHA256 ID) │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  Crawl Loop                                     │
│  1. Pick next state (candidates + priority)     │
│  2. Reset browser → navigate to index           │
│  3. Replay shortest path to target state        │
│  4. Fire unfired actions (click/hover/submit)   │
│  5. Capture new DOM → compare → add state/edge  │
│  6. Repeat until termination condition met       │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  Network Writer                                 │
│  CDP events → httpmsg.HttpRequestResponse       │
│  → RecordSaver (database) → scanning pipeline   │
└─────────────────────────────────────────────────┘
```

## Core Concepts

### States and the State Graph

A **State** is a DOM snapshot identified by `SHA256(strippedDOM)[:16]`. The **State Graph** is a directed graph where nodes are states and edges are actions that caused transitions. Navigation between states uses Dijkstra's shortest path (with Yen's K-shortest as fallback).

**Near-duplicate detection** uses normalized Levenshtein distance (threshold: 10%). For large DOMs (>10K chars), a sampling-based distance is used for performance.

### Actions and Candidate Elements

Candidate clickable elements are discovered via CSS selectors (`a`, `button`, `[onclick]`, `[role=button]`, `input[type=submit]`, framework-specific bindings like `[ng-click]`, `[v-on:click]`, etc.). Each candidate becomes an **Eventable** (graph edge) once fired, linking a source state to a target state with an event type (click, hover, enter).

### Fragments (Visual Page Segmentation)

Pages are decomposed into **Fragments** — DOM regions identified by XPath, bounding box, subtree size, and content hash. Two modes:

- **Landmark** (default): fast DOM-based extraction
- **VIPS**: vision-based page segmentation with multi-pass decreasing thresholds

Fragment comparison uses the **APTED** tree edit distance algorithm. The Fragment Manager tracks exploration status across duplicate/equivalent fragments and uses **candidate influence** scoring to prioritize which states to explore next.

### Form Handling

The Form Handler detects and fills forms with smart value generation:

- Field-name-aware values (email, password, phone, URL, etc.)
- Constraint-aware generation (respects `pattern`, `min`/`max`, `minlength`/`maxlength`)
- Pairwise fallback when filling all inputs at once fails
- File upload support with type-aware file selection (a benign generated
  fixture, created in the run's scratch directory)
- A click fills only the controls of the form it would submit
- Each control's fill is reported as verified, attempted, rejected, skipped or
  unsupported — a value that did not stick is not counted as filled

What the crawl may change — field edits, submissions, uploads, downloads,
account creation, credential attempts, dialog answers — is one explicit policy
(`spidering.interaction`), printed under the Spidering header. See
[Browser policy](../../guides/browser-policy.md).

### Exploration Strategies

| Strategy | Description |
|----------|-------------|
| `adaptive` (default) | **Exp3.1** multi-armed bandit — balances exploitation (known-good actions) with exploration (untried actions) via importance-weighted probability sampling. Rewards are based on new-state discovery. |
| `normal` | BFS state selection with FIFO action selection. |
| `random` | Random state selection with FIFO action selection. |
| `oldest_first` | DFS-like state selection with FIFO action selection. |
| `shallow_first` | Prioritizes states with the lowest crawl depth. |

## Browser Management

- **Browser engines**: select `chromium`, `ungoogled`, or `fingerprint` with
  `--browser-engine`; availability of the latter two depends on the platform and
  build. Embedded browser archives are extracted on first use and cached by
  version. An explicit `spidering.browser_path` overrides automatic resolution.
- **Display mode**: headless is the default. Use `--headed` to show browser
  windows, or set `spidering.headless: false` in configuration.
- **Security posture**: sandbox on (dropped, with a named warning, only where
  the host cannot provide one), same-origin policy and mixed-content blocking
  intact, certificate errors ignored like the scanner's HTTP transport. Each
  exception is configurable (`spidering.browser_compat`, `--browser-insecure`)
  and the effective set is printed as `Browser security:`.
- **One browser**: the crawler is single-threaded; `--browsers N` above 1 is
  clamped to 1 with a warning. Several targets crawl in parallel only as
  separate processes.
- **Cancellation**: a cancelled scan stops browser provisioning (including a
  Chrome for Testing download) and tab creation, not just the crawl loop.

## Network Capture

Traffic is captured at the **browser level** (not page level) via CDP events, covering all tabs, popups, and iframes:

1. `NetworkRequestWillBeSent` → record request
2. `NetworkResponseReceived` → record response headers
3. `NetworkLoadingFinished` → fetch response body

Hash-based deduplication prevents duplicate records. A cleanup loop removes stale pending requests (>15s). Captured traffic is converted to `httpmsg.HttpRequestResponse` and saved via the `RecordSaver` interface with source `"spidering"`.

Stored `duration_ms` is request → response headers; the body fetch over CDP is
timed separately. A dynamic response whose encoded body is over
`spidering.max_capture_body_bytes` (16 MiB) is recorded without its body.

### Capture receipt

Every crawl (and every browser probe that captures) ends with a **capture
receipt** read from the writer after it has drained: records accepted,
persisted, refused after close, failed, and whether the final drain completed.
A phase or tool reports what was persisted, never merely that capture was
configured. The Spidering completion line sums the receipts of every crawl; when
any record was lost it reads `N records (M failed — run incomplete)` (or notes
that the capture did not finish draining), and the low-yield decision that
triggers extra discovery treats lost records as found rather than reading a
lossy run as an empty site. "Incomplete" means the stored traffic is a lower
bound: the browser saw more than the database holds.

### Carried session

Unless `--no-carry-browser-session` is given, the browser's cookie jar at the
end of a crawl is carried forward into Discovery and DynamicAssessment, so those
phases inherit the WAF/bot clearance and the logged-in session the real browser
earned. A harvested bearer token is carried too, scoped to the exact origin
(scheme + host + port) it was minted for.

Cookies are carried **with their attributes** — Domain, Path, Secure, expiry,
and whether the cookie is host-only — and the HTTP path evaluates them per
request the way a browser does (RFC 6265 §5.4): a host-only cookie is not sent
to a subdomain, a `/admin` cookie is not sent to `/` or to `/administrator`, a
`Secure` cookie is not sent over plain http, and an expired cookie is not sent
at all. Content discovery configures one static `Cookie` header per target, so
it evaluates the same jar for the target's **origin** with the path ignored, and
still drops `Secure` cookies on an http target.

Where a browser would send two same-name cookies at different paths, the carried
session sends the more specific one: it leaves as a single flat header, and the
duplicate would be dropped downstream regardless.

An operator `-H Cookie` always wins over the carried session; the carried
cookies are merged into a request's own `Cookie` header only for names it does
not already have.

## Termination Conditions

The crawl stops when any of these are met:

- Maximum states discovered
- Maximum duration elapsed
- Maximum crawl depth reached
- Maximum consecutive failures
- No more candidate actions to explore
- Context cancellation

## Entry Point

```go
result, err := spitolas.RunSpider(ctx, spitolas.SpiderConfig{
    TargetURL:    "https://example.com",
    MaxStates:    100,
    MaxDuration:  10 * time.Minute,
    MaxDepth:     5,
    BrowserCount: 1,
    Strategy:     "adaptive",
}, recordSaver)
```

Returns `SpiderResult` with: states discovered, actions executed/failed, forms
submitted / prevented by policy / uncertain, duration, records saved, the
capture receipt (`Capture`), the authentication outcome (`AuthState`:
`not-requested`, `configured`, `applied` or `failed` — never "verified"), hosts
credential headers were withheld from, auxiliary fetches denied by scope, and
readiness conditions that never met. A crawl that fails after starting returns a
partial result (records saved, capture receipt, auth state) alongside the error.
