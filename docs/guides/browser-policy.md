# Browser policy

The browser crawl (Spidering and the targeted Re-spider) clicks, types and
submits like a user, so it can change application state. This page is the
contract for what it is permitted to change, which browser security exceptions
it runs with, where it sends credentials, and what its reports mean.

Vigolium does not offer a "read-only website" mode. Even a plain GET navigation
can have server-side effects, and a page's own script can send requests from an
ordinary click handler. What the policy states is exactly which client actions
the crawler will and will not take.

## Interaction policy

One table, `spidering.interaction`, decides every category. Each key is
optional; an omitted key keeps its default.

| Key | Default | What it permits |
| --- | --- | --- |
| `edit_fields` | `true` | Type into, toggle and select form controls. |
| `submit_forms` | `true` | Dispatch a form submission by any mechanism: submit-control clicks, Enter, GET-form synthesis, POST-form triggers. |
| `upload_files` | `true` | Attach a benign generated fixture (or the configured value) to file inputs. Withdrawn when `edit_fields` is off. |
| `download_files` | `false` | Let the browser save downloads (into the run's own profile directory, never `~/Downloads`). |
| `register_account` | `false` | Complete a public signup form and continue as that account. Never turned on by intensity. |
| `login_attempts` | by intensity | Try a short documented list of default credentials on a confirmed local login form: off at quick/lite, minimal list at balanced, full list at deep. Withdrawn when `submit_forms` is off. |
| `dialogs` | `record-dismiss` | How JavaScript dialogs are answered (below). |

```yaml
spidering:
  interaction:
    submit_forms: false     # a real no-submission guarantee for the crawler
    register_account: true  # opt in to self-registration
    dialogs: accept-all
```

What `submit_forms: false` (or `--no-forms`, which also turns `edit_fields`
off) enforces: submit-like clicks and Enter actions are refused at dispatch and
counted as "prevented by policy"; GET/POST form synthesis does not run; every
page gets a guard that stops native and script-driven submission
(`form.submit()`, `requestSubmit()`, submit events). It cannot stop a page
script that issues its own `fetch`/XHR. `register_account` and `login_attempts`
are their own authorization and still submit when set.

A click fills only the controls of the form it would submit. Generated email
addresses use `spidering.identity_email_domain` (`example.com` by default —
reserved, null MX — never the target's own domain).

### Precedence

Configuration merges global → project → scanning profile → CLI, key by key, so
a layer that does not name a key leaves the earlier value in place. Within the
merged settings:

1. An explicit `spidering.interaction.<key>` always wins.
2. Otherwise the legacy keys apply: `no_forms: true` turns `edit_fields` and
   `submit_forms` off; `self_register: true` turns `register_account` on. A
   conflict with an explicit key is logged once.
3. Otherwise the default — for `login_attempts`, the intensity default.

Intensity is a work budget, not an authorization: it picks the default for
`login_attempts` and the size of its credential list, and nothing else.

The resolved policy is printed under the Spidering header, with the source of
every value that is not the default:

```
Policy: edit_fields=on, submit_forms=on, upload_files=on, download_files=off, register_account=off, login_attempts=on (intensity), dialogs=record-dismiss
```

Sources: `config`, `no_forms`, `self_register`, `intensity`, `submit_forms`
(login default withdrawn because submits are denied), `edit_fields` (uploads
withdrawn because edits are denied).

## Dialog policy

Every dialog is recorded before it is answered, so dialog-based XSS
confirmation works under either policy. Each recorded dialog says how it was
answered (`accepted` / `dismissed`).

| Dialog | `record-dismiss` (default) | `accept-all` |
| --- | --- | --- |
| `alert` | accept (nothing to decline) | accept |
| `confirm` | dismiss | accept |
| `prompt` | dismiss | accept (empty text) |
| `beforeunload` | accept (dismissing would cancel the crawler's own navigation) | accept |

Under the default a page that gates an action behind `confirm()` takes its
cancel branch. `interaction.dialogs: accept-all` restores the old behavior.

## Browser security exceptions

The crawler launches Chromium with its ordinary boundaries and relaxes each
one only on request:

| Key (`spidering.browser_compat`) | Default | Effect when `true` |
| --- | --- | --- |
| `no_sandbox` | `false` | Run without the Chromium process sandbox. |
| `ignore_tls_errors` | `true` | Accept invalid certificates — matching the scanner's HTTP transport, so a self-signed target the rest of the scan reaches is crawlable. Set `false` to verify. |
| `allow_insecure_content` | `false` | Allow mixed content. |
| `disable_web_security` | `false` | Turn off the same-origin policy. |

The sandbox is dropped automatically, with one warning naming the reason, where
the host cannot provide one: running as root, inside a container, with user
namespaces disabled, or — on Linux — when a sandboxed launch fails and an
unsandboxed retry works (Ubuntu's AppArmor user-namespace restriction is the
usual cause). `--browser-insecure` turns all four exceptions on; use it for
local test apps only. The effective posture is printed under the header and
written into each crawl graph's manifest:

```
Browser security: sandbox=on, tls=ignore-errors, mixed_content=block, web_security=on
```

In-process probes (XSS confirmation, `web_fetch mode=browser`,
`browser_probe`) launch with the defaults; `browser_compat` and
`--browser-insecure` apply to the crawl phases.

## Credentials and scope

- **Cookies** from `--auth` / `--auth-file` keep their own Domain and Path; the
  browser's jar decides where they go.
- **Auth headers** (`Authorization`, API keys, `-H`) are page-wide in the
  browser, so they are installed only while the crawl is on a host the
  operator scope admits (with no custom scope: the target host and its
  subdomains). An off-host start redirect outside that scope clears them for
  the rest of the crawl; the host is logged, never the values. Without request
  interception a header still rides on the redirect hop itself and on
  third-party subresources of an in-scope page.
- **Auth state** is reported per target: `not-requested`, `configured`,
  `applied` or `failed`. There is no "verified" — applying credentials does
  not prove the application accepted them. A `failed` target is crawled
  unauthenticated unless `spidering.require_auth` / `--require-auth` is set, in
  which case it fails.
- **Auxiliary fetches** — the in-page primers that fetch iframe sources,
  GET-form URLs, parameterized links, robots/sitemap locations and URL-like
  strings — go through one check that drops destructive-looking paths and
  anything outside the operator scope (counted as `aux_fetches_denied`). The
  service-worker primer fetches inside its own script, so it is off whenever a
  custom scope is configured.

## Reports and artifacts

- The Spidering summary counts form submissions dispatched by every
  mechanism, those prevented by policy, and POST forms whose outcome could not
  be attributed (`uncertain` — no fallback request is sent, so a write is never
  duplicated).
- Capture is reported from receipts; `run incomplete` means records were lost
  and the stored traffic is a lower bound.
- Crawl graphs (`graph_output_dir`) are written `0600`, atomically, named per
  run and seed, carry the policy and security posture, and are redacted unless
  `graph_include_values: true`. Graph files from before this format (`version`
  1) were not redacted.

## Not supported

- **No read-only mode.** See the top of this page.
- **Cancellation is not rollback.** Cancelling a scan stops the crawl, browser
  provisioning and in-flight waits, but an in-page script already started may
  finish its requests, and nothing the crawl did is undone.
- **No parallel browsers.** `browser_count` / `--browsers` above 1 is clamped
  to 1 (single-threaded crawler); run separate processes for parallel targets.
- **No public web search** tool for the agent; `web_fetch` fetches a URL it is
  given.
- **Form training** (`FormTrainer`) is an internal component with no operator
  workflow.
- **Per-request credential routing** (sending a header to one origin and not
  another on the same page) needs request interception and is not done.
