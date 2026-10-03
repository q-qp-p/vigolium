# Driving Vigolium from a coding agent

A compact, copy-paste reference for running Vigolium **non-interactively** from an
LLM/coding agent and parsing the results. Everything here is additive — the
default human output is unchanged; you opt into machine output with `-j/--json`.

> **Using an agent skill instead?** The same material — plus the replay/fuzz
> confirm chain and the Burp handoff — ships inside the binary as
> `references/agent-loop.md` in the `vigolium-scanner` skill. Install it with
> `vigolium skills install --agent claude` and your agent gets a version-matched
> copy without reading this page. See
> [`public/skills/README.md`](../public/skills/README.md).

## Mental model

- All data is stored in a project-scoped SQLite/Postgres DB. A scan **writes**
  findings + HTTP records; query commands **read** them back.
- Two JSON contracts:
  - **`-j/--json`** on read/query commands (`finding`, `traffic`, `db`) → a single
    structured object with **compact, token-aware** bodies. This is what you parse.
  - **`--format jsonl`** / `export` → the bulk `{"type":...,"data":{...}}` stream
    (one object per line). Use for archival/bulk, not triage. It is a *view*, not
    a lossless copy of the store: HTTP exchanges sharing a URL collapse to the
    first one (plus any exchange a finding links to), and only confirmed findings
    are emitted. `export --no-url-dedup` turns the collapse off; for the complete
    store use `-S --format sqlite` or copy the database file.
- Non-interactive by default: the TUI is opt-in (`--tui`), never auto-launched.
  Destructive commands need `--force`. Add `--no-color` (or `NO_COLOR=1`) for
  clean text; scope with `--project-uuid <uuid>`, `--project-name <name>`,
  `VIGOLIUM_PROJECT_UUID`, or `VIGOLIUM_PROJECT_NAME`.

## Token-aware output (the important part)

Under `--json`, `finding` and `traffic` keep headers + high-signal metadata but
**bound** request/response bodies so you don't blow your context window:

- Bodies are previewed (first ~1–2 KB) with `body_size` + `body_sha256` +
  `body_truncated:true` so you know there's more.
- Binary/static bodies (images, fonts, JS bundles, gzip) are stubbed as
  `{"body_omitted":"binary", ...}`.
- Findings get a `response_evidence` snippet windowed around the match instead of
  the whole page.

Control it:

| Flag | Effect |
|------|--------|
| `--compact` | metadata only, drop bodies (best for surveys / listing endpoints) |
| `--fields a,b,c` | project the JSON to just these top-level keys (cuts tokens hard) |
| `--with-records` | (finding) resolve + embed the linked HTTP records — a self-contained triage bundle |
| `--full-body` | include complete, decoded bodies (use when you need to write an exploit) |
| `--raw` | full raw HTTP request/response, human format (not JSON) |
| `--pick` | (finding) keep only the 1-based position(s) from the result list — `2`, `1,3`, or `2-4`; applied after `--search`/filters + sort |
| `--max-output-bytes N` | cap the whole result document at N bytes, dropping whole trailing items (`0` = unlimited, the default) |

### Capping the size of a result document (`--max-output-bytes`)

`-n/--limit` counts rows, and rows vary in size by orders of magnitude — twenty
compact findings are a few KB, twenty traffic records under `--full-body` are
tens of MB. If what you actually have is a byte budget (a context window, a log
limit, a response body), cap it directly:

```bash
vigolium traffic -j --full-body --max-output-bytes 65536
```

- Opt-in: `0` (the default) is unlimited, and nothing changes for a caller that
  does not pass it. Available on `finding`, `traffic` and `db ls`.
- The cut is at a **record boundary**, so what you get is still one valid JSON
  document — never a prefix of a broken one.
- A truncated document carries an `output_budget` object and nothing else
  changes:

  ```json
  "output_budget": {"max_bytes": 65536, "returned": 14, "omitted": 26,
                    "next_offset": 14}
  ```

  Resume with `--offset <next_offset>`. `total` still describes the whole result
  set, so a page cut by bytes reports exactly as one cut by `-n` does — including
  `complete: false` in the `-o` receipt.
- A budget too small for the envelope's fixed parts fails with exit `1` and
  `error.code: "output_too_large"` rather than emitting an over-budget document.
- It requires `-j/--json` (exit `2` otherwise): a silently ignored budget is
  indistinguishable from one that did not bind.

## Run a scan and gate on results

```bash
# Single-shot into your project DB, JSON findings to stdout, fail on high+.
vigolium scan-url https://target.example --json --fail-on high

# Same, but throw the database away afterwards (nothing persists).
vigolium scan-url https://target.example -S --json --fail-on high

# Full pipeline into the DB, exit non-zero if a high/critical is found (CI gate).
vigolium scan -t https://target.example --fail-on high

# Scan a raw request from stdin (pipeline-friendly).
printf 'GET /api?q=1 HTTP/1.1\r\nHost: target.example\r\n\r\n' \
  | vigolium scan-request --json
```

- `--fail-on <info|low|medium|high|critical>`: exit non-zero when a finding at or
  above that severity is present. `--soft-fail` forces exit 0 (still prints the
  reason). Output is always written first — the gate only changes the exit code.
- **`scan-url` and `scan-request` persist by default.** Their findings and
  traffic go into the project database like any other scan; `-S/--stateless`
  is what makes a run throwaway (pair it with `-o`/`--format` to keep anything).
- `scan-url`/`scan-request` direct JSON shape, for a **single** target:

  ```json
  { "target": "https://target.example/", "method": "GET",
    "scan_duration_ms": 1840, "modules_run": 325, "persisted": true,
    "findings": [ … ] }
  ```

  `persisted` says whether the results also reached a database — `false` for a
  `-S` run, or when no store was named and the scan ran in memory. `errors` is
  omitted when there were none, so test for its presence rather than for an
  empty array. `interrupted: true` appears when a signal cut the scan short.
- **Several targets produce one envelope, not one document each.** `scan-url -j`
  with more than one `-t` emits a single `agentEnvelope` whose `items` are the
  per-target objects above, plus `targets_not_scanned` listing anything an
  interrupt never reached. A single target keeps the bare shape, unchanged.

## Query findings

```bash
# Compact triage list of high+ findings, only the fields you need.
vigolium finding --min-severity high --json --compact \
  --fields id,severity,module_id,url,matched_at

# One finding, fully self-contained (finding + linked request/response).
vigolium finding --id 42 --json --with-records

# Narrow a search to the Nth match by list position (1-based), e.g. the 2nd.
vigolium finding --search 'Reverse Proxy' --pick 2 --raw

# Findings from a specific agent run (autopilot/swarm/audit).
vigolium finding --agentic-scan <agentic_scan_uuid> --json --with-records
```

Filters (shared with `traffic` / `db ls`): `--host --path --method --status
--severity --min-severity --from/--to --search --scan-uuid --agentic-scan
--module-type -n/--limit --offset --sort --asc`.

`--from`/`--to` (also spelled `--since`/`--until`) take a relative offset as well
as an absolute time, so recent work is reachable without computing a date:

```bash
vigolium finding --since today          # found since local midnight
vigolium finding --since 2d             # the last 48 hours
vigolium traffic --since 90m --until 30m
vigolium finding --since yesterday --until yesterday   # just yesterday
vigolium traffic --from 2026-08-05 --to 2026-08-05     # one whole day
vigolium finding --since '2026-08-05 14:30'            # from a wall-clock time
```

Accepted: `30s`/`15m`/`2h`/`3d`/`1w` and compound Go durations (`1h30m`),
`today`, `yesterday`, `now`, `YYYY-MM-DD`, `YYYY-MM-DD HH:MM[:SS]`, and RFC3339.
Bare dates and wall-clock times are **local**, and a bare date on the upper bound
covers that whole day — `--from D --to D` is the full day D, not an empty range.
An inverted range is rejected rather than silently returning nothing.

`--search`/`--header`/`--body` now span the full request/response corpus (URL,
path, headers, and body). Each has an inverse: `--exclude-search` (repeatable,
AND-combined — a row is dropped if ANY term appears), `--exclude-header`, and
`--exclude-body`. Compose them, e.g. keep API traffic but drop noise:
`vigolium traffic --search api --exclude-search /health --exclude-body heartbeat`.

### Query findings → Output shape

Every `-j` read command emits the same envelope. The row array is **`items`**;
the old per-command names (`findings`, `records`, `scans`, …) are gone unless you
ask for them with `--json-legacy-keys` (or `VIGOLIUM_JSON_LEGACY_KEYS=1`), which
duplicates the rows on the wire and exists only for consumers still migrating.

```json
{
  "schema_version": 1,
  "command": "finding",
  "project_uuid": "00000000-0000-0000-defa-c01001000001",
  "project_scoped": true,
  "db_path": "/home/you/.vigolium/database-vgnm.sqlite",
  "total": 39,
  "offset": 0,
  "limit": 100,
  "items": [
    { "id": 2, "severity": "high", "module_id": "…", "url": "…",
      "matched_at": ["…"], "extracted_results": ["…"],
      "response_evidence": "…<match>…" }
  ],
  "query": "vigolium --db /home/you/.vigolium/database-vgnm.sqlite finding --id 2 --json",
  "query_argv": ["vigolium", "--db", "/home/you/.vigolium/database-vgnm.sqlite",
                 "finding", "--id", "2", "--json"],
  "generated_at": "2026-10-03T08:14:22.481Z",
  "generated_at_ms": 1791015262481
}
```

- `schema_version` is the contract version — gate on it. It is bumped on any
  breaking field change.
- `project_scoped` says whether a project filter was applied at all, so "no
  filter" is explicit rather than inferred from an absent `project_uuid`.
- `db_path` names the store that was actually opened, so a consumer pinning
  `VIGOLIUM_DB_PATH` or `--db` can assert the pin survived.
- `query`/`query_argv` are absent together under `--glob-db`; `db_path` is
  absent for a non-SQLite driver. See [Following a result](#following-a-result).
- Commands attach their own keys alongside these (`glob_sources`,
  `output_budget`, `targets_not_scanned`, …). A key colliding with one of the
  envelope's own is dropped rather than shadowing it.

## Query stored HTTP traffic

```bash
# Survey endpoints (no bodies) — cheap.
vigolium traffic --json --compact --fields uuid,method,url,status_code,response_content_type

# A few records with bounded bodies (default).
vigolium traffic --host target.example --status 200 --json -n 5

# Everything for one record, full bodies.
vigolium traffic search-term --json --full-body -n 1
```

## Read a standalone export (`-S/--stateless`)

`finding`, `traffic` and `db ls` can read a file directly instead of your
project DB — handy for inspecting a `--format jsonl` export or a foreign
`.sqlite` lying around. `-S/--stateless` requires `--db` and turns project
scoping **off by default**, so every row in the file is shown regardless of the
`project_uuid` it carries. Nothing is written to your project DB: a JSONL source
is loaded into a throwaway **file-backed** SQLite inside the process scratch
directory, which is deleted on exit. (It was an in-memory database once; a
corpus large enough to matter did not fit, and a `--glob-db` merge of several
sources never did.)

Two things follow from "off by default":

- **An explicit project selection still filters.** `--project-uuid X` (or
  `VIGOLIUM_PROJECT_UUID`) narrows a stateless read to that project; it used to
  be accepted and ignored. When the selection came from the environment rather
  than the command line, one notice line is printed to stderr so an invisible
  filter is not a mystery. `--project-name` needs a project registry to look the
  name up in, which a JSONL export and a `--glob-db` merge do not have — those
  exit `2` and tell you to use `--project-uuid`.
- **Rows keep their own `project_uuid`.** A JSONL load and a `--glob-db` merge
  report the project each row was exported under, not the default project of
  whoever is reading. (`vigolium import` still re-homes rows into the project
  they are imported into — importing means joining.)

`-S` parses on every command so a driver never has to keep a per-command
acceptance table, but on a command that does nothing with it you now get one
stderr line saying it was ignored.

**`--glob-db` accounts for every match.** The merge is still best-effort — a
source that cannot be imported is skipped and the rest are read — but a skipped
source is now *rolled back* rather than left half-merged, and the `-j` envelope
carries a `glob_sources` object on every glob read:

```json
"glob_sources": {"pattern": "scans/*.sqlite", "matched": 40, "loaded": 39,
                 "skipped": [{"file": "scans/partial.sqlite", "error": "..."}]}
```

Assert `matched == loaded` before trusting a merged read to be complete;
`skipped` is `[]` when it is. Pass `--glob-strict` (on `finding`, `traffic`,
`export`) to fail the read on the first bad source instead.

```bash
# Browse a scan's JSONL export with all the normal filters/sorting.
vigolium finding -S --db ./scan-target.jsonl --min-severity medium
vigolium traffic -S --db ./scan-target.jsonl --status 500 -n 20

# A standalone .sqlite works too (auto-detected by extension / header sniff).
vigolium finding -S --db ./run.sqlite --json --with-records
```

A stateless scan can emit that `.sqlite` directly with `--format sqlite` (aliases
`sqlite3`, `db`) — it dumps the per-run DB to `<output>.sqlite` and combines with
other formats. Under `--split-by-host` each per-host file is named
`<base>-<host>.sqlite`:

```bash
vigolium scan -S --format sqlite,html -o scan -t target.example   # → scan.sqlite + scan.html
vigolium scan -S --format sqlite -o run --split-by-host -P 4 -T targets.txt  # → run-<host>.sqlite per target
vigolium finding -S --db ./run-target.example.sqlite --min-severity high
```

## Merge external `.sqlite` scans into one DB (`vigolium import`)

The stateless reads above open a foreign `.sqlite` **in place**. To instead
**fold** those external databases into a single one, `vigolium import` accepts a
vigolium SQLite database as its source and merges it into the destination DB
(the `--db` target, or the configured default when `--db` is omitted). The source
is auto-detected by its SQLite header, so `.sqlite`, `.sqlite3`, `.db`, or a bare
name all work. It's a lossless, **idempotent** merge — HTTP records, findings,
scans, agentic scans, and OAST interactions all flow in, deduped on their natural
keys (records by UUID, findings by `(project_uuid, finding_hash)`), so re-running
the same import adds nothing. Each row keeps its original `project_uuid`.

```bash
# Merge one external scan DB into your default database.
vigolium import other-vigolium-scan.sqlite

# Merge into an explicit destination (--db is the target, not a filter).
vigolium import --db default-db.sqlite other-vigolium-scan.sqlite

# Collapse a directory of per-host/per-run exports into one combined DB.
for f in scans/*.sqlite; do vigolium import --db combined.sqlite "$f"; done
vigolium finding --db combined.sqlite --min-severity high

# -j prints a per-table merge summary for scripting.
vigolium -j import --db combined.sqlite other-vigolium-scan.sqlite
```

This is the natural companion to `vigolium scan -S --format sqlite` above: fan out
scans into standalone per-host `.sqlite` files, then merge them back into one
queryable database. (`import` also still ingests audit folders, JSONL exports,
and `.tar.gz`/`.zip` archives — see `vigolium import -h`.) A Postgres destination
is rejected with a clear error, since the merge is SQLite-to-SQLite.

**JSONL imports are idempotent too.** A record whose `uuid` is already stored is
skipped rather than aborting the run, so re-importing the same export, or two
exports that overlap, is safe. The `-j` document reports
`records_skipped_duplicate` alongside `records_imported`.

**A lossy import exits 1.** Two counters mean data was in the source and is not
in the database, and either being non-zero is now a non-zero exit:

- `findings_failed` — findings the destination refused. Always present in the
  `-j` document. Distinct from `findings_skipped`, which is the benign "already
  present" case; the two used to be summed, so a lossy import and a repeated one
  printed the same line.
- `parse_errors` — lines the JSONL parser could not read (a truncated transfer,
  a mangled file). Present when non-zero.

The summary still prints in full before the non-zero exit, so you can see what
did land. A completely unreadable source is still a plain exit-1 error with no
summary.

A single JSONL line is capped at 256 MiB. Past that the import fails naming the
line number and how many records had already been committed, instead of reading
a non-JSONL file into memory until the kernel intervenes.

## Render one finding/record as Markdown (`--markdown`)

`--markdown` prints the selected findings/records as Markdown (evidence +
request/response in fenced `http` blocks) to stdout — pipe it to a file or a
viewer like `glow`. Pair with `--id` / a fuzzy term / `-n 1` to focus one item.

Under `-S/--stateless`, add `--compact` to window the response around the
finding's `matched_at` / `extracted_results` (records cap the body to a preview)
so a long page doesn't flood the console:

```bash
vigolium finding -S --db ./scan-target.jsonl --id 42 --markdown            # full bodies
vigolium finding -S --db ./scan-target.jsonl --id 42 --markdown --compact  # response windowed at the match
vigolium traffic -S --db ./scan-target.jsonl search-term -n 1 --markdown
```

## AI / agentic scans

These run an LLM-driven scan into the DB. With `--json`, the live agent stream
goes to **stderr** and a single JSON summary is printed to **stdout** at the end:

```bash
vigolium agent audit --source . --intensity balanced --json
vigolium agent autopilot -t https://target.example --json
vigolium agent swarm -t https://target.example --json
```

Summary shape (stdout):
```json
{ "agentic_scan_uuid": "...", "status": "completed", "session_dir": "...",
  "total_findings": 7, "counts_by_severity": {"critical":1,"high":3},
  "top_findings": [ ... ],
  "query": "vigolium finding --agentic-scan <uuid> --json --with-records" }
```

Then pull the full results with the `query` line. The `--agentic-scan` filter
expands to the whole run tree (audit driver legs / swarm sub-runs), so one UUID
returns every finding the run produced.

For a one-shot code review without a full scan:
```bash
vigolium agent query --prompt-template security-code-review --source . --json
```

## Counts, export, housekeeping

```bash
vigolium db stats --json                 # counts by severity / per-host
vigolium export --format jsonl -o out.jsonl   # bulk {type,data} stream
vigolium export --format jsonl --no-url-dedup -o all.jsonl  # every stored exchange
vigolium module --json                   # machine-readable module catalog
vigolium doctor --json                   # environment readiness
```

**Single-file `-o` outputs are published atomically.** `export -o`,
`db export -o` and `db export --format bundle` stage into a sibling temp file and
rename it into place, so a run that fails — a database read error, a full disk,
a Ctrl-C — leaves the *previous* file at that path rather than a half-written one
you cannot tell from the real thing. The one exception is `db export -o` under
`--watch`, which rewrites the same destination on every tick and so has no single
publication point.

**Export reads are strict.** A table the export cannot read fails the run
(exit `1`, with the failing table named in the message) instead of producing a
well-formed file silently missing that table. Under a scan's own `--format
jsonl` the failure is reported as `error.code: "export_failed"` like every other
unwritten artifact. The only thing still reported-but-not-fatal is the
`N endpoint(s) exported without host facts` notice on stderr: those records were
read, they just have no stored DNS/TLS observation.

## Export a browsable filesystem tree (`--format fs`)

When you'd rather `ls`/`grep`/`jq` a scan than query a DB, export a flat tree.
Works on `export`, `db export`, and any scan (`scan`/`scan-url`/`scan-request`/`run`).

```bash
vigolium export --format fs -o run            # whole DB → run-traffic/ + run-findings/
vigolium scan-url https://t/ -S --format fs -o run   # straight from a scan
```

Layout (two sibling dirs off the `-o` base; defaults to `vigolium` in the cwd):

```
run-traffic/
  index.json                 # [{id,host,path,method,url,status,content_type,bytes,finding}, …]
  <host>/0001.req            # "@target https://<host>" + the raw request (replayable)
  <host>/0001.resp.headers   # status line + response headers
  <host>/0001.resp.body      # response body, gzip-decoded so it greps clean
run-findings/
  index.json                 # [{id,host,path,severity,confidence,module,title,url,traffic}, …]
  <host>/0001.md             # the finding, cross-linked to ../../run-traffic/<host>/0001.req
```

`index.json` is the entry point — one `jq` over it maps every id to its url/status
and to the file that holds the bytes, so you never guess paths. The `finding` field
on a traffic row is the top severity of any finding touching that request, and each
finding `.md` links straight to the `.req`/`.resp.*` that proves it. `--omit-response`
drops the `.resp.*` files; `--split-by-host` is a no-op (fs already splits by host).

Each export publishes a whole **generation**: the tree is built in a sibling
`.<name>.staging-*` directory and renamed over the final root only once it is
complete. So:

- A re-export **replaces** the tree. Narrowing the filters no longer leaves the
  previous run's files behind for `index.json` to disagree with.
- A re-export that now matches nothing replaces a stale tree with an empty
  index. A *first* export that matches nothing creates nothing at all.
- A base path colliding with an unrelated directory is an **error** (`refusing
  to replace <dir>: not a vigolium fs export (no index.json)`), and that
  directory is left untouched. Only an empty directory or one holding an
  `index.json` is replaceable.
- Traffic publishes before findings. Two sibling renames are not one atomic act,
  so if the findings pass fails the error says the traffic tree was already
  updated.

### Live mirror from the ingestion server

To watch traffic land as files while another tool (Burp, a proxy, `vigolium ingest`)
feeds the server, run the server with a mirror dir:

```bash
vigolium server --mirror-fs ./mirror     # also: config server.mirror_fs_path
```

Every ingested record and finding is written to `./mirror/traffic/<host>/…` and
`./mirror/findings/<host>/…` as it's saved to the DB. Same layout as `--format fs`,
except the indexes are append-only **`index.jsonl`** (one object per line — tail/grep
it live) and per-host ids resume across server restarts. Point your agent at `./mirror`
and let it `jq`/`grep` the growing tree.

## Process contract

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | success |
| `1` | the work failed |
| `2` | usage error — bad flag, bad value, rejected combination, or a mutation that needed `--force` and had no terminal to ask |
| `3` | `--fail-on-match` / `--fail-on-crack` matched (`fuzz`, `kit secret-scan`, `kit jwt-crack`) |
| `4` | the `--fail-on <severity>` gate tripped |

`3` and `4` are *completed results*, not failures: the output was written before
the code was chosen. When it was NOT written — an unwritable `-o`, a query that
failed mid-stream — the run exits `1` with `error.code: "export_failed"`, and
that outranks the gate: a `4` whose artifact is missing would send a CI job to
read a file that is not there. Each `--format` is attempted independently, so
some of them may still have landed; the "Exports" summary on stderr lists the
ones that did. This covers every artifact the run was asked for — reports
(`html`/`report`/`pdf`/`markdown`/`sarif`), the `fs` tree, the `jsonl` export
and `--upload-results` — on the persisted path as well as under `-S`; a
`--upload-results` that could not reach storage is the run failing to deliver,
while the configured webhook stays best-effort. `--soft-fail` forces the process status to `0` for all of
them while leaving the output intact — under `--json` the error object still
reports the code that would have been used, plus `"soft_fail": true`.

Under `--json` you get **exactly one document per invocation**, whatever happens:

- Flag order does not matter. `traffic --bad --json` and `traffic --json --bad`
  both emit one `usage_error` object.
- A command that already wrote its result does not get an error object appended
  to it — the exit code carries the outcome.
- A command that was *about* to write its result and then failed does get one.
  `-o <path>` that cannot be written exits `1` with `error.code:
  "export_failed"` and a message naming the path; the result document is not
  printed in its place, and stdout is not left empty.
- `import` holds its document until every requested artifact has landed, so a
  failed `--format` report or `--upload` produces the error object alone rather
  than a success summary followed by it. On success the document carries
  `report_path` and `uploaded_to` alongside the import counts.
- `--watch` is the one exception to "one document", and only because its frame
  is NDJSON: a failure appends one more compact line, with `"ok": false`, so a
  stream that stops says why. See Gotchas.
- Nothing else is ever written to stdout. Banners, prompts, progress, and
  warnings all go to stderr.

Confirmation for a destructive command requires a terminal. Without one it
refuses immediately with exit `2` rather than blocking or reading your data
stream as the answer; pass `--force` to authorize it non-interactively. `--json`
is **not** authorization.

Reading stdin is bounded by `--input-read-timeout`, so a producer that never
closes its end cannot hang the process:

- Default `3m`. It applies to every stdin read in the CLI, including commands
  that do not expose the flag.
- **`0` disables the deadline**, as the help text has always said. (It used to
  silently re-arm the default, which is the one value a caller passes precisely
  because their producer is slower than any deadline they can guess.)
- A **negative** value is a usage error (exit `2`).
- `scan-url` and `scan-request` accept it too; they read a request from stdin
  like `scan` does, and had no way to bound it before.
- A single stdin or `-i` read is also capped at 512 MiB, deadline or not.

### Partial scans

A scan that ran to its end having covered less than it was given is a **partial**
scan, and partial is **not** an error:

- **The exit code does not change.** A partial scan still exits `0`. Nothing
  failed; coverage was simply less than complete, and a CI job that treats that
  as a failure would fail on every correctly time-boxed run. There is no
  `--fail-on-partial` gate today.
- **`scan.finished` reports `"status": "curtailed"`** instead of `"completed"`,
  with `stop_reason` (one code) and `reasons` (the union of every phase's
  reasons). `failed` and `interrupted` are never relabelled — a scan that failed
  is a worse outcome than one that was curtailed, and overwriting the status
  would lose the more serious fact.
- **`phase.finished` reports `"status": "curtailed"`** for a phase that was cut
  short, with `reasons` and `limits`. A phase whose own `max_duration` fired
  inside an otherwise healthy scan is included — that used to report
  `"completed"` with nothing to read.
- **`reasons` are defects; `limits` are configured bounds.** A `target_budget`
  limit means a per-target time box did its job, so it never downgrades a status.
  Act on `reasons`.
- **The scan row is authoritative.** `completeness` is `complete`, `partial`, or
  **empty**; empty means unknown (an older binary, or a caller with no outcome
  data) and must never be read as `complete`. `stop_reason` and `phase_outcomes`
  carry the detail. `vigolium db ls scans` shows `completed (partial)`; the REST
  scan object and `-j` output carry all three fields. See
  [the scan API reference](api-references/scan.md#scan-completeness) for the
  field and code vocabulary.

- **`auth_unavailable` changes how you read the findings.** It means configured
  authentication never reached the scan, so everything behind the login was
  probed anonymously. Treat the run as unauthenticated coverage, not as evidence
  that the application exposes nothing — and do not report the resulting 401s as
  findings. The specific cause rides alongside it (`login_budget`, `cancelled`,
  `scan_budget`). It is recorded whichever subsystem failed to log in — the HTTP
  session manager or the browser.
- **`persistence_incomplete` on a browser phase** (`spidering`, `respider`)
  means the crawl captured traffic that did not reach the database. The phase's
  `persistence` block carries the counts (`accepted` / `committed` / `failed` /
  `unknown`), and `timed_out` means the capture writer was abandoned before it
  drained, so some entries have no recorded outcome either way. A crawl that
  lost records is a partial phase even when every page was visited.

Reason and limit codes are added, never renamed, so matching on a code is safe;
a code you do not recognise is a code added after your version.

**An interrupted scan's row says `status: failed`.** The event stream says
`"status": "interrupted"` for the same run, and the two disagree on purpose:
`status` on the scan row is a released value, and the finalizer has always
written `failed` for a run that did not reach its end. (The vocabulary has a
`cancelled` value; the finalizer does not use it.) Do not read the row's
`status` as "something broke" for an interrupted run — read the coverage fields,
which the row and the stream agree on completely: `completeness: partial`,
`stop_reason: cancelled`, and `input_incomplete` among the reasons. If you need
to distinguish an interrupt from a crash, that triple is the signal.

Record delivery is **at-least-once**. A curtailed phase leaves its durable cursor
*behind* the records it did not finish, so a successor run — `scan-on-receive`,
or `--scan-uuid` against a prior scan — re-serves them rather than skipping them.
The phase outcome's `unprocessed` count says how many that was, and
`checkpoint_failed` means the cursor could not be written at all, in which case
the whole round is re-served. Duplicate work is the deliberate trade: findings
dedup downstream, so the cost is time, where a skipped record is a silent gap.

Still check `completeness` before treating a predecessor as a baseline: a partial
predecessor covered less than its target list, whatever its cursor says about the
records it did reach.

### The event stream (`--events ndjson`)

One NDJSON line per event on **stdout**, from `scan.started` to a single
terminal `scan.finished`. Human output stays on stderr throughout.

- **`--events` owns stdout exclusively.** Combining it with another writer of
  stdout — `-j/--json`, `--format jsonl` without `-o`, `--ci-output-format`,
  `--print-finding`, `--print-traffic`, `--print-traffic-tree` — is rejected
  before any work starts, with exit `2` naming the conflict. It used to produce
  a corrupt interleaved stream and exit `0`. Exactly one protocol on stdout,
  always. (First-run setup — the nuclei-template and Chrome-for-Testing
  install a cold `$HOME` triggers — writes to stderr too, so a brand-new
  machine's very first `--events` run is still clean NDJSON.)
- **`seq`** is the stream's own total order: 1-based, stamped under the write
  lock, one per line. Use it rather than `ts` — timestamps are
  millisecond-precision and a busy scan emits several events per millisecond, so
  sorting by `ts` reorders them. A gap in `seq` means a line was lost.
- **`scan.interrupting` is nonterminal.** It is written when SIGINT/SIGTERM
  arrives, carrying the signal name in `message`, and the graceful shutdown then
  runs. The terminal `scan.finished` still follows, with
  `"status": "interrupted"` and the totals. A second signal forces exit `1`
  after a best-effort terminal event that carries no totals.
- **The terminal event is last, and arrives after finalization.** Its totals and
  `reasons` are read from the persisted scan row, and under `--db-isolate` it is
  written after the merge into the real database — so a run whose results never
  landed reports `"status": "failed"` rather than `"completed"`. A consumer that
  stops at the first terminal event is unaffected.
- **A closed consumer does not kill the scan.** `vigolium scan --events ndjson |
  head -5` runs to completion and exits on its own merit; the truncated stream
  is reported on stderr as `event stream delivery failed: …; the scan ran to
  completion`. The exit code is unaffected.
- **SIGTERM shuts a native scan down gracefully**, with or without `--events`,
  including during setup before the first request is sent.

New event types and fields are added, never renamed; an event type you do not
recognise is safe to ignore.

## Discovering the interface

```bash
vigolium strategy --json    # strategies, phase names + aliases, intensities,
                            # agent modes, installed profiles
vigolium config ls --json   # every setting (credentials redacted)
vigolium scope view --json  # scope rules
vigolium module ls --json   # module catalog
vigolium doctor --json      # environment readiness
```

`strategy --json` is generated from the same registries the flags are validated
against, so `phases[].canonical` and `phases[].aliases` are exactly what `--only`,
`--skip`, and `run <phase>` accept.

## Credentials

`auth list` and `config ls` redact secrets by default — session tokens, auth
headers, stored login requests, and login bodies. This applies under `--json`
too, because `--json` output is the output most likely to end up in a transcript.
Pass `--show-secrets` to reveal them; it prints a warning to stderr.

Redacted rows keep `has_session_token`, `header_names`, and a
`session_token_fingerprint` (a short stable digest) so you can still tell two
sessions apart or confirm a rotation landed.

## Following a result

Every `-j` read carries a `query` field: a ready-to-run follow-up pinned to the
same store and scope, correctly shell-quoted — and `query_argv`, the same
command as an argv vector.

```bash
q=$(vigolium --db ./run.sqlite -S finding --limit 1 --json | jq -r .query)
eval "$q"    # reaches the same finding in the same database

# or, without a shell in the middle:
readarray -t argv < <(vigolium --db ./run.sqlite -S finding --limit 1 --json \
                        | jq -r '.query_argv[]')
"${argv[@]}"
```

Prefer `query_argv` from code: `query` is shell-quoted for a human to read, and
re-splitting a quoted string is where that quoting becomes the thing that breaks
the parse. The vector goes straight into `exec`. The two are always present (or
absent) together.

Finding IDs are per-database autoincrement integers, so the `--db`/`--stateless`/
`--project-uuid` flags are load-bearing. Three properties make them reproduce the
read rather than merely resemble it:

- `--db` and `--config` are **absolute**, so the follow-up works from any
  directory.
- The project is pinned as a resolved `--project-uuid`, never as a
  `--project-name` the next process would look up again or as an implicit active
  project that `project use` could change in between.
- Under `-S/--stateless` the `--db` names the **source** you gave (a `.jsonl`
  export, a standalone `.sqlite`), not the scratch database it was loaded into.

Both fields are **absent** under `--glob-db`: the merged source is a temporary
database that no argument list can reopen. `--db` alone is absent for a
non-SQLite driver, whose connection details live in the config rather than in a
path.

## Gotchas

- `-S` means `--stateless` on `scan` but `--scan-on-receive` on `ingest`.
- `--json` (compact, single object) ≠ `--format jsonl` (bulk, one line per row).
- `--json --watch <n>` switches to NDJSON: one compact document per line, no
  clear-screen, no heading. If the read breaks, the last line is a compact error
  object (`"ok": false`) rather than silence. `--watch` is rejected on a command
  that writes.
- `db clean --findings-only`, `--orphans`, `--table`, and `--all` are *modes*,
  not modifiers. The first two are confined to the active project; the last two
  address the whole store and reject a narrowing filter rather than ignoring it.
- With `-P/--parallel`, `--fail-on` is evaluated per child process, and the
  batch exits `4` if any child tripped it. A gated child is a *success* in the
  roll-up — it scanned and wrote its output — and is listed separately from
  failures; `--resume` will not re-scan it.
- `scan-url`/`scan-request` with `--events` route through the full Runner, so
  the stream is real. Several targets under `-j` emit **one** envelope whose
  `items` are the per-target results, with `targets_not_scanned` naming anything
  an interrupt cut off; a single target keeps its existing object shape. Each
  result carries `persisted` (whether it also reached a database) and, when
  interrupted, `interrupted: true`.
- `traffic body`/`traffic headers --uuid` are project-scoped like every other
  read: a record in a project the invocation did not select reports
  `record_not_found`, the same code as a UUID that does not exist. That is
  deliberate — a distinct "wrong project" error would confirm the record exists.
  The receipt carries `project_uuid` and `project_scoped`.
- `vigolium export` defaults to the **whole database**, not your active project.
  Pass `--project-uuid`/`--project-name` to narrow it; the stderr summary and a
  bundle's `manifest.json` both state which scope the contents have.
- A failed `-S` scan deletes its throwaway database, losing whatever it had
  learned before it broke. `--keep-db-on-error` moves it to
  `~/.vigolium/recovered/` instead and names the path in the error, so you can
  read the partial results with `vigolium finding -S --db <that path>`. Nothing
  sweeps that directory — it is yours to delete. The flag requires `-S` (exit
  `2` otherwise) and is inherited by `-P` children.
- A `--db-isolate` run whose merge fails now moves its working database to
  `~/.vigolium/recovered/` and prints the `vigolium import` command that
  completes the merge. The path it used to name was inside process scratch,
  which is deleted at exit.
- **`vigolium version`, `help` and `completion` no longer create `~/.vigolium`.**
  Nothing that only answers a question — including the hidden `__complete` RPC
  a shell runs on every tab press — writes a config or a database any more.
  Everything else still bootstraps on first run, and a first run that pins
  `--db` (or `$VIGOLIUM_DB_PATH`) now skips the *default* store, which it used
  to create, seed and never open. A `--read-only` read with no `--db` still
  creates the default file, because that file is the store it is about to read.
- **A raw request's body bytes are preserved.** `scan-request` used to
  `TrimSpace` its whole input, which rewrote the body of any request ending in
  whitespace while `Content-Length` still declared the original length. Trailing
  whitespace is now stripped only when the headers declare no body (no
  `Content-Length`, no `Transfer-Encoding`); leading whitespace always is.
- **A raw request's body is exactly what its `Content-Length` declares.** Write
  `Content-Length: 3` with the body `a=1` and three bytes go out, even though
  your editor put a newline after it — the trailing byte used to go out too,
  making the body one longer than the request said. `Content-Length` is the
  authority on where the body ends; a body that is *short* of the declaration
  has the header corrected down instead, because nobody can send bytes that are
  not there. A body that genuinely ends in whitespace is unaffected: its
  `Content-Length` counts that whitespace, so write `Content-Length: 7` for
  `a=1 \r\n\n` and all seven bytes are sent. Requests carrying
  `Transfer-Encoding`, or two `Content-Length` headers, are left exactly as
  written — that disagreement is the point of a desync probe.
- **`ingest`'s count is rows, not attempts.** `records_ingested` equals a
  `count(*)` on `http_records` for the run. Records that were read and could not
  be stored are `records_failed` and exit `1` with
  `error.code: "ingest_incomplete"`; records a filter dropped are
  `records_skipped` and are not a failure. A batch (`-i a.har -i b.har`,
  `--dir`) emits **one** envelope covering every source, not one per source.
  Ingesting a capture never re-fetches a record that already carries its
  response, so the origins in a HAR do not have to still resolve.
- **`-I`/`--input-mode` canonical names**: `urls`, `nuclei`, `openapi`, `wsdl`,
  `postman`, `curl`, `burpraw`, `burpxml`, `burpscope`, `har`, `deparos`.
  Aliases are accepted (`nuclei-output`, `swagger`, `burp`, …) but the canonical
  name is what `--list-input-mode` and the `-I` help text now show — the listing
  used to advertise `nuclei-output` as canonical, which is the reverse of what
  the parser resolves.
- Agentic scans need a configured LLM provider (`agent.olium` in
  `vigolium-configs.yaml`); run `vigolium doctor --json` to check.
- **A broken `--config` is now an error (exit 1), not a fallback to defaults.**
  If you pass `--config` and the file is missing or unparseable, the command
  fails naming the file. It used to run against the *default* database with the
  *default* settings and exit 0. A config found by discovery still degrades to
  defaults with one stderr warning. `vigolium doctor` reports it as a failed
  `config` check instead of failing, and `db clean --reset` refuses on any config
  error at all. See [Configuration](configuration.md#when-a-config-file-cannot-be-read).
- A SQLite path containing `#`, `%`, a space or non-ASCII characters now reaches
  the file it names; a `#` used to truncate it at the driver's URI parser and
  open a different, empty database. A path containing a literal `?` is rejected
  with an error — the driver cannot address one in any spelling.
