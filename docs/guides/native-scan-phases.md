# Native Scan: Running Phases Independently

## Overview

Vigolium's native scan pipeline consists of multiple phases that run sequentially. You can run the full pipeline, isolate a single phase with `--only`, or skip specific phases with `--skip`. This guide walks through each phase and how to run them independently.

## The Full Pipeline

When you run a standard scan, phases execute in this order:

1. **Heuristics / Port Sweep** - classify target roots and, in deep mode, find alternate web ports
2. **External Harvest** - gather endpoints from external sources (Wayback Machine, CT logs)
3. **Spidering** - browser-based crawling to discover dynamic content
4. **Discovery / Ingestion** - parse inputs and perform content discovery
5. **DynamicAssessment** - run active, passive, and extension modules
6. **Known Issue Scan** - run Nuclei plus native in-process secret detection

A full scan with all phases enabled:

```bash
vigolium scan -t https://example.com --strategy deep
```

## Running a Single Phase

Use `vigolium run <phase>` or `vigolium scan --only <phase>` to execute one phase in isolation.

### Discovery

Discovers new endpoints through wordlist-based fuzzing and content probing:

```bash
vigolium run discovery -t https://example.com
```

Equivalent to:

```bash
vigolium scan -t https://example.com --only discovery
```

Tune discovery with additional flags:

```bash
vigolium run discovery -t https://example.com \
  --discover-max-time 30m \
  -c 100 \
  --rate-limit 200
```

### Spidering

Crawls the target using a headless browser to discover pages, forms, and JavaScript-rendered content:

```bash
vigolium run spidering -t https://example.com
```

Control the browser engine, time budget and what the crawl may change:

```bash
vigolium run spidering -t https://example.com \
  -E chromium \
  --spider-max-time 20m \
  --no-forms
```

The crawler drives one browser (`-b`/`--browsers` above 1 is clamped to 1).
Under the phase header it prints the resolved interaction `Policy:` and the
`Browser security:` posture (see [Browser policy](browser-policy.md)). Its
completion line is built from capture receipts: when records were lost it says
`run incomplete` instead of reporting the stored count as the whole crawl, and
per-target notes call out authentication that could not be applied, credential
headers withheld from out-of-scope hosts, and readiness conditions that never
met.

The alias `spitolas` also works:

```bash
vigolium run spitolas -t https://example.com
```

### External Harvest

Pulls endpoints from external intelligence sources (Wayback Machine, certificate transparency logs):

```bash
vigolium run external-harvest -t https://example.com
```

### Known Issue Scan

Runs template-based scanning (Nuclei templates) against ingested endpoints:

```bash
vigolium run known-issue-scan -t https://example.com
```

Filter templates by severity or tags:

```bash
vigolium run known-issue-scan -t https://example.com \
  --known-issue-scan-severities critical,high \
  --known-issue-scan-tags cve,rce
```

### DynamicAssessment

Runs active and passive vulnerability scanning modules. This is the core scanning phase. CLI aliases: `audit`, `dast`, `assessment`.

```bash
vigolium run dynamic-assessment -t https://example.com
```

Select specific modules or tags:

```bash
vigolium run dynamic-assessment -t https://example.com -m xss -m sqli
vigolium run dast -t https://example.com --module-tag injection
```

### Extension

Runs only custom JavaScript or YAML extensions:

```bash
vigolium run extension -t https://example.com --ext ./my-checks.js
```

## Skipping Phases

Use `--skip` to disable specific phases while keeping the rest of the pipeline:

```bash
# Run everything except spidering
vigolium scan -t https://example.com --discover --skip spidering

# Skip both spidering and known-issue-scan
vigolium scan -t https://example.com --discover --skip spidering --skip known-issue-scan
```

Note: `--only` and `--skip` cannot be used together.

## Phase Aliases

Every phase answers to several spellings. They work identically with `--only`, `--skip`, the `vigolium run <phase>` argument, the per-phase pace qualifiers (`--rate-limit crawl=20`) and the REST API's `only`/`skip` fields. Names are trimmed and lowercased first, so `--skip Spider` and `--skip ' spider'` both resolve.

| Phase | Also accepts |
|-------|--------------|
| `ingestion` | `ingest`, `ingesting` |
| `discovery` | `discover`, `discovering`, `deparos` |
| `external-harvest` | `harvest`, `harvesting`, `external-harvester`, `external_harvester` |
| `spidering` | `spider`, `spitolas`, `crawl`, `crawling`, `crawler` |
| `known-issue-scan` | `cve`, `kis`, `known-issue`, `known-issues` |
| `dynamic-assessment` | `dast`, `audit`, `assessment`, `assess` |
| `extension` | `ext`, `extensions` |

`--skip extension` is rejected — the extension phase is opt-in, so there is nothing to skip.

One exception applies to the positional form only: `vigolium run audit` is rejected as ambiguous, because it reads as `vigolium agent audit` (the AI source-code audit) rather than the native module-scanning phase. Use `vigolium run dynamic-assessment` (or `dast`). `--only audit` and `--skip audit` are unaffected.

### `run <phase>` and `scan --only <phase>` are the same thing

`vigolium run discover` is not a lighter variant of `vigolium scan --only discovery` — it is literally the same code path, so the two behave identically in every respect.

What *does* differ is running a phase on its own versus running it inside a full pipeline. The clearest case is discovery's FUZZ brute-force: it is enabled whenever the active `--only` set contains `discovery`, and disabled when discovery runs as one phase of a balanced or lite full scan. The Discovery phase header prints which applies:

```
◆ Fuzzing: enabled — fuzz.txt (5369) (embedded default), appends /FUZZ [discovery-only run]
◆ Fuzzing: disabled — off on balanced/lite full scans (enable via `run discover`, --intensity deep, or --discovery-wordlist)
```

### Turning discovery fuzzing off

`--no-discovery-fuzz` (alias `--no-fuzz`) disables the `/FUZZ` brute-force outright. It is checked before every rule that would switch fuzzing on, so it wins over `--intensity deep`, over a discovery-only run, and over the low-yield auto-enable:

```bash
vigolium run discover -T hosts.txt --no-fuzz            # content discovery without the 5369-word brute
vigolium scan -t https://example.com --intensity deep --no-fuzz
```

The rest of discovery is untouched — link extraction, robots.txt, JS parsing (jstangle, Next.js/Angular/CRA manifests, source maps), response-word harvesting into the observed wordlists, form submission, and the short `dir-short.txt`/`file-short.txt` dictionaries all still run. `--intensity deep` still loads the long dictionaries; only the `/FUZZ` task is removed.

Passing `--no-discovery-fuzz` together with `--discovery-wordlist` is an error rather than a precedence rule — the two state opposite intents, and the outcomes differ by thousands of requests per host.

## Chaining Phases Manually

You can chain independent phase runs to build a custom pipeline. Each phase stores its results in the database, so subsequent phases pick up where the previous one left off:

```bash
# Step 1: Discover endpoints
vigolium run discovery -t https://example.com

# Step 2: Dynamic-assessment against the discovered endpoints
vigolium run dynamic-assessment -t https://example.com

# Step 3: Run custom extensions against results
vigolium run extension -t https://example.com --ext ./custom-check.js
```

## Tuning Per-Phase Performance

Override concurrency and rate limits for individual phases using the config file (`vigolium-configs.yaml`):

```yaml
scanning_pace:
  concurrency: 50
  rate_limit: 100

  discovery:
    concurrency: 100
    duration_factor: 1.0

  spidering:
    max_duration: 20m

  dynamic-assessment:
    parallel_passive: true
```

CLI flags (`-c`, `--rate-limit`) always take precedence over config values.

## Controlling Scope

Scope filtering applies across all phases. Use `--scope-origin` to control host matching:

```bash
# Strict: exact host match only
vigolium run discovery -t https://api.example.com --scope-origin strict

# Balanced: same eTLD+1 (*.example.com)
vigolium run discovery -t https://api.example.com --scope-origin balanced

# Relaxed (default): host contains target keyword
vigolium run discovery -t https://api.example.com --scope-origin relaxed
```

## Adding Authentication

All phases respect authentication headers. Pass them with `-H`:

```bash
vigolium run dynamic-assessment -t https://api.example.com \
  -H 'Authorization: Bearer eyJhbGciOi...' \
  -H 'Cookie: session=abc123'
```

For multi-session testing (e.g., IDOR detection), use session configs:

```bash
vigolium run dynamic-assessment -t https://api.example.com \
  --auth-file sessions.yaml
```
