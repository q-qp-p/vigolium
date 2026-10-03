package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/fsexport"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// This file implements the one-shot `fs` output format: a flat, browsable
// filesystem tree of HTTP traffic and findings, laid out so a coding agent (or
// a human with nothing but `ls`/`grep`/`jq`) can reason about a scan without a
// database. The layout and per-record/per-finding rendering live in the shared
// pkg/fsexport package, which the server's live --mirror-fs writer also uses.
//
// Two sibling directories are written off a base path (-o, or "vigolium" in the
// cwd when no -o is given):
//
//	<base>-traffic/
//	  index.json                       # one compact record per request (jq-friendly array)
//	  <host>/0001.req                  # "@target <scheme>://<host>" + the raw request
//	  <host>/0001.resp.headers         # status line + response headers
//	  <host>/0001.resp.body            # response body, gzip-decoded so it greps clean
//	<base>-findings/
//	  index.json                       # one compact entry per finding
//	  <host>/0001.md                   # the finding, cross-linked to its .req file
//
// Per-host ids are zero-padded sequences assigned in sent_at order, so a
// re-export of the same data is reproducible.
//
// Each tree is published as a whole generation: the export is built in a
// sibling ".<name>.staging-*" directory and renamed over the final root only
// once it is complete. Writing in place meant a re-export of a smaller result
// set left the previous run's files behind — 0002.req from a three-record run
// survived a one-record re-export, and index.json (which IS replaced) then
// described a tree that disagreed with its own contents. It also meant a
// failure halfway through left a half-replaced tree. Two sibling renames are
// not one atomic act, so traffic can land while findings fail; that case is
// reported rather than papered over.

// fsExportOptions tunes a single fs export.
type fsExportOptions struct {
	omitResponse bool // drop .resp.* files (mirrors --omit-response)
}

// fsExportStats summarizes what an fs export wrote, for the caller's summary line.
type fsExportStats struct {
	Traffic     int
	Findings    int
	Hosts       int
	TrafficDir  string
	FindingsDir string
}

// fsTrafficPass is what the traffic pass hands on: the index entries it built,
// and the two lookups the findings pass and the index backfill need.
type fsTrafficPass struct {
	entries    []fsexport.TrafficEntry
	byUUID     map[string]int    // record uuid → index in entries
	uuidToPath map[string]string // record uuid → "host/id", for finding cross-links
	// stageDir is the STAGING traffic root the findings pass reads linked
	// records back out of. Not the final root: that may still hold a previous
	// generation, whose 0001.resp.body for the same host/id belongs to a
	// different record entirely. "" when no record was written.
	stageDir string
}

// fsStageHostDir returns the per-host directory inside a staged tree, creating
// it on the host's first row. seq is the caller's per-host counter, which is
// zero exactly when the directory has not been made yet — so the mkdir is one
// syscall per host rather than one per row.
func fsStageHostDir(stage *fsStage, host string, seq map[string]int, what string) (string, error) {
	stageRoot, err := stage.ensure()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(stageRoot, host)
	if seq[host] == 0 {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("create %s dir %s: %w", what, dir, err)
		}
	}
	return dir, nil
}

// fsExportTrafficPass streams http_records into the staged traffic tree.
//
// Its own function so the row cursor can be closed by one defer: the inline
// version repeated `_ = rows.Close()` before each of seven error returns, and
// adding an eighth failure mode meant remembering it again. The findings pass is
// a separate scope for the same reason it is a separate function — a single
// defer in one body would hold this cursor open across the whole of it.
func fsExportTrafficPass(
	ctx context.Context,
	db *database.DB,
	filters database.QueryFilters,
	opts fsExportOptions,
	stage *fsStage,
	hosts map[string]struct{},
) (fsTrafficPass, error) {
	out := fsTrafficPass{
		byUUID:     make(map[string]int),
		uuidToPath: make(map[string]string),
	}
	seq := make(map[string]int)

	recFilters := filters
	recFilters.SortBy = "sent_at"
	recFilters.SortAsc = true
	recQuery := database.NewQueryBuilder(db, recFilters).BuildRecordsQuery().OrderExpr("r.uuid ASC")
	if opts.omitResponse {
		recQuery = recQuery.ExcludeColumn("raw_response")
	}
	rows, err := recQuery.Rows(ctx)
	if err != nil {
		return out, fmt.Errorf("query HTTP records: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		rec := new(database.HTTPRecord)
		if err := db.ScanRow(ctx, rows, rec); err != nil {
			return out, fmt.Errorf("scan HTTP record: %w", err)
		}
		if len(rec.RawRequest) == 0 {
			continue
		}
		host := fsexport.SanitizeHost(rec.Hostname)
		hosts[host] = struct{}{}
		dir, err := fsStageHostDir(stage, host, seq, "traffic")
		if err != nil {
			return out, err
		}
		out.stageDir = stage.dir
		seq[host]++
		id := fmt.Sprintf("%04d", seq[host])

		// .req — "@target ..." line then the raw request verbatim.
		if err := os.WriteFile(filepath.Join(dir, id+".req"), fsexport.RequestBytes(rec), 0o644); err != nil {
			return out, fmt.Errorf("write %s.req: %w", id, err)
		}

		status, bodyLen, err := fsexport.WriteResponseFiles(dir, id, rec, opts.omitResponse)
		if err != nil {
			return out, fmt.Errorf("write %s response: %w", id, err)
		}

		relPath := host + "/" + id
		out.uuidToPath[rec.UUID] = relPath
		out.byUUID[rec.UUID] = len(out.entries)
		out.entries = append(out.entries, fsexport.TrafficEntry{
			ID:          id,
			Host:        rec.Hostname,
			Path:        relPath,
			Method:      rec.Method,
			URL:         rec.Path,
			Status:      status,
			ContentType: fsexport.CleanContentType(rec.ResponseContentType),
			Bytes:       bodyLen,
		})
	}
	if cerr := rows.Err(); cerr != nil {
		return out, fmt.Errorf("read HTTP records: %w", cerr)
	}
	return out, nil
}

// fsExportFindingsPass streams findings into the staged findings tree, embedding
// the traffic the traffic pass just wrote. It returns the index entries and the
// per-record top severity the caller backfills into the traffic index.
func fsExportFindingsPass(
	ctx context.Context,
	db *database.DB,
	filters database.QueryFilters,
	opts fsExportOptions,
	stage *fsStage,
	hosts map[string]struct{},
	traffic fsTrafficPass,
	trafficDirBase string,
) ([]fsexport.FindingEntry, map[string]string, error) {
	var entries []fsexport.FindingEntry
	seq := make(map[string]int)
	recTopSeverity := make(map[string]string) // record uuid → highest finding severity

	fq := db.NewSelect().Model((*database.Finding)(nil)).OrderExpr("found_at ASC, id ASC")
	if filters.ProjectUUID != "" {
		fq = fq.Where("project_uuid = ?", filters.ProjectUUID)
	}
	// An identity selector narrows BOTH halves of the tree. Every other filter
	// here is the findings-side counterpart of a record-side one (--host filters
	// records by hostname and findings by hostname); --uuid had no counterpart,
	// so `db export --uuid <one record> --format fs` wrote that one .req beside
	// every finding in the store — a directory that reads as "these are the
	// findings for this request" and is not. The counterpart of "this record" is
	// "the findings linked to it", which is the same relation `db export --format
	// jsonl` already uses to attach findings to the records it selected.
	if len(filters.RecordUUIDs) > 0 {
		fq = fq.Where("id IN (SELECT finding_id FROM finding_records WHERE record_uuid IN (?))",
			bun.List(filters.RecordUUIDs))
	}
	if filters.HostPattern != "" {
		fq = fq.Where(database.WithLikeEscape("hostname LIKE ?"), fsLikePattern(filters.HostPattern))
	}
	if len(filters.Severity) > 0 {
		sevs := make([]string, len(filters.Severity))
		for i, s := range filters.Severity {
			sevs[i] = strings.ToLower(strings.TrimSpace(s))
		}
		fq = fq.Where("LOWER(severity) IN (?)", bun.List(sevs))
	}
	if term := fsSearchTerm(filters); term != "" {
		p := database.LikeContains(term)
		fq = fq.Where(database.WithLikeEscape(
			"(module_id LIKE ? OR module_name LIKE ? OR description LIKE ? OR url LIKE ? OR hostname LIKE ?)"), p, p, p, p, p)
	}
	if filters.Limit > 0 {
		fq = fq.Limit(filters.Limit)
	}
	frows, err := fq.Rows(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("query findings: %w", err)
	}
	defer func() { _ = frows.Close() }()

	for frows.Next() {
		f := new(database.Finding)
		if err := db.ScanRow(ctx, frows, f); err != nil {
			return nil, nil, fmt.Errorf("scan finding: %w", err)
		}
		host := fsexport.SanitizeHost(fsexport.FindingHost(f))
		hosts[host] = struct{}{}
		dir, err := fsStageHostDir(stage, host, seq, "findings")
		if err != nil {
			return nil, nil, err
		}
		seq[host]++
		id := fmt.Sprintf("%04d", seq[host])

		// Resolve linked traffic that made it into this export, reading the
		// .req/.resp files the traffic pass just wrote back out of its staging
		// tree, so the finding markdown can embed them inline.
		var linked []fsexport.LinkedRecord
		var linkedPaths []string
		for _, u := range f.HTTPRecordUUIDs {
			if p, ok := traffic.uuidToPath[u]; ok {
				linked = append(linked, fsexport.ReadLinkedRecord(traffic.stageDir, p, opts.omitResponse))
				linkedPaths = append(linkedPaths, p)
				recTopSeverity[u] = fsexport.MaxSeverity(recTopSeverity[u], f.Severity)
			}
		}

		md := fsexport.RenderFindingMarkdown(f, linked, trafficDirBase)
		if err := os.WriteFile(filepath.Join(dir, id+".md"), md, 0o644); err != nil {
			return nil, nil, fmt.Errorf("write %s.md: %w", id, err)
		}

		title := f.ModuleName
		if title == "" {
			title = f.ModuleID
		}
		entries = append(entries, fsexport.FindingEntry{
			ID:         id,
			Host:       fsexport.FindingHost(f),
			Path:       host + "/" + id + ".md",
			Severity:   f.Severity,
			Confidence: f.Confidence,
			Module:     f.ModuleID,
			Title:      title,
			URL:        f.URL,
			Traffic:    linkedPaths,
		})
	}
	if cerr := frows.Err(); cerr != nil {
		return nil, nil, fmt.Errorf("read findings: %w", cerr)
	}
	return entries, recTopSeverity, nil
}

// writeFSExport reads http_records and findings (filtered by `filters`) and
// writes the flat filesystem tree described above, rooted at `base`. The two
// passes run in order: traffic first (it builds the uuid→"host/id" map), then
// findings (which cross-link back into traffic and backfill the traffic index's
// per-record top severity). Records and findings are streamed with a row cursor,
// so only the small index entries — not the raw bodies — accumulate in memory.
func writeFSExport(ctx context.Context, db *database.DB, filters database.QueryFilters, base string, opts fsExportOptions) (fsExportStats, error) {
	base = fsResolveBase(base)
	trafficRoot := base + "-traffic"
	findingsRoot := base + "-findings"
	// Cross-links in the finding markdown point at the FINAL directory name, not
	// the staging one, so they resolve after publication.
	trafficDirBase := filepath.Base(base) + "-traffic"

	traffic := &fsStage{root: trafficRoot}
	findings := &fsStage{root: findingsRoot}
	defer traffic.discard()
	defer findings.discard()

	stats := fsExportStats{}
	hosts := make(map[string]struct{})

	written, err := fsExportTrafficPass(ctx, db, filters, opts, traffic, hosts)
	if err != nil {
		return stats, err
	}
	stats.Traffic = len(written.entries)

	findingEntries, recTopSeverity, err := fsExportFindingsPass(
		ctx, db, filters, opts, findings, hosts, written, trafficDirBase)
	if err != nil {
		return stats, err
	}
	stats.Findings = len(findingEntries)
	stats.Hosts = len(hosts)

	// Backfill the traffic index's per-record top severity now that findings are known.
	for uuid, sev := range recTopSeverity {
		if idx, ok := written.byUUID[uuid]; ok {
			s := sev
			written.entries[idx].Finding = &s
		}
	}
	trafficEntries := written.entries

	// Publish whichever trees this export has something to say about. A tree
	// with rows always publishes. A tree with none publishes only when a root is
	// already there, so a re-export that now matches nothing replaces the stale
	// generation with an empty index instead of leaving last run's results
	// sitting under a name that claims to describe this one; a first export that
	// finds nothing still creates nothing ("Nothing to export").
	if err := fsPublishTree(traffic, trafficEntries, &stats.TrafficDir); err != nil {
		return stats, err
	}
	if err := fsPublishTree(findings, findingEntries, &stats.FindingsDir); err != nil {
		return stats, fmt.Errorf("%w (the traffic tree was already updated)", err)
	}

	return stats, nil
}

// fsStage holds one export tree's staging directory, created on first write so
// an export with nothing to say leaves no trace. The staging directory is a
// sibling of the final root because only a same-filesystem rename publishes
// atomically.
type fsStage struct {
	root string
	dir  string // "" until ensure() has run
}

// ensure returns the staging directory, creating it (and the export's parent
// directory) on the first call.
func (s *fsStage) ensure() (string, error) {
	if s.dir != "" {
		return s.dir, nil
	}
	parent := filepath.Dir(s.root)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", fmt.Errorf("create export directory %s: %w", parent, err)
	}
	// Collect staging and retired trees abandoned by an earlier kill -9 before
	// adding one more. Scoped to this root's own name, and only entries left
	// untouched for atomicfile.StaleAge.
	name := filepath.Base(s.root)
	atomicfile.SweepStale(parent, atomicfile.StagingDirGlob(name))
	atomicfile.SweepStale(parent, name+".old-*")

	// 0755 rather than os.MkdirTemp's 0700: the staging directory IS the
	// published root after the rename, so the tree would have come out
	// owner-only while the host directories inside it stayed 0755. The umask
	// still applies, exactly as it did to the MkdirAll this replaced, so an
	// operator running with umask 077 still gets a private tree.
	dir, err := atomicfile.MkdirStaging(parent, name, 0o755)
	if err != nil {
		return "", fmt.Errorf("stage export %s: %w", s.root, err)
	}
	s.dir = dir
	return dir, nil
}

// discard removes an unpublished staging tree. Safe to defer unconditionally: a
// published stage no longer exists under its staging name.
func (s *fsStage) discard() {
	if s.dir != "" {
		_ = os.RemoveAll(s.dir)
	}
}

// fsPublishTree writes one tree's index.json and renames the staged tree over
// its final root, recording the published path in dest. It no-ops when the tree
// has no entries and no root exists to correct.
func fsPublishTree(s *fsStage, entries any, dest *string) error {
	if s.dir == "" {
		if !fsPathExists(s.root) {
			return nil
		}
		if _, err := s.ensure(); err != nil {
			return err
		}
	}
	if err := fsWriteIndex(filepath.Join(s.dir, "index.json"), entries); err != nil {
		return err
	}
	if err := publishFSGeneration(s.dir, s.root); err != nil {
		return err
	}
	*dest = s.root
	return nil
}

// publishFSGeneration replaces root with the completed tree at stage.
//
// An existing root is retired to a "<root>.old-<rand>" sibling first, so the
// window in which root does not exist is one rename wide and a failure to put
// the new tree in place can be undone. It is only ever retired when it looks
// like one of ours — an empty directory, or one holding the index.json every
// generation writes. A base path that collides with an unrelated directory is
// an operator mistake worth an error; silently deleting their files is not a
// reasonable way to report it.
func publishFSGeneration(stage, root string) error {
	info, err := os.Lstat(root)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Rename(stage, root); err != nil {
			return fmt.Errorf("publish %s: %w", root, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("inspect %s: %w", root, err)
	}
	if !info.IsDir() || !fsLooksLikeExportTree(root) {
		return fmt.Errorf("refusing to replace %s: not a vigolium fs export (no index.json)", root)
	}

	suffix, err := atomicfile.RandomSuffix()
	if err != nil {
		return fmt.Errorf("publish %s: %w", root, err)
	}
	old := root + ".old-" + suffix
	if err := os.Rename(root, old); err != nil {
		return fmt.Errorf("retire previous %s: %w", root, err)
	}
	if err := os.Rename(stage, root); err != nil {
		// Put the previous generation back rather than leaving the name empty.
		if rerr := os.Rename(old, root); rerr != nil {
			return fmt.Errorf("publish %s: %w (the previous export is now at %s)", root, err, old)
		}
		return fmt.Errorf("publish %s: %w", root, err)
	}
	_ = os.RemoveAll(old)
	return nil
}

// fsLooksLikeExportTree reports whether dir is one this exporter may replace:
// empty, or carrying the index.json every published generation contains.
func fsLooksLikeExportTree(dir string) bool {
	if fsPathExists(filepath.Join(dir, "index.json")) {
		return true
	}
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) == 0
}

// fsPathExists reports whether path resolves to anything at all (a broken
// symlink counts — it is still a name we would have to replace).
func fsPathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// fsWriteIndex marshals entries to an indented JSON array at path. A nil slice
// is written as an empty array (not "null") so jq always sees a list.
func fsWriteIndex(path string, entries any) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal index: %w", err)
	}
	if string(data) == "null" {
		data = []byte("[]")
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// fsResolveBase strips any known format extension from the operator's -o value
// and defaults to "vigolium" (in the cwd) when no output was given.
func fsResolveBase(output string) string {
	base := types.StripFormatExtension(strings.TrimSpace(output))
	if base == "" {
		base = "vigolium"
	}
	return base
}

// fsSearchTerm picks the fuzzy/search term to filter findings by, preferring the
// broad fuzzy term.
func fsSearchTerm(filters database.QueryFilters) string {
	if filters.FuzzyTerm != "" {
		return filters.FuzzyTerm
	}
	return filters.SearchTerm
}

// fsLikePattern turns a host filter into a SQL LIKE pattern: explicit "*"
// wildcards map to "%", an otherwise literal pattern is wrapped in "%…%".
func fsLikePattern(p string) string {
	if strings.Contains(p, "*") {
		return database.LikeGlob(p)
	}
	return database.LikeContains(p)
}

// fsPrintSummary writes the operator-facing summary for an fs export.
func fsPrintSummary(stats fsExportStats) {
	fmt.Fprintf(os.Stderr, "\n%s Export summary (format: %s)\n", terminal.InfoSymbol(), terminal.Cyan("fs"))
	if stats.TrafficDir != "" {
		fmt.Fprintf(os.Stderr, "  %-20s %s (%d records)\n", "Traffic", terminal.Cyan(stats.TrafficDir), stats.Traffic)
	}
	if stats.FindingsDir != "" {
		fmt.Fprintf(os.Stderr, "  %-20s %s (%d findings)\n", "Findings", terminal.Cyan(stats.FindingsDir), stats.Findings)
	}
	if stats.TrafficDir == "" && stats.FindingsDir == "" {
		fmt.Fprintf(os.Stderr, "  %s\n", "Nothing to export (no matching records or findings)")
	}
}
