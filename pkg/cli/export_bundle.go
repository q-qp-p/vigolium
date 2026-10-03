package cli

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/internal/scratch"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
)

type bundleManifest struct {
	VigoliumVersion string `json:"vigolium_version"`
	GeneratedAt     string `json:"generated_at"`
	BundleRoot      string `json:"bundle_root"`
	// ProjectUUID is the project filter the bundle's contents were read under,
	// omitted when the bundle spans the whole database. A consumer re-importing
	// the archive has no other way to learn the scope of what it holds.
	ProjectUUID string         `json:"project_uuid,omitempty"`
	ItemCounts  map[string]int `json:"item_counts"`
	TotalItems  int            `json:"total_items"`
	Sessions    []string       `json:"sessions,omitempty"`
	Filters     bundleFilters  `json:"filters"`
	Report      struct {
		Title       string `json:"title,omitempty"`
		Target      string `json:"target,omitempty"`
		Duration    string `json:"duration,omitempty"`
		GeneratedAt string `json:"generated_at,omitempty"`
	} `json:"report"`
}

type bundleFilters struct {
	Only         []string `json:"only,omitempty"`
	Exclude      []string `json:"exclude,omitempty"`
	OmitResponse bool     `json:"omit_response,omitempty"`
	Search       string   `json:"search,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	Limit        int      `json:"limit,omitempty"`
}

// exportBundle writes the .tar.gz bundle (export.jsonl + report.html +
// manifest.json + any requested agent session dirs) from the run's shared item set.
func (r *exportRun) exportBundle(ctx context.Context, outputPath string) ([]exportedFile, error) {
	db, err := r.openDB()
	if err != nil {
		return nil, err
	}

	items, err := r.loadItems(ctx, db)
	if err != nil {
		return nil, err
	}

	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return nil, err
	}

	meta := r.resolveBundleReportMeta(ctx, db)

	root := bundleRootName(outputPath)

	includedSessions, err := publishTarGz(outputPath, func(tw *tar.Writer) ([]string, error) {
		return writeBundleMembers(tw, root, items, meta, settings.Agent.EffectiveSessionsDir(), r.projectUUID)
	})
	if err != nil {
		return nil, err
	}

	// The session count is a line under the per-format stats block on a
	// single-format run, and the bundle row's detail in the unified summary
	// otherwise — where the stats block is suppressed and it would be a stray.
	entry := exportedFile{label: "bundle", path: outputPath}
	if len(includedSessions) > 0 {
		entry.detail = fmt.Sprintf("%d sessions", len(includedSessions))
	}
	r.printStats("bundle", outputPath, countExportItems(items))
	if entry.detail != "" && !r.multi {
		fmt.Fprintf(os.Stderr, "  Sessions:           %d included\n", len(includedSessions))
	}
	return []exportedFile{entry}, nil
}

// writeTarGz streams a gzip'd tar built by members into w.
//
// Both writers are closed here and their errors returned: tar's Close writes
// the padding and the end-of-archive marker, gzip's writes the CRC and length
// trailer, so a discarded Close error publishes a truncated archive as a
// success. The old code deferred both closes and ignored both errors.
//
// One copy of that rule for both bundle writers in this package (`export
// --format bundle` and `db export --format bundle`), because two copies are two
// chances for the next edit to drop a Close error from one of them.
func writeTarGz[T any](w io.Writer, members func(*tar.Writer) (T, error)) (T, error) {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	out, err := members(tw)
	if err != nil {
		// The staging file is removed wholesale, so these closes only release the
		// writers; the error that got us here is what the caller needs.
		_ = tw.Close()
		_ = gz.Close()
		return out, err
	}
	if cerr := errors.Join(tw.Close(), gz.Close()); cerr != nil {
		var zero T
		return zero, cerr
	}
	return out, nil
}

// publishTarGz stages the whole archive next to outputPath and renames it on
// success.
//
// os.Create truncated the destination before the first member was rendered, so a
// failed HTML render, an unreadable session directory or a cancelled run
// replaced the previous archive with a half-written one — and because gzip's
// trailer is at the end, that file does not read as a short archive, it does not
// read at all. 0o666 under the umask reproduces os.Create's mode.
func publishTarGz[T any](outputPath string, members func(*tar.Writer) (T, error)) (T, error) {
	var out T
	if err := atomicfile.WriteFile(outputPath, 0o666, func(w *bufio.Writer) error {
		var werr error
		out, werr = writeTarGz(w, members)
		return werr
	}); err != nil {
		var zero T
		return zero, fmt.Errorf("export bundle %s: %w", outputPath, err)
	}
	return out, nil
}

// writeBundleStream writes the whole tar/gzip archive into w and returns the
// session UUIDs it included.
func writeBundleStream(w io.Writer, root string, items []any, meta output.HTMLReportMeta, sessionsBase, projectUUID string) ([]string, error) {
	return writeTarGz(w, func(tw *tar.Writer) ([]string, error) {
		return writeBundleMembers(tw, root, items, meta, sessionsBase, projectUUID)
	})
}

// writeBundleMembers writes every archive member into tw.
func writeBundleMembers(tw *tar.Writer, root string, items []any, meta output.HTMLReportMeta, sessionsBase, projectUUID string) ([]string, error) {
	now := time.Now().UTC()

	if err := writeTarDir(tw, root+"/", now); err != nil {
		return nil, err
	}

	jsonlBytes, err := encodeItemsAsJSONL(items)
	if err != nil {
		return nil, err
	}
	if err := writeTarBytes(tw, root+"/export.jsonl", jsonlBytes, now); err != nil {
		return nil, err
	}

	// report.html is a required member. It used to warn on stderr and publish
	// the archive anyway, which meant the only signal that the human-readable
	// half of the deliverable was missing went to a stream nothing downstream
	// reads — and the exit code said success.
	htmlBytes, err := renderBundleHTML(items, meta)
	if err != nil {
		return nil, fmt.Errorf("render report.html for bundle: %w", err)
	}
	if err := writeTarBytes(tw, root+"/report.html", htmlBytes, now); err != nil {
		return nil, err
	}

	includedSessions, err := writeSessionsToTar(tw, root, sessionsBase, topExportScanUUIDs, now)
	if err != nil {
		return nil, err
	}

	manifest := bundleManifest{
		VigoliumVersion: getVersion(),
		GeneratedAt:     now.Format(time.RFC3339),
		BundleRoot:      root,
		ProjectUUID:     projectUUID,
		ItemCounts:      countItemsByType(items),
		TotalItems:      len(items),
		Sessions:        includedSessions,
		Filters: bundleFilters{
			Only:         topExportOnly,
			Exclude:      topExportExclude,
			OmitResponse: topExportOmitResponse,
			Search:       topExportSearch,
			Severity:     topExportSeverity,
			Limit:        topExportLimit,
		},
	}
	manifest.Report.Title = meta.Title
	manifest.Report.Target = meta.ScanTarget
	manifest.Report.Duration = meta.ScanDuration
	manifest.Report.GeneratedAt = meta.GeneratedAt

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := writeTarBytes(tw, root+"/manifest.json", manifestBytes, now); err != nil {
		return nil, err
	}
	return includedSessions, nil
}

// bundleRootName returns the top-level directory inside the tarball, derived
// from the output path basename minus its archive extension.
func bundleRootName(outputPath string) string {
	base := filepath.Base(outputPath)
	switch {
	case strings.HasSuffix(base, ".tar.gz"):
		base = strings.TrimSuffix(base, ".tar.gz")
	case strings.HasSuffix(base, ".tgz"):
		base = strings.TrimSuffix(base, ".tgz")
	}
	if base == "" {
		base = "vigolium-bundle"
	}
	return base
}

// resolveBundleReportMeta picks report metadata, preferring a single matching
// agentic_scan when --scan-uuid resolves to exactly one row. Falls back to the
// run's shared auto-detected meta and CLI overrides.
func (r *exportRun) resolveBundleReportMeta(ctx context.Context, db *database.DB) output.HTMLReportMeta {
	title := "Vigolium Scan Report"
	if topExportTitle != "" {
		title = topExportTitle
	}

	autoTarget, autoDuration := r.reportMeta(ctx, db)

	if len(topExportScanUUIDs) == 1 {
		var scan database.AgenticScan
		err := db.NewSelect().Model(&scan).
			Where("uuid = ?", topExportScanUUIDs[0]).
			Limit(1).
			Scan(ctx)
		if err == nil && scan.UUID != "" {
			if scan.TargetURL != "" {
				autoTarget = scan.TargetURL
			}
			if scan.DurationMs > 0 {
				d := time.Duration(scan.DurationMs) * time.Millisecond
				autoDuration = d.Round(time.Second).String()
			}
		}
	}

	target := autoTarget
	if topExportTarget != "" {
		target = topExportTarget
	}
	duration := autoDuration
	if topExportDuration != "" {
		duration = topExportDuration
	}

	return output.HTMLReportMeta{
		Title:           title,
		Version:         getVersion(),
		ScanDuration:    duration,
		ScanTarget:      target,
		GeneratedAt:     topExportGeneratedAt,
		ReportSharedURL: topExportReportURL,
	}
}

func encodeItemsAsJSONL(items []any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			return nil, fmt.Errorf("failed to encode jsonl record: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// renderBundleHTML is the bundle's HTML renderer, indirected through a package
// var so a test can make the render fail and assert that the archive is not
// published. Both bundle writers (`export --format bundle` and `db export
// --format bundle`) go through it.
var renderBundleHTML = renderHTMLToBytes

// renderHTMLToBytes calls output.GenerateHTMLReport with a temp file, reads
// the bytes back, and removes the temp. Avoids refactoring the HTML generator.
//
// The temp file goes in process scratch rather than os.TempDir(): a bundle of a
// large corpus writes a report of the same order of magnitude, and scratch is
// what gets collected when a run is killed before its defers run.
func renderHTMLToBytes(items []any, meta output.HTMLReportMeta) ([]byte, error) {
	tmp, err := scratch.CreateTemp("vigolium-bundle-html-*.html")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := output.GenerateHTMLReport(items, tmpPath, meta); err != nil {
		return nil, err
	}
	return os.ReadFile(tmpPath)
}

func countItemsByType(items []any) map[string]int {
	counts := make(map[string]int)
	for _, item := range items {
		if env, ok := item.(exportEnvelope); ok {
			counts[env.Type]++
		}
	}
	return counts
}

// writeSessionsToTar copies each requested session dir into the tarball under
// <root>/sessions/<uuid>/. Missing dirs are warned-and-skipped. Returns the
// list of session UUIDs actually included.
func writeSessionsToTar(tw *tar.Writer, root, sessionsBase string, requested []string, mtime time.Time) ([]string, error) {
	if len(requested) == 0 {
		return nil, nil
	}
	if sessionsBase == "" {
		fmt.Fprintf(os.Stderr, "%s Sessions directory not configured; skipping --scan-uuid entries\n", terminal.WarningSymbol())
		return nil, nil
	}

	if err := writeTarDir(tw, root+"/sessions/", mtime); err != nil {
		return nil, err
	}

	var included []string
	for _, id := range requested {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		src := filepath.Join(sessionsBase, id)
		info, err := os.Stat(src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Session %s not found at %s; skipping\n", terminal.WarningSymbol(), id, src)
			continue
		}
		if !info.IsDir() {
			fmt.Fprintf(os.Stderr, "%s Session path %s is not a directory; skipping\n", terminal.WarningSymbol(), src)
			continue
		}
		prefix := root + "/sessions/" + id
		if err := walkAndTar(tw, src, prefix); err != nil {
			return nil, fmt.Errorf("failed to add session %s: %w", id, err)
		}
		included = append(included, id)
	}
	return included, nil
}

// walkAndTar walks src and writes every regular file and directory entry
// into tw under the given prefix path.
func walkAndTar(tw *tar.Writer, src, prefix string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		var name string
		if rel == "." {
			name = prefix + "/"
		} else {
			name = prefix + "/" + filepath.ToSlash(rel)
		}

		mode := info.Mode()
		switch {
		case mode.IsDir():
			return writeTarDir(tw, strings.TrimSuffix(name, "/")+"/", info.ModTime())
		case mode.IsRegular():
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			hdr := &tar.Header{
				Name:    name,
				Mode:    int64(mode.Perm()),
				Size:    info.Size(),
				ModTime: info.ModTime(),
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if _, err := io.Copy(tw, f); err != nil {
				return err
			}
			return nil
		default:
			return nil
		}
	})
}

func writeTarDir(tw *tar.Writer, name string, mtime time.Time) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o755,
		Typeflag: tar.TypeDir,
		ModTime:  mtime,
	}
	return tw.WriteHeader(hdr)
}

func writeTarBytes(tw *tar.Writer, name string, data []byte, mtime time.Time) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o644,
		Size:    int64(len(data)),
		ModTime: mtime,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(data); err != nil {
		return err
	}
	return nil
}
