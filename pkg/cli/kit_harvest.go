package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/harvester"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	kitHarvestSources []string
	kitHarvestTimeout time.Duration
)

var kitHarvestCmd = &cobra.Command{
	Use:   "harvest [domain...|-]",
	Short: "Collect known URLs for a domain from public archives and indexes",
	Long: `Collect historically-known URLs for one or more domains from public web archives
and URL indexes (Wayback, Common Crawl, AlienVault OTX, Arquivo by default;
urlscan and VirusTotal join when their API key is configured). Domains are given
positionally or one per line on stdin; a URL argument is reduced to its host.

  vigolium kit harvest acme.test                          # one domain
  vigolium kit harvest acme.test shop.acme.test -j        # several, as JSON
  cat domains.txt | vigolium kit harvest -                # stdin
  vigolium kit harvest --source wayback,commoncrawl acme.test

Sources and API keys come from external_harvester in your config; --source
overrides the set for this run. Output is deduplicated URLs (one per line, or a
JSON object under -j).`,
	RunE: runKitHarvest,
}

func init() {
	f := kitHarvestCmd.Flags()
	f.StringSliceVar(&kitHarvestSources, "source", nil, "Override sources (comma-separated): wayback, commoncrawl, alienvault, arquivo, urlscan, virustotal")
	f.DurationVar(&kitHarvestTimeout, "timeout", 5*time.Minute, "Overall harvest timeout")
	kitCmd.AddCommand(kitHarvestCmd)
}

type kitHarvestResult struct {
	Domains []string `json:"domains"`
	Sources []string `json:"sources"`
	Count   int      `json:"count"`
	URLs    []string `json:"urls"`
}

func runKitHarvest(cmd *cobra.Command, args []string) error {
	domains, err := kitCollectDomains(args)
	if err != nil {
		return err
	}
	if len(domains) == 0 {
		return fmt.Errorf("no domains given (pass domains as arguments or on stdin)")
	}

	// Source list + API keys come from the user's config so the utility offers
	// exactly what the scan phase would; --source narrows it for this run.
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	names := kitHarvestSources
	if len(names) == 0 {
		names = settings.ExternalHarvester.Sources
		if len(names) == 0 {
			names = config.DefaultExternalHarvesterConfig().Sources
		}
	}
	sources := harvester.BuildSources(names, harvester.SourceKeys{
		URLScan:    settings.ExternalHarvester.APIKeys.URLScan,
		VirusTotal: settings.ExternalHarvester.APIKeys.VirusTotal,
	}, globalProxy)
	if len(sources) == 0 {
		return fmt.Errorf("no usable sources from %v (keyed sources need an API key in config)", names)
	}

	// Ctrl-C cancels a long harvest cleanly; the harvester also enforces --timeout.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	sourceNames := make([]string, len(sources))
	for i, s := range sources {
		sourceNames[i] = s.Name()
	}
	if !globalJSON {
		fmt.Fprintf(os.Stderr, "%s harvesting %d domain(s) from %s...\n",
			terminal.InfoSymbol(), len(domains), strings.Join(sourceNames, ", "))
	}

	h := harvester.New(sources, kitHarvestTimeout)
	urls := []string{}
	for u := range h.Harvest(ctx, domains) {
		urls = append(urls, u)
		if !globalJSON {
			fmt.Println(u) // plain mode streams unsorted as they arrive
		}
	}

	if globalJSON {
		sort.Strings(urls) // only the JSON payload needs a stable order
		return writeAgentJSON(kitHarvestResult{
			Domains: domains,
			Sources: sourceNames,
			Count:   len(urls),
			URLs:    urls,
		})
	}
	fmt.Fprintf(os.Stderr, "\n%s %d unique URL(s)\n", terminal.InfoSymbol(), len(urls))
	return nil
}

// kitCollectDomains gathers domains from positional args (with "-" meaning
// stdin, one per line) and reduces any URL to its host.
func kitCollectDomains(args []string) ([]string, error) {
	var raw []string
	stdinRequested := len(args) == 0
	for _, a := range args {
		if a == "-" {
			stdinRequested = true
			continue
		}
		raw = append(raw, a)
	}
	if stdinRequested {
		sc := kitLineScanner(os.Stdin)
		for sc.Scan() {
			raw = append(raw, sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
	}

	seen := make(map[string]bool)
	var out []string
	for _, r := range raw {
		d := kitNormalizeDomain(r)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out, nil
}

// kitNormalizeDomain reduces a raw token (bare domain, host:port, or full URL)
// to a lowercase hostname; comments and blanks yield "".
func kitNormalizeDomain(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	// Strip any path and port from a bare host[:port]/path token.
	if i := strings.IndexAny(s, "/"); i >= 0 {
		s = s[:i]
	}
	if h, _, ok := strings.Cut(s, ":"); ok {
		s = h
	}
	return strings.ToLower(strings.TrimSpace(s))
}
