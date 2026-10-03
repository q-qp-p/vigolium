package runner

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"go.uber.org/zap"
)

// initSessions loads, validates, hydrates sessions and creates compare requesters.
// Sources (in priority order): --auth-file/--auth flags → DB authentication_hostnames fallback.
//
// ctx bounds the login flows: hydration runs on it (under the manager's own total
// login budget), so a Ctrl-C during setup stops the logins instead of letting
// them run to their per-request timeouts.
func (r *Runner) initSessions(ctx context.Context, infra *phaseInfra) error {
	opts := r.options
	sessionCfg := r.settings.ScanningStrategy.Session
	hasCLISessions := len(opts.AuthFiles) > 0 || len(opts.AuthInline) > 0

	// Captured BEFORE the primary-session append below. Compare requesters must
	// carry the operator's own headers plus their OWN session's — never the
	// primary session's credentials. Building them from the post-append slice made
	// every compare requester send the primary's Authorization as well as its own,
	// so an authorization-differential module compared the primary against itself
	// and could not report a difference.
	baseHeaders := slices.Clone(opts.Headers)

	var sessions []*authentication.Session
	var sessionHostnameMap map[string]string // session name → hostname (from DB)
	fromDB := false

	if hasCLISessions {
		if len(opts.AuthFiles) > 0 {
			loaded, err := authentication.LoadFromAuthFiles(opts.AuthFiles, sessionCfg.SessionDir)
			if err != nil {
				return err
			}
			sessions = append(sessions, loaded...)
		}
		if len(opts.AuthInline) > 0 {
			loaded, err := authentication.LoadFromAuthInline(opts.AuthInline)
			if err != nil {
				return err
			}
			sessions = append(sessions, loaded...)
		}
	} else {
		// Fallback: load from DB authentication_hostnames for this project's target hostnames
		sessions, sessionHostnameMap, fromDB = r.loadSessionsFromDB(ctx)
		if len(sessions) == 0 {
			return nil
		}
	}

	mgr, err := authentication.NewManager(sessions,
		authentication.WithSessionDir(sessionCfg.SessionDir),
		// A login goes to the host the scan is about to attack, so it follows the
		// same proxy and TLS policy as every other request to that host.
		authentication.WithLoginTransport(http.LoginTransport(opts)),
	)
	if err != nil {
		return err
	}

	// Execute login flows (re-hydrate DB sessions to refresh potentially stale
	// tokens). Bounded by ctx and by the manager's total login budget, so a
	// target that accepts the connection and never answers delays the scan by the
	// budget rather than by one per-request timeout per session.
	if err := mgr.HydrateSessionsContext(ctx); err != nil {
		return fmt.Errorf("session hydration failed: %w", err)
	}

	// Persist CLI sessions to DB for reuse in future scans
	if hasCLISessions {
		r.persistSessionsToDB(ctx, mgr.AllSessions())
	}

	primaryHeaders := mgr.PrimaryHeaders()
	switch {
	case len(primaryHeaders) == 0:
		// Nothing to apply (static-header sessions with no primary headers, or a
		// login that produced none).
	case sessionCfg.UseInDiscovery:
		// Credentials on the shared requester: every phase, discovery and
		// spidering included, sends them.
		opts.Headers = append(opts.Headers, primaryHeaders...)
		// Rebuild the main requester with updated headers
		httpRequester, err := http.NewRequester(opts, infra.svc)
		if err != nil {
			return fmt.Errorf("failed to rebuild requester with session headers: %w", err)
		}
		infra.httpRequester = httpRequester
	default:
		// use_in_discovery: false — keep the credentials OFF the shared requester
		// (discovery and spidering stay anonymous) but hand them to the assessment
		// phases, which derive an authenticated view of that same requester. They
		// used to be resolved here and then discarded, so the whole scan ran
		// unauthenticated.
		infra.assessmentHeaders = primaryHeaders
	}

	// Create separate requesters for compare sessions (IDOR/BOLA testing)
	if !sessionCfg.CompareEnabled {
		zap.L().Info("Multi-session scanning enabled (compare disabled by config)",
			zap.String("primary", mgr.Primary().Name))
		return nil
	}

	cmpSessions := mgr.CompareSessions()
	if len(cmpSessions) == 0 {
		return nil
	}

	for _, cs := range cmpSessions {
		// Clone options, merge the operator's own headers with THIS session's auth
		// headers — from baseHeaders, so the primary session's credentials (which
		// may have been appended to opts.Headers above) are not included.
		compareOpts := *opts
		compareOpts.Headers = append(slices.Clone(baseHeaders), cs.HeaderSlice()...)
		compareRequester, err := http.NewRequester(&compareOpts, infra.svc)
		if err != nil {
			return fmt.Errorf("failed to create requester for session %q: %w", cs.Name, err)
		}
		cmpEntry := compareSession{
			Name:   cs.Name,
			Client: compareRequester,
		}
		// Preserve per-hostname association from DB sessions
		if sessionHostnameMap != nil {
			cmpEntry.Hostname = sessionHostnameMap[cs.Name]
		}
		infra.compareSessions = append(infra.compareSessions, cmpEntry)
	}

	sourceLabel := "CLI"
	if fromDB {
		sourceLabel = "DB"
	}
	zap.L().Info("Multi-session scanning enabled",
		zap.String("source", sourceLabel),
		zap.String("primary", mgr.Primary().Name),
		zap.Int("compare_sessions", len(cmpSessions)))

	return nil
}

// authFailureReason classifies a session-initialization failure into one of the
// phase-outcome reason codes, so a scan that ran unauthenticated says WHY.
//
// A deadline that fired while parent is still live is the login budget's; one
// that fired with parent already expired belongs to the scan budget, which is
// the honest attribution — the logins were not slow, the scan ran out of time.
func authFailureReason(parent context.Context, err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return database.ReasonCancelled
	case errors.Is(err, context.DeadlineExceeded):
		if parent != nil && parent.Err() == nil {
			return database.ReasonLoginBudget
		}
		return database.ReasonScanBudget
	default:
		return database.ReasonAuthUnavailable
	}
}

// assessmentRequester returns the requester the assessing phases (dynamic
// assessment, known-issue scan's edge hooks) should send through: the shared one
// when the primary session's credentials are already on it (or there are none),
// else an authenticated view of it carrying infra.assessmentHeaders.
//
// The view shares the transport, host limiter, request counter, response
// observer and carried browser sessions, and has its own cookie jar and
// response-cache partition — so authenticated responses never coalesce with the
// anonymous parent's, which for an authorization-differential module would be
// the measurement itself.
func (r *Runner) assessmentRequester(infra *phaseInfra) (*http.Requester, error) {
	if infra == nil {
		return nil, fmt.Errorf("no phase infrastructure")
	}
	if len(infra.assessmentHeaders) == 0 {
		return infra.httpRequester, nil
	}
	view, err := infra.httpRequester.WithAdditionalHeaders(infra.assessmentHeaders)
	if err != nil {
		return nil, fmt.Errorf("failed to apply session headers to the assessment requester: %w", err)
	}
	zap.L().Info("Assessment requester carries the primary session (session.use_in_discovery is false, so discovery and spidering stay anonymous)",
		zap.Int("headers", len(infra.assessmentHeaders)))
	return view, nil
}

// assessmentHeaderSlice returns the headers a phase that cannot share the
// scan requester (known-issue scan runs nuclei's own HTTP stack) must send: the
// operator's own, plus the primary session's when they are not already there.
// assessmentHeaders is empty under use_in_discovery: true, where
// r.options.Headers already carries them — so this is correct in both modes and
// never duplicates.
func (r *Runner) assessmentHeaderSlice(infra *phaseInfra) []string {
	headers := slices.Clone(r.options.Headers)
	if infra != nil {
		headers = append(headers, infra.assessmentHeaders...)
	}
	return headers
}

// loadSessionsFromDB loads sessions from the authentication_hostnames table for target hostnames.
// Returns the loaded sessions, a map of session name → hostname for per-host filtering,
// and true if sessions were loaded from DB.
//
// ctx is the setup context, not r.ctx: a cancelled scan must not keep querying.
func (r *Runner) loadSessionsFromDB(ctx context.Context) ([]*authentication.Session, map[string]string, bool) {
	if r.repository == nil || r.options.ProjectUUID == "" {
		return nil, nil, false
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Extract hostnames from CLI targets
	hostnames := r.targetHostnames()
	if len(hostnames) == 0 {
		// No specific targets — try loading all project sessions
		rows, err := r.repository.GetAuthenticationHostnamesByProject(ctx, r.options.ProjectUUID)
		if err != nil || len(rows) == 0 {
			return nil, nil, false
		}
		cfg := database.AuthenticationHostnamesToSessionConfig(rows)
		if cfg == nil || len(cfg.Sessions) == 0 {
			return nil, nil, false
		}
		sessions := make([]*authentication.Session, len(cfg.Sessions))
		hostnameMap := make(map[string]string, len(rows))
		for i := range cfg.Sessions {
			sessions[i] = &cfg.Sessions[i]
		}
		for _, row := range rows {
			hostnameMap[row.SessionName] = row.Hostname
		}
		zap.L().Info("Loaded sessions from DB (project-wide)",
			zap.Int("sessions", len(sessions)))
		return sessions, hostnameMap, true
	}

	// Query authentication_hostnames for each target hostname, deduplicate by session name+hostname
	seen := make(map[string]bool)
	hostnameMap := make(map[string]string)
	var sessions []*authentication.Session
	for _, hostname := range hostnames {
		rows, err := r.repository.GetAuthenticationHostnamesByHostname(ctx, r.options.ProjectUUID, hostname)
		if err != nil || len(rows) == 0 {
			continue
		}
		for _, row := range rows {
			key := row.SessionName + ":" + row.Hostname
			if seen[key] {
				continue
			}
			seen[key] = true
			s := database.AuthenticationHostnameToSession(row)
			if s != nil {
				sessions = append(sessions, s)
				hostnameMap[s.Name] = row.Hostname
			}
		}
	}

	if len(sessions) > 0 {
		zap.L().Info("Loaded sessions from DB (authentication_hostnames)",
			zap.Int("sessions", len(sessions)),
			zap.Strings("hostnames", hostnames))
	}
	return sessions, hostnameMap, len(sessions) > 0
}

// persistSessionsToDB saves hydrated CLI sessions to authentication_hostnames for future reuse.
func (r *Runner) persistSessionsToDB(ctx context.Context, sessions []*authentication.Session) {
	if r.repository == nil || r.options.ProjectUUID == "" || len(sessions) == 0 {
		return
	}

	if ctx == nil {
		ctx = context.Background()
	}

	hostnames := r.targetHostnames()
	if len(hostnames) == 0 {
		return
	}

	for _, hostname := range hostnames {
		rows := database.SessionsToAuthenticationHostnames(sessions, r.options.ProjectUUID, hostname)
		if len(rows) == 0 {
			continue
		}
		if err := r.repository.SaveAuthenticationHostnames(ctx, rows); err != nil {
			zap.L().Debug("Failed to persist sessions to DB",
				zap.String("hostname", hostname), zap.Error(err))
		}
	}

	zap.L().Info("Persisted CLI sessions to authentication_hostnames",
		zap.Int("sessions", len(sessions)),
		zap.Strings("hostnames", hostnames))
}
