package runner

import (
	"context"
	"errors"
	stdhttp "net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// errTestLogin stands in for an ordinary (non-context) login failure.
var errTestLogin = errors.New("login returned status 403")

// newSessionTestRunner builds the minimum Runner initSessions needs: options
// carrying an inline session, settings with the session strategy under test,
// and a phaseInfra with real services and requester. The repository is nil, so
// persistSessionsToDB is a no-op and nothing touches a database.
func newSessionTestRunner(t *testing.T, opts *types.Options, sessionCfg config.SessionStrategyConfig) (*Runner, *phaseInfra) {
	t.Helper()
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	settings := &config.Settings{}
	settings.ScanningStrategy.Session = sessionCfg

	svc := &services.Services{Options: opts}
	requester, err := http.NewRequester(opts, svc)
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	r := &Runner{options: opts, settings: settings}
	return r, &phaseInfra{svc: svc, httpRequester: requester}
}

func sessionTestOptions(auth ...string) *types.Options {
	opts := types.DefaultOptions()
	opts.AuthInline = auth
	return opts
}

// hasHeader reports whether headers contains name under any case.
func hasHeader(headers []string, name string) bool {
	return slices.ContainsFunc(headers, func(h string) bool {
		return strings.HasPrefix(strings.ToLower(h), strings.ToLower(name)+":")
	})
}

// TestInitSessions_UseInDiscoveryFalseReachesAssessment is the headline WP7
// regression. With use_in_discovery:false the primary session's headers were
// resolved and then dropped on the floor — the comment said "handled
// downstream" and nothing downstream handled them — so a scan configured with
// credentials assessed an authenticated app anonymously. They must now reach
// the assessment phases and still stay off the shared requester.
func TestInitSessions_UseInDiscoveryFalseReachesAssessment(t *testing.T) {
	opts := sessionTestOptions("admin:Authorization:Bearer t")
	r, infra := newSessionTestRunner(t, opts, config.SessionStrategyConfig{UseInDiscovery: false})

	if err := r.initSessions(context.Background(), infra); err != nil {
		t.Fatalf("initSessions: %v", err)
	}

	if hasHeader(opts.Headers, "Authorization") {
		t.Errorf("options.Headers gained the session credential: %v", opts.Headers)
	}
	if !hasHeader(infra.assessmentHeaders, "Authorization") {
		t.Fatalf("assessmentHeaders = %v, want the primary session's Authorization", infra.assessmentHeaders)
	}

	// The requester the assessment phases send through carries it; the shared
	// one (discovery, spidering) does not.
	daRequester, err := r.assessmentRequester(infra)
	if err != nil {
		t.Fatalf("assessmentRequester: %v", err)
	}
	if daRequester == infra.httpRequester {
		t.Error("assessmentRequester returned the shared requester; the credentials would not be sent")
	}

	// And nuclei, which runs its own stack, gets the headers themselves.
	if !hasHeader(r.assessmentHeaderSlice(infra), "Authorization") {
		t.Errorf("assessmentHeaderSlice = %v, want the session credential", r.assessmentHeaderSlice(infra))
	}
}

// With use_in_discovery:true the behaviour is unchanged: the headers go onto the
// shared requester's options and assessmentHeaders stays empty, so
// assessmentHeaderSlice does not duplicate them.
func TestInitSessions_UseInDiscoveryTrueUnchanged(t *testing.T) {
	opts := sessionTestOptions("admin:Authorization:Bearer t")
	r, infra := newSessionTestRunner(t, opts, config.SessionStrategyConfig{UseInDiscovery: true})
	original := infra.httpRequester

	if err := r.initSessions(context.Background(), infra); err != nil {
		t.Fatalf("initSessions: %v", err)
	}

	if !hasHeader(opts.Headers, "Authorization") {
		t.Errorf("options.Headers = %v, want the session credential", opts.Headers)
	}
	if len(infra.assessmentHeaders) != 0 {
		t.Errorf("assessmentHeaders = %v, want empty when the shared requester already carries them", infra.assessmentHeaders)
	}
	if infra.httpRequester == original {
		t.Error("the shared requester must be rebuilt with the session headers")
	}

	// No second view, and no duplicated header for nuclei.
	daRequester, err := r.assessmentRequester(infra)
	if err != nil {
		t.Fatalf("assessmentRequester: %v", err)
	}
	if daRequester != infra.httpRequester {
		t.Error("with the credentials already on the shared requester, no view is needed")
	}
	var auths int
	for _, h := range r.assessmentHeaderSlice(infra) {
		if strings.HasPrefix(strings.ToLower(h), "authorization:") {
			auths++
		}
	}
	if auths != 1 {
		t.Errorf("assessmentHeaderSlice carries %d Authorization headers, want exactly 1", auths)
	}
}

// TestInitSessions_CompareRequestersExcludePrimaryCredentials: a compare
// requester built from the post-append slice sent the PRIMARY session's
// Authorization alongside its own, so an authorization-differential module
// compared the primary against itself and could never report a difference.
func TestInitSessions_CompareRequestersExcludePrimaryCredentials(t *testing.T) {
	opts := sessionTestOptions(
		"admin:Authorization:Bearer admin-token",
		"viewer:Authorization:Bearer viewer-token",
	)
	opts.Headers = []string{"X-Operator: 1"}
	r, infra := newSessionTestRunner(t, opts, config.SessionStrategyConfig{
		UseInDiscovery: true,
		CompareEnabled: true,
	})

	if err := r.initSessions(context.Background(), infra); err != nil {
		t.Fatalf("initSessions: %v", err)
	}

	if len(infra.compareSessions) != 1 {
		t.Fatalf("compareSessions = %d, want 1", len(infra.compareSessions))
	}
	cmp := infra.compareSessions[0]
	if cmp.Name != "viewer" {
		t.Errorf("compare session name = %q, want viewer", cmp.Name)
	}

	// Asserted on the wire rather than on an internal map: what matters is the
	// header the target receives.
	var gotAuth, gotOperator string
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, req *stdhttp.Request) {
		gotAuth = req.Header.Get("Authorization")
		gotOperator = req.Header.Get("X-Operator")
		w.WriteHeader(stdhttp.StatusOK)
	}))
	defer srv.Close()

	rr, err := httpmsg.GetRawRequestFromURL(srv.URL)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if _, _, err := cmp.Client.Execute(rr, http.Options{NoClustering: true}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotAuth != "Bearer viewer-token" {
		t.Errorf("compare Authorization = %q, want only its own token", gotAuth)
	}
	if gotOperator != "1" {
		t.Errorf("compare requester lost the operator's own header (X-Operator = %q)", gotOperator)
	}
}

// A session whose login flow never succeeded is an error, and the caller
// decides what to do with it; this only pins that the error is returned rather
// than swallowed, since the auth_unavailable marking hangs off it.
func TestInitSessions_NoSessionsIsNoOp(t *testing.T) {
	opts := sessionTestOptions()
	r, infra := newSessionTestRunner(t, opts, config.SessionStrategyConfig{UseInDiscovery: false})

	if err := r.initSessions(context.Background(), infra); err != nil {
		t.Fatalf("initSessions with nothing configured: %v", err)
	}
	if len(infra.assessmentHeaders) != 0 || infra.authFailureReason != "" {
		t.Errorf("nothing configured must leave the infra untouched: headers=%v reason=%q",
			infra.assessmentHeaders, infra.authFailureReason)
	}
}

// TestAuthFailureReason classifies a hydration failure for the phase ledger. A
// deadline that fired while the scan context is still live is the login
// budget's; one that fired with the scan context already gone belongs to the
// scan budget — the logins were not slow, the scan ran out of time.
func TestAuthFailureReason(t *testing.T) {
	live := context.Background()
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()

	for _, tc := range []struct {
		name   string
		parent context.Context
		err    error
		want   string
	}{
		{"cancelled login", live, context.Canceled, database.ReasonCancelled},
		{"login budget", live, context.DeadlineExceeded, database.ReasonLoginBudget},
		{"scan budget outranks", expired, context.DeadlineExceeded, database.ReasonScanBudget},
		{"cancelled parent", cancelled, context.Canceled, database.ReasonCancelled},
		{"ordinary failure", live, errTestLogin, database.ReasonAuthUnavailable},
		{"nil parent", nil, context.DeadlineExceeded, database.ReasonScanBudget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := authFailureReason(tc.parent, tc.err); got != tc.want {
				t.Errorf("authFailureReason = %q, want %q", got, tc.want)
			}
		})
	}
}

// assessmentRequester must tolerate a nil infra rather than panic: it is called
// from a phase, and a phase with no infrastructure is a programming error that
// should surface as one.
func TestAssessmentRequester_NilInfra(t *testing.T) {
	r := &Runner{options: types.DefaultOptions()}
	if _, err := r.assessmentRequester(nil); err == nil {
		t.Error("expected an error for a nil phaseInfra")
	}
	if got := r.assessmentHeaderSlice(nil); len(got) != 0 {
		t.Errorf("assessmentHeaderSlice(nil) = %v, want the options' own headers only", got)
	}
}
