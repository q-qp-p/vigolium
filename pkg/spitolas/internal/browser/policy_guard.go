package browser

import (
	"os"
	"path/filepath"

	"github.com/go-rod/rod/lib/proto"
	"github.com/vigolium/vigolium/internal/scratch"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"go.uber.org/zap"
)

// submitGuardScript blocks native form submission in every document of a page
// whose policy denies submits. The crawler's own dispatch gates refuse submit
// controls and Enter actions; this covers what they cannot see — a script on an
// ordinary element calling form.submit(), implicit submission, a submit event
// the page dispatches itself. The capture-phase listener on window runs before
// any page listener, so stopping the event also stops a JS-driven form's own
// submit handler (and the request it would send).
//
// window.__vigAllowSubmit lifts the guard for the current document only — set by
// AllowAuthorizedSubmit for a submission the policy authorizes separately (a
// credential attempt, a registration). A navigation resets it.
const submitGuardScript = `(() => {
  if (window.__vigSubmitGuard) return;
  try { Object.defineProperty(window, '__vigSubmitGuard', { value: true }); } catch (e) {}
  const allowed = () => window.__vigAllowSubmit === true;
  window.addEventListener('submit', (e) => {
    if (allowed()) return;
    try { e.preventDefault(); e.stopImmediatePropagation(); } catch (x) {}
  }, true);
  try {
    const P = HTMLFormElement.prototype;
    const realSubmit = P.submit;
    const realRequest = P.requestSubmit;
    P.submit = function () { if (allowed()) return realSubmit.apply(this, arguments); };
    if (realRequest) P.requestSubmit = function () { if (allowed()) return realRequest.apply(this, arguments); };
  } catch (e) {}
})()`

// needsSubmitGuard reports whether pages under cfg get submitGuardScript.
func needsSubmitGuard(cfg *config.Config) bool {
	return cfg != nil && !cfg.Policy.SubmitForms
}

// installSubmitGuard registers submitGuardScript for every document the page
// loads from now on. Best-effort: a failure is logged, and the dispatch gates
// still hold.
func (p *Page) installSubmitGuard() {
	if _, err := p.rodPage.EvalOnNewDocument(submitGuardScript); err != nil {
		zap.L().Warn("Could not install the form-submission guard; dispatch gates still apply", zap.Error(err))
	}
}

// AllowAuthorizedSubmit lifts the submit guard for the page's current document
// so a submission the policy authorizes on its own terms (a credential attempt,
// a registration) can go through even though ordinary submits are denied. No-op
// when no guard is installed.
func (p *Page) AllowAuthorizedSubmit() {
	if !needsSubmitGuard(p.config) {
		return
	}
	_, _ = p.Eval(`(() => { window.__vigAllowSubmit = true; })()`)
}

// downloadBehavior is the Browser.setDownloadBehavior call for policy: deny
// unless downloads are permitted, and then only into dir — never the
// operator's own Downloads folder, which is where headless Chrome would put
// them by default.
func downloadBehavior(p config.InteractionPolicy, dir string) proto.BrowserSetDownloadBehavior {
	if !p.DownloadFiles || dir == "" {
		return proto.BrowserSetDownloadBehavior{Behavior: proto.BrowserSetDownloadBehaviorBehaviorDeny}
	}
	return proto.BrowserSetDownloadBehavior{
		Behavior:     proto.BrowserSetDownloadBehaviorBehaviorAllowAndName,
		DownloadPath: dir,
	}
}

// applyDownloadPolicy sets the browser-wide download behavior. Permitted
// downloads land in the browser's own profile directory (removed by Close), or
// a run-owned scratch directory when there is none.
func (b *Browser) applyDownloadPolicy() {
	if b.config == nil || b.rodBrowser == nil {
		return
	}
	dir := ""
	if b.config.Policy.DownloadFiles {
		if b.profileDir != "" {
			dir = filepath.Join(b.profileDir, "vig-downloads")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				dir = ""
			}
		}
		if dir == "" {
			if d, err := scratch.MkdirTemp("downloads-*"); err == nil {
				dir = d
			}
		}
	}
	if err := downloadBehavior(b.config.Policy, dir).Call(b.boundedBrowser()); err != nil {
		zap.L().Debug("Could not set the browser download behavior", zap.Error(err))
	}
}
