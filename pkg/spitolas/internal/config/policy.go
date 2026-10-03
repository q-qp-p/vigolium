package config

// DialogPolicy selects how the browser answers a JavaScript dialog once it has
// been recorded. Recording never depends on the answer.
type DialogPolicy string

const (
	// DialogRecordDismiss accepts an alert (nothing to cancel) and a
	// beforeunload (dismissing it cancels the crawler's own navigation), and
	// dismisses confirm/prompt — the only answer that cannot authorize an
	// application change.
	DialogRecordDismiss DialogPolicy = "record-dismiss"
	// DialogAcceptAll accepts every dialog, confirm and prompt included.
	DialogAcceptAll DialogPolicy = "accept-all"
)

// InteractionPolicy is the crawler-side mirror of spitolas.InteractionPolicy:
// what a browser run is permitted to change. Set it through ApplyPolicy so the
// legacy derived switches (FormFillEnabled, SubmitGetForms, SubmitPostForms,
// SelfRegister, LoginCredentialAttempts) cannot disagree with it.
type InteractionPolicy struct {
	EditFields      bool
	SubmitForms     bool
	UploadFiles     bool
	DownloadFiles   bool
	RegisterAccount bool
	LoginAttempts   bool
	DialogResponse  DialogPolicy
}

// DefaultInteractionPolicy is the policy a Config starts with: fields are
// edited, forms submitted and the generated upload fixture attached (the
// crawl's discovery depends on all three), while account actions and downloads
// stay off and dialogs are dismissed.
func DefaultInteractionPolicy() InteractionPolicy {
	return InteractionPolicy{
		EditFields:     true,
		SubmitForms:    true,
		UploadFiles:    true,
		DialogResponse: DialogRecordDismiss,
	}
}

// ApplyPolicy installs p and recomputes every switch derived from it. The
// derived fields predate the policy and are still read across the package;
// deriving them here keeps a single source for each permission.
//
// Which half of the policy a reader should consult differs by field, and the
// split is worth knowing: SubmitForms, UploadFiles, DownloadFiles and
// DialogResponse are read from c.Policy directly, while EditFields,
// RegisterAccount and LoginAttempts are consumed here into FormFillEnabled,
// SelfRegister and LoginCredentialAttempts, which are what the crawler reads.
// The setters for those three (EnableFormFill, SetLoginCredentialAttempts) write
// both halves, so c.Policy stays an accurate description of the installed
// permissions either way.
func (c *Config) ApplyPolicy(p InteractionPolicy) {
	if p.DialogResponse == "" {
		p.DialogResponse = DialogRecordDismiss
	}
	c.Policy = p
	c.FormFillEnabled = p.EditFields
	c.SubmitGetForms = p.SubmitForms
	c.SubmitPostForms = p.SubmitForms
	c.SelfRegister = p.RegisterAccount
	c.LoginCredentialAttempts = p.LoginAttempts
}

// BrowserCompat lists the browser security exceptions a launch runs with. Each
// field relaxes one ordinary Chromium boundary; the launcher sets exactly the
// flag that field names and nothing else (see browser.applySecurityFlags). The
// hygiene flags around them (crash reporting, caches, media stubs, HTTPS-upgrade
// suppression) are not security boundaries and stay unconditional.
type BrowserCompat struct {
	// NoSandbox runs Chromium without its process sandbox. Off by default; the
	// launcher still forces it on — with a named warning — where the host cannot
	// provide a sandbox (root, a container, user namespaces disabled) or a
	// sandboxed launch fails on Linux.
	NoSandbox bool
	// IgnoreTLSErrors accepts invalid certificates. On by default, matching the
	// scanner's own HTTP transport, which does not verify either: a verifying
	// browser would fail on the self-signed targets the rest of the scan handles.
	IgnoreTLSErrors bool
	// AllowInsecureContent lets an HTTPS page load active HTTP subresources.
	AllowInsecureContent bool
	// DisableWebSecurity turns off the same-origin policy (and is the only case
	// in which reduce-security-for-testing is also set).
	DisableWebSecurity bool
}

// DefaultBrowserCompat is the launch posture when the operator configures
// nothing: sandbox on, same-origin policy and mixed-content blocking intact,
// certificate errors ignored (see IgnoreTLSErrors).
func DefaultBrowserCompat() BrowserCompat {
	return BrowserCompat{IgnoreTLSErrors: true}
}
