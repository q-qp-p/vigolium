package form

// FillOutcome is what a single fill actually achieved. Verification is part of
// the result rather than a log line, so a value that did not stick is never
// counted as a successful fill. An outcome is meaningful only when the fill
// returned no error.
type FillOutcome string

const (
	// FillVerified: the control's state was read back and matches the value.
	FillVerified FillOutcome = "verified"
	// FillAttempted: the value was written; this control type has no read-back.
	FillAttempted FillOutcome = "attempted"
	// FillRejected: the read-back disagreed — the value did not stick, or a
	// select had no option for it.
	FillRejected FillOutcome = "rejected"
	// FillSkipped: nothing was written and nothing needed to be — a disabled or
	// readonly control, an empty value, a select with no options. Not an error.
	FillSkipped FillOutcome = "skipped"
	// FillUnsupported: not filled because of the control type or the
	// interaction policy (a file input without upload permission).
	FillUnsupported FillOutcome = "unsupported"
)

// Succeeded reports whether the outcome counts as a successful fill.
func (o FillOutcome) Succeeded() bool {
	return o == FillVerified || o == FillAttempted
}

// fillTarget is the slice of *browser.Element the verifying fills use, so their
// outcome logic can be exercised without a browser.
type fillTarget interface {
	Property(name string) (interface{}, error)
	Click() error
	EvalWithResult(script string) (interface{}, error)
}

// asBool reads a JS boolean property value; anything else is false.
func asBool(v interface{}) bool {
	b, ok := v.(bool)
	return ok && b
}
