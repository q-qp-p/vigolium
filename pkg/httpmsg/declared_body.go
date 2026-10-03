package httpmsg

// Content-Length / body reconciliation for parsed raw requests.
//
// A raw request that comes from outside — a file an operator wrote, a paste
// from a proxy, an API submission — routinely carries one more byte than it
// declares: nearly every editor and every shell heredoc terminates the last
// line, so a body written as `a=1` under `Content-Length: 3` is four bytes on
// disk. The declared length and the body then disagree, and whichever side the
// sender picks is wrong for the other: send four bytes and the body is not the
// one the request describes; send the header and the body as they are and a
// conformant server reads three bytes and treats the fourth as the first byte
// of the next pipelined request. `Connection: close` hides it.
//
// WHICH SIDE IS AUTHORITATIVE: Content-Length. It is HTTP's own statement of
// where this message's body ends, so bytes past it are not part of this message
// and are dropped. It cannot be authoritative about bytes that do not exist,
// though, so when the body is SHORT of the declaration the declaration is
// corrected down to what is actually there — the alternative is a request that
// hangs a conformant server waiting for bytes the sender does not have.
//
// A body that genuinely ends in whitespace is unaffected, because its
// Content-Length counts that whitespace; that is the case blanket trimming used
// to corrupt.
//
// Deliberate framing disagreements are left alone: a message carrying
// Transfer-Encoding, or more than one Content-Length, is not reconciled. Those
// shapes are the CL.TE / TE.CL / duplicate-header desync probes, where the
// disagreement IS the test. (The request-smuggling module builds its probes
// with BuildHttpMessage and sends them as raw bytes, so it never reaches this
// path — the exclusion is belt and braces for anything that later does.)

// ReconcileDeclaredBody returns raw with its body and its declared
// Content-Length in agreement. See the file comment for which side wins and
// why. It returns raw itself — not a copy — whenever there is nothing to
// reconcile, which is the overwhelmingly common case.
func ReconcileDeclaredBody(raw []byte) []byte {
	f, ok := scanRequestFraming(raw)
	if !ok {
		return raw
	}

	actual := len(raw) - f.bodyOffset
	switch {
	case f.declared == actual:
		return raw
	case f.declared < actual:
		// Surplus bytes belong to no message. Reslicing keeps the headers and the
		// declared body byte-identical.
		return raw[:f.bodyOffset+f.declared]
	default:
		// Short body: correct the header down, in place, so the value keeps its
		// position in the header block. Rebuilding through UpdateContentLength
		// would move Content-Length to the end and change the request's identity
		// hash for a repair that is meant to be invisible.
		actualStr := intToString(actual)
		out := make([]byte, 0, len(raw)-(f.valueEnd-f.valueStart)+len(actualStr))
		out = append(out, raw[:f.valueStart]...)
		out = append(out, actualStr...)
		out = append(out, raw[f.valueEnd:]...)
		return out
	}
}

// requestFraming is what one pass over a raw request's header block needs to
// report for ReconcileDeclaredBody to act: where the body starts, and where the
// single Content-Length value it must agree with lives.
type requestFraming struct {
	bodyOffset int // first byte of the body (just past the blank line)
	valueStart int // first byte of the Content-Length value
	valueEnd   int // just past the Content-Length value (before any CR)
	declared   int // the parsed Content-Length
}

// scanRequestFraming walks the header block once and reports the framing when
// — and only when — reconciliation is well defined: a header/body separator
// exists, exactly one Content-Length header precedes it, its value is a
// non-negative integer, and no Transfer-Encoding is present.
//
// One pass with no allocation, deliberately: this runs inside ParseRawRequest,
// which modules call per payload. ExtractAllHeaders would answer the same
// questions and allocate a string per header line to do it.
func scanRequestFraming(raw []byte) (requestFraming, bool) {
	var f requestFraming
	if len(raw) == 0 {
		return f, false
	}

	// Skip the request line.
	lineStart := -1
	for i := 0; i < len(raw); i++ {
		if raw[i] == LF {
			lineStart = i + 1
			break
		}
	}
	if lineStart < 0 {
		return f, false
	}

	clSeen := 0
	for lineStart <= len(raw) {
		lineEnd := lineStart
		for lineEnd < len(raw) && raw[lineEnd] != LF {
			lineEnd++
		}
		// A blank line (bare LF, or CRLF) terminates the header block; the body
		// begins on the byte after it.
		if lineEnd == lineStart || (lineEnd == lineStart+1 && raw[lineStart] == CR) {
			if lineEnd >= len(raw) {
				return f, false // separator ran off the end: no body region
			}
			f.bodyOffset = lineEnd + 1
			break
		}
		if lineEnd >= len(raw) {
			return f, false // headers never terminated
		}

		colon := -1
		for i := lineStart; i < lineEnd; i++ {
			if raw[i] == ':' {
				colon = i
				break
			}
		}
		if colon >= 0 {
			name := raw[lineStart:colon]
			switch {
			case equalsASCIIFold(name, "transfer-encoding"):
				return f, false
			case equalsASCIIFold(name, "content-length"):
				clSeen++
				if clSeen > 1 {
					return f, false
				}
				valueStart := colon + 1
				for valueStart < lineEnd && (raw[valueStart] == ' ' || raw[valueStart] == '\t') {
					valueStart++
				}
				valueEnd := lineEnd
				if valueEnd > valueStart && raw[valueEnd-1] == CR {
					valueEnd--
				}
				for valueEnd > valueStart && (raw[valueEnd-1] == ' ' || raw[valueEnd-1] == '\t') {
					valueEnd--
				}
				f.valueStart, f.valueEnd = valueStart, valueEnd
			}
		}
		lineStart = lineEnd + 1
	}

	if clSeen != 1 || f.bodyOffset == 0 {
		return f, false
	}
	declared, ok := parseNonNegativeDecimal(raw[f.valueStart:f.valueEnd])
	if !ok {
		return f, false
	}
	f.declared = declared
	return f, true
}

// parseNonNegativeDecimal parses a bare non-negative decimal integer. A value
// with a sign, a space, or any other character is rejected rather than
// best-effort parsed: a Content-Length we cannot read exactly is one we must
// not act on.
func parseNonNegativeDecimal(b []byte) (int, bool) {
	if len(b) == 0 || len(b) > 18 { // 18 digits stays inside int64 on every arch
		return 0, false
	}
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// equalsASCIIFold compares a header name slice against an all-lowercase literal
// without allocating a string for it.
func equalsASCIIFold(b []byte, lower string) bool {
	if len(b) != len(lower) {
		return false
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}
