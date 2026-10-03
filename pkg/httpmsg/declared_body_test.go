package httpmsg

import (
	"strings"
	"testing"
)

// The reported defect: a request file written by any ordinary editor ends in a
// newline, so `a=1` under `Content-Length: 3` is four bytes on disk and the
// fourth one leaks past the declared body.
func TestReconcileDropsTheEditorsTrailingNewline(t *testing.T) {
	raw := "POST /login HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\na=1\n"
	got := string(ReconcileDeclaredBody([]byte(raw)))
	want := "POST /login HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\na=1"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A body whose declared length COUNTS its trailing whitespace keeps every byte.
// This is WP13's smoke test 10 shape and the reason blanket trimming is wrong.
func TestReconcileKeepsWhitespaceTheLengthCounts(t *testing.T) {
	body := "a=1 \r\n\n" // 7 bytes, all declared
	raw := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 7\r\n\r\n" + body
	got := string(ReconcileDeclaredBody([]byte(raw)))
	if got != raw {
		t.Fatalf("declared body was altered:\ngot  %q\nwant %q", got, raw)
	}
}

func TestReconcileLeavesAnExactBodyAlone(t *testing.T) {
	raw := []byte("POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\na=1")
	got := ReconcileDeclaredBody(raw)
	if string(got) != string(raw) {
		t.Fatalf("got %q, want unchanged", got)
	}
	// No copy for the common case: the same backing array comes back.
	if &got[0] != &raw[0] {
		t.Error("an already-consistent request was reallocated")
	}
}

// A declaration longer than the bytes available cannot be honoured — nobody can
// invent the missing bytes — so the header is corrected down rather than left
// to hang a server waiting for them.
func TestReconcileCorrectsAnOverDeclaredLengthDown(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 40\r\nAccept: */*\r\n\r\na=1"
	got := string(ReconcileDeclaredBody([]byte(raw)))
	want := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nAccept: */*\r\n\r\na=1"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// The repair must not move the header: a rebuild through UpdateContentLength
// would push Content-Length to the end of the block and change the request's
// bytes (and so its identity hash) for a fix that is meant to be invisible.
func TestReconcileKeepsHeaderOrderWhenCorrectingDown(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nContent-Length: 99\r\nHost: h\r\nX-Last: 1\r\n\r\nab"
	got := string(ReconcileDeclaredBody([]byte(raw)))
	names := []string{"Content-Length: 2", "Host: h", "X-Last: 1"}
	pos := -1
	for _, n := range names {
		i := strings.Index(got, n)
		if i < 0 {
			t.Fatalf("%q missing from %q", n, got)
		}
		if i < pos {
			t.Fatalf("header order changed: %q", got)
		}
		pos = i
	}
}

func TestReconcileZeroLengthDropsAStrayNewline(t *testing.T) {
	raw := "GET /x HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n\n"
	got := string(ReconcileDeclaredBody([]byte(raw)))
	want := "GET /x HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestReconcileHandlesLFOnlyLineEndings(t *testing.T) {
	raw := "POST /x HTTP/1.1\nHost: h\nContent-Length: 3\n\na=1\n"
	got := string(ReconcileDeclaredBody([]byte(raw)))
	want := "POST /x HTTP/1.1\nHost: h\nContent-Length: 3\n\na=1"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Deliberate framing disagreements are the point of the desync probes; they
// must survive untouched.
func TestReconcileLeavesDeliberateDisagreementsAlone(t *testing.T) {
	cases := map[string]string{
		"transfer-encoding present": "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGPOST / HTTP/1.1\r\n\r\n",
		"duplicate content-length":  "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nContent-Length: 11\r\n\r\nabcdefghijk",
		"no content-length":         "POST /x HTTP/1.1\r\nHost: h\r\n\r\nabcdefghijk",
		"unparseable length":        "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 4 , 11\r\n\r\nabcdefghijk",
		"negative length":           "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: -1\r\n\r\nabcdefghijk",
		"no separator at all":       "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if got := string(ReconcileDeclaredBody([]byte(raw))); got != raw {
				t.Fatalf("altered:\ngot  %q\nwant %q", got, raw)
			}
		})
	}
}

func TestReconcileEmptyInput(t *testing.T) {
	if got := ReconcileDeclaredBody(nil); got != nil {
		t.Errorf("nil input returned %q", got)
	}
	if got := ReconcileDeclaredBody([]byte{}); len(got) != 0 {
		t.Errorf("empty input returned %q", got)
	}
}

// The end-to-end guarantee: what ParseRawRequest hands a sender is exactly the
// number of bytes the request declares.
func TestParseRawRequestBodyMatchesDeclaredLength(t *testing.T) {
	for _, src := range []string{
		"POST /login HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\na=1\n",
		"POST /login HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\na=1",
		"POST /login HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\na=1\r\n\r\n",
	} {
		rr, err := ParseRawRequest(src)
		if err != nil {
			t.Fatalf("ParseRawRequest(%q): %v", src, err)
		}
		body := rr.Request().Body()
		if string(body) != "a=1" {
			t.Errorf("ParseRawRequest(%q) body = %q, want %q", src, body, "a=1")
		}
		if cl := rr.Request().Header("Content-Length"); cl != "3" {
			t.Errorf("ParseRawRequest(%q) Content-Length = %q, want 3", src, cl)
		}
	}
}

func TestParseRawRequestLeavesABodylessRequestAlone(t *testing.T) {
	src := "GET /x HTTP/1.1\r\nHost: h\r\n\r\n"
	rr, err := ParseRawRequest(src)
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}
	if got := string(rr.Request().Raw()); got != src {
		t.Fatalf("got %q, want %q", got, src)
	}
}
