package har

import (
	"bytes"
	"os"
)

// sniffLimit bounds how many bytes SniffFile reads. A HAR's envelope — the
// `log` object with its `version` and `creator` — is the first thing in the
// file; `entries` is the large part and may start well past this, which is
// exactly why the sniff must not depend on reaching it.
const sniffLimit = 64 * 1024

// IsHAR reports whether data is the head of an HTTP Archive: a JSON object
// whose `log` member carries a `version` and a `creator` or `entries`.
//
// All of them are required because a HAR arrives through the same slot as a
// plain URL list (-i with the default -I urls), so the sniff displaces the URL
// parser and must not do so for arbitrary JSON. A URL list is never a JSON
// object, which is what makes this safe at all.
func IsHAR(data []byte) bool {
	// A UTF-8 BOM is common on archives exported from Windows tooling.
	head := bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	head = bytes.TrimLeft(head, " \t\r\n")
	if len(head) == 0 || head[0] != '{' {
		return false
	}
	if !bytes.Contains(head, []byte(`"log"`)) || !bytes.Contains(head, []byte(`"version"`)) {
		return false
	}
	return bytes.Contains(head, []byte(`"creator"`)) || bytes.Contains(head, []byte(`"entries"`))
}

// SniffFile reads the head of a file and reports whether it looks like a HAR.
//
// Used to auto-detect a HAR passed without an explicit -I har (mirrors
// burpscope.SniffFile and wsdl.SniffFile). Without it, `vigolium ingest -i
// traffic.har` read the archive line by line as a URL list and turned its JSON
// punctuation into targets. Returns false on any read error.
func SniffFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, sniffLimit)
	n, _ := f.Read(buf)
	return IsHAR(buf[:n])
}
