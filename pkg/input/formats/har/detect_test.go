package har

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsHARAcceptsAnArchiveHead(t *testing.T) {
	head := `{"log":{"version":"1.2","creator":{"name":"WebInspector","version":"537.36"},"pages":[],"entries":[`
	assert.True(t, IsHAR([]byte(head)))
	assert.True(t, IsHAR([]byte("\xef\xbb\xbf"+head)), "a UTF-8 BOM must not defeat the sniff")
	assert.True(t, IsHAR([]byte("\n  "+head)))
}

// The sniff displaces the URL-list parser, so anything that is not clearly a
// HAR has to fall through to it.
func TestIsHARRejectsEverythingElse(t *testing.T) {
	for name, data := range map[string]string{
		"url list":        "https://example.com/a\nhttps://example.com/b\n",
		"json array":      `[{"log":{"version":"1.2","entries":[]}}]`,
		"burp scope":      `{"target":{"scope":{"include":[{"host":"example.com"}]}}}`,
		"openapi":         `{"openapi":"3.0.0","info":{"title":"x","version":"1"}}`,
		"empty":           "",
		"log without ver": `{"log":{"entries":[]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			assert.False(t, IsHAR([]byte(data)))
		})
	}
}

func TestSniffFileReadsOnlyTheHead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.har")
	// An envelope followed by far more than the sniff limit of entries: the
	// sniff must decide from the head alone.
	body := `{"log":{"version":"1.2","creator":{"name":"fixture","version":"1"},"entries":[`
	body += string(make([]byte, 0))
	padding := make([]byte, sniffLimit*2)
	for i := range padding {
		padding[i] = ' '
	}
	require.NoError(t, os.WriteFile(path, append([]byte(body), padding...), 0o644))

	assert.True(t, SniffFile(path))
	assert.False(t, SniffFile(filepath.Join(t.TempDir(), "missing.har")))
}
