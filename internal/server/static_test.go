package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func gzipBytes(t *testing.T, content []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestServeCompressedAsset(t *testing.T) {
	plain := []byte("console.log('netgrip')")
	compressed := gzipBytes(t, plain)
	files := fstest.MapFS{"assets/app.js.gz": {Data: compressed}}

	t.Run("gzip client", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/assets/app.js", nil)
		req.Header.Set("Accept-Encoding", "br, gzip")
		w := httptest.NewRecorder()
		if !serveCompressedAsset(w, req, files, "assets/app.js") {
			t.Fatal("compressed asset was not served")
		}
		if got := w.Header().Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("Content-Encoding = %q, want gzip", got)
		}
		if !bytes.Equal(w.Body.Bytes(), compressed) {
			t.Fatal("response did not contain the stored gzip bytes")
		}
	})

	t.Run("identity client", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/assets/app.js", nil)
		w := httptest.NewRecorder()
		if !serveCompressedAsset(w, req, files, "assets/app.js") {
			t.Fatal("compressed asset was not served")
		}
		body, err := io.ReadAll(w.Result().Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body, plain) {
			t.Fatalf("body = %q, want %q", body, plain)
		}
	})
}
