package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The recurring failure in this feature has been the panel reporting what was
// configured or intended instead of what is actually on the wire: the card
// said "no certificate" and "serving plain HTTP" while the browser was
// plainly on HTTPS, and the selector named a pair that was neither configured
// nor in use. Whatever else it gets wrong, GET /api/https must never
// understate the transport.
func TestHTTPSStateNeverUnderstatesTheTransport(t *testing.T) {
	for _, tc := range []struct {
		name        string
		secure      bool
		servingCert string
		wantSource  string
	}{
		{"TLS with the panel's own pair", true, "/etc/netgrip/ssl/cert.pem", "panel"},
		{"TLS with a pair from somewhere else", true, "/srv/ssl/wildcard.pem", "custom"},
		{"plain HTTP", false, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinPanelPair(t, "/etc/netgrip/ssl/cert.pem", "/etc/netgrip/ssl/key.pem")
			pinRouterPair(t, "/etc/uhttpd.crt", "/etc/uhttpd.key")
			s := &Server{secure: tc.secure, servingCert: tc.servingCert}
			w := httptest.NewRecorder()
			s.handleHTTPSGet(w, httptest.NewRequest(http.MethodGet, "/api/https", nil))

			var got map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("response is not JSON: %v", err)
			}
			if got["serving"] != tc.secure {
				t.Errorf("serving = %v, want %v: this is the field the card turns into "+
					"\"Serving plain HTTP\", and saying that over TLS is the one error "+
					"that must never happen", got["serving"], tc.secure)
			}
			if got["serving_source"] != tc.wantSource {
				t.Errorf("serving_source = %q, want %q", got["serving_source"], tc.wantSource)
			}
			if tc.secure && got["serving_cert"] != tc.servingCert {
				t.Errorf("serving_cert = %q, want the pair actually opened %q",
					got["serving_cert"], tc.servingCert)
			}
		})
	}
}

// An unrecognised path still means TLS is on. Reporting an empty source is
// fine - the card has wording for a certificate it cannot name - but the
// transport must stay true.
func TestAnUnknownCertificatePathStillReportsTLS(t *testing.T) {
	s := &Server{secure: true, servingCert: "/tmp/somewhere/else.pem"}
	w := httptest.NewRecorder()
	s.handleHTTPSGet(w, httptest.NewRequest(http.MethodGet, "/api/https", nil))

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["serving"] != true {
		t.Error("an unrecognised certificate path must not read as plain HTTP")
	}
	if got["serving_source"] == "" {
		t.Error("a served pair always has a source, even if it is only \"custom\"")
	}
}

// servingSource follows uhttpd's configured pair, not the conventional path,
// for the same reason the rest of the feature does: /etc/uhttpd.crt is only
// the default value of a UCI option.
func TestServingSourceFollowsUhttpdsConfiguredPair(t *testing.T) {
	pinRouterPair(t, "/etc/ssl/moved.crt", "/etc/ssl/moved.key")
	pinPanelPair(t, "/etc/netgrip/ssl/cert.pem", "/etc/netgrip/ssl/key.pem")

	if got := servingSource("/etc/ssl/moved.crt"); got != "router" {
		t.Errorf("servingSource = %q, want %q for the pair uhttpd names", got, "router")
	}
	if got := servingSource("/etc/uhttpd.crt"); got != "custom" {
		t.Errorf("servingSource = %q; once uhttpd names another pair, the conventional "+
			"path is not the router's any more", got)
	}
}
