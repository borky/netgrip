package modules

// FORK: enrolment and NetGrip's own requests over https, pinned.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/runtime"
)

// pairingServer is an https NetPulse stand-in with a key of its own, which
// answers pairing.
func pairingServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"slug":"test-router","token":"tok-https","server_fp":"ignored"}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, hex.EncodeToString(sum[:])
}

// Enrolling over https pins the key the discovery reply named, and refuses a
// server that presents another.
func TestEnrollOverHTTPSPinsTheDiscoveredKey(t *testing.T) {
	resetDiscoveryState(t)
	srv, fp := pairingServer(t)

	p := tmpPaths(t)
	if err := enrollNetPulse(p, srv.URL, fp, "ptok"); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	cfg, err := ReadNetPulseConfig(p.env)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != srv.URL || cfg.ServerFP != fp || cfg.Token != "tok-https" {
		t.Fatalf("config after enroll: %+v", cfg)
	}

	p2 := tmpPaths(t)
	if err := enrollNetPulse(p2, srv.URL, strings.Repeat("ab", 32), "ptok"); err == nil {
		t.Fatal("enrolled with a server whose key is not the one named")
	}
	if err := enrollNetPulse(p2, srv.URL, "", "ptok"); err == nil {
		t.Fatal("enrolled over https with nothing to pin")
	}
}

// A discovery reply that offers https is enrolled over it, with its pin.
func TestDiscoveryPrefersHTTPS(t *testing.T) {
	resetDiscoveryState(t)
	p := tmpPaths(t)
	fp := strings.Repeat("cd", 32)
	got := make(chan [2]string, 1)
	withFakeDiscovery(t,
		func(int, time.Duration) *netPulseDiscoveryResult {
			return &netPulseDiscoveryResult{V: 1, Type: "netpulse-server", URL: "http://192.0.2.50:3000",
				URLHTTPS: "https://192.0.2.50:3443", ServerFP: fp, Autoenroll: true, PairingToken: "ptok"}
		},
		func(_ netpulsePaths, server, pin, _ string) error {
			got <- [2]string{server, pin}
			return nil
		})
	netPulseTryDiscovery(p)
	select {
	case g := <-got:
		if g[0] != "https://192.0.2.50:3443" || g[1] != fp {
			t.Fatalf("enrolled with %v", g)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no enrolment")
	}
}

// The backup push pins the embedded agent's key when both address the same
// server, and keeps checking system CAs when it knows no pin.
func TestSnapshotPushClientPins(t *testing.T) {
	srv, fp := pairingServer(t)
	c, err := snapshotPushClient(PushConfig{ServerURL: srv.URL, ServerFP: fp})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("pinned push client could not reach its server: %v", err)
	}
	res.Body.Close()
	c, _ = snapshotPushClient(PushConfig{ServerURL: srv.URL, ServerFP: strings.Repeat("ab", 32)})
	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("a push client pinned to another key reached the server")
	}
	c, _ = snapshotPushClient(PushConfig{ServerURL: srv.URL})
	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("with no pin, a self-signed server was accepted without verification")
	}
}

// Saving the settings without a fingerprint keeps the one stored, as it does
// the token: a form that does not send it must not cut an https agent off.
func TestSavingWithoutAPinKeepsIt(t *testing.T) {
	resetDiscoveryState(t)
	p := tmpPaths(t)
	fp := strings.Repeat("ef", 32)
	if err := setNetPulseConfigAt(p, NetPulseConfig{Server: "https://192.0.2.50:3443", Slug: "test-router",
		Token: "tok", ServerFP: fp}); err != nil {
		t.Fatal(err)
	}
	if err := setNetPulseConfigAt(p, NetPulseConfig{Server: "https://192.0.2.50:3443", Slug: "test-router"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := ReadNetPulseConfig(p.env)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerFP != fp || cfg.Token != "tok" {
		t.Fatalf("after a save without them: %+v", cfg)
	}
}

// An agent pinned to an https server is not moved by a discovery reply, even
// once its server has been silent long enough for the stale fallback: that
// would hand the pin to whoever answered the probe.
func TestDiscoveryNeverMovesAPinnedAgent(t *testing.T) {
	resetDiscoveryState(t)
	p := tmpPaths(t)
	mustWrite(t, p.env, "NETPULSE_SERVER=https://192.0.2.50:3443\nNETPULSE_SLUG=s\nNETPULSE_TOKEN=t\n"+
		"NETPULSE_SERVER_FP="+strings.Repeat("ab", 32)+"\nNETPULSE_ENABLED=1\n")
	enrolled := make(chan struct{}, 1)
	withFakeDiscovery(t,
		func(int, time.Duration) *netPulseDiscoveryResult {
			return &netPulseDiscoveryResult{V: 1, Type: "netpulse-server", URL: "http://198.51.100.9:3000",
				URLHTTPS: "https://198.51.100.9:3443", ServerFP: strings.Repeat("cd", 32), Autoenroll: true, PairingToken: "ptok"}
		},
		func(netpulsePaths, string, string, string) error {
			enrolled <- struct{}{}
			return nil
		})
	npMu.Lock()
	oldStarted := npStartedAt
	npStartedAt = time.Now().Add(-time.Hour)
	npMu.Unlock()
	t.Cleanup(func() { npMu.Lock(); npStartedAt = oldStarted; npMu.Unlock() })
	storeNetPulseStatus(runtime.Status{Running: true, PushOk: false, LastPush: time.Now().Add(-netPulseStaleAfter - time.Minute)})

	netPulseTryDiscovery(p)
	select {
	case <-enrolled:
		t.Fatal("a pinned agent was re-enrolled from a UDP reply")
	case <-time.After(300 * time.Millisecond):
	}
}
