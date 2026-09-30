package modules

// FORK: tests for fleet_tls.go, against real local servers.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// tlsPeer is a panel on HTTPS with a key of its own (httptest's servers all
// share one, which would make a "different key" test pass for nothing).
func tlsPeer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	return tlsPeerServing(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
}

// tlsPeerServing is tlsPeer answering with h.
func tlsPeerServing(t *testing.T, h http.Handler) (*httptest.Server, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "peer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, spkiHex(c.RawSubjectPublicKeyInfo)
}

func hostPort(u string) string {
	return strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
}

func TestFleetPeerOnHTTPSIsPinnedOnFirstContact(t *testing.T) {
	srv, spki := tlsPeer(t)
	node := &FleetNode{ID: "peer", Address: hostPort(srv.URL)}
	base, client, learned, err := fleetPeerClient(node, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !learned || !node.TLS || node.SPKI != spki || !strings.HasPrefix(base, "https://") {
		t.Fatalf("learned=%v tls=%v spki=%q base=%q", learned, node.TLS, node.SPKI, base)
	}
	res, err := client.Get(base + "/")
	if err != nil {
		t.Fatalf("pinned request: %v", err)
	}
	res.Body.Close()

	// Next time it is reached through the pin, without learning again.
	if _, _, learned, err := fleetPeerClient(node, 3*time.Second); err != nil || learned {
		t.Fatalf("second contact: learned=%v err=%v", learned, err)
	}
}

func TestFleetPeerWithAnotherKeyIsRefused(t *testing.T) {
	srv, _ := tlsPeer(t)
	node := &FleetNode{ID: "peer", Address: hostPort(srv.URL), TLS: true, SPKI: strings.Repeat("ab", 32)}
	base, client, _, err := fleetPeerClient(node, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := client.Get(base + "/"); err == nil {
		res.Body.Close()
		t.Fatal("a peer presenting another key was accepted")
	}
}

func TestFleetPeerOnPlainHTTPStaysPlain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	node := &FleetNode{ID: "peer", Address: hostPort(srv.URL)}
	base, client, learned, err := fleetPeerClient(node, 3*time.Second)
	if err != nil || learned || node.TLS || !strings.HasPrefix(base, "http://") {
		t.Fatalf("base=%q learned=%v tls=%v err=%v", base, learned, node.TLS, err)
	}
	res, err := client.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	// A node known to serve HTTPS must not drop to plain HTTP: its password
	// would travel in clear.
	node.TLS = true
	if _, _, _, err := fleetPeerClient(node, 3*time.Second); err == nil {
		t.Fatal("a node that served HTTPS was reached over plain HTTP")
	}
}
