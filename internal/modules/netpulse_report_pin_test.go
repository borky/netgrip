package modules

// FORK: the self-update reports reach NetPulse over https the way NetGrip's
// other requests do - pinned to the server's key, and to nothing else.

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
	"sync/atomic"
	"testing"
	"time"
)

// reportServer is an https NetPulse stand-in on a key of its own, which
// counts the reports it receives.
func reportServer(t *testing.T) (*httptest.Server, string, *atomic.Int32) {
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
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, hex.EncodeToString(sum[:]), &hits
}

func TestUpgradeReportReachesAPinnedServer(t *testing.T) {
	srv, fp, hits := reportServer(t)
	cfg := NetPulseConfig{Server: srv.URL, Slug: "test-router", Token: "tok", ServerFP: fp}
	npReportUpgradeResult(cfg, true, "")
	if hits.Load() != 1 {
		t.Fatalf("a server on its own key, pinned, got %d reports, want 1", hits.Load())
	}
}

func TestUpgradeReportRefusesAnotherKey(t *testing.T) {
	srv, _, hits := reportServer(t)
	cfg := NetPulseConfig{Server: srv.URL, Slug: "test-router", Token: "tok", ServerFP: strings.Repeat("ab", 32)}
	npReportUpgradeResult(cfg, true, "")
	if hits.Load() != 0 {
		t.Fatal("the report, agent token included, went to a server whose key is not the pinned one")
	}
}
