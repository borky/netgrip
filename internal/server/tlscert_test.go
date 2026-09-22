package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair writes a self-signed pair with the given CN, the shape px5g
// leaves on an OpenWrt box (EC key, no IP SAN).
func writePair(t *testing.T, dir, cn string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	cb := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, cb, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func leafCN(t *testing.T, r *CertReloader) string {
	t.Helper()
	c, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

// Asking for TLS with a pair that is not there must fail at startup. The
// caller turns this into a refusal to run: serving the router's password in
// clear after TLS was requested is the one outcome nobody would notice.
func TestNewCertReloaderMissingPair(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewCertReloader(filepath.Join(dir, "nope.crt"), filepath.Join(dir, "nope.key")); err == nil {
		t.Fatal("a missing pair must be an error, not a silent fallback")
	}
}

// px5g regenerates uhttpd's pair when it expires. A panel that cached the old
// one at boot would serve a dead certificate for months, so a changed file
// must be picked up without a restart.
func TestCertReloaderPicksUpARegeneratedPair(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, "first")
	r, err := NewCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := leafCN(t, r); got != "first" {
		t.Fatalf("initial CN = %q", got)
	}

	// Rewrite in place with a later mtime, as a regeneration would.
	writePair(t, dir, "second")
	future := time.Now().Add(2 * time.Second)
	for _, p := range []string{certPath, keyPath} {
		if err := os.Chtimes(p, future, future); err != nil {
			t.Fatal(err)
		}
	}
	if got := leafCN(t, r); got != "second" {
		t.Fatalf("after regeneration CN = %q, want the new pair", got)
	}
}

// A pair caught half-written must not take the listener down: keep serving
// the last good certificate and try again later.
func TestCertReloaderKeepsLastGoodPairOnGarbage(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, "good")
	r, err := NewCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\ntruncated"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatal(err)
	}
	if got := leafCN(t, r); got != "good" {
		t.Fatalf("CN = %q, want the last good pair while the new one is unreadable", got)
	}
}

// A pair that vanishes (a regeneration that removes before writing) is the
// same case: serve what we have rather than failing the handshake.
func TestCertReloaderSurvivesAVanishedPair(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, "good")
	r, err := NewCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(certPath)
	if got := leafCN(t, r); got != "good" {
		t.Fatalf("CN = %q, want the cached pair when the file is gone", got)
	}
}

// The defaults are uhttpd's pair: that is what makes the panel inherit the
// trust decision the operator already made for LuCI.
func TestDefaultPathsAreUhttpds(t *testing.T) {
	if DefaultCertPath != "/etc/uhttpd.crt" || DefaultKeyPath != "/etc/uhttpd.key" {
		t.Fatalf("defaults = %q, %q", DefaultCertPath, DefaultKeyPath)
	}
}

// A configured pair that is missing must not take the panel down: the point
// of HTTPS here is that the panel keeps working over TLS, and a deleted or
// half-written certificate would otherwise leave the router with no panel
// until somebody logs in over SSH. Falling back is still TLS; falling back
// to plaintext is what must never happen.
func TestOpenCertificateFallsBackToAUsablePair(t *testing.T) {
	dir := t.TempDir()
	goodCert, goodKey := writePair(t, dir, "fallback")

	// Point the "configured" pair at nothing, and make the fallbacks the
	// good pair by overriding the package paths for the test.
	origCert, origKey := PanelCertPath, PanelKeyPath
	t.Cleanup(func() { PanelCertPath, PanelKeyPath = origCert, origKey })
	PanelCertPath, PanelKeyPath = goodCert, goodKey

	r, usedCert, _, err := OpenCertificate(filepath.Join(dir, "gone.crt"), filepath.Join(dir, "gone.key"))
	if err != nil {
		t.Fatalf("should have fallen back, got %v", err)
	}
	if usedCert != goodCert {
		t.Errorf("used %s, want the fallback %s", usedCert, goodCert)
	}
	if got := leafCN(t, r); got != "fallback" {
		t.Errorf("serving CN %q", got)
	}
}

// With nothing usable anywhere it must fail, so the caller refuses to start
// rather than serving the router's password in clear.
func TestOpenCertificateFailsWhenNothingIsUsable(t *testing.T) {
	dir := t.TempDir()
	origCert, origKey := PanelCertPath, PanelKeyPath
	origDef, origDefKey := DefaultCertPath, DefaultKeyPath
	t.Cleanup(func() {
		PanelCertPath, PanelKeyPath = origCert, origKey
		DefaultCertPath, DefaultKeyPath = origDef, origDefKey
	})
	PanelCertPath = filepath.Join(dir, "a.crt")
	PanelKeyPath = filepath.Join(dir, "a.key")
	DefaultCertPath = filepath.Join(dir, "b.crt")
	DefaultKeyPath = filepath.Join(dir, "b.key")

	if _, _, _, err := OpenCertificate("", ""); err == nil {
		t.Fatal("no usable pair must be an error")
	}
}
