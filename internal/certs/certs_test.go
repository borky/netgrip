package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type pairSpec struct {
	cn         string
	dnsNames   []string
	ips        []net.IP
	expiredFor time.Duration // how long ago it expired, zero for a valid one
}

func writePair(t *testing.T, dir string, s pairSpec) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(24 * time.Hour)
	if s.expiredFor != 0 {
		notAfter = time.Now().Add(-s.expiredFor)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: s.cn},
		DNSNames:     s.dnsNames,
		IPAddresses:  s.ips,
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, s.cn+".crt")
	keyFile = filepath.Join(dir, s.cn+".key")
	write := func(path string, blockType string, b []byte, mode os.FileMode) {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: b}), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(certFile, "CERTIFICATE", der, 0o644)
	write(keyFile, "EC PRIVATE KEY", keyDER, 0o600)
	return certFile, keyFile
}

// The bug this guards: px5g wrote a certificate whose subjectAltName
// extension was present and EMPTY. OpenSSL and curl accept it, so every
// command-line check passed, while Chromium refuses to load it at all - "the
// website sent scrambled credentials", with no way to continue. It loads
// fine, which is why only a separate check catches it.
func TestUsableRejectsAnEmptySAN(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writePair(t, dir, pairSpec{cn: "nosan"})

	if _, err := LoadPair(certFile, keyFile); err != nil {
		t.Fatalf("it has to load, or the test is not about the SAN: %v", err)
	}
	if err := Usable(certFile, keyFile, time.Now()); err == nil {
		t.Fatal("an empty subjectAltName must not count as usable; no Chromium-based browser opens it")
	}
}

func TestUsableAcceptsAPairWithNames(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writePair(t, dir, pairSpec{
		cn: "router", dnsNames: []string{"router"}, ips: []net.IP{net.ParseIP("192.0.2.1")},
	})
	if err := Usable(certFile, keyFile, time.Now()); err != nil {
		t.Fatalf("a named, in-date pair must be usable: %v", err)
	}
}

// An expired pair is worth replacing rather than serving: px5g rotates
// uhttpd's, and nothing rotates one the panel generated years ago.
func TestUsableRejectsAnExpiredPair(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writePair(t, dir, pairSpec{
		cn: "old", dnsNames: []string{"old"}, expiredFor: time.Hour,
	})
	if err := Usable(certFile, keyFile, time.Now()); err == nil {
		t.Fatal("an expired certificate must not count as usable")
	}
}

// The whole chain is kept, not just the leaf: dropping intermediates leaves
// clients unable to build a path to a certificate that is otherwise fine.
func TestLoadPairKeepsTheWholeChain(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writePair(t, dir, pairSpec{cn: "leaf", dnsNames: []string{"leaf"}})
	leafPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	// A second certificate appended, standing in for an intermediate.
	otherCert, _ := writePair(t, dir, pairSpec{cn: "issuer", dnsNames: []string{"issuer"}})
	issuerPEM, err := os.ReadFile(otherCert)
	if err != nil {
		t.Fatal(err)
	}
	chainFile := filepath.Join(dir, "chain.crt")
	if err := os.WriteFile(chainFile, append(leafPEM, issuerPEM...), 0o644); err != nil {
		t.Fatal(err)
	}

	pair, err := LoadPair(chainFile, keyFile)
	if err != nil {
		t.Fatalf("a chain must load: %v", err)
	}
	if len(pair.Certificate) != 2 {
		t.Errorf("chain has %d certificates, want both", len(pair.Certificate))
	}
	if pair.Leaf.Subject.CommonName != "leaf" {
		t.Errorf("leaf is %q, want the first certificate in the file", pair.Leaf.Subject.CommonName)
	}
}
