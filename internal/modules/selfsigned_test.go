package modules

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

func parseGenerated(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		t.Fatal("certificate is not PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

// The bug this replaced: the generated certificate carried a subjectAltName
// extension that was present and EMPTY. OpenSSL and curl accept that, so
// every command-line check passed, while Chromium refuses to load the
// certificate at all - "the website sent scrambled credentials", with no way
// to continue. A panel nobody can open in a browser is not served.
func TestGeneratedCertHasANonEmptySAN(t *testing.T) {
	certPEM, _, err := buildSelfSigned("router", []net.IP{net.ParseIP("192.0.2.1")}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c := parseGenerated(t, certPEM)
	if len(c.DNSNames) == 0 && len(c.IPAddresses) == 0 {
		t.Fatal("subjectAltName is empty; Chromium rejects the certificate outright")
	}
}

// Browsers match the SAN, not the CN. A router is reached by address, so the
// addresses have to be in there or every visit warns about a name mismatch.
func TestGeneratedCertNamesTheAddressesItIsReachedBy(t *testing.T) {
	ips := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("198.51.100.7")}
	certPEM, _, err := buildSelfSigned("router", ips, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c := parseGenerated(t, certPEM)
	for _, want := range ips {
		found := false
		for _, got := range c.IPAddresses {
			if got.Equal(want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s missing from the SAN", want)
		}
	}
	if len(c.DNSNames) != 1 || c.DNSNames[0] != "router" {
		t.Errorf("DNS names = %v, want the hostname", c.DNSNames)
	}
}

// A router without a hostname still needs a certificate with a name in it.
func TestGeneratedCertFallsBackToAName(t *testing.T) {
	certPEM, _, err := buildSelfSigned("", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c := parseGenerated(t, certPEM)
	if len(c.DNSNames) == 0 || c.DNSNames[0] == "" {
		t.Fatalf("DNS names = %v, want a fallback name", c.DNSNames)
	}
	if c.Subject.CommonName == "" {
		t.Error("CN is empty")
	}
}

// The pair has to be usable together, and valid now: a router without an RTC
// boots in 1970, so notBefore is backdated.
func TestGeneratedPairIsUsableAndValidNow(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, err := buildSelfSigned("router", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	c := parseGenerated(t, certPEM)
	if c.NotBefore.After(now) {
		t.Errorf("notBefore %v is in the future", c.NotBefore)
	}
	if !c.NotAfter.After(now.Add(365 * 24 * time.Hour)) {
		t.Errorf("notAfter %v is too soon", c.NotAfter)
	}
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		t.Fatal("key is not PEM")
	}
	if _, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err != nil {
		t.Fatalf("key does not parse: %v", err)
	}
	if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("certificate cannot be used for a TLS handshake")
	}
}
