package server

// FORK: tests for CertReloader.SPKI, which the fork adds so the monitoring
// side can pin this panel's certificate.

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// The key reported must be the key a client actually sees in the handshake -
// the value NetPulse compares against - not merely the key of some file.
func TestSPKIIsWhatAClientSees(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, "panel")
	r, err := NewCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", r.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sum := sha256.Sum256(conn.ConnectionState().PeerCertificates[0].RawSubjectPublicKeyInfo)
	seen := hex.EncodeToString(sum[:])

	if got := r.SPKI(); got != seen {
		t.Fatalf("SPKI() = %s, but a client sees %s; the pin would never match", got, seen)
	}
}

// After the pair is regenerated, the next report carries the new key, so the
// pin follows a rotation instead of locking NetPulse out of the panel.
func TestSPKIFollowsARotation(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, "first")
	r, err := NewCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	before := r.SPKI()

	writePairAt(t, certPath, keyPath, pairOpts{cn: "second"})
	future := time.Now().Add(2 * time.Second)
	for _, p := range []string{certPath, keyPath} {
		if err := os.Chtimes(p, future, future); err != nil {
			t.Fatal(err)
		}
	}
	r.forgetStatCache()

	if after := r.SPKI(); after == before || after == "" {
		t.Fatalf("after rotation SPKI() = %q (was %q); the pin would go stale", after, before)
	}
}
