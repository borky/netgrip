// Package certs loads and vets the certificate/key pairs the panel serves
// HTTPS with.
//
// It sits apart from the server and the modules because both need the same
// answers and they must not differ: the Access card decides whether a pair is
// worth offering, the listener decides whether it can serve it, and a pair
// that one accepts and the other refuses is how a save takes the panel down.
package certs

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// LoadPair reads a pair in either encoding, and refuses one whose two halves
// do not belong together.
//
// OpenWrt stores uhttpd's in DER: /etc/uhttpd.crt starts with 30 82 (an ASN.1
// SEQUENCE), not "-----BEGIN", because ustream-ssl reads it that way. Go's
// standard library only understands PEM, so loading the router's pair - which
// is the whole point of the option - means recognising both. Verified on a
// router, not deduced: with PEM only the panel refused to start.
//
// The two files are decoded independently, because nothing says they use the
// same encoding, and the match between them is then checked explicitly.
// tls.X509KeyPair does that check for PEM; hand-building the certificate for
// DER skipped it, and a mismatched pair loaded, started and logged "listening
// on https://" while failing every single handshake.
func LoadPair(certPath, keyPath string) (tls.Certificate, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	chain, leaf, err := parseCertChain(certBytes)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := parseKey(keyBytes)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := keyMatchesCert(leaf, key); err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}, nil
}

// Usable reports why a pair should not be served, or nil if it should.
//
// Stricter than LoadPair, and deliberately so: this is what decides whether an
// existing pair is kept or regenerated. A pair that loads can still be one no
// browser will open - an empty subjectAltName is exactly that, and it is the
// shape px5g produced. Checking only that the files exist meant such a pair
// survived forever, because the code that would have replaced it saw two files
// and stopped looking.
func Usable(certPath, keyPath string, now time.Time) error {
	pair, err := LoadPair(certPath, keyPath)
	if err != nil {
		return err
	}
	leaf := pair.Leaf
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		return errors.New("the certificate has an empty subjectAltName; Chromium refuses it outright")
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("the certificate expired on %s", leaf.NotAfter.Format(time.RFC3339))
	}
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("the certificate is not valid until %s", leaf.NotBefore.Format(time.RFC3339))
	}
	return nil
}

// parseCertChain returns every certificate in the file, leaf first. The whole
// chain is kept, not just the leaf: a pair with an intermediate needs it sent,
// or clients that do not already hold that intermediate cannot build a path.
func parseCertChain(raw []byte) ([][]byte, *x509.Certificate, error) {
	var chain [][]byte
	if bytes.Contains(raw, []byte("-----BEGIN")) {
		for rest := raw; ; {
			var blk *pem.Block
			if blk, rest = pem.Decode(rest); blk == nil {
				break
			}
			if blk.Type == "CERTIFICATE" {
				chain = append(chain, blk.Bytes)
			}
		}
		if len(chain) == 0 {
			return nil, nil, errors.New("the certificate file is PEM but holds no CERTIFICATE block")
		}
	} else {
		chain = [][]byte{raw}
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, nil, fmt.Errorf("certificate is neither PEM nor DER: %w", err)
	}
	return chain, leaf, nil
}

// parseKey accepts the key in PEM or DER. The certificate's encoding says
// nothing about the key's: a pair assembled by hand can mix them.
func parseKey(raw []byte) (crypto.PrivateKey, error) {
	der := raw
	if blk, _ := pem.Decode(raw); blk != nil {
		if len(blk.Headers) > 0 && blk.Headers["Proc-Type"] != "" {
			return nil, errors.New("the private key is encrypted; the panel has no passphrase to open it")
		}
		der = blk.Bytes
	}
	return parseDERKey(der)
}

// parseDERKey accepts the three shapes a key can arrive in; px5g writes EC
// (SEC1) with OpenWrt's defaults, but a pair of one's own may be PKCS#8 or
// PKCS#1.
func parseDERKey(der []byte) (crypto.PrivateKey, error) {
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("the private key parses as none of EC (SEC1), PKCS#8 or PKCS#1, in PEM or DER")
}

// keyMatchesCert is what separates "the two files loaded" from "the two files
// are a pair". Without it the failure surfaces one handshake at a time, with
// the panel apparently up and the startup log saying so.
func keyMatchesCert(leaf *x509.Certificate, key crypto.PrivateKey) error {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("the private key cannot sign, so it cannot serve TLS")
	}
	pub, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return fmt.Errorf("unsupported public key type %T in the certificate", leaf.PublicKey)
	}
	if !pub.Equal(signer.Public()) {
		return errors.New("the private key does not match the certificate; they are not a pair")
	}
	return nil
}
