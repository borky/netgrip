package modules

// FORK: reaching a fleet peer's panel on HTTPS.
//
// Every call to a peer - adoption's login, which sends the peer's root
// password, the update check, the remote update - was built as http://, so a
// peer serving its panel with -https could be neither adopted nor managed,
// and the panel's "Open" link pointed at http:// too.
//
// A peer's certificate is self-signed and cannot be checked by name, so the
// peer is pinned to its key instead: the first contact records the key the
// peer presents (trust on first use, as when a browser's warning is accepted
// once), and every later request must meet the same key. A peer that answers
// plain HTTP is reached as before.

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// fleetTLSProbeTimeout bounds the handshake that tells TLS from plain HTTP.
const fleetTLSProbeTimeout = 3 * time.Second

// probePanelTLS reports whether the panel at address ("host:port") speaks
// TLS, and the SPKI fingerprint of the certificate it presents.
func probePanelTLS(address string) (spki string, ok bool) {
	d := &net.Dialer{Timeout: fleetTLSProbeTimeout}
	conn, err := tls.DialWithDialer(d, "tcp", address, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // only reads the key, which is then pinned
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return "", false
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", false
	}
	return spkiHex(certs[0].RawSubjectPublicKeyInfo), true
}

func spkiHex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// fleetPeerClient returns the base URL and client for requests to node, and
// whether node's TLS fields were filled in by this call (the caller saves
// them). A node pinned to a key only ever gets HTTPS to that key.
func fleetPeerClient(node *FleetNode, timeout time.Duration) (base string, client *http.Client, learned bool, err error) {
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if node.SPKI == "" {
		spki, isTLS := probePanelTLS(node.Address)
		if !isTLS {
			// A node that served HTTPS before must not quietly drop to plain
			// HTTP: its password would then travel in clear.
			if node.TLS {
				return "", nil, false, errors.New("the node served HTTPS before and now does not answer it")
			}
			return "http://" + node.Address, &http.Client{Timeout: timeout, CheckRedirect: noRedirect}, false, nil
		}
		node.TLS, node.SPKI, learned = true, spki, true
	}
	want := node.SPKI
	client = &http.Client{
		Timeout:       timeout,
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // verified by the pin below
				MinVersion:         tls.VersionTLS12,
				// VerifyConnection also runs on resumed sessions.
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return errors.New("the node presented no certificate")
					}
					got := spkiHex(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
					if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
						return fmt.Errorf("the node's certificate key changed (now %s…); remove and adopt it again if that is expected", got[:12])
					}
					return nil
				},
			},
		},
	}
	return "https://" + node.Address, client, learned, nil
}

var fleetPinMu sync.Mutex

// saveFleetNodePin records what fleetPeerClient learned about node.
func saveFleetNodePin(node FleetNode) {
	fleetPinMu.Lock()
	defer fleetPinMu.Unlock()
	cfg, err := LoadFleetConfig()
	if err != nil {
		return
	}
	for i := range cfg.Nodes {
		if cfg.Nodes[i].ID == node.ID && cfg.Nodes[i].SPKI == "" {
			cfg.Nodes[i].TLS, cfg.Nodes[i].SPKI = node.TLS, node.SPKI
			_ = SaveFleetConfig(cfg)
			return
		}
	}
}
