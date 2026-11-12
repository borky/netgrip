// sign-release signs a release binary for self-update verification (#561).
//
// Usage:
//
//	NETGRIP_RELEASE_KEY=<hex-ed25519-private-key> go run deploy/sign-release.go <binary> <release-tag>
//
// Produces next to <binary>:
//
//	<binary>.sha256        the sha256 hex digest of the binary
//	<binary>.sha256.sig    an ed25519 signature over the .sha256 file contents
//	<binary>.manifest      the asset name, the release tag and the digest
//	<binary>.manifest.sig  an ed25519 signature over the .manifest contents
//
// Devices verify the manifest: it binds the digest to the asset (and so the
// architecture) and to the release, which a signature over the digest alone
// does not. The .sha256 pair stays for devices running a verifier that
// predates the manifest, so they can still update to a release signed here.
//
// The public key is embedded in the netgrip binary; the private key lives in
// the NETGRIP_RELEASE_KEY repo secret and never ships in the repo.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 3 || os.Args[2] == "" {
		fmt.Fprintln(os.Stderr, "usage: sign-release <binary> <release-tag>")
		os.Exit(1)
	}
	path, version := os.Args[1], os.Args[2]

	privHex := os.Getenv("NETGRIP_RELEASE_KEY")
	if privHex == "" {
		fmt.Fprintln(os.Stderr, "NETGRIP_RELEASE_KEY not set")
		os.Exit(1)
	}
	raw, err := hex.DecodeString(privHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, "NETGRIP_RELEASE_KEY is not valid hex")
		os.Exit(1)
	}
	// Accept either the 32-byte seed or the full 64-byte private key
	// (seed || public); only the seed is needed to reconstruct the key.
	var seed []byte
	switch len(raw) {
	case ed25519.SeedSize:
		seed = raw
	case ed25519.PrivateKeySize:
		seed = raw[:ed25519.SeedSize]
	default:
		fmt.Fprintln(os.Stderr, "NETGRIP_RELEASE_KEY must be a 32-byte seed or 64-byte private key (hex)")
		os.Exit(1)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read binary: %v\n", err)
		os.Exit(1)
	}

	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:]) + "\n"
	if err := os.WriteFile(path+".sha256", []byte(digest), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write .sha256: %v\n", err)
		os.Exit(1)
	}

	sig := ed25519.Sign(priv, []byte(digest))
	if err := os.WriteFile(path+".sha256.sig", sig, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write .sha256.sig: %v\n", err)
		os.Exit(1)
	}

	manifest := fmt.Sprintf("netgrip-release-manifest v1\nasset %s\nversion %s\nsha256 %s\n",
		filepath.Base(path), version, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(path+".manifest", []byte(manifest), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write .manifest: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(path+".manifest.sig", ed25519.Sign(priv, []byte(manifest)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write .manifest.sig: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("signed %s (%d bytes) for %s\n", path, len(data), version)
}
