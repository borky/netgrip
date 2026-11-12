package modules

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

const (
	testAsset   = "netgrip-linux-arm7"
	testVersion = "v9.9.9"
)

// signManifestForTest builds the manifest deploy/sign-release.go writes for
// binary as asset at version, and signs it with a throwaway key.
func signManifestForTest(t *testing.T, binary []byte, asset, version string) (pub ed25519.PublicKey, priv ed25519.PrivateKey, manifest, sig []byte) {
	t.Helper()
	p, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(binary)
	manifest = []byte(fmt.Sprintf("%s\nasset %s\nversion %s\nsha256 %s\n",
		releaseManifestHeader, asset, version, hex.EncodeToString(sum[:])))
	return p, k, manifest, ed25519.Sign(k, manifest)
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := t.TempDir() + "/" + name
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerifyManifestAcceptsTheRightBinary(t *testing.T) {
	binary := []byte("fake netgrip binary")
	pub, _, manifest, sig := signManifestForTest(t, binary, testAsset, testVersion)
	path := writeTemp(t, "bin", binary)
	if err := verifyManifestWithKey(pub, path, manifest, sig, testAsset, testVersion); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
}

func TestVerifyManifestRejectsBadSignatureAndWrongKey(t *testing.T) {
	binary := []byte("fake netgrip binary")
	pub, _, manifest, sig := signManifestForTest(t, binary, testAsset, testVersion)
	otherPub, _, _, _ := signManifestForTest(t, binary, testAsset, testVersion)
	path := writeTemp(t, "bin", binary)
	if err := verifyManifestWithKey(pub, path, manifest, make([]byte, ed25519.SignatureSize), testAsset, testVersion); err == nil {
		t.Fatal("a zeroed signature was accepted")
	}
	if err := verifyManifestWithKey(otherPub, path, manifest, sig, testAsset, testVersion); err == nil {
		t.Fatal("a signature from another key was accepted")
	}
}

func TestVerifyManifestRejectsHashMismatch(t *testing.T) {
	pub, _, manifest, sig := signManifestForTest(t, []byte("fake netgrip binary"), testAsset, testVersion)
	path := writeTemp(t, "bin", []byte("a different binary"))
	if err := verifyManifestWithKey(pub, path, manifest, sig, testAsset, testVersion); err == nil {
		t.Fatal("a hash mismatch was accepted")
	}
}

// A validly signed binary for another architecture, or from another
// release, is refused: that is what a digest-only signature let through.
func TestVerifyManifestRejectsAnotherAssetOrRelease(t *testing.T) {
	binary := []byte("a mips binary, validly signed")
	pub, _, manifest, sig := signManifestForTest(t, binary, "netgrip-linux-mipsle", testVersion)
	path := writeTemp(t, "bin", binary)
	if err := verifyManifestWithKey(pub, path, manifest, sig, testAsset, testVersion); err == nil || !strings.Contains(err.Error(), "asset") {
		t.Fatalf("another architecture's binary: %v", err)
	}
	pub, _, manifest, sig = signManifestForTest(t, binary, testAsset, "v0.1.0")
	if err := verifyManifestWithKey(pub, path, manifest, sig, testAsset, testVersion); err == nil || !strings.Contains(err.Error(), "release") {
		t.Fatalf("an older release's binary: %v", err)
	}
	if err := verifyManifestWithKey(pub, path, manifest, sig, testAsset, ""); err == nil {
		t.Fatal("an empty offered version must not match anything")
	}
}

// The legacy .sha256 signature signs a bare hex line; served as a manifest
// it must not verify as one.
func TestLegacyDigestSignatureIsNotAManifest(t *testing.T) {
	binary := []byte("fake netgrip binary")
	_, priv, _, _ := signManifestForTest(t, binary, testAsset, testVersion)
	sum := sha256.Sum256(binary)
	digest := []byte(hex.EncodeToString(sum[:]) + "\n")
	path := writeTemp(t, "bin", binary)
	if err := verifyManifestWithKey(priv.Public().(ed25519.PublicKey), path, digest, ed25519.Sign(priv, digest), testAsset, testVersion); err == nil {
		t.Fatal("a signed legacy digest was accepted as a manifest")
	}
}

func TestParseReleaseManifestRejectsMalformed(t *testing.T) {
	for name, m := range map[string]string{
		"no header":     "asset a\nversion v\nsha256 x\n",
		"missing key":   releaseManifestHeader + "\nasset a\nversion v\n",
		"duplicate key": releaseManifestHeader + "\nasset a\nasset b\nversion v\nsha256 x\n",
		"empty value":   releaseManifestHeader + "\nasset \nversion v\nsha256 x\n",
	} {
		if _, err := parseReleaseManifest([]byte(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A release that only carries the legacy .sha256 pair is not offered: this
// verifier cannot install it.
func TestLegacyOnlyReleaseIsPending(t *testing.T) {
	resetUpdateState(t)
	srv := serveRelease(t, `{"tag_name":"v9.9.9","body":"","assets":[`+
		`{"name":"`+binaryAssetName()+`","browser_download_url":"http://example.com/b","size":1},`+
		`{"name":"`+binaryAssetName()+`.sha256","browser_download_url":"http://example.com/b.sha256","size":65},`+
		`{"name":"`+binaryAssetName()+`.sha256.sig","browser_download_url":"http://example.com/b.sha256.sig","size":64}]}`)
	orig := githubAPIURL
	githubAPIURL = srv.URL
	t.Cleanup(func() { githubAPIURL = orig })
	ck := CheckSelfUpdate("0.1.0")
	if ck == nil || ck.Available || !ck.AssetsPending {
		t.Fatalf("legacy-only release: %+v", ck)
	}
}
