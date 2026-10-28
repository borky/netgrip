package modules

// Sealing of channel credentials before they are written to /etc/netgrip.
//
// AES-256-GCM with a fresh random nonce per value and the field name as
// associated data, so a sealed value copied into another field does not
// open. The key is a 0600 file next to the configs and, like them, is kept
// across sysupgrades. That means a backup archive carries both: sealing
// keeps the credentials out of a config file read or shared on its own,
// not out of a full backup. Losing the key makes the sealed values
// unreadable; the channel then reports itself as not configured and the
// credentials are entered again.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// secretKeyPath is a var (not const) so tests can point it at a temp dir.
var secretKeyPath = "/etc/netgrip/secrets.key"

const (
	secretKeyLen = 32
	sealedPrefix = "enc:v1:"
)

var (
	errNotSealed  = errors.New("value is not sealed")
	errBadKeyFile = errors.New("not a valid key")
)

func readSecretKey() ([]byte, error) {
	key, err := os.ReadFile(secretKeyPath)
	if err != nil {
		return nil, err
	}
	if len(key) != secretKeyLen {
		return nil, fmt.Errorf("%s holds %d bytes, want %d: %w", secretKeyPath, len(key), secretKeyLen, errBadKeyFile)
	}
	return key, nil
}

// secretKeyMu serializes key creation and replacement within the process:
// two saves at once must not both replace a bad key, the second deleting
// the key the first just sealed with.
var secretKeyMu sync.Mutex

// secretKey returns the key, creating it if create is set and it is missing.
func secretKey(create bool) ([]byte, error) {
	key, err := readSecretKey()
	if err == nil || !create {
		return key, err
	}
	secretKeyMu.Lock()
	defer secretKeyMu.Unlock()
	// Re-read under the lock: another save may have just fixed it.
	if key, err = readSecretKey(); err == nil {
		return key, nil
	}
	// A key of the wrong size cannot have sealed anything that opens, so
	// on a save it is replaced rather than blocking every save for good.
	if errors.Is(err, errBadKeyFile) {
		if rerr := os.Remove(secretKeyPath); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return nil, fmt.Errorf("replace bad key: %w", rerr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return key, err
	}
	if err := os.MkdirAll(filepath.Dir(secretKeyPath), 0755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	key = make([]byte, secretKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	// Write a temp file and hard-link it into place: the key appears whole
	// or not at all, and a key some other writer installed first wins.
	tmp, err := os.CreateTemp(filepath.Dir(secretKeyPath), ".tmp-secrets-*")
	if err != nil {
		return nil, fmt.Errorf("create key: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	_, werr := tmp.Write(key)
	if werr == nil {
		werr = tmp.Chmod(0o600)
	}
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return nil, fmt.Errorf("write key: %w", werr)
	}
	if err := os.Link(name, secretKeyPath); err != nil {
		if errors.Is(err, os.ErrExist) {
			// One re-read only: a dangling symlink reads as missing yet
			// blocks the link, and must not loop.
			if key, rerr := readSecretKey(); rerr == nil {
				return key, nil
			}
			return nil, fmt.Errorf("%s exists but is not a usable key", secretKeyPath)
		}
		return nil, fmt.Errorf("install key: %w", err)
	}
	return key, nil
}

func secretAEAD(create bool) (cipher.AEAD, error) {
	key, err := secretKey(create)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealSecret encrypts plaintext for field name, creating the key on first
// use. An empty plaintext stays empty.
func sealSecret(name, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	aead, err := secretAEAD(true)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	out := aead.Seal(nonce, nonce, []byte(plaintext), []byte(name))
	return sealedPrefix + base64.RawStdEncoding.EncodeToString(out), nil
}

// unsealSecret decrypts a value sealSecret produced for the same field. It
// never creates a key: a missing key is an error like a wrong one.
func unsealSecret(name, stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if !strings.HasPrefix(stored, sealedPrefix) {
		return "", errNotSealed
	}
	raw, err := base64.RawStdEncoding.DecodeString(stored[len(sealedPrefix):])
	if err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	aead, err := secretAEAD(false)
	if err != nil {
		return "", err
	}
	ns := aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("sealed value too short")
	}
	pt, err := aead.Open(nil, raw[:ns], raw[ns:], []byte(name))
	if err != nil {
		return "", errors.New("cannot decrypt (wrong key or tampered value)")
	}
	return string(pt), nil
}
