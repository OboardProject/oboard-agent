// Package stealth implements the local at-rest protection used when a server
// runs with the security-process feature enabled: every state file is stored
// under a key-derived physical name with AES-256-GCM encrypted content, so a
// filesystem scan finds neither OBoard markers nor readable credentials.
//
// The protection is deliberately simple. It defends against provider-side
// name and content scans inside an LXC container, not against a hostile root
// on the host: anyone who can read the key file can decrypt everything, and
// the running process must always hold the key in memory.
package stealth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	// KeyLen is the stealth key length in bytes (AES-256).
	KeyLen = 32
	// EnvelopeMagic prefixes every encrypted envelope so a reader can tell
	// encrypted and legacy plaintext payloads apart without knowing the key.
	EnvelopeMagic = "OBSE1"
	// nonceLen is the AES-GCM nonce length used for every envelope.
	nonceLen = 12
	// nameLen is the number of hex characters in a derived physical name.
	nameLen = 16
	// nameDomain prefixes the logical name inside the HMAC input. Bumping it
	// rotates every derived filename at once without touching the key format.
	nameDomain = "oboard-stealth-name-v1:"
)

var (
	// ErrBadKey is returned for keys of the wrong length.
	ErrBadKey = errors.New("stealth key must be 32 bytes")
	// ErrNotEncrypted is returned when Decrypt is called on data without the
	// envelope magic.
	ErrNotEncrypted = errors.New("data is not a stealth envelope")
	// ErrCorruptEnvelope is returned for data that carries the magic but
	// cannot be decrypted (truncated, tampered, or wrong key).
	ErrCorruptEnvelope = errors.New("stealth envelope is corrupt or the key does not match")
)

// GenerateKey returns a fresh random stealth key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// LoadKey reads a stealth key file. The file must contain exactly KeyLen
// bytes; anything else is rejected so a truncated or tampered key fails
// loudly instead of decrypting garbage.
func LoadKey(path string) ([]byte, error) {
	// #nosec G304 -- path comes from the local -key flag or the agent's own config.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != KeyLen {
		return nil, fmt.Errorf("stealth key file %s must contain %d bytes, found %d", path, KeyLen, len(data))
	}
	return data, nil
}

// SaveKey writes a stealth key with 0600 permissions via a temporary file so
// the key never appears on disk with wider modes.
func SaveKey(path string, key []byte) error {
	if len(key) != KeyLen {
		return ErrBadKey
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(key); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, ErrBadKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt seals plaintext into an envelope: magic || nonce || ciphertext.
// Every call uses a fresh nonce; identical plaintext encrypts to different
// envelopes, so file contents never become a fingerprint across hosts.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(EnvelopeMagic)+nonceLen+len(plaintext)+aead.Overhead())
	out = append(out, EnvelopeMagic...)
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, nil), nil
}

// Decrypt opens an envelope produced by Encrypt.
func Decrypt(key, data []byte) ([]byte, error) {
	if !IsEncrypted(data) {
		return nil, ErrNotEncrypted
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(data) < len(EnvelopeMagic)+nonceLen+aead.Overhead() {
		return nil, ErrCorruptEnvelope
	}
	rest := data[len(EnvelopeMagic):]
	nonce := rest[:nonceLen]
	sealed := rest[nonceLen:]
	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, ErrCorruptEnvelope
	}
	return plaintext, nil
}

// IsEncrypted reports whether data carries the stealth envelope magic.
func IsEncrypted(data []byte) bool {
	return len(data) >= len(EnvelopeMagic) && string(data[:len(EnvelopeMagic)]) == EnvelopeMagic
}

// PhysicalName derives the on-disk name for a logical state entry:
// hex(HMAC-SHA256(key, domain+logical))[:16]. The mapping is deterministic,
// so the agent and the kernel independently derive the same layout from the
// same key, and no plaintext manifest of file names ever exists on disk.
func PhysicalName(key []byte, logical string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(nameDomain + logical))
	return hex.EncodeToString(mac.Sum(nil)[:nameLen/2])
}

// randomName is a seam for tests; production always uses RandomName.
var randomName = RandomName

// RandomName returns a random identifier of the form [a-z][a-z0-9]{9}. It is
// used for binary, service, directory, and socket names that must look
// unremarkable and carry no OBoard marker. The 36^9 space makes collisions
// with real system names unlikely, and callers verify uniqueness anyway.
func RandomName() (string, error) {
	var seed [8]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return "", err
	}
	v := binary.BigEndian.Uint64(seed[:])
	const digits = "abcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, 0, 10)
	// First character stays in [a-z] so the name is also a valid service unit
	// name and never starts with a digit.
	out = append(out, byte('a'+int(v%26)))
	v /= 26
	for i := 0; i < 9; i++ {
		out = append(out, digits[int(v%36)])
		v /= 36
	}
	return string(out), nil
}
