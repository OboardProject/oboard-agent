// Package stealth is the kernel-side copy of the agent's at-rest protection
// primitives: the OBSE1 AES-256-GCM envelope and the HMAC-derived physical
// file names. The kernel is a separate Go module and must stay buildable
// without the agent module, so the ~100 lines are duplicated on purpose —
// the same pattern as the authorization store.
//
// The derivation is a wire contract with the agent: both sides must produce
// identical envelopes and identical physical names for the same key. The
// pinned test vectors in stealth_test.go match the agent package's vectors;
// changing either side requires changing both in the same release.
package stealth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	KeyLen       = 32
	EnvelopeMagic = "OBSE1"
	nonceLen     = 12
	nameLen      = 16
	nameDomain   = "oboard-stealth-name-v1:"
)

var (
	ErrBadKey           = errors.New("stealth key must be 32 bytes")
	ErrNotEncrypted     = errors.New("data is not a stealth envelope")
	ErrCorruptEnvelope  = errors.New("stealth envelope is corrupt or the key does not match")
)

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

// PhysicalName derives the on-disk name for a logical state entry. It must
// match the agent implementation exactly.
func PhysicalName(key []byte, logical string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(nameDomain + logical))
	return hex.EncodeToString(mac.Sum(nil)[:nameLen/2])
}

// LoadKey reads a stealth key file of exactly KeyLen bytes.
func LoadKey(path string) ([]byte, error) {
	// #nosec G304 -- path comes from the local -key flag passed by the Agent service.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != KeyLen {
		return nil, fmt.Errorf("stealth key file must contain %d bytes, found %d", KeyLen, len(data))
	}
	return data, nil
}
