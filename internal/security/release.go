package security

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

type ReleaseManifest struct {
	Version string                `json:"version"`
	Build   string                `json:"build"`
	Commit  string                `json:"commit"`
	Date    string                `json:"date"`
	Repo    string                `json:"repo"`
	Files   []ReleaseManifestFile `json:"files"`
}

type ReleaseManifestFile struct {
	Name      string `json:"name"`
	Component string `json:"component"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
}

func CanonicalReleaseManifest(m ReleaseManifest) ([]byte, error) {
	return json.Marshal(m)
}

func SignReleaseManifest(m ReleaseManifest, privateKeyB64 string) (string, error) {
	priv, err := ParseEd25519PrivateKey(privateKeyB64)
	if err != nil {
		return "", err
	}
	payload, err := CanonicalReleaseManifest(m)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, payload)), nil
}

func VerifyReleaseManifest(m ReleaseManifest, signatureB64 string, publicKeyB64 string) error {
	if publicKeyB64 == "" {
		return errors.New("release public key is not configured")
	}
	pub, err := base64.RawStdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid release public key")
	}
	sig, err := base64.RawStdEncoding.DecodeString(signatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid release manifest signature")
	}
	payload, err := CanonicalReleaseManifest(m)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return errors.New("release manifest signature verification failed")
	}
	return nil
}

func ParseEd25519PrivateKey(value string) (ed25519.PrivateKey, error) {
	b, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		if padded, err2 := base64.StdEncoding.DecodeString(value); err2 == nil {
			b = padded
		} else {
			return nil, err
		}
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("ed25519 private key must be %d-byte seed or %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

func PublicKeyFromPrivateKey(value string) (string, error) {
	priv, err := ParseEd25519PrivateKey(value)
	if err != nil {
		return "", err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("invalid ed25519 private key")
	}
	return base64.RawStdEncoding.EncodeToString(pub), nil
}

func SHA256File(path string) (string, int64, error) {
	// #nosec G304 -- callers resolve paths from a verified release directory and fixed manifest names.
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}
