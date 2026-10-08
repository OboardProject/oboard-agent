// Package protectedstate binds an existing AEAD envelope to a state purpose.
package protectedstate

import (
	"bytes"
	"errors"
	"github.com/OboardProject/oboard-agent/internal/stealth"
)

const Magic = "OBRP1"

func IsProtected(raw []byte) bool { return bytes.HasPrefix(raw, []byte(Magic)) }
func Seal(key []byte, purpose string, raw []byte) ([]byte, error) {
	bound := append([]byte("oboard-runtime-state-v1:"+purpose+"\x00"), raw...)
	sealed, err := stealth.Encrypt(key, bound)
	if err != nil {
		return nil, err
	}
	return append([]byte(Magic), sealed...), nil
}
func Open(key []byte, purpose string, raw []byte) ([]byte, error) {
	if !IsProtected(raw) {
		return nil, errors.New("invalid protected state")
	}
	bound, err := stealth.Decrypt(key, raw[len(Magic):])
	if err != nil {
		return nil, errors.New("protected state authentication failed")
	}
	prefix := []byte("oboard-runtime-state-v1:" + purpose + "\x00")
	if !bytes.HasPrefix(bound, prefix) {
		return nil, errors.New("protected state purpose mismatch")
	}
	return bound[len(prefix):], nil
}
