package protectedstate

import (
	"bytes"
	"testing"
)

func TestAuthenticatedPurposeBoundState(t *testing.T) {
	key := bytes.Repeat([]byte{42}, 32)
	secret := []byte("private-value")
	a, err := Seal(key, "ssh", secret)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(key, "ssh", secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) || bytes.Contains(a, secret) {
		t.Fatal("nonce reuse or plaintext disclosure")
	}
	plain, err := Open(key, "ssh", a)
	if err != nil || !bytes.Equal(plain, secret) {
		t.Fatal("round trip", err)
	}
	if _, err := Open(key, "tunnel", a); err == nil {
		t.Fatal("purpose swap accepted")
	}
	for i := range a {
		damaged := bytes.Clone(a)
		damaged[i] ^= 1
		if _, err := Open(key, "ssh", damaged); err == nil {
			t.Fatalf("corruption accepted at %d", i)
		}
	}
	if _, err := Open(bytes.Repeat([]byte{43}, 32), "ssh", a); err == nil {
		t.Fatal("wrong key accepted")
	}
}
