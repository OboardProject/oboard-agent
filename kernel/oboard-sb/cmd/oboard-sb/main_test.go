package main

import "testing"

func TestValidateLocalAPIListen(t *testing.T) {
	for _, address := range []string{"unix:/run/oboard-sb.sock", "127.0.0.1:9090", "[::1]:9090", "localhost:9090"} {
		if err := validateLocalAPIListen(address); err != nil {
			t.Fatalf("%s should be accepted: %v", address, err)
		}
	}
	for _, address := range []string{"unix:", ":9090", "0.0.0.0:9090", "[::]:9090", "192.0.2.1:9090", "invalid"} {
		if err := validateLocalAPIListen(address); err == nil {
			t.Fatalf("%s should be rejected", address)
		}
	}
}
