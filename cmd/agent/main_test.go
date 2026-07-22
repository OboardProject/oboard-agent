package main

import (
	"os"
	"testing"
)

func TestConsumeEnrollTokenClearsEnvironment(t *testing.T) {
	t.Setenv("OBOARD_ENROLL_TOKEN", "one-time-secret")
	if got := consumeEnrollToken(); got != "one-time-secret" {
		t.Fatalf("token = %q", got)
	}
	if _, ok := os.LookupEnv("OBOARD_ENROLL_TOKEN"); ok {
		t.Fatal("enrollment token remained in process environment")
	}
}
