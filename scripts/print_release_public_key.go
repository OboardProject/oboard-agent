//go:build ignore

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/OboardProject/oboard-agent/internal/security"
)

func main() {
	log.SetFlags(0)
	if os.Getenv("OBOARD_RELEASE_SIGNING_KEY") == "" {
		log.Fatal("OBOARD_RELEASE_SIGNING_KEY is required")
	}
	pub, err := security.PublicKeyFromPrivateKey(os.Getenv("OBOARD_RELEASE_SIGNING_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(pub)
}
