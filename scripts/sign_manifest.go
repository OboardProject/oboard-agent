//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/OboardProject/oboard-agent/internal/security"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) != 2 {
		log.Fatal("usage: sign_manifest manifest.json")
	}
	key := os.Getenv("OBOARD_RELEASE_SIGNING_KEY")
	if key == "" {
		log.Fatal("OBOARD_RELEASE_SIGNING_KEY is required")
	}
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	var m security.ReleaseManifest
	if err := json.Unmarshal(b, &m); err != nil {
		log.Fatal(err)
	}
	sig, err := security.SignReleaseManifest(m, key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sig)
}
