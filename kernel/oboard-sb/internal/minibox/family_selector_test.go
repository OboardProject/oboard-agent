package minibox

import (
	"context"
	"testing"

	box "github.com/sagernet/sing-box"
)

func TestFamilySelectorConfigCanBeCreated(t *testing.T) {
	opts, _, err := LoadConfig("testdata/family-selector.json", HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: Context(context.Background()), Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
}
