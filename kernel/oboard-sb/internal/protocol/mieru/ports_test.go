// SPDX-License-Identifier: GPL-3.0-or-later

package mieru

import (
	"reflect"
	"testing"
)

func TestExpandPortsCanonicalizesRanges(t *testing.T) {
	got, err := expandPorts(3000, []string{"3001-3003", "3000-3001", "4000-4000"})
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{3000, 3001, 3002, 3003, 4000}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ports = %v, want %v", got, want)
	}
}

func TestExpandPortsRejectsInvalidAndOversizedRanges(t *testing.T) {
	tests := []struct {
		name   string
		ranges []string
	}{
		{name: "missing separator", ranges: []string{"3000"}},
		{name: "trailing data", ranges: []string{"3000-3001-extra"}},
		{name: "descending", ranges: []string{"3001-3000"}},
		{name: "zero", ranges: []string{"0-1"}},
		{name: "too many", ranges: []string{"3000-3064"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := expandPorts(0, test.ranges); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestUint16PortRejectsOutOfRangeValues(t *testing.T) {
	for _, value := range []int{-1, 0, 65536} {
		if _, err := uint16Port(value); err == nil {
			t.Fatalf("uint16Port(%d) accepted an invalid port", value)
		}
	}
	if port, err := uint16Port(65535); err != nil || port != 65535 {
		t.Fatalf("uint16Port(65535) = %d, %v", port, err)
	}
}
