//go:build !linux

package runtimeguard

import "errors"

func Apply(mode string) error {
	if mode == "" || mode == "standard" {
		return nil
	}
	return errors.New("runtime security profile is unsupported on this platform")
}
func Snapshot() State { state := State{Mode: "standard"}; processEvidence(&state); return state }
