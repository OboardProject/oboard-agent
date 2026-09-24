package agent

import (
	"path/filepath"
	"strings"
)

// executableName returns the on-disk file name of a managed binary.
func executableName(base string) string {
	return base + executableSuffix
}

// executableBase returns the managed name of a binary path without the
// platform executable suffix, so name checks agree on Linux and Windows.
func executableBase(path string) string {
	base := filepath.Base(path)
	if executableSuffix != "" && len(base) > len(executableSuffix) && strings.EqualFold(base[len(base)-len(executableSuffix):], executableSuffix) {
		return base[:len(base)-len(executableSuffix)]
	}
	return base
}
