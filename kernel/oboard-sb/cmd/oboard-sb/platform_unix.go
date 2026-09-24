//go:build !windows

package main

import (
	"context"
	"os"
)

// runUnderServiceManager is a no-op outside Windows: systemd and OpenRC stop
// the kernel with SIGTERM, which the caller's signal context already handles.
func runUnderServiceManager(ctx context.Context, _ string) (context.Context, func()) {
	return ctx, func() {}
}

func restrictLocalSocket(path string) error {
	return os.Chmod(path, 0o600)
}
