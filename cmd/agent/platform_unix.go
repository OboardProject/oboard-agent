//go:build !windows

package main

import "context"

// runUnderServiceManager is a no-op outside Windows: systemd and OpenRC stop
// the Agent with SIGTERM, which the caller's signal context already handles.
func runUnderServiceManager(ctx context.Context, _ string) (context.Context, func()) {
	return ctx, func() {}
}
