//go:build windows

package main

import (
	"context"
	"log"

	"golang.org/x/sys/windows/svc"
)

// runUnderServiceManager connects the kernel to the Windows service control
// manager when SCM started it. A stop or shutdown request cancels the returned
// context, so the kernel closes through the same path as SIGTERM on Linux. The
// returned function must run after the kernel has closed; it reports the
// service as stopped only then.
func runUnderServiceManager(ctx context.Context, name string) (context.Context, func()) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return ctx, func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	handler := &serviceHandler{cancel: cancel, done: make(chan struct{})}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		if err := svc.Run(name, handler); err != nil {
			log.Printf("service control manager: %v", err)
			cancel()
		}
	}()
	return ctx, func() {
		cancel()
		close(handler.done)
		<-finished
	}
}

type serviceHandler struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case <-h.done:
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				h.cancel()
			}
		}
	}
}

// restrictLocalSocket relies on the directory ACL on Windows. The installer
// creates the runtime directory readable only by SYSTEM and Administrators;
// POSIX mode bits do not exist for an AF_UNIX socket file there.
func restrictLocalSocket(string) error {
	return nil
}
