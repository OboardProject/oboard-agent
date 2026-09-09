package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
	"golang.org/x/crypto/ssh"
)

type sshAuthenticationObservation struct {
	CredentialMatched bool
	Reason            string
}

// Probe the real listener and authenticator without opening a forwarding channel.
// Only locally registered connections suppress rejection audit; authentication
// and authorization use exactly the same checks as ordinary client connections.
func (r *Runner) verifySSHAuthentication(plan model.SSHInboundPlan) (authenticated, rejected int, err error) {
	r.mu.Lock()
	manager := r.sshInboundManager
	r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, inbound := range plan.Inbounds {
		if !inbound.Enabled {
			continue
		}
		if manager == nil {
			return authenticated, rejected, errors.New("SSH authentication verification: runtime missing")
		}
		manager.mu.RLock()
		live := manager.listeners[inbound.InboundID]
		manager.mu.RUnlock()
		if live == nil {
			return authenticated, rejected, errors.New("SSH authentication verification: listener missing")
		}
		for _, user := range inbound.Users {
			if !user.Enabled {
				continue
			}
			denied, probeErr := live.verifyAuthentication(ctx, manager.signer.PublicKey(), user)
			if probeErr != nil {
				return authenticated, rejected, fmt.Errorf("SSH authentication verification failed for inbound %d user %d path %d: %w", inbound.InboundID, user.UserID, user.PathID, probeErr)
			}
			if denied {
				rejected++
			} else {
				authenticated++
			}
		}
	}
	return authenticated, rejected, nil
}

func (m *managedSSHInbound) verifyAuthentication(ctx context.Context, hostKey ssh.PublicKey, user model.SSHInboundUser) (bool, error) {
	m.authMu.RLock()
	credential, ok := m.auth[user.Username]
	m.authMu.RUnlock()
	expected := sshInboundCredentials([]model.SSHInboundUser{user})[user.Username]
	if !ok || credential != expected {
		return false, errors.New("live credential differs from deployment")
	}
	wantReason := ""
	if expected.credentialStatus != "active" {
		wantReason = "credential_inactive"
	} else if counter := m.counterFor(user.UserID); counter != nil && !counter.allowNewConnection() {
		wantReason = "quota_exhausted"
	}
	m.mu.Lock()
	listener := m.listener
	m.mu.Unlock()
	if listener == nil {
		return false, errors.New("listener is not running")
	}
	addresses, err := sshAuthenticationProbeAddresses(listener.Addr().String())
	if err != nil {
		return false, err
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var conn net.Conn
	var address string
	var dialErrors []error
	for _, candidate := range addresses {
		conn, err = (&net.Dialer{}).DialContext(probeCtx, "tcp", candidate)
		if err == nil {
			address = candidate
			break
		}
		dialErrors = append(dialErrors, err)
	}
	if conn == nil {
		return false, fmt.Errorf("cannot connect to SSH listener: %w", errors.Join(dialErrors...))
	}
	defer conn.Close()
	deadline, _ := probeCtx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return false, err
	}
	observations := make(chan sshAuthenticationObservation, 1)
	local := conn.LocalAddr().String()
	m.mu.Lock()
	if m.probes == nil {
		m.probes = make(map[string]chan sshAuthenticationObservation)
	}
	m.probes[local] = observations
	m.mu.Unlock()
	defer func() { m.mu.Lock(); delete(m.probes, local); m.mu.Unlock() }()
	client, _, _, authErr := ssh.NewClientConn(conn, address, &ssh.ClientConfig{
		User: user.Username, Auth: []ssh.AuthMethod{ssh.Password(user.Password)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	})
	if client != nil {
		_ = client.Close()
	}
	select {
	case observation := <-observations:
		if !observation.CredentialMatched || observation.Reason != wantReason {
			return false, fmt.Errorf("authenticator rejected expected state (%s)", observation.Reason)
		}
		if wantReason == "" && authErr == nil {
			return false, nil
		}
		if wantReason != "" && authErr != nil && strings.Contains(authErr.Error(), "unable to authenticate") {
			return true, nil
		}
	default:
	}
	return false, errors.New("SSH handshake did not confirm authentication")
}

func sshAuthenticationProbeAddresses(address string) ([]string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid SSH listener address: %w", err)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		// Go can report [::] for an IPv4 wildcard listener on dual-stack hosts.
		// IPv6 loopback may be disabled even when that socket accepts IPv4.
		addresses := []string{net.JoinHostPort("127.0.0.1", port)}
		if ip.To4() == nil {
			addresses = append(addresses, net.JoinHostPort("::1", port))
		}
		return addresses, nil
	}
	return []string{address}, nil
}
