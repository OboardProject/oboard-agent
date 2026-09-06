package agent

import (
	"time"

	"golang.org/x/crypto/ssh"
)

func (m *sshInboundManager) reapAuthorization() {
	if m == nil {
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, inbound := range m.listeners {
		inbound.mu.Lock()
		connections := make(map[*ssh.ServerConn]string, len(inbound.sessions))
		for connection, username := range inbound.sessions {
			connections[connection] = username
		}
		inbound.mu.Unlock()
		for connection, username := range connections {
			if !inbound.sessionAuthorized(username) {
				_ = connection.Close()
			}
		}
	}
}

func (m *managedSSHInbound) credentialAuthorized(credential sshInboundCredential, admitted bool) bool {
	if m.authorizationAllows == nil || !m.authorizationAllows(credential.authorizationKey) {
		return false
	}
	return credential.credentialStatus == "active" || admitted && credential.credentialStatus == "reject_new"
}

func (m *managedSSHInbound) sessionAuthorized(username string) bool {
	m.authMu.RLock()
	credential, ok := m.auth[username]
	m.authMu.RUnlock()
	return ok && m.credentialAuthorized(credential, true)
}

func (m *managedSSHInbound) watchAuthorization(connection *ssh.ServerConn, done <-chan struct{}) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if !m.sessionAuthorized(connection.User()) {
			_ = connection.Close()
			return
		}
		select {
		case <-done:
			return
		case <-ticker.C:
		}
	}
}
