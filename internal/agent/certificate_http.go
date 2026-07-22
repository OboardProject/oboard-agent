package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/core"
	"github.com/OboardProject/oboard-agent/internal/model"
)

func (r *Runner) issueCertificateHTTP(taskID int64, payload model.IssueCertificateHTTPTaskPayload) (map[string]any, error) {
	if taskID <= 0 || payload.CertificateID <= 0 || len(payload.Domains) == 0 {
		return nil, errors.New("invalid HTTP-01 certificate task")
	}
	for _, domain := range payload.Domains {
		if strings.Contains(domain, "*") || core.ValidateSafeHost(domain) != nil {
			return nil, fmt.Errorf("invalid HTTP-01 domain %q", domain)
		}
	}
	switch payload.ACMECA {
	case "letsencrypt", "zerossl", "buypass", "google":
	default:
		return nil, fmt.Errorf("unsupported ACME CA %q", payload.ACMECA)
	}
	home := filepath.Join(r.stateDir(), "acme")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(home, 0o700); err != nil { // #nosec G302 -- ACME home is a private directory and requires its execute bit.
		return nil, err
	}
	args := []string{"--home", home, "--config-home", home, "--server", payload.ACMECA, "--issue", "--standalone", "--httpport", "80", "--keylength", "ec-256"}
	if payload.Renew {
		args = append(args, "--force")
	}
	if payload.AccountEmail != "" {
		args = append(args, "--accountemail", payload.AccountEmail)
	}
	for _, domain := range payload.Domains {
		args = append(args, "-d", domain)
	}
	if output, err := runAgentACME(home, args...); err != nil {
		return nil, fmt.Errorf("acme.sh HTTP-01 failed: %s", trimAgentACMEOutput(output))
	}
	workDir, err := os.MkdirTemp(home, "install-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(workDir)
	if err := os.Chmod(workDir, 0o700); err != nil { // #nosec G302 -- certificate staging uses a private traversable directory.
		return nil, err
	}
	certPath := filepath.Join(workDir, "cert.pem")
	fullchainPath := filepath.Join(workDir, "fullchain.pem")
	keyPath := filepath.Join(workDir, "privkey.pem")
	installArgs := []string{"--home", home, "--config-home", home, "--install-cert", "--ecc", "-d", payload.Domains[0], "--cert-file", certPath, "--fullchain-file", fullchainPath, "--key-file", keyPath}
	if output, err := runAgentACME(home, installArgs...); err != nil {
		return nil, fmt.Errorf("install HTTP-01 certificate failed: %s", trimAgentACMEOutput(output))
	}
	certificatePEM, err := os.ReadFile(certPath) // #nosec G304 -- fixed file in private Agent-created directory.
	if err != nil {
		return nil, err
	}
	fullchainPEM, err := os.ReadFile(fullchainPath) // #nosec G304 -- fixed file in private Agent-created directory.
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := os.ReadFile(keyPath) // #nosec G304 -- fixed file in private Agent-created directory.
	if err != nil {
		return nil, err
	}
	report := model.CertificateIssueReport{TaskID: taskID, CertificateID: payload.CertificateID, Domains: payload.Domains, CertificatePEM: string(certificatePEM), FullchainPEM: string(fullchainPEM), PrivateKeyPEM: string(privateKeyPEM)}
	if err := r.postControllerJSON(context.Background(), "/api/v1/agent/certificate-issues", report, nil, true); err != nil {
		return nil, fmt.Errorf("report issued certificate: %w", err)
	}
	return map[string]any{"message": "HTTP-01 certificate issued", "certificate_id": payload.CertificateID, "domains": payload.Domains}, nil
}

func runAgentACME(home string, args ...string) (string, error) {
	command := strings.TrimSpace(os.Getenv("OBOARD_ACME_SH"))
	if command == "" {
		command = "acme.sh"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...) // #nosec G204,G702 -- binary path is local startup configuration; validated values are passed as separate arguments without a shell.
	cmd.Env = append(os.Environ(), "LE_WORKING_DIR="+home)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func trimAgentACMEOutput(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 4000 {
		value = value[len(value)-4000:]
	}
	if value == "" {
		return "acme.sh failed without output"
	}
	return value
}
