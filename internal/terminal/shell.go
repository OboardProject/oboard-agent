package terminal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrLoginDisabled = errors.New("terminal login disabled for this account")
)

type ShellMissingError struct {
	Path string
}

func (e ShellMissingError) Error() string {
	path := strings.TrimSpace(e.Path)
	if path == "" {
		path = "/bin/sh"
	}
	return "configured login shell does not exist: " + path
}

func IsLoginDisabled(err error) bool {
	return errors.Is(err, ErrLoginDisabled)
}

func IsShellMissing(err error) bool {
	var missing ShellMissingError
	return errors.As(err, &missing)
}

func ResolveLoginShell(configured string) (string, error) {
	configured = strings.TrimSpace(configured)
	if configured == "" {
		return fallbackShell()
	}
	if isNologinShell(configured) {
		return "", ErrLoginDisabled
	}
	if !shellExecutable(configured) {
		return "", ShellMissingError{Path: configured}
	}
	return configured, nil
}

func fallbackShell() (string, error) {
	const path = "/bin/sh"
	if !shellExecutable(path) {
		return "", ShellMissingError{Path: path}
	}
	return path, nil
}

func isNologinShell(path string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(path)))
	return base == "nologin" || base == "false"
}

func shellExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}

func LoginShellArgs(shell string, mode Mode) []string {
	if mode != ModeLogin {
		return nil
	}
	base := strings.ToLower(filepath.Base(strings.TrimSpace(shell)))
	switch base {
	case "bash", "sh", "dash", "ash", "zsh", "ksh", "mksh", "fish":
		return []string{"-l"}
	default:
		return []string{"-l"}
	}
}
