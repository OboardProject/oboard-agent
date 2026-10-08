package main

import (
	"errors"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/redact"
	"log"
	"os"
	"path/filepath"
)

// redirectProcessOutput appends standard output, standard error, and the
// standard logger to path. Windows services have no journal that captures a
// console, so the service definition passes the log file explicitly.
func redirectProcessOutput(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// #nosec G304 -- the log path is an operator-provided service argument.
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile(filepath.Base(path), managedPolicyReadFlags()|os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return errors.New("unsafe managed log")
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	os.Stdout = file
	os.Stderr = file
	log.SetOutput(redact.Writer{Output: file})
	return nil
}
