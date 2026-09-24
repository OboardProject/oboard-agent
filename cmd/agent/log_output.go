package main

import (
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
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	os.Stdout = file
	os.Stderr = file
	log.SetOutput(file)
	return nil
}
