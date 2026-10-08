package main

import (
	"bufio"
	"fmt"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/redact"
	"os"
	"strings"
	"sync"
)

// The upstream logger writes to os.Stderr directly. This bounded in-process
// pipe covers that sink as well as the standard logger, without a subprocess.
func startRedactedRuntimeOutput() (func(), error) {
	read, write, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = write, write
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer read.Close()
		reader := bufio.NewReaderSize(read, 64<<10)
		private := false
		for {
			raw, prefix, err := reader.ReadLine()
			if err != nil {
				break
			}
			if prefix {
				for prefix && err == nil {
					_, prefix, err = reader.ReadLine()
				}
				fmt.Fprintln(stderr, "[oversized runtime log record omitted]")
				continue
			}
			line := string(raw)
			if strings.Contains(line, "-----BEGIN ") && strings.Contains(line, "PRIVATE KEY-----") {
				private = true
				fmt.Fprintln(stderr, "[private key redacted]")
			}
			if private {
				if strings.Contains(line, "-----END ") && strings.Contains(line, "PRIVATE KEY-----") {
					private = false
				}
				continue
			}
			fmt.Fprintln(stderr, redact.Text(line))
		}

	}()
	var once sync.Once
	return func() { once.Do(func() { os.Stdout, os.Stderr = stdout, stderr; write.Close(); <-done }) }, nil
}
