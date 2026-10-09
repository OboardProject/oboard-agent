package runtimeguard

import (
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func Apply(mode string) error {
	if mode == "" || mode == "standard" {
		return nil
	}
	if mode != "enhanced" {
		return errors.New("invalid runtime security mode")
	}
	// All Go OS threads must inherit this restriction, including threads that
	// already existed before main. CGO builds that cannot do so fail closed.
	if _, _, err := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); err != 0 {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}

func Snapshot() State {
	state := State{Mode: "standard", Supported: true, UID: os.Geteuid(), GID: os.Getegid()}
	processEvidence(&state)
	if file, err := os.Open("/proc/self/status"); err == nil {
		raw, err := io.ReadAll(io.LimitReader(file, 64<<10))
		file.Close()
		if err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				if value, ok := strings.CutPrefix(line, "CapEff:"); ok {
					value = strings.TrimSpace(value)
					if _, err := strconv.ParseUint(value, 16, 64); err == nil {
						state.EffectiveCapabilities = value
						state.IdentitySupported = true
					}
				}
			}
		}
	}
	nnp, _, e1 := syscall.Syscall6(syscall.SYS_PRCTL, unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0)
	dump, _, e2 := syscall.Syscall6(syscall.SYS_PRCTL, unix.PR_GET_DUMPABLE, 0, 0, 0, 0, 0)
	var limit unix.Rlimit
	e3 := unix.Getrlimit(unix.RLIMIT_CORE, &limit)
	if e1 != 0 || e2 != 0 || e3 != nil {
		state.Supported = false
		return state
	}
	state.NoNewPrivileges = nnp == 1
	state.Dumpable = dump != 0
	state.CoreDumpsDisabled = limit.Cur == 0 && limit.Max == 0
	if state.NoNewPrivileges && !state.Dumpable && state.CoreDumpsDisabled {
		state.Mode = "enhanced"
	}
	return state
}
