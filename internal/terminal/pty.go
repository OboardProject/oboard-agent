package terminal

import (
	"os"
	"os/exec"

	"github.com/creack/pty"
)

func Spawn(spec SessionSpec) (*os.File, *exec.Cmd, error) {
	cmd := exec.Command(spec.Shell, spec.ShellArgs...)
	cmd.Dir = spec.WorkDir
	cmd.Env = append([]string{}, spec.Env...)
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	cols, rows := spec.Cols, spec.Rows
	if cols <= 0 {
		cols = 120
	}
	if rows <= 0 {
		rows = 32
	}
	// pty.StartWithSize sets Setsid and Setctty. Do not also set Setpgid:
	// a session leader cannot change its process group (EPERM).
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	return ptmx, cmd, err
}
