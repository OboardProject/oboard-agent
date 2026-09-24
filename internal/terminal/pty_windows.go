//go:build windows

package terminal

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// consoleCloseTimeout bounds ClosePseudoConsole. On older Windows builds it
// blocks until the output pipe is drained, so it never runs on a path that
// could wait on the reader forever.
const consoleCloseTimeout = 3 * time.Second

// buildPlatformSession resolves the Windows shell session. The Agent runs as
// LocalSystem, so the terminal is that account's PowerShell in its own profile
// directory. The environment is the account's default block from
// CreateEnvironmentBlock, not the Agent's process environment, which keeps
// Agent secrets out of the shell exactly as the Unix sanitizer does.
func buildPlatformSession(mode Mode, req Request) (SessionSpec, bool, error) {
	token, err := openProcessToken()
	if err != nil {
		return SessionSpec{}, true, fmt.Errorf("open process token: %w", err)
	}
	defer token.Close()
	username := "SYSTEM"
	if current, err := user.Current(); err == nil && strings.TrimSpace(current.Username) != "" {
		username = strings.TrimSpace(current.Username)
	}
	home, _ := token.GetUserProfileDirectory()
	shell, args, err := windowsShell(mode)
	if err != nil {
		return SessionSpec{}, true, err
	}
	term := SanitizeTERM(req.TERM)
	colorterm := SanitizeCOLORTERM(req.COLORTERM)
	base, err := accountEnvironment(token)
	if err != nil {
		return SessionSpec{}, true, fmt.Errorf("build terminal environment: %w", err)
	}
	values := map[string]string{}
	for _, entry := range base {
		key, value, ok := strings.Cut(entry, "=")
		// Keys starting with "=" are per-drive working directories.
		if !ok || key == "" {
			continue
		}
		values[key] = value
	}
	values["TERM"] = term
	values["COLORTERM"] = colorterm
	for key := range values {
		if forbiddenWindowsEnvKey(key) {
			delete(values, key)
		}
	}
	return SessionSpec{
		Mode:      mode,
		Username:  username,
		HomeDir:   home,
		Shell:     shell,
		ShellArgs: args,
		WorkDir:   windowsWorkingDirectory(home),
		Env:       envList(values),
		Rows:      req.Rows,
		Cols:      req.Cols,
		Term:      term,
		// The account block already carries the machine and user
		// environment that /etc/environment provides on Linux.
		SystemEnvironmentLoaded: true,
	}, true, nil
}

// accountEnvironment returns the account's default environment without
// inheriting anything from the Agent process.
func accountEnvironment(token windows.Token) ([]string, error) {
	var block *uint16
	if err := windows.CreateEnvironmentBlock(&block, token, false); err != nil {
		return nil, err
	}
	defer windows.DestroyEnvironmentBlock(block)
	var env []string
	for ptr := unsafe.Pointer(block); ; {
		entry := windows.UTF16PtrToString((*uint16)(ptr))
		if entry == "" {
			return env, nil
		}
		env = append(env, entry)
		ptr = unsafe.Add(ptr, (len(windows.StringToUTF16(entry)))*2)
	}
}

func forbiddenWindowsEnvKey(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	return forbiddenEnvKey(key) || strings.HasPrefix(upper, "OBOARD_")
}

func openProcessToken() (windows.Token, error) {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE, &token)
	return token, err
}

// windowsShell resolves Windows PowerShell, falling back to cmd.exe, from the
// system directory rather than PATH. Login mode loads the PowerShell profiles;
// minimal mode skips them, matching the Unix login/minimal split.
func windowsShell(mode Mode) (string, []string, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return "", nil, err
	}
	powershell := filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe")
	if info, err := os.Stat(powershell); err == nil && !info.IsDir() {
		args := []string{"-NoLogo"}
		if mode != ModeLogin {
			args = append(args, "-NoProfile")
		}
		return powershell, args, nil
	}
	cmd := filepath.Join(system, "cmd.exe")
	if info, err := os.Stat(cmd); err == nil && !info.IsDir() {
		return cmd, nil, nil
	}
	return "", nil, ShellMissingError{Path: powershell}
}

func windowsWorkingDirectory(home string) string {
	if home = strings.TrimSpace(home); home != "" {
		if info, err := os.Stat(home); err == nil && info.IsDir() {
			return home
		}
	}
	drive := strings.TrimSpace(os.Getenv("SystemDrive"))
	if drive == "" {
		drive = "C:"
	}
	fallback := strings.TrimRight(drive, `\`) + `\`
	logHomeFallback(home)
	return fallback
}

type conptySession struct {
	console   windows.Handle
	process   windows.Handle
	job       windows.Handle
	input     *os.File
	output    *os.File
	closeOnce sync.Once
	consoleMu sync.Mutex
	closed    bool
}

// Start spawns the shell on a ConPTY pseudo console. The shell is created
// suspended and placed in a kill-on-close job before it runs, so closing the
// session ends every process the shell started, including ones that detached
// from the console.
func Start(spec SessionSpec) (Session, error) {
	cols, rows := spec.Cols, spec.Rows
	if cols <= 0 {
		cols = 120
	}
	if rows <= 0 {
		rows = 32
	}
	var consoleIn, inputWrite, outputRead, consoleOut windows.Handle
	if err := windows.CreatePipe(&consoleIn, &inputWrite, nil, 0); err != nil {
		return nil, fmt.Errorf("create input pipe: %w", err)
	}
	if err := windows.CreatePipe(&outputRead, &consoleOut, nil, 0); err != nil {
		_ = windows.CloseHandle(consoleIn)
		_ = windows.CloseHandle(inputWrite)
		return nil, fmt.Errorf("create output pipe: %w", err)
	}
	var console windows.Handle
	err := windows.CreatePseudoConsole(windows.Coord{X: int16(cols), Y: int16(rows)}, consoleIn, consoleOut, 0, &console)
	// The pseudo console duplicated its ends of the pipes.
	_ = windows.CloseHandle(consoleIn)
	_ = windows.CloseHandle(consoleOut)
	if err != nil {
		_ = windows.CloseHandle(inputWrite)
		_ = windows.CloseHandle(outputRead)
		return nil, fmt.Errorf("create pseudo console: %w", err)
	}
	session := &conptySession{
		console: console,
		input:   os.NewFile(uintptr(inputWrite), "conpty-input"),
		output:  os.NewFile(uintptr(outputRead), "conpty-output"),
	}
	if err := session.spawn(spec); err != nil {
		_ = session.Close()
		return nil, err
	}
	go session.closeConsoleOnExit()
	return session, nil
}

func (s *conptySession) spawn(spec SessionSpec) error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("create job object: %w", err)
	}
	s.job = job
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return fmt.Errorf("configure job object: %w", err)
	}
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return err
	}
	defer attributes.Delete()
	// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE takes the HPCON value itself.
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, *(*unsafe.Pointer)(unsafe.Pointer(&s.console)), unsafe.Sizeof(s.console)); err != nil {
		return fmt.Errorf("attach pseudo console: %w", err)
	}
	startup := &windows.StartupInfoEx{ProcThreadAttributeList: attributes.List()}
	startup.Cb = uint32(unsafe.Sizeof(*startup))
	// Without explicit (empty) standard handles the shell would inherit the
	// service's redirected log handles instead of attaching to the console.
	startup.Flags = windows.STARTF_USESTDHANDLES
	application, err := windows.UTF16PtrFromString(spec.Shell)
	if err != nil {
		return err
	}
	commandLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{spec.Shell}, spec.ShellArgs...)))
	if err != nil {
		return err
	}
	environment, err := environmentBlock(spec.Env)
	if err != nil {
		return err
	}
	var workDir *uint16
	if strings.TrimSpace(spec.WorkDir) != "" {
		if workDir, err = windows.UTF16PtrFromString(spec.WorkDir); err != nil {
			return err
		}
	}
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_SUSPENDED)
	var info windows.ProcessInformation
	if err := windows.CreateProcess(application, commandLine, nil, nil, false, flags, &environment[0], workDir, &startup.StartupInfo, &info); err != nil {
		return fmt.Errorf("start shell: %w", err)
	}
	defer windows.CloseHandle(info.Thread)
	s.process = info.Process
	if err := windows.AssignProcessToJobObject(job, info.Process); err != nil {
		_ = windows.TerminateProcess(info.Process, 1)
		return fmt.Errorf("assign shell to job: %w", err)
	}
	if _, err := windows.ResumeThread(info.Thread); err != nil {
		_ = windows.TerminateProcess(info.Process, 1)
		return fmt.Errorf("resume shell: %w", err)
	}
	return nil
}

// environmentBlock renders a CREATE_UNICODE_ENVIRONMENT block: NUL-separated
// KEY=value entries followed by an extra NUL.
func environmentBlock(env []string) ([]uint16, error) {
	var block []uint16
	for _, entry := range env {
		if strings.ContainsRune(entry, 0) {
			return nil, errors.New("environment entry contains a NUL byte")
		}
		encoded, err := windows.UTF16FromString(entry)
		if err != nil {
			return nil, err
		}
		block = append(block, encoded...)
	}
	if len(block) == 0 {
		block = append(block, 0)
	}
	return append(block, 0), nil
}

// closeConsoleOnExit closes the pseudo console when the shell exits. A ConPTY
// output pipe does not reach end-of-file while the console exists, so this is
// what turns a shell exit into a read error for the session reader.
func (s *conptySession) closeConsoleOnExit() {
	if _, err := windows.WaitForSingleObject(s.process, windows.INFINITE); err != nil {
		return
	}
	s.closeConsole()
}

func (s *conptySession) closeConsole() {
	s.consoleMu.Lock()
	if s.closed {
		s.consoleMu.Unlock()
		return
	}
	s.closed = true
	console := s.console
	s.consoleMu.Unlock()
	done := make(chan struct{})
	go func() {
		windows.ClosePseudoConsole(console)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(consoleCloseTimeout):
	}
}

func (s *conptySession) Read(p []byte) (int, error)  { return s.output.Read(p) }
func (s *conptySession) Write(p []byte) (int, error) { return s.input.Write(p) }

func (s *conptySession) Resize(cols, rows int) error {
	s.consoleMu.Lock()
	defer s.consoleMu.Unlock()
	if s.closed {
		return errors.New("terminal is closed")
	}
	return windows.ResizePseudoConsole(s.console, windows.Coord{X: int16(cols), Y: int16(rows)})
}

func (s *conptySession) Close() error {
	s.closeOnce.Do(func() {
		if s.job != 0 {
			_ = windows.TerminateJobObject(s.job, 1)
		} else if s.process != 0 {
			_ = windows.TerminateProcess(s.process, 1)
		}
		_ = s.input.Close()
		s.closeConsole()
		_ = s.output.Close()
		if s.job != 0 {
			_ = windows.CloseHandle(s.job)
		}
	})
	return nil
}

func (s *conptySession) ExitCode() int {
	if s.process == 0 {
		return -1
	}
	var code uint32
	if err := windows.GetExitCodeProcess(s.process, &code); err != nil {
		return -1
	}
	const stillActive = 259
	if code == stillActive {
		return -1
	}
	return int(code)
}
