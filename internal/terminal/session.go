package terminal

import (
	"fmt"
	"log"
	"os"
	"strings"
)

type Mode string

const (
	ModeLogin   Mode = "login"
	ModeMinimal Mode = "minimal"

	DefaultPATH      = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	DefaultTERM      = "xterm-256color"
	DefaultCOLORTERM = "truecolor"
)

type FileSources struct {
	Passwd       string
	Environment  string
	LocaleDebian string
	LocaleConf   string
	TerminalEnv  string
}

func DefaultFileSources() FileSources {
	return FileSources{
		Passwd:       "/etc/passwd",
		Environment:  "/etc/environment",
		LocaleDebian: "/etc/default/locale",
		LocaleConf:   "/etc/locale.conf",
		TerminalEnv:  "/etc/oboard-agent/terminal.env",
	}
}

func (s FileSources) withDefaults() FileSources {
	defaults := DefaultFileSources()
	if strings.TrimSpace(s.Passwd) == "" {
		s.Passwd = defaults.Passwd
	}
	if strings.TrimSpace(s.Environment) == "" {
		s.Environment = defaults.Environment
	}
	if strings.TrimSpace(s.LocaleDebian) == "" {
		s.LocaleDebian = defaults.LocaleDebian
	}
	if strings.TrimSpace(s.LocaleConf) == "" {
		s.LocaleConf = defaults.LocaleConf
	}
	if strings.TrimSpace(s.TerminalEnv) == "" {
		s.TerminalEnv = defaults.TerminalEnv
	}
	return s
}

type Request struct {
	Mode      Mode
	Cols      int
	Rows      int
	TERM      string
	COLORTERM string
	Account   *Account
	Files     FileSources
}

type SessionSpec struct {
	Mode                      Mode
	UID                       int
	GID                       int
	Username                  string
	HomeDir                   string
	Shell                     string
	ShellArgs                 []string
	WorkDir                   string
	Env                       []string
	Rows                      int
	Cols                      int
	Term                      string
	SystemEnvironmentLoaded   bool
	TerminalEnvironmentLoaded bool
}

type Diagnostic struct {
	Username                  string `json:"username"`
	UID                       int    `json:"uid"`
	GID                       int    `json:"gid"`
	Home                      string `json:"home"`
	Shell                     string `json:"shell"`
	Mode                      string `json:"mode"`
	Cwd                       string `json:"cwd"`
	Term                      string `json:"term"`
	SystemEnvironmentLoaded   bool   `json:"system_environment_loaded"`
	TerminalEnvironmentLoaded bool   `json:"terminal_environment_loaded"`
}

func ParseMode(value string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(ModeLogin):
		return ModeLogin, nil
	case string(ModeMinimal):
		return ModeMinimal, nil
	default:
		return "", fmt.Errorf("unsupported terminal mode %q", value)
	}
}

func BuildSession(req Request) (SessionSpec, error) {
	mode, err := ParseMode(string(req.Mode))
	if err != nil {
		return SessionSpec{}, err
	}
	files := req.Files.withDefaults()
	account := req.Account
	if account == nil {
		resolved, resolveErr := ResolveTerminalUser(files.Passwd)
		if resolveErr != nil {
			return SessionSpec{}, resolveErr
		}
		account = &resolved
	}
	shell, err := ResolveLoginShell(account.Shell)
	if err != nil {
		return SessionSpec{}, err
	}
	workDir := ResolveWorkingDirectory(account.HomeDir)
	term := SanitizeTERM(req.TERM)
	colorterm := SanitizeCOLORTERM(req.COLORTERM)
	env, sysLoaded, termLoaded := BuildTerminalEnvironment(EnvironmentInput{
		Mode:      mode,
		Account:   *account,
		Shell:     shell,
		TERM:      term,
		COLORTERM: colorterm,
		Files:     files,
	})
	return SessionSpec{
		Mode:                      mode,
		UID:                       account.UID,
		GID:                       account.GID,
		Username:                  account.Username,
		HomeDir:                   account.HomeDir,
		Shell:                     shell,
		ShellArgs:                 LoginShellArgs(shell, mode),
		WorkDir:                   workDir,
		Env:                       env,
		Rows:                      req.Rows,
		Cols:                      req.Cols,
		Term:                      term,
		SystemEnvironmentLoaded:   sysLoaded,
		TerminalEnvironmentLoaded: termLoaded,
	}, nil
}

func (s SessionSpec) Diagnostic() Diagnostic {
	return Diagnostic{
		Username:                  s.Username,
		UID:                       s.UID,
		GID:                       s.GID,
		Home:                      s.HomeDir,
		Shell:                     s.Shell,
		Mode:                      string(s.Mode),
		Cwd:                       s.WorkDir,
		Term:                      s.Term,
		SystemEnvironmentLoaded:   s.SystemEnvironmentLoaded,
		TerminalEnvironmentLoaded: s.TerminalEnvironmentLoaded,
	}
}

func ResolveWorkingDirectory(home string) string {
	home = strings.TrimSpace(home)
	if home != "" {
		info, err := os.Stat(home)
		if err == nil && info.IsDir() {
			f, err := os.Open(home)
			if err == nil {
				_ = f.Close()
				return home
			}
		}
	}
	logHomeFallback(home)
	return "/"
}

func logHomeFallback(home string) {
	if home == "" {
		home = "(empty)"
	}
	log.Printf("terminal home unavailable, fallback to / path=%s", home)
}
