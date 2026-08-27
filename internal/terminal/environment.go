package terminal

import (
	"sort"
	"strings"
)

type EnvironmentInput struct {
	Mode      Mode
	Account   Account
	Shell     string
	TERM      string
	COLORTERM string
	Files     FileSources
}

var allowedTERM = map[string]struct{}{
	"xterm-256color":        {},
	"xterm":                 {},
	"xterm-color":           {},
	"xterm-16color":         {},
	"screen":                {},
	"screen-256color":       {},
	"tmux":                  {},
	"tmux-256color":         {},
	"vt100":                 {},
	"linux":                 {},
	"rxvt-unicode":          {},
	"rxvt-unicode-256color": {},
}

var allowedCOLORTERM = map[string]struct{}{
	"truecolor": {},
	"24bit":     {},
}

func SanitizeTERM(value string) string {
	value = strings.TrimSpace(value)
	if _, ok := allowedTERM[value]; ok && len(value) <= 32 {
		return value
	}
	return DefaultTERM
}

func SanitizeCOLORTERM(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if _, ok := allowedCOLORTERM[value]; ok && len(value) <= 16 {
		return value
	}
	if value == "" {
		return DefaultCOLORTERM
	}
	return DefaultCOLORTERM
}

func BuildTerminalEnvironment(input EnvironmentInput) (env []string, systemLoaded, terminalLoaded bool) {
	values := map[string]string{
		"PATH": DefaultPATH,
	}
	if input.Mode == ModeLogin {
		mergeEnv(values, loadLocaleFiles(input.Files))
		system, loaded := LoadEnvironmentFile(input.Files.Environment)
		systemLoaded = loaded
		mergeEnv(values, system)
		local, loaded := LoadEnvironmentFile(input.Files.TerminalEnv)
		terminalLoaded = loaded
		mergeEnv(values, local)
	}
	home := strings.TrimSpace(input.Account.HomeDir)
	if home == "" {
		home = defaultHome(input.Account.UID)
	}
	username := strings.TrimSpace(input.Account.Username)
	if username == "" {
		username = synthesizeAccount(input.Account.UID, input.Account.GID).Username
	}
	shell := strings.TrimSpace(input.Shell)
	values["HOME"] = home
	values["USER"] = username
	values["LOGNAME"] = username
	values["SHELL"] = shell
	values["TERM"] = SanitizeTERM(input.TERM)
	if color := SanitizeCOLORTERM(input.COLORTERM); color != "" {
		values["COLORTERM"] = color
	}
	deleteForbidden(values)
	return envList(values), systemLoaded, terminalLoaded
}

func mergeEnv(dst, src map[string]string) {
	for key, value := range src {
		if !validEnvKey(key) || forbiddenEnvKey(key) {
			continue
		}
		dst[key] = value
	}
}

func deleteForbidden(values map[string]string) {
	for key := range values {
		if forbiddenEnvKey(key) {
			delete(values, key)
		}
	}
}

func forbiddenEnvKey(key string) bool {
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, "SSH_") {
		return true
	}
	return false
}

func envList(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+values[key])
	}
	return out
}
