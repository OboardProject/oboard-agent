package terminal

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"strings"
	"unicode"
)

const (
	maxEnvFileBytes = 64 << 10
	maxEnvLineBytes = 4096
	maxEnvKeys      = 256
)

func LoadEnvironmentFile(path string) (map[string]string, bool) {
	values, err := parseEnvFile(path, nil)
	if err != nil {
		return map[string]string{}, false
	}
	return values, true
}

func loadLocaleFiles(files FileSources) map[string]string {
	out := map[string]string{}
	for _, path := range []string{files.LocaleDebian, files.LocaleConf} {
		values, err := parseEnvFile(path, isLocaleKey)
		if err != nil {
			continue
		}
		mergeEnv(out, values)
	}
	return out
}

func isLocaleKey(key string) bool {
	switch key {
	case "LANG", "LANGUAGE":
		return true
	}
	return strings.HasPrefix(key, "LC_")
}

func parseEnvFile(path string, allow func(string) bool) (map[string]string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, os.ErrNotExist
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	limited := io.LimitReader(file, maxEnvFileBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxEnvFileBytes {
		data = data[:maxEnvFileBytes]
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	out := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 1024), maxEnvLineBytes)
	for scanner.Scan() {
		if len(out) >= maxEnvKeys {
			break
		}
		key, value, ok := parseEnvLine(scanner.Text())
		if !ok {
			continue
		}
		if allow != nil && !allow(key) {
			continue
		}
		if forbiddenEnvKey(key) {
			continue
		}
		out[key] = value
	}
	return out, nil
}

func parseEnvLine(line string) (string, string, bool) {
	line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	if strings.ContainsAny(line, "`") {
		return "", "", false
	}
	key, raw, ok := strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}
	key = strings.TrimSpace(key)
	if strings.ContainsAny(key, " \t") || !validEnvKey(key) {
		return "", "", false
	}
	value, ok := unquoteEnvValue(strings.TrimSpace(raw))
	if !ok {
		return "", "", false
	}
	if strings.Contains(value, "$(") || strings.Contains(value, "`") {
		return "", "", false
	}
	return key, value, true
}

func validEnvKey(key string) bool {
	if key == "" || len(key) > 128 {
		return false
	}
	for i, r := range key {
		if r == '_' || unicode.IsLetter(r) {
			continue
		}
		if i > 0 && unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}

func unquoteEnvValue(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	switch raw[0] {
	case '"':
		if len(raw) < 2 || raw[len(raw)-1] != '"' {
			return "", false
		}
		inner := raw[1 : len(raw)-1]
		if strings.Contains(inner, "$(") || strings.Contains(inner, "`") {
			return "", false
		}
		return inner, true
	case '\'':
		if len(raw) < 2 || raw[len(raw)-1] != '\'' {
			return "", false
		}
		inner := raw[1 : len(raw)-1]
		if strings.Contains(inner, "$(") || strings.Contains(inner, "`") {
			return "", false
		}
		return inner, true
	}
	if strings.ContainsAny(raw, " \t") {
		return "", false
	}
	return raw, true
}
