// Package redact removes labelled credentials from diagnostic text. It is a
// final output boundary; callers must still avoid logging secret payloads.
package redact

import (
	"io"
	"regexp"
)

var privateKey = regexp.MustCompile("(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
var field = regexp.MustCompile("(?i)([\"']?(?:token|agent[_-]?token|access[_-]?token|refresh[_-]?token|enrollment[_-]?token|password|passwd|psk|private[_-]?key|secret|userkey|uuid|authorization)[\"']?\\s*[:=]\\s*)(?:\"(?:[^\"\\\\]|\\\\.)*\"|'[^']*'|[^\\s,;}]+)")
var bearer = regexp.MustCompile("(?i)Bearer\\s+[a-z0-9._~+/=-]+")
var userinfo = regexp.MustCompile("([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\\s]+:[^/@\\s]+@")

func Text(value string) string {
	value = privateKey.ReplaceAllString(value, "[private key redacted]")
	value = field.ReplaceAllStringFunc(value, func(match string) string { return field.FindStringSubmatch(match)[1] + "[redacted]" })
	value = bearer.ReplaceAllString(value, "Bearer [redacted]")
	return userinfo.ReplaceAllStringFunc(value, func(match string) string { return userinfo.FindStringSubmatch(match)[1] + "[redacted]@" })
}

type Writer struct{ Output io.Writer }

func (w Writer) Write(raw []byte) (int, error) {
	_, err := io.WriteString(w.Output, Text(string(raw)))
	if err != nil {
		return 0, err
	}
	return len(raw), nil
}
