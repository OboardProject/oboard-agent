package logging

import (
	"bytes"
	"log"
	"testing"
)

func captureAt(t *testing.T, level Level, emit func()) string {
	t.Helper()
	previousLevel := CurrentLevel()
	previousFlags := log.Flags()
	previousWriter := log.Writer()
	t.Cleanup(func() {
		SetLevel(previousLevel)
		log.SetFlags(previousFlags)
		log.SetOutput(previousWriter)
	})
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0)
	SetLevel(level)
	emit()
	return buf.String()
}

func TestParseLevelAcceptsOperatorNames(t *testing.T) {
	for name, want := range map[string]Level{
		"trace": LevelTrace, "debug": LevelDebug, "info": LevelInfo,
		"warn": LevelWarn, "warning": LevelWarn, "error": LevelError,
		" Debug ": LevelDebug,
	} {
		got, ok := ParseLevel(name)
		if !ok || got != want {
			t.Fatalf("ParseLevel(%q) = %v ok=%t, want %v ok=true", name, got, ok, want)
		}
	}
}

func TestParseLevelRejectsUnknownWithoutLosingDefault(t *testing.T) {
	got, ok := ParseLevel("verbose")
	if ok {
		t.Fatal("ParseLevel accepted an unknown level")
	}
	if got != DefaultLevel {
		t.Fatalf("ParseLevel fallback = %v, want %v", got, DefaultLevel)
	}
}

func TestLevelGateDropsQuieterRecords(t *testing.T) {
	out := captureAt(t, LevelWarn, func() {
		Debugf("dropped debug")
		Infof("dropped info")
		Warnf("kept warn")
		Errorf("kept error")
	})
	if bytes.Contains([]byte(out), []byte("dropped")) {
		t.Fatalf("quieter records were written: %q", out)
	}
	if !bytes.Contains([]byte(out), []byte("[warn] kept warn")) || !bytes.Contains([]byte(out), []byte("[error] kept error")) {
		t.Fatalf("expected warn and error records, got %q", out)
	}
}

func TestTraceLevelWritesEverything(t *testing.T) {
	out := captureAt(t, LevelTrace, func() {
		Tracef("t")
		Debugf("d")
		Infof("i")
	})
	for _, want := range []string{"[trace] t", "[debug] d", "[info] i"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
}

func TestVerboseCoversOnlyTraceAndDebug(t *testing.T) {
	for level, want := range map[Level]bool{
		LevelTrace: true, LevelDebug: true,
		LevelInfo: false, LevelWarn: false, LevelError: false,
	} {
		if level.Verbose() != want {
			t.Fatalf("%v.Verbose() = %t, want %t", level, level.Verbose(), want)
		}
	}
}
