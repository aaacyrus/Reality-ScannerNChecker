package ui

import (
	"context"
	"strings"
	"testing"
)

func TestReadUsesDefaultOnlyForBlankLine(t *testing.T) {
	console := NewConsole(strings.NewReader("\n"), &strings.Builder{}, false)
	value, ok := console.Read(context.Background(), "", "1")
	if !ok || value != "1" {
		t.Fatalf("Read() = %q, %v; want default value and success", value, ok)
	}
}

func TestReadTreatsEOFAsExit(t *testing.T) {
	console := NewConsole(strings.NewReader(""), &strings.Builder{}, false)
	value, ok := console.Read(context.Background(), "", "1")
	if ok || value != "" {
		t.Fatalf("Read() = %q, %v; want empty value and exit", value, ok)
	}
}

func TestNonInteractiveOutputStaysPlain(t *testing.T) {
	var output strings.Builder
	console := NewConsole(strings.NewReader(""), &output, false)
	console.Banner("Reality Scanner", "plain output")
	console.Status(ToneSuccess, "ready")
	console.Menu("1. Start (default)\n0. Exit")
	console.ProgressBar("Scanning", 5, 10)

	text := output.String()
	if strings.Contains(text, "\x1b[") {
		t.Fatalf("non-interactive output contains ANSI escapes: %q", text)
	}
	for _, expected := range []string{"REALITY SCANNER", "✓ ready", "1. Start", "Scanning"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("non-interactive output does not contain %q:\n%s", expected, text)
		}
	}
}

func TestInteractiveThemeAndProgress(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	var output strings.Builder
	console := NewConsole(strings.NewReader(""), &output, true)
	console.Banner("Reality Scanner", "color output")
	console.Section("Scanner")
	console.Status(ToneWarning, "authorized networks only")
	console.Menu("1. Start (default)\n0. Exit")
	console.ProgressBar("Scanning", 5, 10)
	console.FinishProgress()

	text := output.String()
	for _, expected := range []string{"\x1b[", "◆", "!", "━", "50%", "\r\x1b[2K"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("interactive output does not contain %q: %q", expected, text)
		}
	}
}
