package ui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mattn/go-runewidth"
)

const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "1"
	ansiDim     = "2"
	ansiRed     = "31"
	ansiGreen   = "32"
	ansiYellow  = "33"
	ansiMagenta = "35"
	ansiCyan    = "36"
	ansiWhite   = "97"
)

// Tone describes the visual meaning of a status line.
type Tone int

const (
	ToneInfo Tone = iota
	ToneSuccess
	ToneWarning
	ToneError
)

func paint(enabled bool, text string, codes ...string) string {
	if !enabled || text == "" {
		return text
	}
	return "\x1b[" + strings.Join(codes, ";") + "m" + text + ansiReset
}

func toneStyle(tone Tone) (icon, color string) {
	switch tone {
	case ToneSuccess:
		return "✓", ansiGreen
	case ToneWarning:
		return "!", ansiYellow
	case ToneError:
		return "✕", ansiRed
	default:
		return "◆", ansiCyan
	}
}

func fitBannerText(text string, width int) (string, int) {
	available := width - 4
	if runewidth.StringWidth(text) > available {
		text = runewidth.Truncate(text, available-1, "…")
	}
	return text, max(0, available-runewidth.StringWidth(text))
}

func displayWidth(text string) int {
	return runewidth.StringWidth(text)
}

func menuText(text string, colors bool) string {
	if !colors {
		return text
	}
	lines := strings.Split(text, "\n")
	for index, line := range lines {
		separator := strings.Index(line, ". ")
		if separator <= 0 {
			continue
		}
		if _, err := strconv.Atoi(line[:separator]); err != nil {
			continue
		}
		number := paint(true, line[:separator+1], ansiBold, ansiCyan)
		label := line[separator+2:]
		if strings.HasPrefix(line, "0.") {
			label = paint(true, label, ansiDim)
		} else if strings.Contains(strings.ToLower(label), "default") || strings.Contains(label, "預設") {
			label = paint(true, label, ansiGreen)
		}
		lines[index] = number + " " + label
	}
	return strings.Join(lines, "\n")
}

func progressBar(current, total int64, width int, colors bool) string {
	if total <= 0 {
		return ""
	}
	if current < 0 {
		current = 0
	}
	if current > total {
		current = total
	}
	filled := int(current * int64(width) / total)
	bar := strings.Repeat("━", filled) + strings.Repeat("─", width-filled)
	percentage := current * 100 / total
	return fmt.Sprintf("%s %s", paint(colors, bar, ansiCyan), paint(colors, fmt.Sprintf("%3d%%", percentage), ansiBold, ansiWhite))
}
