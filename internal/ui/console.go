package ui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aaacyrus/Reality-ScannerNChecker/internal/domain"
	"github.com/aaacyrus/Reality-ScannerNChecker/internal/i18n"
)

type Console struct {
	out         io.Writer
	lines       <-chan string
	interactive bool
	colors      bool
	translator  i18n.Translator
	mu          sync.Mutex
	progress    bool
}

func NewConsole(in io.Reader, out io.Writer, interactive bool) *Console {
	lines := make(chan string, 8)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(in)
		for scanner.Scan() {
			lines <- strings.TrimSpace(scanner.Text())
		}
	}()
	dynamic := interactive && strings.ToLower(os.Getenv("TERM")) != "dumb"
	colors := dynamic && os.Getenv("NO_COLOR") == ""
	return &Console{out: out, lines: lines, interactive: dynamic, colors: colors}
}

func (c *Console) SetLanguage(language domain.Language) {
	c.translator = i18n.Translator{Language: language}
}

func (c *Console) Translator() i18n.Translator { return c.translator }

func (c *Console) Interactive() bool { return c.interactive }

func (c *Console) ColorsEnabled() bool { return c.colors }

func (c *Console) clearProgressLocked() {
	if c.progress && c.interactive {
		fmt.Fprint(c.out, "\r\x1b[2K")
	}
	c.progress = false
}

func (c *Console) Printf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearProgressLocked()
	fmt.Fprintf(c.out, format, args...)
}

func (c *Console) Println(values ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearProgressLocked()
	fmt.Fprintln(c.out, values...)
}

func (c *Console) Tln(key string, args ...any) {
	c.Println(c.translator.T(key, args...))
}

func (c *Console) Banner(title, subtitle string) {
	const width = 72
	border := paint(c.colors, strings.Repeat("─", width-2), ansiCyan)
	title, titlePadding := fitBannerText("◆ "+strings.ToUpper(title), width)
	subtitle, subtitlePadding := fitBannerText("  "+subtitle, width)
	c.Println(paint(c.colors, "╭", ansiCyan) + border + paint(c.colors, "╮", ansiCyan))
	c.Println(paint(c.colors, "│ ", ansiCyan) + paint(c.colors, title[:len("◆ ")], ansiBold, ansiMagenta) + paint(c.colors, title[len("◆ "):], ansiBold, ansiWhite) + strings.Repeat(" ", titlePadding) + paint(c.colors, " │", ansiCyan))
	c.Println(paint(c.colors, "│ ", ansiCyan) + paint(c.colors, subtitle, ansiDim, ansiCyan) + strings.Repeat(" ", subtitlePadding) + paint(c.colors, " │", ansiCyan))
	c.Println(paint(c.colors, "╰", ansiCyan) + border + paint(c.colors, "╯", ansiCyan))
}

func (c *Console) Section(title string) {
	label := "◆ " + title + " "
	remaining := max(3, 72-3-displayWidth(label))
	c.Println()
	c.Println(paint(c.colors, "┌─ ", ansiCyan) + paint(c.colors, label, ansiBold, ansiWhite) + paint(c.colors, strings.Repeat("─", remaining), ansiCyan))
}

func (c *Console) TSection(key string, args ...any) {
	c.Section(c.translator.T(key, args...))
}

func (c *Console) Status(tone Tone, text string) {
	icon, color := toneStyle(tone)
	c.Println(paint(c.colors, icon, ansiBold, color) + " " + text)
}

func (c *Console) TStatus(tone Tone, key string, args ...any) {
	c.Status(tone, c.translator.T(key, args...))
}

func (c *Console) Menu(text string) {
	c.Println(menuText(text, c.colors))
}

func (c *Console) TMenu(key string, args ...any) {
	c.Menu(c.translator.T(key, args...))
}

func (c *Console) Progress(text string) {
	c.ProgressBar(text, 0, 0)
}

func (c *Console) ProgressBar(text string, current, total int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.interactive {
		frames := [...]string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		frame := frames[(time.Now().UnixMilli()/80)%int64(len(frames))]
		bar := progressBar(current, total, 22, c.colors)
		if bar != "" {
			bar += "  "
		}
		fmt.Fprintf(c.out, "\r\x1b[2K%s %s%s", paint(c.colors, frame, ansiBold, ansiMagenta), bar, text)
		c.progress = true
		return
	}
	fmt.Fprintln(c.out, text)
}

// StartSpinner animates a status line until the returned stop function is called.
func (c *Console) StartSpinner(text string) func() {
	if !c.interactive {
		c.Println(text)
		return func() {}
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	c.Progress(text)
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				c.Progress(text)
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
			<-stopped
			c.FinishProgress()
		})
	}
}

func (c *Console) FinishProgress() {
	if !c.interactive {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearProgressLocked()
}

func (c *Console) Read(ctx context.Context, prompt, defaultValue string) (string, bool) {
	c.Printf("%s", paint(c.colors, prompt, ansiBold, ansiCyan))
	select {
	case <-ctx.Done():
		return "", false
	case line, ok := <-c.lines:
		if !ok {
			return "", false
		}
		if line == "" {
			return defaultValue, true
		}
		return line, true
	}
}

func (c *Console) Choice(ctx context.Context, prompt string, defaultValue int, allowed ...int) (int, bool) {
	set := make(map[int]struct{}, len(allowed))
	for _, value := range allowed {
		set[value] = struct{}{}
	}
	for {
		line, ok := c.Read(ctx, prompt, strconv.Itoa(defaultValue))
		if !ok {
			return 0, false
		}
		value, err := strconv.Atoi(line)
		if err == nil {
			if _, exists := set[value]; exists {
				return value, true
			}
		}
		c.Tln("invalid_number")
	}
}

func (c *Console) Commands() <-chan string { return c.lines }
