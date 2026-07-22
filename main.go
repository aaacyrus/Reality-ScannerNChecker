package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	application "github.com/aaacyrus/Reality-ScannerNChecker/internal/app"
	"github.com/aaacyrus/Reality-ScannerNChecker/internal/ui"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	console := ui.NewConsole(os.Stdin, os.Stdout, isCharacterDevice(os.Stdout))
	program, err := application.New(console)
	if err == nil {
		err = program.Run(ctx)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func isCharacterDevice(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
