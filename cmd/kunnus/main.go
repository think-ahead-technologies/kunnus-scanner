// ABOUTME: Entry point for the kunnus CLI binary.
// ABOUTME: Wires signal handling and delegates everything else to internal/command.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/think-ahead/kunnus-scanner/internal/command"
)

// Populated by goreleaser at build time.
var (
	commit = "n/a"
	date   = "n/a"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return command.Run(ctx, os.Args, commit, date)
}
