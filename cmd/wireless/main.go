// Command wireless is the multi-controller wireless operations tool.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/gatework/wireless/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	home, _ := os.UserHomeDir()
	code := cli.Run(ctx, os.Args[1:], cli.Env{
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Environ: os.Environ(), Home: home,
		Interactive: term.IsTerminal(int(os.Stdin.Fd())),
	})
	stop()
	os.Exit(code)
}
