// ABOUTME: Shell-completion candidates for every command in the tree.
// ABOUTME: Completes subcommand and flag aliases, and leaves paths to the shell's file completion.
package command

import (
	"context"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/urfave/cli/v3"
)

// installCompletion gives cmd and every subcommand below it our completion
// candidates in place of urfave/cli's default.
func installCompletion(cmd *cli.Command) {
	cmd.ShellComplete = completeCommand
	for _, sub := range cmd.Commands {
		installCompletion(sub)
	}
}

// completeCommand prints the candidates for the word the shell is completing,
// in cli's `token:description` format. Every generated script filters the list
// by what has been typed, so we print the full set for the current command.
//
// It replaces cli.DefaultCompleteWithFlags for three reasons. The default
// prints each subcommand's Name only, so the `sbom image` alias never
// completes even though it dispatches. It prints the built-in help command
// everywhere, including on leaf commands — making `help` the sole candidate
// for `kunnus sbom repo <TAB>`, which crowds out path completion for the one
// argument that command actually takes (the scripts fall back to file
// completion only when we print nothing). And it reads the root command's
// request straight from os.Args, which no in-process test can drive.
func completeCommand(_ context.Context, cmd *cli.Command) {
	out := cmd.Root().Writer

	// The scripts append the sentinel flag, which cli strips before parsing,
	// so the word under the cursor is whatever argument is left last.
	args := cmd.Args().Slice()
	if len(args) > 0 && strings.HasPrefix(args[len(args)-1], "-") {
		completeFlags(out, cmd)
		return
	}
	completeSubcommands(out, cmd)
}

// completeSubcommands prints every spelling that dispatches — names and
// aliases alike. The built-in help command is left out: it is machinery, not
// one of the choices on offer, and on a leaf command it would be the only
// candidate and so suppress the shell's own path completion.
func completeSubcommands(out io.Writer, cmd *cli.Command) {
	for _, sub := range cmd.VisibleCommands() {
		if sub.HasName("help") {
			continue
		}
		for _, name := range sub.Names() {
			printCandidate(out, name, sub.Usage)
		}
	}
}

// completeFlags prints the current command's flags, each with the leading
// dashes the user would type.
func completeFlags(out io.Writer, cmd *cli.Command) {
	for _, flag := range cmd.Flags {
		if visible, ok := flag.(cli.VisibleFlag); ok && !visible.IsVisible() {
			continue
		}
		usage := ""
		if documented, ok := flag.(cli.DocGenerationFlag); ok {
			usage = documented.GetUsage()
		}
		for _, name := range flag.Names() {
			dashes := "--"
			if utf8.RuneCountInString(name) == 1 {
				dashes = "-"
			}
			printCandidate(out, dashes+name, usage)
		}
	}
}

// printCandidate writes one `token:description` line, or a bare token when
// there is no description to show.
func printCandidate(out io.Writer, token, usage string) {
	if usage == "" {
		_, _ = fmt.Fprintln(out, token)
		return
	}
	_, _ = fmt.Fprintf(out, "%s:%s\n", token, usage)
}
