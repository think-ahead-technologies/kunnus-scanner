// ABOUTME: Action for commands that exist only to dispatch to subcommands.
// ABOUTME: Reports an unknown argument by name and lists the subcommands that would work.
package command

import (
	"context"
	"fmt"
	"strings"

	"github.com/urfave/cli/v3"
)

// dispatchOnly handles the leftover argument of a command that has no scan
// action of its own. urfave/cli's default here is its help lookup, which
// reports "No help topic for '<arg>'" — true, but it neither says the argument
// was meant to be a subcommand nor names the ones that exist.
func dispatchOnly(_ context.Context, cmd *cli.Command) error {
	arg := cmd.Args().First()
	if arg == "" {
		if cmd.Root() == cmd {
			return cli.ShowRootCommandHelp(cmd)
		}
		return cli.ShowSubcommandHelp(cmd)
	}
	return fmt.Errorf("unknown command %q for %q, please use: %s",
		arg, cmd.FullName(), strings.Join(subcommandNames(cmd), ", "))
}

// subcommandNames lists every spelling that dispatches — names and aliases
// alike, so `sbom image` is as discoverable as `sbom container`. The built-in
// help command is left out: it is machinery, not one of the choices on offer.
func subcommandNames(cmd *cli.Command) []string {
	var names []string
	for _, sub := range cmd.VisibleCommands() {
		if sub.HasName("help") {
			continue
		}
		names = append(names, sub.Names()...)
	}
	return names
}
