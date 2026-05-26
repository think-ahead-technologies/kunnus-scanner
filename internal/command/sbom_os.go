// ABOUTME: Wires the `kunnus sbom os` subcommand: OS-package / firmware SBOM generation.
// ABOUTME: Adds the --target-os override for cross-platform scanning (e.g. firmware-on-Mac).
package command

import (
	"context"
	"runtime"

	"github.com/urfave/cli/v3"

	"github.com/think-ahead/kunnus-scanner/internal/mode"
	osmode "github.com/think-ahead/kunnus-scanner/internal/mode/os"
)

func sbomOS() *cli.Command {
	return &cli.Command{
		Name:      "os",
		Usage:     "generate an SBOM for an OS or firmware image",
		ArgsUsage: "[path] (default: filesystem root)",
		Flags: append(commonSBOMFlags(),
			&cli.StringFlag{
				Name:  "target-os",
				Usage: "override host OS auto-detection (linux | windows | mac)",
			},
		),
		Action: runOSScan,
	}
}

func runOSScan(ctx context.Context, cmd *cli.Command) error {
	path := cmd.Args().First()
	if path == "" {
		path = defaultOSScanRoot()
	}
	ov := mode.Overrides{
		TargetOS:       cmd.String("target-os"),
		EnablePlugins:  cmd.StringSlice("enable"),
		DisablePlugins: cmd.StringSlice("disable"),
	}
	return runScan(ctx, cmd, osmode.New(), path, ov, nil)
}

func defaultOSScanRoot() string {
	if runtime.GOOS == "windows" {
		return `C:\`
	}
	return "/"
}
