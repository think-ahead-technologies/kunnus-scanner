// ABOUTME: Wires the `kunnus sbom container` subcommand: SBOM generation for a container image.
// ABOUTME: Owns its flags; the shared scan-and-encode pipeline (runScan) handles the rest.
package command

import (
	"context"

	"github.com/urfave/cli/v3"

	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/mode/container"
)

func sbomContainer() *cli.Command {
	return &cli.Command{
		Name:      "container",
		Aliases:   []string{"image"},
		Usage:     "generate an SBOM for a container image",
		ArgsUsage: "<image-ref | tarball-path>",
		Flags: append(commonSBOMFlags(),
			&cli.StringFlag{
				Name:  "source",
				Usage: "image source: auto | remote | tarball | docker",
				Value: "auto",
			},
		),
		Action: runContainerScan,
	}
}

func runContainerScan(ctx context.Context, cmd *cli.Command) error {
	ov := mode.Overrides{
		Source:         cmd.String("source"),
		EnablePlugins:  cmd.StringSlice("enable"),
		DisablePlugins: cmd.StringSlice("disable"),
		OnlineLicenses: cmd.Bool("online-licenses"),
	}
	return runScan(ctx, cmd, container.New(), cmd.Args().First(), ov)
}
