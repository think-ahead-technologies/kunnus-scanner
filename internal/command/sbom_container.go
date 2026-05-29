// ABOUTME: Wires the `kunnus sbom container` subcommand: SBOM generation for a container image.
// ABOUTME: Resolves the image (registry pull, tarball, or local docker) then scans its layers.
package command

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/mode/container"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
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
	ref := cmd.Args().First()
	if ref == "" {
		return fmt.Errorf("a container image reference or tarball path is required")
	}
	ov := mode.Overrides{
		EnablePlugins:  cmd.StringSlice("enable"),
		DisablePlugins: cmd.StringSlice("disable"),
	}

	plan, err := container.Open(ctx, ref, container.Source(cmd.String("source")), ov)
	if err != nil {
		return fmt.Errorf("open image: %w", err)
	}

	result, err := scan.RunContainer(ctx, plan.Image, plan.Config)
	if err != nil {
		return fmt.Errorf("run container scan: %w", err)
	}

	// Container scans harvest no native digests of their own and add no extra
	// components; scalibr's per-package hashes ride in the inventory.
	return encodeResult(cmd, result, plan.Component, nil, nil)
}
