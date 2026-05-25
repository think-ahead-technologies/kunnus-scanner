// ABOUTME: Wires the `kunnus upload` subcommand for pushing an SBOM to the Kunnus platform.
// ABOUTME: All HTTP behaviour lives in internal/upload; this file is just flag plumbing.
package command

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/think-ahead/kunnus-scanner/internal/upload"
)

// uploadCmd returns the `kunnus upload` command.
func uploadCmd() *cli.Command {
	return &cli.Command{
		Name:      "upload",
		Usage:     "upload an SBOM file to the Kunnus platform",
		ArgsUsage: "<sbom-file>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "url",
				Value:   upload.DefaultURL,
				Sources: cli.EnvVars("KUNNUS_UPLOAD_URL"),
				Usage:   "upload endpoint",
			},
			&cli.StringFlag{
				Name:     "api-key",
				Required: true,
				Sources:  cli.EnvVars("KUNNUS_API_KEY"),
				Usage:    "API key for the Kunnus platform",
			},
			&cli.StringFlag{
				Name:    "component-id",
				Sources: cli.EnvVars("KUNNUS_COMPONENT_ID"),
				Usage:   "associate the SBOM with this component on the platform",
			},
		},
		Action: runUpload,
	}
}

func runUpload(ctx context.Context, cmd *cli.Command) error {
	file := cmd.Args().First()
	if file == "" {
		return errors.New("missing sbom file argument")
	}

	body, err := upload.Do(ctx, upload.Options{
		URL:         cmd.String("url"),
		APIKey:      cmd.String("api-key"),
		ComponentID: cmd.String("component-id"),
		File:        file,
	})
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintln(os.Stdout, string(body))
	return nil
}
