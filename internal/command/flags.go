// ABOUTME: Flags shared across the sbom repo / os subcommands.
// ABOUTME: Keeps both subcommand files focused on their unique target-selection logic.
package command

import "github.com/urfave/cli/v3"

// commonSBOMFlags are the flags accepted by every sbom subcommand.
// Output format is CycloneDX 1.6 (BSI-conformant).
func commonSBOMFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "output",
			Aliases: []string{"o"},
			Usage:   "write SBOM to file (default: stdout)",
		},
		&cli.StringSliceFlag{
			Name:  "enable",
			Usage: "add a scalibr plugin by name (repeatable)",
		},
		&cli.StringSliceFlag{
			Name:  "disable",
			Usage: "remove a scalibr plugin by name (repeatable)",
		},
		&cli.BoolFlag{
			Name:  "online-licenses",
			Usage: "look up component licences via deps.dev (requires network; off by default)",
		},
		&cli.StringFlag{
			Name:    "component-id",
			Sources: cli.EnvVars("KUNNUS_COMPONENT_ID"),
			Usage:   "stable component identity; scans sharing an id and version reuse one SBOM serialNumber (a document series)",
		},
		&cli.StringFlag{
			Name:    "component-version",
			Sources: cli.EnvVars("KUNNUS_COMPONENT_VERSION"),
			Usage:   "component version for the SBOM root component and the serial-number series",
		},
		&cli.StringFlag{
			Name:    "serial-number",
			Sources: cli.EnvVars("KUNNUS_SERIAL_NUMBER"),
			Usage:   "explicit SBOM serialNumber (UUID, bare or urn:uuid form); overrides derivation from --component-id",
		},
	}
}
