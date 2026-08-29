// ABOUTME: Flags shared across the sbom repo / os subcommands.
// ABOUTME: Keeps both subcommand files focused on their unique target-selection logic.
package command

import (
	"fmt"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
)

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
			Name:    "author",
			Sources: cli.EnvVars("KUNNUS_AUTHOR"),
			Usage:   "SBOM author: the entity running the scan, as \"Name\" or \"Name <email>\" (default: the kunnus creator identity)",
		},
		&cli.StringFlag{
			Name:    "serial-number",
			Sources: cli.EnvVars("KUNNUS_SERIAL_NUMBER"),
			Usage:   "explicit SBOM serialNumber (UUID, bare or urn:uuid form); overrides derivation from --component-id",
		},
	}
}

// parseAuthor parses the --author flag value: a display name optionally
// followed by an email in angle brackets ("ACME GmbH <psirt@acme.example>").
// An empty value yields the zero Author.
func parseAuthor(s string) (bom.Author, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return bom.Author{}, nil
	}
	open := strings.IndexByte(s, '<')
	if open < 0 {
		if strings.ContainsRune(s, '>') {
			return bom.Author{}, fmt.Errorf("malformed author %q: '>' without '<'", s)
		}
		return bom.Author{Name: s}, nil
	}
	if !strings.HasSuffix(s, ">") {
		return bom.Author{}, fmt.Errorf("malformed author %q: expected \"Name <email>\"", s)
	}
	name := strings.TrimSpace(s[:open])
	email := strings.TrimSpace(s[open+1 : len(s)-1])
	if name == "" {
		return bom.Author{}, fmt.Errorf("malformed author %q: a name is required before the <email>", s)
	}
	if email == "" {
		return bom.Author{}, fmt.Errorf("malformed author %q: empty <email>", s)
	}
	return bom.Author{Name: name, Email: email}, nil
}

// flagForRequestField maps an app.Request field the use case can reject to the
// flag that carried its value, so a validation failure is reported in the
// user's vocabulary rather than the application service's.
var flagForRequestField = map[string]string{
	"SerialNumber": "serial-number",
}
