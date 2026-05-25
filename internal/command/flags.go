// ABOUTME: Flags and helpers shared across the sbom repo / os subcommands.
// ABOUTME: Keeps both subcommand files focused on their unique target-selection logic.
package command

import (
	"context"
	"io"

	"github.com/urfave/cli/v3"

	scalibr "github.com/google/osv-scalibr"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/sbom"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
)

// commonSBOMFlags are the flags accepted by every sbom subcommand.
// Output format is CycloneDX 1.7 (BSI TR-03183-2 v2.1 compliant); we do not
// expose a format flag because there is only one supported format.
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
	}
}

// scanRun is a thin shim so subcommands don't import the scan package directly.
func scanRun(ctx context.Context, cfg *scalibr.ScanConfig, logOut io.Writer) (*scan.Result, error) {
	return scan.Run(ctx, cfg, logOut)
}

// encodeSBOM is a thin shim so subcommands don't import the sbom package directly.
// hashMap is optional native-hash data harvested from lockfiles under the scan
// root; pass nil for OS-mode scans where no lockfiles exist.
func encodeSBOM(out io.Writer, result *scan.Result, comp mode.ComponentInfo, hashMap hashes.Map) error {
	return sbom.Encode(out, result, comp, hashMap)
}

// collectLockfileHashes is a thin shim that re-parses lockfiles under root
// for SHA-512 deployable hashes. Empty/missing lockfiles produce an empty map.
func collectLockfileHashes(root string) hashes.Map {
	return hashes.FromLockfiles(root)
}
