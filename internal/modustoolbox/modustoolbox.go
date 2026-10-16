// ABOUTME: ModusToolbox extractor — surfaces Infineon/Cypress embedded dependencies declared in .mtb manifest files.
// ABOUTME: A kunnus filesystem.Extractor (no scalibr plugin exists for ModusToolbox): each .mtb names a GitHub repo + git ref -> a pkg:github package.
package modustoolbox

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name is the scalibr plugin name for the ModusToolbox extractor. It is a
// kunnus-native extractor appended directly by the modes (like binclass), not a
// name in scalibr's registry.
const Name = "kunnus/modustoolbox"

// mtbSuffix is the marker extension ModusToolbox writes for each dependency.
// A .mtb file holds a single line: "<git-url>#<ref>#<storage-location>".
const mtbSuffix = ".mtb"

// maxLineBytes bounds how much of a matched file we read while looking for the
// manifest line. A real .mtb is one short line; this guards against a file that
// merely shares the suffix being slurped whole.
const maxLineBytes = 64 << 10 // 64 KiB

// Extractor surfaces ModusToolbox dependencies. Each .mtb manifest names a
// GitHub repository and the git ref the project pins, which map directly to a
// pkg:github package. ModusToolbox has no scalibr extractor, so this is the only
// path that turns an embedded-firmware dependency tree into SBOM components.
type Extractor struct{}

// New returns a ModusToolbox extractor.
func New() *Extractor { return &Extractor{} }

// Name returns the kunnus plugin name.
func (*Extractor) Name() string { return Name }

// Version is the plugin version, bumped on behavioural changes.
func (*Extractor) Version() int { return 0 }

// Requirements declares no special capabilities: the extractor reads file bytes
// through the scan input, so it works against a host filesystem or any abstract
// FS, on any OS.
func (*Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired reports whether path is a ModusToolbox manifest (a *.mtb file).
// The suffix is matched case-insensitively; ".mtbqueryapi" and other longer
// suffixes do not match.
func (*Extractor) FileRequired(api filesystem.FileAPI) bool {
	return strings.HasSuffix(strings.ToLower(api.Path()), mtbSuffix)
}

// Extract reads the manifest's single line and, if it names a GitHub repo at a
// git ref, emits one pkg:github package. A malformed or non-github manifest
// yields no package (and no error): a single bad .mtb must not fail the scan.
//
// Running past maxLineBytes without finding a manifest line is the one case
// that does return an error. It is not a malformed manifest but an unread one —
// the file was cut off rather than understood — and scalibr surfaces that as a
// per-plugin status instead of letting it read as "this .mtb declares nothing".
func (*Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	sc := bufio.NewScanner(input.Reader)
	sc.Buffer(make([]byte, 0, 4096), maxLineBytes)
	for sc.Scan() {
		ref := parseLine(sc.Text())
		if ref == nil {
			continue
		}
		return inventory.Inventory{Packages: []*extractor.Package{{
			Name:     ref.name,
			Version:  ref.version,
			PURLType: "github",
			Location: extractor.LocationFromPath(input.Path),
		}}}, nil
	}
	if err := sc.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("read %s: %w", input.Path, err)
	}
	return inventory.Inventory{}, nil
}

// mtbRef is the GitHub coordinate parsed from a .mtb line: name is the
// "owner/repo" namespaced form (kunnus's purl-normalisation step decodes the
// embedded slash on output), version is the git ref verbatim.
type mtbRef struct {
	name    string
	version string
}

// parseLine parses one .mtb manifest line of the form
//
//	https://github.com/<owner>/<repo>[.git]#<ref>#<storage-location>
//
// returning the GitHub coordinate, or nil if the line is blank, not a GitHub
// URL, or missing the owner/repo/ref it needs to form a package. The storage
// location (third field) is ModusToolbox bookkeeping and is ignored.
func parseLine(line string) *mtbRef {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	rawURL, rest, ok := strings.Cut(line, "#")
	if !ok {
		return nil // no ref segment
	}
	ref, _, _ := strings.Cut(rest, "#") // drop the trailing storage location
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || !strings.EqualFold(u.Host, "github.com") {
		return nil
	}
	owner, repo, ok := strings.Cut(strings.Trim(u.Path, "/"), "/")
	if !ok || owner == "" || repo == "" {
		return nil
	}
	repo = strings.TrimSuffix(repo, ".git")
	// A repo path can carry further segments (e.g. /owner/repo/tree/...); keep
	// only the first, which is the repository name.
	repo, _, _ = strings.Cut(repo, "/")
	if repo == "" {
		return nil
	}
	return &mtbRef{name: path.Join(owner, repo), version: ref}
}
