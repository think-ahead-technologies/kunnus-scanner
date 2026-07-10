// ABOUTME: CMSIS extractor — surfaces Open-CMSIS-Pack software packs declared in *.csolution.yml solution files.
// ABOUTME: A kunnus filesystem.Extractor (no scalibr plugin exists for CMSIS): each Vendor::Pack spec -> a vendor-namespaced pkg:generic package.
package cmsis

import (
	"context"
	"io"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name is the scalibr plugin name for the CMSIS extractor. It is a
// kunnus-native extractor appended directly by mode/repo (like modustoolbox),
// not a name in scalibr's registry.
const Name = "kunnus/cmsis"

// The csolution file suffixes (the filename is <solution-name>.csolution.yml).
var solutionSuffixes = []string{".csolution.yml", ".csolution.yaml"}

// maxFileBytes bounds how much of a matched file we read.
const maxFileBytes = 1 << 20 // 1 MiB

// Extractor surfaces CMSIS software packs. A csolution file's solution.packs
// list declares each pack the build consumes as "Vendor::Pack[@constraint]" —
// CMSIS-DFPs, RTOS kernels, middleware — which map to vendor-namespaced
// pkg:generic packages with the constraint kept verbatim (resolving a range
// needs the pack index, i.e. network access the scanner forbids). Packs with a
// local "path:" are in-development code, not third-party components, and
// wildcard selections ("NXP::*") name no single component; both are dropped.
type Extractor struct{}

// New returns a CMSIS extractor.
func New() *Extractor { return &Extractor{} }

// Name returns the kunnus plugin name.
func (*Extractor) Name() string { return Name }

// Version is the plugin version, bumped on behavioural changes.
func (*Extractor) Version() int { return 0 }

// Requirements declares no special capabilities: the extractor reads file bytes
// through the scan input, so it works against a host filesystem or any abstract
// FS, on any OS.
func (*Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired reports whether path is a csolution file (matched
// case-insensitively on the .csolution.yml/.csolution.yaml suffix). Project
// and layer files carry no pack declarations and do not match.
func (*Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := strings.ToLower(path.Base(api.Path()))
	for _, suffix := range solutionSuffixes {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

// Extract parses the solution's pack list and emits one package per resolvable
// spec. A malformed file yields no packages (and no error): a single bad
// csolution must not fail the scan.
func (*Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	specs := parseSolution(input.Reader)
	pkgs := make([]*extractor.Package, 0, len(specs))
	for _, s := range specs {
		pkgs = append(pkgs, &extractor.Package{
			Name:     s.name,
			Version:  s.version,
			PURLType: "generic",
			Location: extractor.LocationFromPath(input.Path),
		})
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

// pkgSpec is one declared pack: the "Vendor/Pack" namespaced name and the
// version constraint verbatim ("" when unconstrained).
type pkgSpec struct {
	name    string
	version string
}

// csolutionFile mirrors the fields the parser reads: the solution's pack list,
// each entry a mapping with the "pack" spec and an optional local "path".
type csolutionFile struct {
	Solution struct {
		Packs []struct {
			Pack string `yaml:"pack"`
			Path string `yaml:"path"`
		} `yaml:"packs"`
	} `yaml:"solution"`
}

// parseSolution reads solution.packs and returns the resolvable pack specs.
// Local-path packs are dropped (in-development code, not third-party).
func parseSolution(r io.Reader) []pkgSpec {
	data, err := io.ReadAll(io.LimitReader(r, maxFileBytes))
	if err != nil {
		return nil
	}
	var sol csolutionFile
	if err := yaml.Unmarshal(data, &sol); err != nil {
		return nil
	}
	var specs []pkgSpec
	for _, p := range sol.Solution.Packs {
		if p.Path != "" {
			continue
		}
		if s := parsePackSpec(p.Pack); s != nil {
			specs = append(specs, *s)
		}
	}
	return specs
}

// parsePackSpec parses one "Vendor::Pack[@constraint]" spec into a
// vendor-namespaced package. Wildcard selections (a "*" anywhere in the
// vendor/pack part) name no single component and yield nil, as do specs
// missing either side of the "::" separator. The constraint (exact version,
// ^range, >=floor) is kept verbatim.
func parsePackSpec(spec string) *pkgSpec {
	spec = strings.TrimSpace(spec)
	name, version, _ := strings.Cut(spec, "@")
	name = strings.TrimSpace(name)
	if strings.Contains(name, "*") {
		return nil
	}
	vendor, pack, ok := strings.Cut(name, "::")
	vendor, pack = strings.TrimSpace(vendor), strings.TrimSpace(pack)
	if !ok || vendor == "" || pack == "" {
		return nil
	}
	// A slash in either part would corrupt the vendor/pack purl namespace.
	if strings.ContainsRune(vendor, '/') || strings.ContainsRune(pack, '/') {
		return nil
	}
	return &pkgSpec{name: vendor + "/" + pack, version: strings.TrimSpace(version)}
}
