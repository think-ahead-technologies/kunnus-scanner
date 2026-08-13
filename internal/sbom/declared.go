// ABOUTME: Stage: drops manifest-declared version ranges that a resolved lockfile in the same project already pins.
// ABOUTME: Two extractors read one dependency — the manifest's range and the lock's pin — so it would be counted twice.
package sbom

import (
	"path"
	"regexp"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// declaredRule describes one ecosystem's manifest/lockfile pair: which files
// declare a requirement, which resolve it, and how that ecosystem compares
// package names. One rule per purl type.
//
// A rule exists only where the lockfile's authority is a *directory* — NuGet's
// packages.lock.json is opt-in per project, and a python lockfile speaks for the
// project it sits in, not for every requirements file in the repository. Cargo
// is deliberately absent: a Cargo.lock resolves its whole workspace, so the
// redundant extractor is stood down at plan time instead (see
// ecosystem.Ecosystem.Supersedes) and no phantom component is created at all.
// Prefer that mechanism whenever a lockfile's scope is the whole scan.
type declaredRule struct {
	// purlType is the PURL type this rule governs; components of any other type
	// are never touched.
	purlType string
	// locks are the resolved-lockfile basenames whose entries are authoritative.
	locks []string
	// isManifest reports whether a basename is a file that merely *declares*
	// requirements. It must accept exactly the files the declaring extractor
	// reads, so a file kunnus cannot recognise is never mistaken for a manifest.
	isManifest func(base string) bool
	// lockDirSpeaksForParent names the directory basenames a lockfile may sit in
	// while still resolving the manifests of the directory *above* it — for a
	// build tool that writes its resolved output into a subdirectory of the
	// project it belongs to. Empty for locks that sit beside their manifests.
	lockDirSpeaksForParent []string
}

var declaredRules = []declaredRule{
	{
		// scalibr's dotnet/csproj reads MSBuild project files and dotnet/nugetcpm
		// the central-package-management props; both carry declared versions
		// (floating "13.0.*", ranges "[3.0.0,4.0.0)") that packages.lock.json
		// resolves to a single pin.
		purlType: "nuget",
		locks:    []string{"packages.lock.json", "project.assets.json"},
		isManifest: func(base string) bool {
			switch path.Ext(base) {
			case ".csproj", ".vbproj", ".fsproj":
				return true
			}
			return base == "Directory.Packages.props" || base == "Directory.Build.props"
		},
		// NuGet restore writes project.assets.json into the project's
		// intermediate output directory — obj/ unless BaseIntermediateOutputPath
		// says otherwise — so the file that resolves ProjA/ProjA.csproj is
		// ProjA/obj/project.assets.json. A custom output path simply means no
		// suppression, which lists a dependency twice rather than losing one.
		lockDirSpeaksForParent: []string{"obj"},
	},
	{
		// scalibr's python/requirements reads any *requirements*.txt and
		// python/pyprojecttoml the PEP 621 [project.dependencies] and
		// [project.optional-dependencies] tables; both report a constraint's
		// floor as the version (">=2.0" becomes "2.0"), or no version at all for
		// a bare requirement. Every python lockfile kunnus detects resolves those
		// to real pins.
		purlType: "pypi",
		locks:    []string{"uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock", "pylock.toml"},
		isManifest: func(base string) bool {
			if base == "pyproject.toml" {
				return true
			}
			return path.Ext(base) == ".txt" && strings.Contains(base, "requirements")
		},
	},
}

// suppressResolvedDeclarations removes every component that exists only as a
// manifest-declared requirement which a lockfile in the same project has already
// resolved. The two extractors report the same dependency under different
// versions — the declared range and the resolved pin — so their PURLs differ,
// dedup cannot collapse them, and the dependency is counted twice: once with a
// version that was never released, carrying a CPE that matches no advisory.
//
// The pin is authoritative. A declared component is dropped only when both
// signals agree:
//
//   - Coverage (path): every location it was found at is a manifest in, or
//     below, a directory holding one of the ecosystem's lockfiles — so a
//     resolver ran over that manifest.
//   - Pinned (name): a component extracted from such a lockfile carries the same
//     package name, under that ecosystem's name-equivalence rules, proving the
//     resolution really includes this package.
//
// Requiring both keeps every honest case. A project that never opted into a
// lockfile keeps its declarations (no lock above its manifest), a docs
// requirements file keeps the packages its project's lock does not resolve (no
// pin of that name), and a conditional dependency the resolver never saw
// survives with its range and its unknown-information markers.
func suppressResolvedDeclarations(bom *cyclonedx.BOM) {
	if bom == nil || bom.Components == nil {
		return
	}
	comps := *bom.Components

	for i := range declaredRules {
		rule := &declaredRules[i]
		lockDirs, pinned := resolvedBy(comps, rule)
		if len(lockDirs) == 0 {
			continue
		}
		out := make([]cyclonedx.Component, 0, len(comps))
		for j := range comps {
			c := comps[j]
			if purlType(c.PackageURL) == rule.purlType &&
				pinned[normalizePackageName(rule.purlType, c.Name)] &&
				declaredUnderLock(c, rule, lockDirs) {
				continue
			}
			out = append(out, c)
		}
		comps = out
	}

	*bom.Components = comps
}

// resolvedBy indexes what the ecosystem's lockfiles resolved: the directories
// they sit in, and the normalized names they pin.
func resolvedBy(comps []cyclonedx.Component, rule *declaredRule) (lockDirs map[string]bool, pinned map[string]bool) {
	lockDirs = make(map[string]bool)
	pinned = make(map[string]bool)
	for i := range comps {
		if purlType(comps[i].PackageURL) != rule.purlType {
			continue
		}
		for _, loc := range occurrenceLocations(comps[i]) {
			if !containsFold(rule.locks, path.Base(loc)) {
				continue
			}
			dir := path.Dir(loc)
			lockDirs[dir] = true
			// A lock written into the project's build output directory resolves
			// the manifests of the project itself, which sits one level up.
			if containsFold(rule.lockDirSpeaksForParent, path.Base(dir)) {
				lockDirs[path.Dir(dir)] = true
			}
			pinned[normalizePackageName(rule.purlType, comps[i].Name)] = true
		}
	}
	return lockDirs, pinned
}

// declaredUnderLock reports whether every location the component was found at is
// a manifest covered by a lockfile. A component with no locations, or with any
// location a lockfile does not cover (a manifest outside every lock's tree, or a
// lockfile itself), is not a purely declared one.
func declaredUnderLock(c cyclonedx.Component, rule *declaredRule, lockDirs map[string]bool) bool {
	locs := occurrenceLocations(c)
	if len(locs) == 0 {
		return false
	}
	for _, loc := range locs {
		if !rule.isManifest(path.Base(loc)) || !lockCoversDir(path.Dir(loc), lockDirs) {
			return false
		}
	}
	return true
}

// lockCoversDir reports whether dir, or one of its ancestors, holds a lockfile.
func lockCoversDir(dir string, lockDirs map[string]bool) bool {
	for {
		if lockDirs[dir] {
			return true
		}
		if dir == "." || dir == "/" {
			return false
		}
		dir = path.Dir(dir)
	}
}

// pypiSeparators matches a run of the characters PEP 503 treats as one separator.
var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// normalizePackageName folds a package name to the form its ecosystem considers
// equal. NuGet ids are case-insensitive; PyPI names additionally treat runs of
// "-", "_" and "." as one separator (PEP 503), so a requirements file's
// "Ruamel.YAML" and a lockfile's "ruamel-yaml" are the same package.
func normalizePackageName(purlType, name string) string {
	lower := strings.ToLower(name)
	if purlType == "pypi" {
		return pypiSeparators.ReplaceAllString(lower, "-")
	}
	return lower
}

// occurrenceLocations returns the component's evidence locations, normalized to
// slash-separated paths (scalibr reports forward slashes; a Windows scan root can
// still surface a backslash).
func occurrenceLocations(c cyclonedx.Component) []string {
	if c.Evidence == nil || c.Evidence.Occurrences == nil {
		return nil
	}
	locs := make([]string, 0, len(*c.Evidence.Occurrences))
	for _, occ := range *c.Evidence.Occurrences {
		locs = append(locs, strings.ReplaceAll(occ.Location, `\`, "/"))
	}
	return locs
}

// containsFold reports whether names contains target, case-insensitively —
// lockfile basenames are fixed strings, but a filesystem may have preserved a
// different case than the tool that wrote them.
func containsFold(names []string, target string) bool {
	for _, n := range names {
		if strings.EqualFold(n, target) {
			return true
		}
	}
	return false
}
