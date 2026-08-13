// ABOUTME: Tests for the stage that drops manifest-declared version ranges a resolved lockfile already pins.
// ABOUTME: Covers the two required signals (a lock covers the manifest path, the lock pins the same name) per ecosystem.
package sbom

import (
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

func TestSuppressResolvedDeclarations_Dotnet(t *testing.T) {
	// A solution where only ProjA opted into a lockfile (NuGet's
	// RestorePackagesWithLockFile is per project) — the realistic mixed case.
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		// Resolved pins from ProjA's lock.
		{Name: "Newtonsoft.Json", Version: "13.0.1", PackageURL: "pkg:nuget/Newtonsoft.Json@13.0.1", Evidence: occs("ProjA/packages.lock.json")},
		{Name: "Serilog", Version: "3.1.1", PackageURL: "pkg:nuget/Serilog@3.1.1", Evidence: occs("ProjA/packages.lock.json")},

		// ProjA's declared floating version and range — both pinned above, drop.
		{Name: "Newtonsoft.Json", Version: "13.0.*", PackageURL: "pkg:nuget/Newtonsoft.Json@13.0.%2A", Evidence: occs("ProjA/ProjA.csproj")},
		{Name: "Serilog", Version: "[3.0.0,4.0.0)", PackageURL: "pkg:nuget/Serilog@%5B3.0.0%2C4.0.0%29", Evidence: occs("ProjA/ProjA.csproj")},
		// Central package management in the same locked project — same phantom class.
		{Name: "Newtonsoft.Json", Version: "13.0.0", PackageURL: "pkg:nuget/Newtonsoft.Json@13.0.0", Evidence: occs("ProjA/Directory.Packages.props")},

		// ProjB never opted into a lockfile: its declarations are the only record
		// of its dependencies, even the one whose name ProjA's lock also pins.
		{Name: "Newtonsoft.Json", Version: "12.0.3", PackageURL: "pkg:nuget/Newtonsoft.Json@12.0.3", Evidence: occs("ProjB/ProjB.vbproj")},
		{Name: "NUnit", Version: "4.*", PackageURL: "pkg:nuget/NUnit@4.%2A", Evidence: occs("ProjB/ProjB.vbproj")},

		// Declared in the locked project but absent from the lock — a conditional
		// PackageReference the restore never resolved. Keep: nothing else records it.
		{Name: "OnlyDeclared", Version: "1.0.0", PackageURL: "pkg:nuget/OnlyDeclared@1.0.0", Evidence: occs("ProjA/ProjA.csproj")},
	}}

	suppressResolvedDeclarations(bom)

	assertPURLs(t, bom,
		[]string{
			"pkg:nuget/Newtonsoft.Json@13.0.1",
			"pkg:nuget/Serilog@3.1.1",
			"pkg:nuget/Newtonsoft.Json@12.0.3",
			"pkg:nuget/NUnit@4.%2A",
			"pkg:nuget/OnlyDeclared@1.0.0",
		},
		[]string{
			"pkg:nuget/Newtonsoft.Json@13.0.%2A",
			"pkg:nuget/Serilog@%5B3.0.0%2C4.0.0%29",
			"pkg:nuget/Newtonsoft.Json@13.0.0",
		},
	)
}

func TestSuppressResolvedDeclarations_Python(t *testing.T) {
	// A uv-locked project whose requirements.txt restates the pins, plus a
	// docs/requirements.txt listing packages the lock does not resolve.
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		{Name: "requests", Version: "2.32.3", PackageURL: "pkg:pypi/requests@2.32.3", Evidence: occs("uv.lock")},
		{Name: "urllib3", Version: "2.2.3", PackageURL: "pkg:pypi/urllib3@2.2.3", Evidence: occs("uv.lock")},
		{Name: "ruamel-yaml", Version: "0.18.6", PackageURL: "pkg:pypi/ruamel-yaml@0.18.6", Evidence: occs("uv.lock")},

		// ">=2.0" surfaced as the version "2.0", and a bare requirement with no
		// version at all: the two shapes the requirements extractor emits.
		{Name: "requests", Version: "2.0", PackageURL: "pkg:pypi/requests@2.0", Evidence: occs("requirements.txt")},
		{Name: "urllib3", PackageURL: "pkg:pypi/urllib3", Evidence: occs("requirements.txt")},
		// PyPI names are case- and separator-insensitive (PEP 503), so this is the
		// same package as the locked "ruamel-yaml".
		{Name: "Ruamel.YAML", Version: "0.18", PackageURL: "pkg:pypi/Ruamel.YAML@0.18", Evidence: occs("requirements-dev.txt")},

		// The lock resolves nothing called sphinx, so the docs requirements are
		// the only record of it.
		{Name: "sphinx", Version: "7.0", PackageURL: "pkg:pypi/sphinx@7.0", Evidence: occs("docs/requirements.txt")},
	}}

	suppressResolvedDeclarations(bom)

	assertPURLs(t, bom,
		[]string{
			"pkg:pypi/requests@2.32.3",
			"pkg:pypi/urllib3@2.2.3",
			"pkg:pypi/ruamel-yaml@0.18.6",
			"pkg:pypi/sphinx@7.0",
		},
		[]string{
			"pkg:pypi/requests@2.0",
			"pkg:pypi/urllib3",
			"pkg:pypi/Ruamel.YAML@0.18",
		},
	)
}

// TestSuppressResolvedDeclarations_DotnetProjectAssets covers NuGet's other
// resolved file: restore writes project.assets.json into the project's
// intermediate output directory (obj/ by default), one level *below* the
// .csproj whose declarations it resolves.
func TestSuppressResolvedDeclarations_DotnetProjectAssets(t *testing.T) {
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		// Resolved pins, as restore wrote them under the project.
		{Name: "Newtonsoft.Json", Version: "13.0.3", PackageURL: "pkg:nuget/Newtonsoft.Json@13.0.3", Evidence: occs("ProjA/obj/project.assets.json")},
		{Name: "Serilog", Version: "3.1.1", PackageURL: "pkg:nuget/Serilog@3.1.1", Evidence: occs("ProjA/obj/project.assets.json")},

		// The declarations that produced them, one directory up.
		{Name: "Newtonsoft.Json", Version: "13.0.*", PackageURL: "pkg:nuget/Newtonsoft.Json@13.0.%2A", Evidence: occs("ProjA/ProjA.csproj")},
		{Name: "Serilog", Version: "[3.0.0,4.0.0)", PackageURL: "pkg:nuget/Serilog@%5B3.0.0%2C4.0.0%29", Evidence: occs("ProjA/ProjA.fsproj")},

		// A sibling project that was never restored keeps its declarations.
		{Name: "Newtonsoft.Json", Version: "12.0.3", PackageURL: "pkg:nuget/Newtonsoft.Json@12.0.3", Evidence: occs("ProjB/ProjB.vbproj")},
	}}

	suppressResolvedDeclarations(bom)

	assertPURLs(t, bom,
		[]string{
			"pkg:nuget/Newtonsoft.Json@13.0.3",
			"pkg:nuget/Serilog@3.1.1",
			"pkg:nuget/Newtonsoft.Json@12.0.3",
		},
		[]string{
			"pkg:nuget/Newtonsoft.Json@13.0.%2A",
			"pkg:nuget/Serilog@%5B3.0.0%2C4.0.0%29",
		},
	)
}

// TestSuppressResolvedDeclarations_PythonPyprojectAndPylock covers the other two
// python files that carry declared ranges and resolved pins: a PEP 621
// pyproject.toml (whose [project.dependencies] the pyprojecttoml extractor
// reports at its lowest satisfying version) and a PEP 751 pylock.toml.
func TestSuppressResolvedDeclarations_PythonPyprojectAndPylock(t *testing.T) {
	// A monorepo where app/ is locked with pylock.toml and lib/ is not.
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		{Name: "httpx", Version: "0.28.1", PackageURL: "pkg:pypi/httpx@0.28.1", Evidence: occs("app/pylock.toml")},
		{Name: "anyio", Version: "4.8.0", PackageURL: "pkg:pypi/anyio@4.8.0", Evidence: occs("app/pylock.toml")},

		// app/ declares what its lock resolved — the phantom pair, both dropped.
		{Name: "httpx", Version: "0.27", PackageURL: "pkg:pypi/httpx@0.27", Evidence: occs("app/pyproject.toml")},
		{Name: "anyio", PackageURL: "pkg:pypi/anyio", Evidence: occs("app/pyproject.toml")},

		// An optional-dependency group the resolver never saw (the extra was not
		// installed), so the declaration is the only record. Keep.
		{Name: "pytest", Version: "8.0", PackageURL: "pkg:pypi/pytest@8.0", Evidence: occs("app/pyproject.toml")},

		// lib/ has no lock of its own and app/'s lock does not speak for it,
		// even though it pins the same name.
		{Name: "httpx", Version: "0.20", PackageURL: "pkg:pypi/httpx@0.20", Evidence: occs("lib/pyproject.toml")},
	}}

	suppressResolvedDeclarations(bom)

	assertPURLs(t, bom,
		[]string{
			"pkg:pypi/httpx@0.28.1",
			"pkg:pypi/anyio@4.8.0",
			"pkg:pypi/pytest@8.0",
			"pkg:pypi/httpx@0.20",
		},
		[]string{
			"pkg:pypi/httpx@0.27",
			"pkg:pypi/anyio",
		},
	)
}

// TestSuppressResolvedDeclarations_LockOutsideManifestTree proves the path
// signal is required: a lockfile in a sibling subtree does not license dropping
// another project's declarations, even when the names match.
func TestSuppressResolvedDeclarations_LockOutsideManifestTree(t *testing.T) {
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		{Name: "requests", Version: "2.32.3", PackageURL: "pkg:pypi/requests@2.32.3", Evidence: occs("service-a/poetry.lock")},
		{Name: "requests", Version: "2.0", PackageURL: "pkg:pypi/requests@2.0", Evidence: occs("service-b/requirements.txt")},
	}}

	suppressResolvedDeclarations(bom)

	assertPURLs(t, bom,
		[]string{"pkg:pypi/requests@2.32.3", "pkg:pypi/requests@2.0"},
		nil,
	)
}

// TestSuppressResolvedDeclarations_UntouchedEcosystems proves the stage only
// acts on the purl types it has a rule for. Cargo is handled at plan time
// (ecosystem.Survey supersedes rust/cargotoml), so no cargo component may be
// dropped here even though the shape matches.
func TestSuppressResolvedDeclarations_UntouchedEcosystems(t *testing.T) {
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		{Name: "anyhow", Version: "1.0.102", PackageURL: "pkg:cargo/anyhow@1.0.102", Evidence: occs("Cargo.lock")},
		{Name: "anyhow", Version: "1.0", PackageURL: "pkg:cargo/anyhow@1.0", Evidence: occs("Cargo.toml")},
		{Name: "testify", Version: "1.8.0", PackageURL: "pkg:golang/github.com/stretchr/testify@1.8.0", Evidence: occs("go.mod")},
		{Name: "no-purl", Version: "1"},
	}}

	suppressResolvedDeclarations(bom)

	if len(*bom.Components) != 4 {
		t.Errorf("got %d components, want all 4 kept", len(*bom.Components))
	}
}

// TestSuppressResolvedDeclarations_NoEvidenceKept covers the component whose
// origin nothing proves: with no evidence locations there is no path signal.
func TestSuppressResolvedDeclarations_NoEvidenceKept(t *testing.T) {
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		{Name: "requests", Version: "2.32.3", PackageURL: "pkg:pypi/requests@2.32.3", Evidence: occs("uv.lock")},
		{Name: "requests", Version: "2.0", PackageURL: "pkg:pypi/requests@2.0"},
	}}

	suppressResolvedDeclarations(bom)

	if len(*bom.Components) != 2 {
		t.Errorf("got %d components, want both kept", len(*bom.Components))
	}
}

func TestSuppressResolvedDeclarations_NilSafe(t *testing.T) {
	suppressResolvedDeclarations(nil)
	suppressResolvedDeclarations(&cyclonedx.BOM{})
}

func TestLockCoversManifest(t *testing.T) {
	lockDirs := map[string]bool{".": true, "vendor/embedded": true}
	cases := []struct {
		dir  string
		want bool
	}{
		{".", true},                     // same dir as the root lock
		{"bootstrap", true},             // under the root lock
		{"a/b/c", true},                 // any depth under the root lock
		{"vendor/embedded", true},       // the nested lock's own dir
		{"vendor/embedded/sub", true},   // under the nested lock
		{"vendor/embedded-other", true}, // still under the root lock
	}
	for _, c := range cases {
		if got := lockCoversDir(c.dir, lockDirs); got != c.want {
			t.Errorf("lockCoversDir(%q) = %v, want %v", c.dir, got, c.want)
		}
	}

	// Without a root lock, only the nested subtree is covered.
	nested := map[string]bool{"vendor/embedded": true}
	for _, c := range []struct {
		dir  string
		want bool
	}{
		{".", false},
		{"bootstrap", false},
		{"vendor/embedded", true},
		{"vendor/embedded/sub", true},
		{"vendor/embedded-other", false}, // prefix match must respect path segments
	} {
		if got := lockCoversDir(c.dir, nested); got != c.want {
			t.Errorf("lockCoversDir(%q, nested) = %v, want %v", c.dir, got, c.want)
		}
	}
}

func TestNormalizePackageName(t *testing.T) {
	cases := []struct {
		purlType, name, want string
	}{
		// PEP 503: runs of -, _ and . are equivalent, case-insensitively.
		{"pypi", "Ruamel.YAML", "ruamel-yaml"},
		{"pypi", "ruamel_yaml", "ruamel-yaml"},
		{"pypi", "zope..interface", "zope-interface"},
		// NuGet ids are case-insensitive but separators are literal.
		{"nuget", "Newtonsoft.Json", "newtonsoft.json"},
		{"nuget", "newtonsoft.json", "newtonsoft.json"},
		{"nuget", "Newtonsoft_Json", "newtonsoft_json"},
	}
	for _, c := range cases {
		if got := normalizePackageName(c.purlType, c.name); got != c.want {
			t.Errorf("normalizePackageName(%q, %q) = %q, want %q", c.purlType, c.name, got, c.want)
		}
	}
}

// occs builds an Evidence carrying one occurrence per location, as scalibr's
// converter does from a package's Locations.
func occs(locations ...string) *cyclonedx.Evidence {
	out := make([]cyclonedx.EvidenceOccurrence, 0, len(locations))
	for _, loc := range locations {
		out = append(out, cyclonedx.EvidenceOccurrence{Location: loc})
	}
	return &cyclonedx.Evidence{Occurrences: &out}
}

// assertPURLs checks that every purl in kept survived the stage, that every purl
// in dropped did not, and that nothing else remains.
func assertPURLs(t *testing.T, bom *cyclonedx.BOM, kept, dropped []string) {
	t.Helper()
	got := map[string]bool{}
	for _, c := range *bom.Components {
		got[c.PackageURL] = true
	}
	for _, p := range kept {
		if !got[p] {
			t.Errorf("expected %q to be kept, but it was dropped", p)
		}
	}
	for _, p := range dropped {
		if got[p] {
			t.Errorf("expected %q to be dropped, but it was kept", p)
		}
	}
	if len(*bom.Components) != len(kept) {
		t.Errorf("got %d components, want %d", len(*bom.Components), len(kept))
	}
}
