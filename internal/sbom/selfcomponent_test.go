// ABOUTME: Tests the stage that drops a manifest's own project identity from the component list.
// ABOUTME: The interesting cases are the ones it must NOT drop — a real dependency sharing the purl.
package sbom

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pyprojecttoml"
	"github.com/google/osv-scalibr/inventory"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
)

// pyprojectSelf builds the package scalibr's python/pyprojecttoml emits for the
// project a pyproject.toml describes: its own name and version, with the
// declared dependencies carried as metadata rather than as packages.
func pyprojectSelf(name, version string) *extractor.Package {
	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: "pypi",
		Plugins:  []string{pyprojecttoml.Name},
		Location: extractor.LocationFromPath("pyproject.toml"),
		Metadata: &pyprojecttoml.Metadata{
			Dependencies: []string{"blinker>=1.9.0", "click>=8.1.3"},
		},
	}
}

func TestEncode_DropsPyprojectSelfComponent(t *testing.T) {
	// The scanned project is already metadata.component; listing it again as a
	// component of itself is the duplication that disqualified misc/gitrepo.
	inv := inventory.Inventory{Packages: []*extractor.Package{
		pyprojectSelf("flask", "3.2.0.dev"),
		{Name: "requests", Version: "2.31.0", PURLType: "pypi", Plugins: []string{"python/requirements"}},
	}}

	var buf bytes.Buffer
	if err := Encode(&buf, &scan.Result{Inventory: inv},
		bom.ComponentInfo{Name: "flask", Type: "application"},
		bom.Series{}, "", bom.Author{}, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	purls := encodedPURLs(t, &buf)
	if purls["pkg:pypi/flask@3.2.0.dev"] {
		t.Error("the pyproject.toml project's own identity was kept as a component")
	}
	if !purls["pkg:pypi/requests@2.31.0"] {
		t.Error("a real dependency was dropped alongside it")
	}
}

// The suppression keys on every package behind a purl being the manifest's own
// identity. A lockfile that genuinely pins a package of the same name and
// version is real evidence and must survive.
func TestEncode_KeepsSelfPURLAlsoPinnedByALock(t *testing.T) {
	inv := inventory.Inventory{Packages: []*extractor.Package{
		pyprojectSelf("flask", "3.2.0.dev"),
		{Name: "flask", Version: "3.2.0.dev", PURLType: "pypi", Plugins: []string{"python/pylock"}},
	}}

	var buf bytes.Buffer
	if err := Encode(&buf, &scan.Result{Inventory: inv},
		bom.ComponentInfo{Name: "app", Type: "application"},
		bom.Series{}, "", bom.Author{}, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if !encodedPURLs(t, &buf)["pkg:pypi/flask@3.2.0.dev"] {
		t.Error("a lock-pinned package was dropped because a manifest shared its purl")
	}
}

func TestEncode_SelfComponentSuppressionLeavesOtherEcosystemsAlone(t *testing.T) {
	inv := inventory.Inventory{Packages: []*extractor.Package{
		{Name: "github.com/stretchr/testify", Version: "1.8.0", PURLType: "golang", Plugins: []string{"go/gomod"}},
	}}

	var buf bytes.Buffer
	if err := Encode(&buf, &scan.Result{Inventory: inv},
		bom.ComponentInfo{Name: "app", Type: "application"},
		bom.Series{}, "", bom.Author{}, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if !encodedPURLs(t, &buf)["pkg:golang/github.com/stretchr/testify@1.8.0"] {
		t.Error("a non-python component was dropped")
	}
}

// encodedPURLs returns the set of component purls in an encoded document.
func encodedPURLs(t *testing.T, buf *bytes.Buffer) map[string]bool {
	t.Helper()
	var doc struct {
		Components []struct {
			PackageURL string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v\nbody:\n%s", err, buf.String())
	}
	out := make(map[string]bool, len(doc.Components))
	for _, c := range doc.Components {
		out[c.PackageURL] = true
	}
	return out
}
