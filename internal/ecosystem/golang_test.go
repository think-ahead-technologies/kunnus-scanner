// ABOUTME: Tests for go.sum hash extraction.
// ABOUTME: h1: lines are base64-encoded SHA-256 of the module zip; /go.mod lines are skipped.
package ecosystem

import (
	"encoding/base64"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// realisticH1 is a known-shape SHA-256 produced from arbitrary bytes —
// the parser cares about format, not provenance against a real module.
var realisticH1 = "h1:" + base64.StdEncoding.EncodeToString(make([]byte, 32))

func TestParseGoSum_ZipHashesKept(t *testing.T) {
	content := `github.com/stretchr/testify v1.8.0 ` + realisticH1 + `
github.com/stretchr/testify v1.8.0/go.mod ` + realisticH1 + `
github.com/google/uuid v1.6.0 ` + realisticH1 + `
github.com/google/uuid v1.6.0/go.mod ` + realisticH1 + `
`
	path := fixtureReader(t, "go.sum", content)

	got, err := parseGoSum(path)
	if err != nil {
		t.Fatalf("parseGoSum: %v", err)
	}
	for _, want := range []string{
		"pkg:golang/github.com/stretchr/testify@1.8.0",
		"pkg:golang/github.com/google/uuid@1.6.0",
	} {
		h, ok := firstHash(t, got, want)
		if !ok {
			t.Errorf("missing %q in %v", want, got)
			continue
		}
		if h.Algorithm != hashes.AlgSHA256 {
			t.Errorf("%q algorithm = %q, want SHA-256", want, h.Algorithm)
		}
		if len(h.Hex) != 64 {
			t.Errorf("%q hex length = %d, want 64", want, len(h.Hex))
		}
	}
}

func TestParseGoSum_SkipsGoModLines(t *testing.T) {
	// /go.mod lines hash just the go.mod file, not the module zip. We only
	// want the zip hash because BSI's "deployable component" semantics
	// describe the package artefact.
	content := `github.com/stretchr/testify v1.8.0/go.mod ` + realisticH1 + `
`
	got, _ := parseGoSum(fixtureReader(t, "go.sum", content))
	if _, ok := got["pkg:golang/github.com/stretchr/testify@1.8.0"]; ok {
		t.Error("a go.sum file with only /go.mod hashes should produce no zip-hash entries")
	}
}

func TestParseGoSum_V2ModulePath(t *testing.T) {
	// Major-version-suffixed modules carry the suffix in their path.
	content := `github.com/foo/bar/v2 v2.1.0 ` + realisticH1 + `
`
	got, _ := parseGoSum(fixtureReader(t, "go.sum", content))
	// Module path keeps /v2 (it's part of the module identity); version
	// loses the "v" prefix so the PURL key matches what scalibr emits.
	if _, ok := got["pkg:golang/github.com/foo/bar/v2@2.1.0"]; !ok {
		t.Errorf("v2 module path lost: %v", got)
	}
}

func TestParseGoSum_SkipsMalformedLines(t *testing.T) {
	content := `# this is not a real comment but should be tolerated
just-one-word
github.com/foo/bar v1.0.0 not-an-h1-hash
github.com/ok/pkg v0.1.0 ` + realisticH1 + `
`
	got, _ := parseGoSum(fixtureReader(t, "go.sum", content))
	if _, ok := got["pkg:golang/github.com/ok/pkg@0.1.0"]; !ok {
		t.Error("valid line lost when surrounded by garbage")
	}
}
