// ABOUTME: Tests for the application service — the use case driven without a CLI.
// ABOUTME: Uses the real repo mode over the shared fixture corpus; no mocks, per the project rule.
package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/think-ahead/kunnus-scanner/internal/app"
	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	repomode "github.com/think-ahead/kunnus-scanner/internal/mode/repo"
)

// npmFixture is a real lockfile from the shared corpus at the module root —
// the same fixtures the scan-seam and binary e2e tiers read.
func npmFixture(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "ecosystems", "npm")
}

// decode runs the use case and parses the document it wrote.
func decode(t *testing.T, req app.Request) (map[string]any, *app.Result) {
	t.Helper()
	var buf bytes.Buffer
	res, err := app.New().GenerateSBOM(context.Background(), &buf, req)
	if err != nil {
		t.Fatalf("GenerateSBOM: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v\nbody:\n%s", err, buf.String())
	}
	return doc, res
}

// The point of the extraction: the use case runs against a plain struct, with
// no *cli.Command anywhere in sight.
func TestGenerateSBOM_RunsWithoutACLI(t *testing.T) {
	doc, res := decode(t, app.Request{
		Mode:   repomode.New(),
		Target: npmFixture(t),
	})

	if res == nil {
		t.Fatal("nil Result for a successful scan")
	}
	if len(res.FailedPlugins) != 0 {
		t.Errorf("FailedPlugins = %v, want none for a clean scan", res.FailedPlugins)
	}
	if got := doc["bomFormat"]; got != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", got)
	}
	comps, _ := doc["components"].([]any)
	if len(comps) == 0 {
		t.Error("no components encoded from the npm fixture")
	}
}

// The component identity on the Request wins over whatever the mode derived
// from the target, and the same values key the serial series — so the root
// component and the serial can never disagree.
func TestGenerateSBOM_RequestIdentityReachesRootComponentAndSeries(t *testing.T) {
	req := app.Request{
		Mode:             repomode.New(),
		Target:           npmFixture(t),
		ComponentID:      "acme/widget",
		ComponentVersion: "1.2.3",
	}

	first, _ := decode(t, req)
	second, _ := decode(t, req)

	meta, _ := first["metadata"].(map[string]any)
	root, _ := meta["component"].(map[string]any)
	if got := root["version"]; got != "1.2.3" {
		t.Errorf("root component version = %v, want 1.2.3", got)
	}

	serial, _ := first["serialNumber"].(string)
	if serial == "" {
		t.Fatal("serialNumber missing")
	}
	if serial != second["serialNumber"] {
		t.Errorf("same identity must reuse one serial: %q vs %v", serial, second["serialNumber"])
	}
}

func TestGenerateSBOM_AuthorReachesTheDocument(t *testing.T) {
	doc, _ := decode(t, app.Request{
		Mode:   repomode.New(),
		Target: npmFixture(t),
		Author: bom.Author{Name: "ACME GmbH", Email: "psirt@acme.example"},
	})

	meta, _ := doc["metadata"].(map[string]any)
	authors, _ := meta["authors"].([]any)
	if len(authors) == 0 {
		t.Fatal("metadata.authors missing")
	}
	first, _ := authors[0].(map[string]any)
	if got := first["name"]; got != "ACME GmbH" {
		t.Errorf("author name = %v, want ACME GmbH", got)
	}
}

// A malformed serial must be rejected before the scan runs, not after — the
// scan is the expensive half.
func TestGenerateSBOM_InvalidSerialFailsBeforeScanning(t *testing.T) {
	var buf bytes.Buffer
	_, err := app.New().GenerateSBOM(context.Background(), &buf, app.Request{
		Mode:         repomode.New(),
		Target:       npmFixture(t),
		SerialNumber: "not-a-uuid",
	})
	if err == nil {
		t.Fatal("want an error for a malformed serial number")
	}
	if buf.Len() != 0 {
		t.Errorf("nothing may be written when validation fails, got %d bytes", buf.Len())
	}
	if !strings.Contains(err.Error(), "serial number") {
		t.Errorf("error should name the offending input, got: %v", err)
	}
}

func TestGenerateSBOM_ExplicitSerialOverridesDerivation(t *testing.T) {
	const want = "urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8"

	doc, _ := decode(t, app.Request{
		Mode:         repomode.New(),
		Target:       npmFixture(t),
		ComponentID:  "acme/widget",
		SerialNumber: "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
	})

	if got := doc["serialNumber"]; got != want {
		t.Errorf("serialNumber = %v, want the explicit %s", got, want)
	}
}

// The clock and serial source are Request fields, so a caller can pin the two
// values that would otherwise drift between runs.
func TestGenerateSBOM_ClockAndSerialArePinnable(t *testing.T) {
	const fixed = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

	doc, _ := decode(t, app.Request{
		Mode:      repomode.New(),
		Target:    npmFixture(t),
		Now:       func() time.Time { return now },
		NewSerial: func() string { return fixed },
	})

	// No component id was given, so the document takes the identity-less
	// branch and draws its serial from the injected source.
	if got := doc["serialNumber"]; got != "urn:uuid:"+fixed {
		t.Errorf("serialNumber = %v, want urn:uuid:%s", got, fixed)
	}
}

func TestGenerateSBOM_PlanFailureIsReportedAgainstTheMode(t *testing.T) {
	var buf bytes.Buffer
	_, err := app.New().GenerateSBOM(context.Background(), &buf, app.Request{
		Mode:   repomode.New(),
		Target: filepath.Join(t.TempDir(), "no-such-directory"),
	})
	if err == nil {
		t.Fatal("want an error when the target cannot be planned")
	}
	if !strings.Contains(err.Error(), "repo") {
		t.Errorf("error should name the mode that failed, got: %v", err)
	}
}

func TestGenerateSBOM_RequiresAMode(t *testing.T) {
	var buf bytes.Buffer
	_, err := app.New().GenerateSBOM(context.Background(), &buf, app.Request{Target: "."})
	if err == nil {
		t.Fatal("want an error when no mode is set on the request")
	}
}

// Overrides ride through untouched: restricting the scan to an ecosystem the
// fixture does not contain leaves the planner with nothing to do, which is an
// error rather than an empty document.
func TestGenerateSBOM_OverridesReachThePlanner(t *testing.T) {
	var buf bytes.Buffer
	_, err := app.New().GenerateSBOM(context.Background(), &buf, app.Request{
		Mode:      repomode.New(),
		Target:    npmFixture(t),
		Overrides: mode.Overrides{Ecosystems: []string{"cargo"}},
	})
	if err == nil {
		t.Fatal("want an error when the overrides select no extractors")
	}
}
