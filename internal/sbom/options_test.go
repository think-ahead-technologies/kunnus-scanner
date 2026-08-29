// ABOUTME: Tests for the Options boundary: the injected clock and serial source and their defaults.
// ABOUTME: These ports exist so a document's two non-deterministic fields are pinnable from a test.
package sbom

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
)

func TestOptions_NowDefaultsToWallClock(t *testing.T) {
	before := time.Now()
	got := Options{}.now()
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Errorf("default now() = %v, want a reading between %v and %v", got, before, after)
	}
}

func TestOptions_NowUsesInjectedClock(t *testing.T) {
	want := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	got := Options{Now: func() time.Time { return want }}.now()

	if !got.Equal(want) {
		t.Errorf("now() = %v, want the injected %v", got, want)
	}
}

func TestOptions_NewSerialDefaultsToDistinctRandomUUIDs(t *testing.T) {
	o := Options{}
	first, second := o.newSerial(), o.newSerial()

	if first == "" {
		t.Fatal("default newSerial() returned an empty string")
	}
	if first == second {
		t.Errorf("default newSerial() must be random, got %q twice", first)
	}
	// It has to be a bare UUID: deriveSerial prefixes the urn:uuid scheme itself.
	if _, err := NormalizeSerial(first); err != nil {
		t.Errorf("default newSerial() = %q, not a UUID: %v", first, err)
	}
}

func TestOptions_NewSerialUsesInjectedSource(t *testing.T) {
	const want = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	got := Options{NewSerial: func() string { return want }}.newSerial()

	if got != want {
		t.Errorf("newSerial() = %q, want the injected %q", got, want)
	}
}

// The serial source reaches the encoded document: a scan with no stable
// identity takes the random-serial branch, so pinning the source pins the
// document's serialNumber.
func TestEncode_InjectedSerialSourceReachesTheDocument(t *testing.T) {
	const fixed = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

	var buf bytes.Buffer
	err := Encode(&buf, Options{
		Inventory: sampleInventory(),
		Component: bom.ComponentInfo{Name: "x", Type: "application"},
		Series:    bom.Series{Mode: "repo"}, // no ID: the identity-less branch
		NewSerial: func() string { return fixed },
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := doc["serialNumber"]; got != "urn:uuid:"+fixed {
		t.Errorf("serialNumber = %v, want urn:uuid:%s", got, fixed)
	}
}

// The clock is the fallback for a document version when the converter's
// timestamp cannot be parsed. Encode always produces a parseable one, so the
// port is exercised where it actually reads: the metadata stage.
func TestEnrichCDXMetadata_InjectedClockDatesAnUnparseableTimestamp(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	cdxBom := &cyclonedx.BOM{
		Metadata: &cyclonedx.Metadata{Timestamp: "not-a-timestamp"},
	}

	err := enrichCDXMetadata(cdxBom, Options{
		Series: bom.Series{Mode: "repo", ID: "acme/widget", Version: "1.2.3"},
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("enrichCDXMetadata: %v", err)
	}

	if cdxBom.Version != int(now.Unix()) {
		t.Errorf("document version = %d, want the injected clock's %d", cdxBom.Version, now.Unix())
	}
}
