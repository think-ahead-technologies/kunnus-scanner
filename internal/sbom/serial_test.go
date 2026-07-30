// ABOUTME: Tests for SBOM serial-number derivation: deterministic UUIDv8 series keys,
// ABOUTME: explicit overrides, the random fallback, and the timestamp-derived document version.
package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
)

func TestSerialNamespacePinned(t *testing.T) {
	// The namespace is derived from the kunnus.tech DNS name (RFC 9562's
	// recommended way to mint a namespace) but must never change value:
	// a different namespace silently splits every existing document series.
	// This pins the concrete UUID so any drift — a typo in the name, a
	// different base namespace — turns the suite red.
	if got := serialNamespace.String(); got != "d22e9dc1-292c-5b0d-a2d4-b10793fdb5ea" {
		t.Errorf("serialNamespace = %s, want d22e9dc1-292c-5b0d-a2d4-b10793fdb5ea", got)
	}
}

func TestDeriveSerial_DeterministicForSameSeries(t *testing.T) {
	s := bom.Series{Mode: "repo", ID: "acme/widget", Version: "1.2.3"}
	first, det, err := deriveSerial(s)
	if err != nil {
		t.Fatalf("deriveSerial: %v", err)
	}
	if !det {
		t.Error("identity-derived serial must report deterministic")
	}
	second, _, err := deriveSerial(s)
	if err != nil {
		t.Fatalf("deriveSerial: %v", err)
	}
	if first != second {
		t.Errorf("same series produced different serials: %q vs %q", first, second)
	}
	if !strings.HasPrefix(first, "urn:uuid:") {
		t.Errorf("serial %q missing urn:uuid: prefix", first)
	}
	u, err := uuid.Parse(strings.TrimPrefix(first, "urn:uuid:"))
	if err != nil {
		t.Fatalf("serial %q is not a UUID: %v", first, err)
	}
	if u.Version() != 8 {
		t.Errorf("serial UUID version = %d, want 8", u.Version())
	}
	if u.Variant() != uuid.RFC4122 {
		t.Errorf("serial UUID variant = %v, want RFC4122", u.Variant())
	}
}

func TestDeriveSerial_KeyFieldsSplitSeries(t *testing.T) {
	base := bom.Series{Mode: "repo", ID: "acme/widget", Version: "1.2.3"}
	baseSerial, _, err := deriveSerial(base)
	if err != nil {
		t.Fatalf("deriveSerial: %v", err)
	}

	variants := map[string]bom.Series{
		"mode":    {Mode: "os", ID: "acme/widget", Version: "1.2.3"},
		"id":      {Mode: "repo", ID: "acme/gadget", Version: "1.2.3"},
		"version": {Mode: "repo", ID: "acme/widget", Version: "1.2.4"},
	}
	for field, s := range variants {
		got, _, err := deriveSerial(s)
		if err != nil {
			t.Fatalf("deriveSerial(%s variant): %v", field, err)
		}
		if got == baseSerial {
			t.Errorf("changing %s did not change the serial", field)
		}
	}
}

func TestDeriveSerial_NoIdentityIsRandom(t *testing.T) {
	s := bom.Series{Mode: "repo"}
	first, det, err := deriveSerial(s)
	if err != nil {
		t.Fatalf("deriveSerial: %v", err)
	}
	if det {
		t.Error("serial without identity must not report deterministic")
	}
	second, _, err := deriveSerial(s)
	if err != nil {
		t.Fatalf("deriveSerial: %v", err)
	}
	if first == second {
		t.Errorf("no-identity serials must be random, got %q twice", first)
	}
}

func TestDeriveSerial_ExplicitOverrideWins(t *testing.T) {
	s := bom.Series{
		Mode:   "repo",
		ID:     "acme/widget",
		Serial: "b3c5bd21-1e46-4a44-9b62-8dcbcafb54b7",
	}
	got, det, err := deriveSerial(s)
	if err != nil {
		t.Fatalf("deriveSerial: %v", err)
	}
	if !det {
		t.Error("explicit serial must report deterministic")
	}
	if want := "urn:uuid:b3c5bd21-1e46-4a44-9b62-8dcbcafb54b7"; got != want {
		t.Errorf("serial = %q, want %q", got, want)
	}
}

func TestNormalizeSerial(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"bare uuid gains prefix", "b3c5bd21-1e46-4a44-9b62-8dcbcafb54b7", "urn:uuid:b3c5bd21-1e46-4a44-9b62-8dcbcafb54b7", false},
		{"urn form kept", "urn:uuid:b3c5bd21-1e46-4a44-9b62-8dcbcafb54b7", "urn:uuid:b3c5bd21-1e46-4a44-9b62-8dcbcafb54b7", false},
		{"uppercase lowered", "B3C5BD21-1E46-4A44-9B62-8DCBCAFB54B7", "urn:uuid:b3c5bd21-1e46-4a44-9b62-8dcbcafb54b7", false},
		{"garbage rejected", "not-a-uuid", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeSerial(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizeSerial(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeSerial(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeSerial(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestBOMVersion(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	if got := bomVersion("2026-07-30T10:30:00Z", now); got != 1785407400 {
		t.Errorf("bomVersion from timestamp = %d, want 1785407400", got)
	}
	if got := bomVersion("garbage", now); got != int(now.Unix()) {
		t.Errorf("bomVersion fallback = %d, want %d", got, now.Unix())
	}
	if got := bomVersion("", now); got != int(now.Unix()) {
		t.Errorf("bomVersion empty = %d, want %d", got, now.Unix())
	}
}

func TestEncode_SeriesSetsSerialAndTimestampVersion(t *testing.T) {
	series := bom.Series{Mode: "repo", ID: "acme/widget", Version: "1.2.3"}
	comp := bom.ComponentInfo{Name: "widget", Version: "1.2.3", Type: "application"}

	encode := func() map[string]any {
		var buf bytes.Buffer
		if err := Encode(&buf, sampleResult(), comp, series, "", bom.Author{}, nil, nil, nil, nil); err != nil {
			t.Fatalf("Encode: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return doc
	}

	first := encode()
	second := encode()

	serial, _ := first["serialNumber"].(string)
	if serial == "" || serial != second["serialNumber"] {
		t.Errorf("series serial not stable across runs: %v vs %v", first["serialNumber"], second["serialNumber"])
	}

	// The document version must be the generation timestamp in epoch seconds,
	// so series members are strictly ordered by the field CycloneDX orders on.
	meta, _ := first["metadata"].(map[string]any)
	ts, _ := meta["timestamp"].(string)
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		t.Fatalf("metadata.timestamp %q not RFC3339: %v", ts, err)
	}
	version, _ := first["version"].(float64)
	if int64(version) != parsed.Unix() {
		t.Errorf("version = %d, want metadata.timestamp epoch %d", int64(version), parsed.Unix())
	}
}

func TestEncode_NoSeriesKeepsRandomSerialAndVersionOne(t *testing.T) {
	comp := bom.ComponentInfo{Name: "x", Type: "application"}

	encode := func() map[string]any {
		var buf bytes.Buffer
		if err := Encode(&buf, sampleResult(), comp, bom.Series{Mode: "repo"}, "", bom.Author{}, nil, nil, nil, nil); err != nil {
			t.Fatalf("Encode: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return doc
	}

	first := encode()
	second := encode()

	s1, _ := first["serialNumber"].(string)
	s2, _ := second["serialNumber"].(string)
	if s1 == "" || s2 == "" {
		t.Fatal("serialNumber missing")
	}
	if s1 == s2 {
		t.Errorf("no-identity serials must differ per run, got %q twice", s1)
	}
	if v, _ := first["version"].(float64); v != 1 {
		t.Errorf("version = %v, want 1 for a document outside any series", first["version"])
	}
}

func TestEncode_InvalidExplicitSerialErrors(t *testing.T) {
	var buf bytes.Buffer
	err := Encode(&buf, sampleResult(), bom.ComponentInfo{Name: "x", Type: "application"},
		bom.Series{Mode: "repo", Serial: "not-a-uuid"}, "", bom.Author{}, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("want error for invalid explicit serial")
	}
}
