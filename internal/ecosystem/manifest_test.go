// ABOUTME: Tests per-installed-package manifest license parsers (e.g. node_modules/*/package.json).
// ABOUTME: Keyed by the scalibr extractor that produced the package, since the manifest is the package's own file.
package ecosystem

import (
	"reflect"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
)

func TestManifestLicenseParser_Registered(t *testing.T) {
	for _, name := range []string{packagejson.Name, wheelegg.Name} {
		if _, ok := ManifestLicenseParser(name); !ok {
			t.Errorf("no manifest license parser registered for %q", name)
		}
	}
	if _, ok := ManifestLicenseParser("os/dpkg"); ok {
		t.Error("unexpected manifest license parser for an extractor without manifests")
	}
}

func TestParseWheelMetadataLicense(t *testing.T) {
	cases := map[string]struct {
		meta string
		want []string
	}{
		"license-expression wins": {
			"Metadata-Version: 2.4\nName: x\nLicense-Expression: Apache-2.0\nLicense: legacy text\n" +
				"Classifier: License :: OSI Approved :: MIT License\n",
			[]string{"Apache-2.0"},
		},
		"classifiers mapped to spdx": {
			"Metadata-Version: 2.1\nName: x\n" +
				"Classifier: License :: OSI Approved :: MIT License\n" +
				"Classifier: License :: OSI Approved :: Apache Software License\n",
			[]string{"MIT", "Apache-2.0"},
		},
		"free-text license fallback": {
			"Metadata-Version: 2.1\nName: x\nLicense: BSD-3-Clause\n",
			[]string{"BSD-3-Clause"},
		},
		"long license text is skipped": {
			"Metadata-Version: 2.1\nName: x\nLicense: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files\n",
			nil,
		},
		"none": {"Metadata-Version: 2.1\nName: x\nVersion: 1\n", nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parseWheelMetadataLicense(strings.NewReader(tc.meta))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParsePackageJSONLicense(t *testing.T) {
	cases := map[string]struct {
		json string
		want []string
	}{
		"modern string":   {`{"name":"x","version":"1","license":"MIT"}`, []string{"MIT"}},
		"spdx expression": {`{"license":"(MIT OR Apache-2.0)"}`, []string{"(MIT OR Apache-2.0)"}},
		"legacy object":   {`{"license":{"type":"BSD-3-Clause","url":"x"}}`, []string{"BSD-3-Clause"}},
		"legacy array":    {`{"licenses":[{"type":"MIT"},{"type":"Apache-2.0"}]}`, []string{"MIT", "Apache-2.0"}},
		"none":            {`{"name":"x","version":"1"}`, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parsePackageJSONLicense(strings.NewReader(tc.json))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
