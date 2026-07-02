// ABOUTME: Fuzz targets for the licence pipeline — Normalize (declared strings) and Classify (licence prose).
// ABOUTME: Both must never panic; Normalize's ok flag must track a non-empty Value, Classify must dedupe its output.
package license

import "testing"

// FuzzNormalize drives Normalize with arbitrary declared-licence strings. The
// contract couples ok and Value: ok=true means a non-empty Value (an SPDX id,
// expression, or LicenseRef), ok=false means the zero Normalized. A caller that
// trusts ok must never receive an empty Value under it.
func FuzzNormalize(f *testing.F) {
	seeds := []string{
		"",
		"   ",
		"MIT",
		"mit",
		"GPLv2",
		"asl 2.0",
		"MIT OR Apache-2.0",
		"(MIT AND BSD-3-Clause)",
		"GPL-2.0-only WITH Classpath-exception-2.0",
		"NONE",
		"NOASSERTION",
		"UNKNOWN",
		"some custom licence text!!",
		"LicenseRef-kunnus-foo",
		// Regression: a dangling "(" panicked go-spdx (nil-pointer deref).
		"(",
		")",
		"(MIT OR Apache-2.0",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		n, ok := Normalize(raw)
		if ok {
			if n.Value == "" {
				t.Fatalf("Normalize(%q) returned ok with empty Value", raw)
			}
			return
		}
		if n != (Normalized{}) {
			t.Fatalf("Normalize(%q) returned !ok but non-zero Normalized: %+v", raw, n)
		}
	})
}

// FuzzClassify drives the full-text classifier with arbitrary bytes. Its
// documented contract is a deduplicated, URL-free list of non-empty SPDX ids; a
// duplicate or empty id would violate what callers feed into Normalize.
func FuzzClassify(f *testing.F) {
	seeds := [][]byte{
		nil,
		[]byte(""),
		[]byte("MIT License\n\nPermission is hereby granted, free of charge, to any person"),
		[]byte("Licensed under the Apache License, Version 2.0"),
		[]byte("random prose that is not a licence at all"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, text []byte) {
		got := Classify(text)
		seen := make(map[string]bool, len(got))
		for _, id := range got {
			if id == "" {
				t.Fatalf("Classify returned an empty SPDX id in %v", got)
			}
			if seen[id] {
				t.Fatalf("Classify returned duplicate SPDX id %q in %v", id, got)
			}
			seen[id] = true
		}
	})
}
