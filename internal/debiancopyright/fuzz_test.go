// ABOUTME: Fuzz target for the Debian copyright licence extractor — DEP-5 fields, common-license pointers, text classifier.
// ABOUTME: licensesFromCopyright takes raw file bytes (the fs read lives in Enrich), so it fuzzes without a filesystem.
package debiancopyright

import "testing"

// FuzzLicensesFromCopyright drives the whole copyright→licences pipeline with
// arbitrary bytes: DEP-5 "License:" parsing, /usr/share/common-licenses/
// pointer matching, then the full-text classifier fallback. Each branch emits
// deduplicated, non-empty SPDX ids, so the result must never contain an empty or
// duplicate identifier regardless of input.
func FuzzLicensesFromCopyright(f *testing.F) {
	seeds := []string{
		"",
		"Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nLicense: GPL-2+\n",
		"License: Apache-2.0\nLicense: MIT\n",
		"This package is free software; see /usr/share/common-licenses/GPL-2 for details.\n",
		"Copyright 2020 Someone. Licensed under the Apache License, Version 2.0.\n",
		"License: public-domain\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		got := licensesFromCopyright([]byte(data))
		seen := make(map[string]bool, len(got))
		for _, id := range got {
			if id == "" {
				t.Fatalf("licensesFromCopyright(%q) returned an empty SPDX id in %v", data, got)
			}
			if seen[id] {
				t.Fatalf("licensesFromCopyright(%q) returned duplicate SPDX id %q in %v", data, id, got)
			}
			seen[id] = true
		}
	})
}
