// ABOUTME: Tests for hashes.Map dedup semantics, including the Path-aware case.
// ABOUTME: Per-file evidence (vendored C/C++) shares an Algorithm+Hex across files only by accident; Path keeps them distinct.
package hashes

import "testing"

func TestMap_Add_DedupesIdenticalEntries(t *testing.T) {
	m := make(Map)
	h := Hash{Algorithm: AlgSHA256, Hex: "deadbeef"}
	m.Add("pkg:npm/foo@1.0.0", h)
	m.Add("pkg:npm/foo@1.0.0", h)
	if got := len(m["pkg:npm/foo@1.0.0"]); got != 1 {
		t.Errorf("identical entries should collapse, got %d", got)
	}
}

func TestMap_Add_DistinctAlgorithmsCoexist(t *testing.T) {
	m := make(Map)
	m.Add("pkg:npm/foo@1.0.0", Hash{Algorithm: AlgSHA256, Hex: "deadbeef"})
	m.Add("pkg:npm/foo@1.0.0", Hash{Algorithm: AlgSHA512, Hex: "deadbeef"})
	if got := len(m["pkg:npm/foo@1.0.0"]); got != 2 {
		t.Errorf("different algorithms should both survive, got %d", got)
	}
}

func TestMap_Add_SamePathCollapses(t *testing.T) {
	// Two parsers both observe the same file with the same hash → one entry.
	m := make(Map)
	m.Add("pkg:generic/zlib", Hash{Algorithm: AlgMD5, Hex: "abc", Path: "src/deflate.c"})
	m.Add("pkg:generic/zlib", Hash{Algorithm: AlgMD5, Hex: "abc", Path: "src/deflate.c"})
	if got := len(m["pkg:generic/zlib"]); got != 1 {
		t.Errorf("same path+hash should collapse, got %d", got)
	}
}

func TestMap_Add_DifferentPathsBothSurvive(t *testing.T) {
	// Two distinct files happen to share an MD5 (collision or empty file).
	// Without Path in the dedup key the second entry would be silently dropped.
	m := make(Map)
	m.Add("pkg:generic/zlib", Hash{Algorithm: AlgMD5, Hex: "d41d8cd98f00b204e9800998ecf8427e", Path: "src/empty1.c"})
	m.Add("pkg:generic/zlib", Hash{Algorithm: AlgMD5, Hex: "d41d8cd98f00b204e9800998ecf8427e", Path: "src/empty2.c"})
	if got := len(m["pkg:generic/zlib"]); got != 2 {
		t.Errorf("same hash at different paths should both survive, got %d", got)
	}
}

func TestMap_Merge_RespectsPath(t *testing.T) {
	a := make(Map)
	a.Add("pkg:generic/zlib", Hash{Algorithm: AlgMD5, Hex: "abc", Path: "src/deflate.c"})

	b := make(Map)
	b.Add("pkg:generic/zlib", Hash{Algorithm: AlgMD5, Hex: "abc", Path: "src/inflate.c"})
	b.Add("pkg:generic/zlib", Hash{Algorithm: AlgMD5, Hex: "abc", Path: "src/deflate.c"}) // duplicate

	a.Merge(b)

	if got := len(a["pkg:generic/zlib"]); got != 2 {
		t.Errorf("merge should keep two distinct paths, got %d", got)
	}
}
