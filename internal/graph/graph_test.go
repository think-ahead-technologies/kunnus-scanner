// ABOUTME: Tests for graph.Map: edge accumulation with dedup and merge semantics.
// ABOUTME: Mirrors the hashes.Map / license.Map tests, as the three ride the same Survey pass.
package graph

import (
	"reflect"
	"testing"
)

func TestMapAdd(t *testing.T) {
	m := make(Map)
	m.Add("pkg:cargo/fixture@0.1.0", "pkg:cargo/libc@0.2.147")
	m.Add("pkg:cargo/fixture@0.1.0", "pkg:cargo/libc@0.2.147") // exact repeat: dropped
	m.Add("pkg:cargo/fixture@0.1.0", "pkg:cargo/serde@1.0.0")
	m.Add("pkg:cargo/fixture@0.1.0", "") // blank target: dropped
	m.Add("", "pkg:cargo/libc@0.2.147")  // blank source: dropped

	want := Map{"pkg:cargo/fixture@0.1.0": {"pkg:cargo/libc@0.2.147", "pkg:cargo/serde@1.0.0"}}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("map = %v, want %v", m, want)
	}
}

func TestMapMerge(t *testing.T) {
	m := Map{"a": {"b"}}
	m.Merge(Map{"a": {"b", "c"}, "d": {"e"}})
	want := Map{"a": {"b", "c"}, "d": {"e"}}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("merged = %v, want %v", m, want)
	}
}
