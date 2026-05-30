// ABOUTME: Tests the license.Map carrier (purl -> raw license strings) used by offline lockfile parsers.
// ABOUTME: Dedup and merge mirror hashes.Map so the survey can fold many parsers into one result.
package license

import (
	"reflect"
	"testing"
)

func TestMap_AddDedups(t *testing.T) {
	m := Map{}
	m.Add("pkg:composer/psr/log@3.0.0", "MIT")
	m.Add("pkg:composer/psr/log@3.0.0", "MIT") // duplicate
	m.Add("pkg:composer/psr/log@3.0.0", "Apache-2.0")
	got := m["pkg:composer/psr/log@3.0.0"]
	want := []string{"MIT", "Apache-2.0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMap_AddSkipsEmpty(t *testing.T) {
	m := Map{}
	m.Add("pkg:x/y@1", "")
	m.Add("pkg:x/y@1", "  ")
	if len(m) != 0 {
		t.Errorf("empty/blank licenses should be ignored, got %v", m)
	}
}

func TestMap_Merge(t *testing.T) {
	a := Map{"p1": {"MIT"}}
	b := Map{"p1": {"MIT", "BSD-3-Clause"}, "p2": {"Apache-2.0"}}
	a.Merge(b)
	if got := a["p1"]; !reflect.DeepEqual(got, []string{"MIT", "BSD-3-Clause"}) {
		t.Errorf("p1 = %v, want [MIT BSD-3-Clause]", got)
	}
	if got := a["p2"]; !reflect.DeepEqual(got, []string{"Apache-2.0"}) {
		t.Errorf("p2 = %v, want [Apache-2.0]", got)
	}
}
