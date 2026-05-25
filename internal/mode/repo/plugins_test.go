// ABOUTME: Pure mapping tests for the repo-mode ecosystem → plugin table and the intersect helper.
// ABOUTME: No filesystem, no scalibr — fastest feedback loop in the project.
package repo

import (
	"reflect"
	"slices"
	"testing"
)

func TestPluginsFor(t *testing.T) {
	tests := []struct {
		name       string
		ecosystems []string
		wantSome   []string // plugins that MUST be in the result
		wantNone   []string // plugins that MUST NOT be in the result
	}{
		{
			name:       "single npm",
			ecosystems: []string{"npm"},
			wantSome:   []string{"javascript/packagelockjson", "javascript/yarnlock"},
			wantNone:   []string{"go/gomod", "dotnet/pe"},
		},
		{
			name:       "go and dotnet dedup",
			ecosystems: []string{"go", "dotnet"},
			wantSome:   []string{"go/gomod", "dotnet/csproj", "dotnet/pe"},
		},
		{
			name:       "unknown ecosystem yields no plugins",
			ecosystems: []string{"klingon"},
			wantSome:   nil,
			wantNone:   []string{"go/gomod"},
		},
		{
			name:       "empty input",
			ecosystems: nil,
			wantSome:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pluginsFor(tc.ecosystems)
			if !slices.IsSorted(got) {
				t.Errorf("pluginsFor result %v is not sorted", got)
			}
			for _, p := range tc.wantSome {
				if !slices.Contains(got, p) {
					t.Errorf("pluginsFor(%v) missing %q (got %v)", tc.ecosystems, p, got)
				}
			}
			for _, p := range tc.wantNone {
				if slices.Contains(got, p) {
					t.Errorf("pluginsFor(%v) contains %q but should not (got %v)", tc.ecosystems, p, got)
				}
			}
		})
	}
}

func TestIntersect(t *testing.T) {
	got := intersect([]string{"npm", "go", "dotnet"}, []string{"go", "rust", "dotnet"})
	want := []string{"go", "dotnet"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("intersect = %v, want %v", got, want)
	}
}
