// ABOUTME: Pure mapping tests for the repo-mode ecosystem → plugin table and overrides logic.
// ABOUTME: No filesystem, no scalibr — fastest feedback loop in the project.
package repo

import (
	"reflect"
	"slices"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/mode"
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

func TestApplyOverrides(t *testing.T) {
	base := []string{"go/gomod", "go/gobinary"}

	tests := []struct {
		name string
		ov   mode.Overrides
		want []string
	}{
		{
			name: "no overrides",
			ov:   mode.Overrides{},
			want: []string{"go/gobinary", "go/gomod"},
		},
		{
			name: "enable adds new",
			ov:   mode.Overrides{EnablePlugins: []string{"dotnet/pe"}},
			want: []string{"dotnet/pe", "go/gobinary", "go/gomod"},
		},
		{
			name: "enable existing is no-op",
			ov:   mode.Overrides{EnablePlugins: []string{"go/gomod"}},
			want: []string{"go/gobinary", "go/gomod"},
		},
		{
			name: "disable removes",
			ov:   mode.Overrides{DisablePlugins: []string{"go/gobinary"}},
			want: []string{"go/gomod"},
		},
		{
			name: "enable + disable",
			ov: mode.Overrides{
				EnablePlugins:  []string{"dotnet/pe"},
				DisablePlugins: []string{"go/gomod"},
			},
			want: []string{"dotnet/pe", "go/gobinary"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// applyOverrides mutates its input; pass a fresh copy each time.
			input := slices.Clone(base)
			got := applyOverrides(input, tc.ov)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("applyOverrides = %v, want %v", got, tc.want)
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
