// ABOUTME: Tests for the shared ApplyOverrides helper.
// ABOUTME: Both repo and os modes rely on this, so the test lives next to the implementation.
package mode

import (
	"reflect"
	"slices"
	"testing"
)

func TestApplyOverrides(t *testing.T) {
	base := []string{"go/gomod", "go/gobinary"}

	tests := []struct {
		name string
		ov   Overrides
		want []string
	}{
		{
			name: "no overrides",
			ov:   Overrides{},
			want: []string{"go/gobinary", "go/gomod"},
		},
		{
			name: "enable adds new",
			ov:   Overrides{EnablePlugins: []string{"dotnet/pe"}},
			want: []string{"dotnet/pe", "go/gobinary", "go/gomod"},
		},
		{
			name: "enable existing is no-op",
			ov:   Overrides{EnablePlugins: []string{"go/gomod"}},
			want: []string{"go/gobinary", "go/gomod"},
		},
		{
			name: "disable removes",
			ov:   Overrides{DisablePlugins: []string{"go/gobinary"}},
			want: []string{"go/gomod"},
		},
		{
			name: "enable + disable",
			ov: Overrides{
				EnablePlugins:  []string{"dotnet/pe"},
				DisablePlugins: []string{"go/gomod"},
			},
			want: []string{"dotnet/pe", "go/gobinary"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// ApplyOverrides may mutate its input; pass a fresh copy each time.
			input := slices.Clone(base)
			got := ApplyOverrides(input, tc.ov)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ApplyOverrides = %v, want %v", got, tc.want)
			}
		})
	}
}
