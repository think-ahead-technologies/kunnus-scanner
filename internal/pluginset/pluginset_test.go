// ABOUTME: Tests for the sorted-deduped union of scalibr plugin-name lists.
// ABOUTME: Pins the invariant every registry fan-out relies on: deduped, sorted, non-nil.
package pluginset

import (
	"reflect"
	"testing"
)

func TestUnion(t *testing.T) {
	tests := []struct {
		name  string
		lists [][]string
		want  []string
	}{
		{
			name:  "no lists yields empty, non-nil",
			lists: nil,
			want:  []string{},
		},
		{
			name:  "single list is sorted",
			lists: [][]string{{"npm", "cargo", "maven"}},
			want:  []string{"cargo", "maven", "npm"},
		},
		{
			name:  "duplicates within one list collapse",
			lists: [][]string{{"rpm", "rpm", "dpkg"}},
			want:  []string{"dpkg", "rpm"},
		},
		{
			name:  "overlapping lists merge and dedup",
			lists: [][]string{{"rpm"}, {"rpm", "apk"}, {"dpkg"}},
			want:  []string{"apk", "dpkg", "rpm"},
		},
		{
			name:  "nil and empty sublists are ignored",
			lists: [][]string{nil, {}, {"nix"}},
			want:  []string{"nix"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Union(tt.lists...)
			if got == nil {
				t.Fatal("Union returned nil; want non-nil slice")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Union(%v) = %v, want %v", tt.lists, got, tt.want)
			}
		})
	}
}
