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

func TestWithout(t *testing.T) {
	tests := []struct {
		name   string
		list   []string
		remove []string
		want   []string
	}{
		{
			name:   "nothing to remove still normalizes",
			list:   []string{"rust/cargolock", "rust/cargoauditable", "rust/cargolock"},
			remove: nil,
			want:   []string{"rust/cargoauditable", "rust/cargolock"},
		},
		{
			name:   "named plugin is dropped",
			list:   []string{"rust/cargoauditable", "rust/cargolock", "rust/cargotoml"},
			remove: []string{"rust/cargotoml"},
			want:   []string{"rust/cargoauditable", "rust/cargolock"},
		},
		{
			name:   "removing a name that isn't there changes nothing",
			list:   []string{"go/gomod"},
			remove: []string{"rust/cargotoml"},
			want:   []string{"go/gomod"},
		},
		{
			name:   "removing everything yields empty, non-nil",
			list:   []string{"rust/cargotoml"},
			remove: []string{"rust/cargotoml"},
			want:   []string{},
		},
		{
			name:   "empty list yields empty, non-nil",
			list:   nil,
			remove: []string{"rust/cargotoml"},
			want:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Without(tt.list, tt.remove)
			if got == nil {
				t.Fatal("Without returned nil; want non-nil slice")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Without(%v, %v) = %v, want %v", tt.list, tt.remove, got, tt.want)
			}
		})
	}
}
