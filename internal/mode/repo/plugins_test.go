// ABOUTME: Tests for repo-mode override-intersection logic.
// ABOUTME: The ecosystem→plugin mapping is owned by internal/ecosystem now and tested there.
package repo

import (
	"reflect"
	"testing"
)

func TestIntersect(t *testing.T) {
	got := intersect([]string{"npm", "go", "dotnet"}, []string{"go", "rust", "dotnet"})
	want := []string{"go", "dotnet"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("intersect = %v, want %v", got, want)
	}
}
