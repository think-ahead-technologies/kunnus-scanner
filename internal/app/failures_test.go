// ABOUTME: Tests for the per-plugin failure reporting a completed scan carries into Result.
// ABOUTME: A degraded scan still produces an SBOM, so the caller needs the names to act on.
package app

import (
	"slices"
	"testing"

	"github.com/google/osv-scalibr/plugin"
)

func TestFailedPlugins_FiltersByFailureReason(t *testing.T) {
	cases := []struct {
		name     string
		statuses []*plugin.Status
		want     []string
	}{
		{
			name:     "empty",
			statuses: nil,
			want:     nil,
		},
		{
			name: "all succeeded",
			statuses: []*plugin.Status{
				{Name: "go/gomod", Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}},
				{Name: "python/requirements", Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}},
			},
			want: nil,
		},
		{
			name: "one failed",
			statuses: []*plugin.Status{
				{Name: "go/gomod", Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}},
				{Name: "ruby/gemfilelock", Status: &plugin.ScanStatus{Status: plugin.ScanStatusFailed, FailureReason: "boom"}},
			},
			want: []string{"ruby/gemfilelock"},
		},
		{
			name: "nil entries skipped",
			statuses: []*plugin.Status{
				nil,
				{Name: "x"}, // nil Status
				{Name: "y", Status: &plugin.ScanStatus{}}, // empty FailureReason
				{Name: "z", Status: &plugin.ScanStatus{Status: plugin.ScanStatusFailed, FailureReason: "broken"}},
			},
			want: []string{"z"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := failedPlugins(c.statuses)
			if !slices.Equal(got, c.want) {
				t.Errorf("failedPlugins = %v, want %v", got, c.want)
			}
		})
	}
}
