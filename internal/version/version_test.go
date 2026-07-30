// ABOUTME: Tests for the version package: extracting the scalibr module version from build info.
// ABOUTME: Uses synthetic debug.BuildInfo values — go-test binaries embed no dependency modules.
package version

import (
	"runtime/debug"
	"testing"
)

func TestScalibrFrom(t *testing.T) {
	cases := []struct {
		name string
		deps []*debug.Module
		want string
	}{
		{
			"plain dependency",
			[]*debug.Module{
				{Path: "github.com/google/uuid", Version: "v1.6.0"},
				{Path: "github.com/google/osv-scalibr", Version: "v0.4.5"},
			},
			"v0.4.5",
		},
		{
			"replace directive wins",
			[]*debug.Module{
				{
					Path:    "github.com/google/osv-scalibr",
					Version: "v0.4.5",
					Replace: &debug.Module{Path: "github.com/fork/osv-scalibr", Version: "v0.4.6-patched"},
				},
			},
			"v0.4.6-patched",
		},
		{
			"absent dependency",
			[]*debug.Module{{Path: "github.com/google/uuid", Version: "v1.6.0"}},
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scalibrFrom(&debug.BuildInfo{Deps: tc.deps}); got != tc.want {
				t.Errorf("scalibrFrom = %q, want %q", got, tc.want)
			}
		})
	}
}
