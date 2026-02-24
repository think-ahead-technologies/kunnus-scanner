// ABOUTME: Unit tests for SBOM summary helper functions (white-box, package sbom).
// ABOUTME: Tests buildFileName, primaryEcosystem, and buildScanSummary helpers.
package sbom

import (
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
)

func TestBuildFileName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		project string
		format  string
		date    string
		want    string
	}{
		{"my-project", "spdx-2-3", "2026-02-24", "sbom-my-project-2026-02-24.spdx.json"},
		{"my-project", "cyclonedx-1-4", "2026-02-24", "sbom-my-project-2026-02-24.cdx.json"},
		{"my-project", "cyclonedx-1-5", "2026-02-24", "sbom-my-project-2026-02-24.cdx.json"},
		{"kunnus-scanner", "spdx-2-3", "2025-01-01", "sbom-kunnus-scanner-2025-01-01.spdx.json"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			got := buildFileName(tc.project, tc.format, tc.date)
			if got != tc.want {
				t.Errorf("buildFileName(%q, %q, %q) = %q, want %q", tc.project, tc.format, tc.date, got, tc.want)
			}
		})
	}
}

func TestPrimaryEcosystem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		packages []models.PackageVulns
		want     string
	}{
		{
			name:     "empty returns empty string",
			packages: nil,
			want:     "",
		},
		{
			name: "single ecosystem",
			packages: []models.PackageVulns{
				{Package: models.PackageInfo{Ecosystem: "Go"}},
				{Package: models.PackageInfo{Ecosystem: "Go"}},
			},
			want: "Go",
		},
		{
			name: "most common ecosystem wins",
			packages: []models.PackageVulns{
				{Package: models.PackageInfo{Ecosystem: "Go"}},
				{Package: models.PackageInfo{Ecosystem: "npm"}},
				{Package: models.PackageInfo{Ecosystem: "npm"}},
			},
			want: "npm",
		},
		{
			name: "tie broken alphabetically",
			packages: []models.PackageVulns{
				{Package: models.PackageInfo{Ecosystem: "PyPI"}},
				{Package: models.PackageInfo{Ecosystem: "Go"}},
			},
			want: "Go",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := primaryEcosystem(tc.packages)
			if got != tc.want {
				t.Errorf("primaryEcosystem() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildScanSummary(t *testing.T) {
	t.Parallel()

	t.Run("shows scanning header with first dir", func(t *testing.T) {
		t.Parallel()
		result := &models.VulnerabilityResults{}
		got := buildScanSummary([]string{"./my-project"}, result, "")
		if !strings.Contains(got, "Scanning ./my-project") {
			t.Errorf("expected scanning header, got: %q", got)
		}
	})

	t.Run("no packages shows informative message", func(t *testing.T) {
		t.Parallel()
		result := &models.VulnerabilityResults{}
		got := buildScanSummary([]string{"./empty-dir"}, result, "")
		if !strings.Contains(got, "No package sources found") {
			t.Errorf("expected no-packages message, got: %q", got)
		}
	})

	t.Run("no packages does not show saved path", func(t *testing.T) {
		t.Parallel()
		result := &models.VulnerabilityResults{}
		got := buildScanSummary([]string{"./empty-dir"}, result, "")
		if strings.Contains(got, "SBOM saved") {
			t.Errorf("expected no saved-path line for empty result, got: %q", got)
		}
	})

	t.Run("with packages shows ecosystem name", func(t *testing.T) {
		t.Parallel()
		result := &models.VulnerabilityResults{
			Results: []models.PackageSource{
				{
					Source: models.SourceInfo{Path: "/project/go.mod"},
					Packages: []models.PackageVulns{
						{Package: models.PackageInfo{Ecosystem: "Go"}},
						{Package: models.PackageInfo{Ecosystem: "Go"}},
					},
				},
			},
		}
		got := buildScanSummary([]string{"./project"}, result, "")
		if !strings.Contains(got, "Go") {
			t.Errorf("expected ecosystem 'Go' in summary, got: %q", got)
		}
	})

	t.Run("with packages shows package count", func(t *testing.T) {
		t.Parallel()
		result := &models.VulnerabilityResults{
			Results: []models.PackageSource{
				{
					Source: models.SourceInfo{Path: "/project/go.mod"},
					Packages: []models.PackageVulns{
						{Package: models.PackageInfo{Ecosystem: "Go"}},
						{Package: models.PackageInfo{Ecosystem: "Go"}},
						{Package: models.PackageInfo{Ecosystem: "Go"}},
					},
				},
			},
		}
		got := buildScanSummary([]string{"./project"}, result, "")
		if !strings.Contains(got, "3") {
			t.Errorf("expected count '3' in summary, got: %q", got)
		}
	})

	t.Run("with packages shows source filename", func(t *testing.T) {
		t.Parallel()
		result := &models.VulnerabilityResults{
			Results: []models.PackageSource{
				{
					Source: models.SourceInfo{Path: "/project/go.mod"},
					Packages: []models.PackageVulns{
						{Package: models.PackageInfo{Ecosystem: "Go"}},
					},
				},
			},
		}
		got := buildScanSummary([]string{"./project"}, result, "")
		if !strings.Contains(got, "go.mod") {
			t.Errorf("expected 'go.mod' in summary, got: %q", got)
		}
	})

	t.Run("saved path shown when provided", func(t *testing.T) {
		t.Parallel()
		result := &models.VulnerabilityResults{
			Results: []models.PackageSource{
				{
					Source: models.SourceInfo{Path: "/project/go.mod"},
					Packages: []models.PackageVulns{
						{Package: models.PackageInfo{Ecosystem: "Go"}},
					},
				},
			},
		}
		got := buildScanSummary([]string{"./project"}, result, "sbom-project-2026-02-24.spdx.json")
		if !strings.Contains(got, "sbom-project-2026-02-24.spdx.json") {
			t.Errorf("expected saved path in summary, got: %q", got)
		}
		if !strings.Contains(got, "SBOM saved") {
			t.Errorf("expected 'SBOM saved' label, got: %q", got)
		}
	})

	t.Run("multiple sources aggregate same ecosystem", func(t *testing.T) {
		t.Parallel()
		result := &models.VulnerabilityResults{
			Results: []models.PackageSource{
				{
					Source: models.SourceInfo{Path: "/project/go.mod"},
					Packages: []models.PackageVulns{
						{Package: models.PackageInfo{Ecosystem: "Go"}},
						{Package: models.PackageInfo{Ecosystem: "Go"}},
					},
				},
				{
					Source: models.SourceInfo{Path: "/project/subdir/go.mod"},
					Packages: []models.PackageVulns{
						{Package: models.PackageInfo{Ecosystem: "Go"}},
					},
				},
			},
		}
		got := buildScanSummary([]string{"./project"}, result, "")
		// Total should be 3 across both sources
		if !strings.Contains(got, "3") {
			t.Errorf("expected total count '3' in summary, got: %q", got)
		}
	})
}
