package sbom

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	scalibrextractor "github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
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

	t.Run("no vulnerabilities shows message", func(t *testing.T) {
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
		if !strings.Contains(got, "No vulnerabilities found") {
			t.Errorf("expected no-vuln message, got: %q", got)
		}
	})

	t.Run("vulnerability count is shown", func(t *testing.T) {
		t.Parallel()
		result := &models.VulnerabilityResults{
			Results: []models.PackageSource{
				{
					Source: models.SourceInfo{Path: "/project/go.mod"},
					Packages: []models.PackageVulns{
						{
							Package: models.PackageInfo{Ecosystem: "Go"},
							Vulnerabilities: []*osvschema.Vulnerability{
								{Id: "GHSA-0001"},
								{Id: "GHSA-0002"},
							},
						},
					},
				},
			},
		}
		got := buildScanSummary([]string{"./project"}, result, "")
		if !strings.Contains(got, "2 vulnerabilities found") {
			t.Errorf("expected '2 vulnerabilities found', got: %q", got)
		}
	})

	t.Run("duplicate vuln IDs are counted once", func(t *testing.T) {
		t.Parallel()
		result := &models.VulnerabilityResults{
			Results: []models.PackageSource{
				{
					Source: models.SourceInfo{Path: "/project/go.mod"},
					Packages: []models.PackageVulns{
						{
							Package:         models.PackageInfo{Ecosystem: "Go"},
							Vulnerabilities: []*osvschema.Vulnerability{{Id: "GHSA-0001"}},
						},
						{
							Package:         models.PackageInfo{Ecosystem: "Go"},
							Vulnerabilities: []*osvschema.Vulnerability{{Id: "GHSA-0001"}},
						},
					},
				},
			},
		}
		got := buildScanSummary([]string{"./project"}, result, "")
		if !strings.Contains(got, "1 vulnerabilities found") {
			t.Errorf("expected '1 vulnerabilities found', got: %q", got)
		}
	})

	t.Run("multiple dirs shows all dirs when 2", func(t *testing.T) {
		t.Parallel()
		result := &models.VulnerabilityResults{}
		got := buildScanSummary([]string{"./frontend", "./backend"}, result, "")
		if !strings.Contains(got, "./frontend") || !strings.Contains(got, "./backend") {
			t.Errorf("expected both dirs in header, got: %q", got)
		}
	})

	t.Run("many dirs shows count", func(t *testing.T) {
		t.Parallel()
		result := &models.VulnerabilityResults{}
		got := buildScanSummary([]string{"./a", "./b", "./c", "./d"}, result, "")
		if !strings.Contains(got, "4 directories") {
			t.Errorf("expected '4 directories' in header, got: %q", got)
		}
	})

	t.Run("extra sources shown in row", func(t *testing.T) {
		t.Parallel()
		result := &models.VulnerabilityResults{
			Results: []models.PackageSource{
				{
					Source:   models.SourceInfo{Path: "/project/go.mod"},
					Packages: []models.PackageVulns{{Package: models.PackageInfo{Ecosystem: "Go"}}},
				},
				{
					Source:   models.SourceInfo{Path: "/project/sub/go.mod"},
					Packages: []models.PackageVulns{{Package: models.PackageInfo{Ecosystem: "Go"}}},
				},
			},
		}
		got := buildScanSummary([]string{"./project"}, result, "")
		if !strings.Contains(got, "+1 more") {
			t.Errorf("expected '+1 more' in row, got: %q", got)
		}
	})

	t.Run("Windows Registry source is labelled as Windows ecosystem", func(t *testing.T) {
		t.Parallel()
		result := &models.VulnerabilityResults{
			Results: []models.PackageSource{
				{
					Source: models.SourceInfo{
						Path: "Windows Registry",
						Type: models.SourceTypeOSPackage,
					},
					Packages: []models.PackageVulns{
						{Package: models.PackageInfo{Ecosystem: ""}},
						{Package: models.PackageInfo{Ecosystem: ""}},
					},
				},
			},
		}
		got := buildScanSummary([]string{"."}, result, "")
		if !strings.Contains(got, "Windows") {
			t.Errorf("expected 'Windows' ecosystem label in summary, got: %q", got)
		}
		if !strings.Contains(got, "2") {
			t.Errorf("expected package count '2' in summary, got: %q", got)
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

func TestMergeWindowsInventory(t *testing.T) {
	t.Parallel()

	t.Run("empty inventory leaves result unchanged", func(t *testing.T) {
		t.Parallel()
		result := &models.VulnerabilityResults{}
		mergeWindowsInventory(inventory.Inventory{}, result)
		if len(result.Results) != 0 {
			t.Errorf("expected no results, got %d", len(result.Results))
		}
	})

	t.Run("packages produce correct PackageSource", func(t *testing.T) {
		t.Parallel()
		p := &scalibrextractor.Package{Name: "SomeApp", Version: "1.2.3", PURLType: "windows"}
		inv := inventory.Inventory{Packages: []*scalibrextractor.Package{p}}
		result := &models.VulnerabilityResults{}
		mergeWindowsInventory(inv, result)
		if len(result.Results) != 1 {
			t.Fatalf("expected 1 PackageSource, got %d", len(result.Results))
		}
		src := result.Results[0]
		if src.Source.Path != "Windows Registry" {
			t.Errorf("Source.Path = %q, want %q", src.Source.Path, "Windows Registry")
		}
		if src.Source.Type != models.SourceTypeOSPackage {
			t.Errorf("Source.Type = %q, want %q", src.Source.Type, models.SourceTypeOSPackage)
		}
		if len(src.Packages) != 1 {
			t.Fatalf("expected 1 package, got %d", len(src.Packages))
		}
		pkg := src.Packages[0]
		if pkg.Package.Name != "SomeApp" {
			t.Errorf("Name = %q, want %q", pkg.Package.Name, "SomeApp")
		}
		if pkg.Package.Version != "1.2.3" {
			t.Errorf("Version = %q, want %q", pkg.Package.Version, "1.2.3")
		}
		if pkg.Package.Ecosystem != "" {
			t.Errorf("Ecosystem = %q, want %q (Windows is not a valid OSV ecosystem)", pkg.Package.Ecosystem, "")
		}
		if pkg.Package.Inventory == nil {
			t.Error("Inventory pointer must not be nil (SPDX formatter dereferences it)")
		}
	})

	t.Run("nil packages in inventory are skipped", func(t *testing.T) {
		t.Parallel()
		inv := inventory.Inventory{Packages: []*scalibrextractor.Package{
			nil,
			{Name: "ValidApp", Version: "2.0", PURLType: "windows"},
			nil,
		}}
		result := &models.VulnerabilityResults{}
		mergeWindowsInventory(inv, result)
		if len(result.Results) != 1 {
			t.Fatalf("expected 1 PackageSource, got %d", len(result.Results))
		}
		if len(result.Results[0].Packages) != 1 {
			t.Errorf("expected 1 non-nil package, got %d", len(result.Results[0].Packages))
		}
	})

	t.Run("appends to existing results", func(t *testing.T) {
		t.Parallel()
		existing := models.PackageSource{
			Source:   models.SourceInfo{Path: "/project/go.mod"},
			Packages: []models.PackageVulns{{Package: models.PackageInfo{Ecosystem: "Go"}}},
		}
		result := &models.VulnerabilityResults{Results: []models.PackageSource{existing}}
		p := &scalibrextractor.Package{Name: "WinApp", Version: "3.0", PURLType: "windows"}
		mergeWindowsInventory(inventory.Inventory{Packages: []*scalibrextractor.Package{p}}, result)
		if len(result.Results) != 2 {
			t.Fatalf("expected 2 PackageSources, got %d", len(result.Results))
		}
		if result.Results[0].Source.Path != "/project/go.mod" {
			t.Errorf("existing result was overwritten")
		}
	})
}

func TestAutoProjectName(t *testing.T) {
	t.Parallel()

	t.Run("returns filepath.Base of the directory", func(t *testing.T) {
		t.Parallel()
		if runtime.GOOS == "windows" {
			testutility.Skip(t, "on Windows, autoProjectName returns hostname instead of directory path")
		}
		dir := filepath.Join(t.TempDir(), "my-project")
		got := autoProjectName([]string{dir})
		if got != "my-project" {
			t.Errorf("autoProjectName(%q) = %q, want %q", dir, got, "my-project")
		}
	})

	t.Run("returns hostname on Windows", func(t *testing.T) {
		t.Parallel()
		if runtime.GOOS != "windows" {
			testutility.Skip(t, "hostname-based naming is Windows-only")
		}
		hostname, err := os.Hostname()
		if err != nil {
			t.Fatalf("os.Hostname() error: %v", err)
		}
		got := autoProjectName([]string{t.TempDir()})
		if got != hostname {
			t.Errorf("autoProjectName() = %q, want hostname %q", got, hostname)
		}
	})
}
