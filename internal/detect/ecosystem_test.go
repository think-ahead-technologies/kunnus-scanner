// ABOUTME: Tests for Ecosystems(): assert detection across a variety of fixture trees.
// ABOUTME: Each subtest builds a temp dir, drops marker files, and checks the result set.
package detect

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestEcosystems(t *testing.T) {
	tests := []struct {
		name  string
		files []string // file paths relative to scan root
		want  []string // expected canonical ecosystems, sorted
	}{
		{
			name:  "empty tree",
			files: nil,
			want:  []string{},
		},
		{
			name:  "node project",
			files: []string{"package.json", "package-lock.json"},
			want:  []string{"npm"},
		},
		{
			name:  "bun project",
			files: []string{"package.json", "bun.lock"},
			want:  []string{"npm"},
		},
		{
			name:  "bun-only project",
			files: []string{"bun.lock"},
			want:  []string{"npm"},
		},
		{
			name:  "go project",
			files: []string{"go.mod", "go.sum"},
			want:  []string{"go"},
		},
		{
			name:  "rust project",
			files: []string{"Cargo.toml", "Cargo.lock"},
			want:  []string{"cargo"},
		},
		{
			name:  "dotnet csproj",
			files: []string{"myapp/MyApp.csproj"},
			want:  []string{"dotnet"},
		},
		{
			name:  "dotnet packages.lock.json",
			files: []string{"packages.lock.json"},
			want:  []string{"dotnet"},
		},
		{
			name:  "python pyproject + poetry",
			files: []string{"pyproject.toml", "poetry.lock"},
			want:  []string{"python"},
		},
		{
			name: "mixed monorepo",
			files: []string{
				"backend/go.mod",
				"frontend/package.json",
				"frontend/pnpm-lock.yaml",
				"services/api/MyApi.csproj",
			},
			want: []string{"dotnet", "go", "npm"},
		},
		{
			name: "skip-dir contents ignored",
			files: []string{
				"go.mod",
				"node_modules/foo/package.json",
				".git/HEAD",
				"vendor/cargo/Cargo.toml",
			},
			want: []string{"go"},
		},
		{
			name:  "case-insensitive lockfile names",
			files: []string{"Gemfile", "Gemfile.lock"},
			want:  []string{"ruby"},
		},
		{
			name:  "unrelated files ignored",
			files: []string{"README.md", "src/main.go", "LICENSE"},
			want:  []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, rel := range tc.files {
				writeEmptyFile(t, filepath.Join(root, rel))
			}

			got, err := Ecosystems(root)
			if err != nil {
				t.Fatalf("Ecosystems(%q): %v", root, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Ecosystems(%q) = %v, want %v", root, got, tc.want)
			}
		})
	}
}

func TestEcosystems_PermissionErrorOnSubdirSkipped(t *testing.T) {
	root := t.TempDir()
	writeEmptyFile(t, filepath.Join(root, "go.mod"))

	// Create an unreadable subdir; WalkDir should skip it without failing the
	// whole scan.
	bad := filepath.Join(root, "locked")
	if err := os.Mkdir(bad, 0o000); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o755) })

	got, err := Ecosystems(root)
	if err != nil {
		t.Fatalf("Ecosystems with unreadable subdir: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"go"}) {
		t.Errorf("Ecosystems = %v, want [go]", got)
	}
}

func writeEmptyFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
