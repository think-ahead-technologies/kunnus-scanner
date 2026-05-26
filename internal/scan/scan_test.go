// ABOUTME: Integration tests for scan.Run that exercise scalibr against fixture trees.
// ABOUTME: Real scalibr, real filesystem walking — no mocks.
package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	scalibr "github.com/google/osv-scalibr"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"
)

func TestRun_NilConfigErrors(t *testing.T) {
	_, err := Run(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestRun_ScansGoModFixture(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"),
		"module example.com/x\n\ngo 1.21\n\nrequire github.com/stretchr/testify v1.8.0\n")

	plugins, err := pl.FromNames([]string{"go/gomod"}, nil)
	if err != nil {
		t.Fatalf("FromNames: %v", err)
	}

	cfg := &scalibr.ScanConfig{
		ScanRoots: []*scalibrfs.ScanRoot{{
			FS:   scalibrfs.DirFS(root),
			Path: root,
		}},
		Plugins:      plugins,
		Capabilities: &plugin.Capabilities{OS: plugin.OSAny},
	}

	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res == nil {
		t.Fatal("Run returned nil result")
	}
	if len(res.Inventory.Packages) == 0 {
		t.Errorf("expected packages from go.mod scan, got 0")
	}

	// Sanity: one of the packages should be the testify require we declared.
	found := false
	for _, p := range res.Inventory.Packages {
		if strings.Contains(p.Name, "testify") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected testify in inventory, got %v", packageNames(res))
	}
}

func TestRun_EmptyTreeProducesEmptyInventory(t *testing.T) {
	root := t.TempDir()
	plugins, _ := pl.FromNames([]string{"go/gomod"}, nil)

	cfg := &scalibr.ScanConfig{
		ScanRoots: []*scalibrfs.ScanRoot{{
			FS:   scalibrfs.DirFS(root),
			Path: root,
		}},
		Plugins:      plugins,
		Capabilities: &plugin.Capabilities{OS: plugin.OSAny},
	}

	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Inventory.Packages) != 0 {
		t.Errorf("want empty inventory, got %d packages", len(res.Inventory.Packages))
	}
}

func packageNames(r *Result) []string {
	names := make([]string, 0, len(r.Inventory.Packages))
	for _, p := range r.Inventory.Packages {
		names = append(names, p.Name)
	}
	return names
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
