// ABOUTME: Tests for the shared pipeline helpers: atomic output sinks and per-plugin failure detection.
// ABOUTME: Covers commit/abort semantics for file output and the exit-code path for partial scan failures.
package command

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/plugin"
)

func TestOpenOutput_StdoutCommitIsNoop(t *testing.T) {
	for _, name := range []string{"", "-"} {
		t.Run("path="+name, func(t *testing.T) {
			sink, err := openOutput(name)
			if err != nil {
				t.Fatalf("openOutput(%q): %v", name, err)
			}
			if sink.w != os.Stdout {
				t.Errorf("expected stdout writer for %q", name)
			}
			if err := sink.commit(); err != nil {
				t.Errorf("commit on stdout returned error: %v", err)
			}
			sink.abort() // must be safe to call as well
		})
	}
}

func TestOpenOutput_FileCommitWritesAtomically(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "sbom.json")

	sink, err := openOutput(final)
	if err != nil {
		t.Fatalf("openOutput: %v", err)
	}

	// Before commit, the final path must not exist — only a temp sibling.
	if _, err := os.Stat(final); !os.IsNotExist(err) {
		t.Errorf("final path should not exist before commit, stat err = %v", err)
	}

	if _, err := sink.w.Write([]byte(`{"ok":true}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sink.commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	data, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if string(data) != `{"ok":true}` {
		t.Errorf("file contents = %q, want {\"ok\":true}", string(data))
	}

	// No temp leftover in the directory.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() == filepath.Base(final) {
			continue
		}
		t.Errorf("unexpected leftover file in dir: %s", e.Name())
	}
}

func TestOpenOutput_FileAbortLeavesNoFile(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "sbom.json")

	sink, err := openOutput(final)
	if err != nil {
		t.Fatalf("openOutput: %v", err)
	}

	// Write something but never commit.
	if _, err := sink.w.Write([]byte(`partial garbage`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	sink.abort()

	if _, err := os.Stat(final); !os.IsNotExist(err) {
		t.Errorf("final path must not exist after abort, stat err = %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("abort left files in dir: %v", names)
	}
}

func TestOpenOutput_FileMissingParentDirErrors(t *testing.T) {
	// The output directory must exist. Returning an error early — before any
	// file is created — keeps callers from worrying about cleanup.
	bad := filepath.Join(t.TempDir(), "does-not-exist", "sbom.json")
	if _, err := openOutput(bad); err == nil {
		t.Fatal("expected error for missing parent dir")
	}
}

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

func TestPluginFailureError_FormatsNames(t *testing.T) {
	// The error string must name the failing plugins so CI logs are actionable.
	err := pluginFailureError([]string{"ruby/gemfilelock", "python/requirements"})
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	msg := err.Error()
	for _, want := range []string{"ruby/gemfilelock", "python/requirements"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q: %s", want, msg)
		}
	}
}
