// ABOUTME: Tests for the ownership scanner: real dpkg .list and apk installed-db fixtures on a temp filesystem.
package ownership

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScan(t *testing.T) {
	root := t.TempDir()
	// dpkg: a package whose name differs from the binary it owns (the case the
	// name heuristic could not bridge).
	write(t, filepath.Join(root, "var/lib/dpkg/info/postgresql-18.list"),
		"/.\n/usr\n/usr/lib/postgresql/18/bin/postgres\n/usr/lib/postgresql/18/bin/initdb\n")
	write(t, filepath.Join(root, "var/lib/dpkg/info/xz-utils.list"),
		"/usr/bin/xz\n/usr/bin/xzcat\n")
	// apk: F:/R: records.
	write(t, filepath.Join(root, "lib/apk/db/installed"),
		"P:busybox\nV:1.37.0-r30\nF:bin\nR:busybox\nR:busybox.suid\nF:usr/sbin\nR:ssl_client\n")

	got := Scan(os.DirFS(root))

	owned := []string{
		"usr/lib/postgresql/18/bin/postgres",
		"usr/lib/postgresql/18/bin/initdb",
		"usr/bin/xz",
		"usr/bin/xzcat",
		"bin/busybox",
		"bin/busybox.suid",
		"usr/sbin/ssl_client",
	}
	for _, p := range owned {
		if !got.Owns(p) {
			t.Errorf("expected %q to be owned", p)
		}
	}
	// Owns tolerates a leading slash and rejects unknown / empty paths.
	if !got.Owns("/usr/bin/xz") {
		t.Errorf("Owns should tolerate a leading slash")
	}
	if got.Owns("usr/local/bin/memcached") {
		t.Errorf("an unowned path must not be reported as owned")
	}
	if Set(nil).Owns("anything") {
		t.Errorf("a nil Set owns nothing")
	}
}

func TestScanMissingDatabases(t *testing.T) {
	// A root with neither database yields an empty Set, not a panic or error.
	got := Scan(os.DirFS(t.TempDir()))
	if len(got) != 0 {
		t.Errorf("expected empty Set for a root with no package DB, got %d entries", len(got))
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
