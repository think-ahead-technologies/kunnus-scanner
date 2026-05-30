// ABOUTME: Tests the Java archive (.jar) offline license parser — reads the licence embedded in the JAR's zip.
// ABOUTME: Source is META-INF/maven/.../pom.xml <licenses>, falling back to MANIFEST.MF Bundle-License.
package ecosystem

import (
	"archive/zip"
	"bytes"
	"reflect"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
)

func jarWith(t *testing.T, files map[string]string) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return bytes.NewReader(buf.Bytes())
}

func TestParseJavaArchiveLicense_PomXML(t *testing.T) {
	jar := jarWith(t, map[string]string{
		"META-INF/maven/com.example/lib/pom.xml": `<project xmlns="http://maven.apache.org/POM/4.0.0">
			<licenses><license>
				<name>Apache License, Version 2.0</name>
				<url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
			</license></licenses>
		</project>`,
	})
	got, err := parseJavaArchiveLicense(jar)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"Apache-2.0"}) {
		t.Errorf("got %v, want [Apache-2.0]", got)
	}
}

func TestParseJavaArchiveLicense_BundleLicenseFallback(t *testing.T) {
	// No pom.xml; OSGi Bundle-License header in the manifest.
	jar := jarWith(t, map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nBundle-License: MIT\r\n",
	})
	got, err := parseJavaArchiveLicense(jar)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"MIT"}) {
		t.Errorf("got %v, want [MIT]", got)
	}
}

func TestParseJavaArchiveLicense_None(t *testing.T) {
	jar := jarWith(t, map[string]string{
		"com/example/Foo.class": "not a license",
	})
	got, err := parseJavaArchiveLicense(jar)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil for a JAR with no licence metadata", got)
	}
}

func TestParseJavaArchiveLicense_NotAZip(t *testing.T) {
	// A truncated / non-zip reader must not error the scan — just no licence.
	got, err := parseJavaArchiveLicense(bytes.NewReader([]byte("not a zip")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil for a non-zip input", got)
	}
}

func TestManifestLicenseParser_RegistersJava(t *testing.T) {
	if _, ok := ManifestLicenseParser(archive.Name); !ok {
		t.Errorf("no manifest license parser registered for %q", archive.Name)
	}
}
