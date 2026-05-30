// ABOUTME: Offline Java archive (.jar) license parser — cracks the JAR's zip for its embedded licence metadata.
// ABOUTME: Reads META-INF/maven/.../pom.xml <licenses> first, then MANIFEST.MF Bundle-License; maps common names to SPDX.
package ecosystem

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/xml"
	"io"
	"net/textproto"
	"strings"
)

// maxJarBytes caps how much of a JAR we read into memory to inspect its zip
// directory. Licence metadata lives in tiny files near the archive; this guards
// against pulling a pathologically large (e.g. shaded) JAR fully into memory.
const maxJarBytes = 64 << 20 // 64 MiB

// parseJavaArchiveLicense extracts a licence from a .jar by reading its embedded
// metadata: a Maven pom.xml's <licenses> (the reliable, structured source),
// falling back to the OSGi Bundle-License manifest header. Licence names are
// mapped to SPDX where recognised (see javaLicenseAliases); unmapped values pass
// through for downstream normalization. A non-zip or licence-less JAR yields nil
// without error — a JAR we cannot read must not fail the scan.
func parseJavaArchiveLicense(r io.Reader) ([]string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxJarBytes))
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, nil // not a readable zip — nothing to mine
	}

	var manifest *zip.File
	for _, f := range zr.File {
		name := f.Name
		if strings.HasPrefix(name, "META-INF/maven/") && strings.HasSuffix(name, "/pom.xml") {
			if lics := licensesFromPom(f); len(lics) > 0 {
				return lics, nil
			}
		}
		if name == "META-INF/MANIFEST.MF" {
			manifest = f
		}
	}

	// Fallback: OSGi Bundle-License from the manifest.
	if manifest != nil {
		if lic := bundleLicense(manifest); lic != "" {
			return []string{lic}, nil
		}
	}
	return nil, nil
}

// licensesFromPom reads <project><licenses><license><name>/<url> from an embedded
// pom.xml and maps each to SPDX where recognised. Licences inherited from a
// parent pom are not present in the JAR and so cannot be recovered here.
func licensesFromPom(f *zip.File) []string {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, 1<<20))
	if err != nil {
		return nil
	}
	var project struct {
		Licenses []struct {
			Name string `xml:"name"`
			URL  string `xml:"url"`
		} `xml:"licenses>license"`
	}
	if err := xml.Unmarshal(data, &project); err != nil {
		return nil
	}
	var out []string
	for _, l := range project.Licenses {
		if id := javaLicense(l.Name, l.URL); id != "" {
			out = append(out, id)
		}
	}
	return out
}

// bundleLicense reads the OSGi Bundle-License header from a MANIFEST.MF. The
// header may be a bare SPDX id, a licence name, or a URL (optionally with
// ";link=..." / ";description=..." parameters); we take the value before any ';'.
func bundleLicense(f *zip.File) string {
	rc, err := f.Open()
	if err != nil {
		return ""
	}
	defer func() { _ = rc.Close() }()
	hdr, err := textproto.NewReader(bufio.NewReader(rc)).ReadMIMEHeader()
	if err != nil && len(hdr) == 0 {
		return ""
	}
	v := strings.TrimSpace(hdr.Get("Bundle-License"))
	if v == "" || strings.EqualFold(v, "<<EXTERNAL>>") {
		return ""
	}
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return javaLicense(v, v)
}

// javaLicense maps a Maven/OSGi licence name or URL to an SPDX identifier,
// returning the mapped id, or the raw name when unmapped (for downstream
// normalization), or "" when nothing usable is present.
func javaLicense(name, url string) string {
	if id, ok := javaLicenseAliases[strings.ToLower(strings.TrimSpace(name))]; ok {
		return id
	}
	if id := licenseFromURL(url); id != "" {
		return id
	}
	return strings.TrimSpace(name)
}

// licenseFromURL recognises a few well-known licence URLs that pom <url> or a
// Bundle-License commonly point at.
func licenseFromURL(url string) string {
	u := strings.ToLower(url)
	switch {
	case strings.Contains(u, "apache.org/licenses/license-2.0"):
		return "Apache-2.0"
	case strings.Contains(u, "opensource.org/licenses/mit"):
		return "MIT"
	case strings.Contains(u, "eclipse.org/legal/epl-2.0"), strings.Contains(u, "eclipse.org/legal/epl-v20"):
		return "EPL-2.0"
	case strings.Contains(u, "eclipse.org/legal/epl-v10"):
		return "EPL-1.0"
	case strings.Contains(u, "opensource.org/licenses/bsd-3-clause"):
		return "BSD-3-Clause"
	}
	return ""
}

// javaLicenseAliases maps common Maven/OSGi licence-name spellings to SPDX
// identifiers. Keyed lowercase. Only unambiguous mappings belong here; "BSD
// License" maps to the 3-clause variant, its common Java meaning.
var javaLicenseAliases = map[string]string{
	"apache license, version 2.0":                    "Apache-2.0",
	"apache license 2.0":                             "Apache-2.0",
	"apache license v2.0":                            "Apache-2.0",
	"apache 2.0":                                     "Apache-2.0",
	"the apache software license, version 2.0":       "Apache-2.0",
	"mit license":                                    "MIT",
	"the mit license":                                "MIT",
	"the mit license (mit)":                          "MIT",
	"eclipse public license - v 1.0":                 "EPL-1.0",
	"eclipse public license, version 1.0":            "EPL-1.0",
	"eclipse public license v1.0":                    "EPL-1.0",
	"eclipse public license - v 2.0":                 "EPL-2.0",
	"eclipse public license v2.0":                    "EPL-2.0",
	"eclipse public license, version 2.0":            "EPL-2.0",
	"gnu lesser general public license, version 2.1": "LGPL-2.1-only",
	"gnu lesser general public license":              "LGPL-2.1-only",
	"gnu general public license, version 2":          "GPL-2.0-only",
	"the bsd license":                                "BSD-3-Clause",
	"bsd license":                                    "BSD-3-Clause",
	"bsd-3-clause":                                   "BSD-3-Clause",
}
