// ABOUTME: Offline scalibr enricher that recovers Debian/Ubuntu package licences from /usr/share/doc/<pkg>/copyright.
// ABOUTME: dpkg's status DB carries no licence (unlike apk/rpm); reads structured DEP-5, falling back to a text classifier.
package debiancopyright

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"

	"github.com/think-ahead/kunnus-scanner/internal/license"
)

// Name is the unique enricher name.
const Name = "kunnus/license/debian-copyright"

// debPURLType is the purl type dpkg assigns to Debian/Ubuntu packages.
const debPURLType = "deb"

// maxCopyrightBytes caps how much of a copyright file we read. Files that inline
// full licence texts (GPL, …) run tens of KB; this bounds the classifier's work
// without truncating realistic files.
const maxCopyrightBytes = 1 << 20 // 1 MiB

var _ enricher.Enricher = (*Enricher)(nil)

// Enricher fills in Debian/Ubuntu package licences offline. scalibr's dpkg
// extractor reads /var/lib/dpkg/status, which has no licence field, so the
// licence is recovered from the package's machine-readable copyright file at
// /usr/share/doc/<name>/copyright (Debian Policy DEP-5). Non-deb packages,
// already-licensed packages, and packages whose copyright is absent or
// free-text are left untouched.
type Enricher struct{}

// New returns a Debian copyright enricher.
func New() *Enricher { return &Enricher{} }

// Name of the enricher.
func (*Enricher) Name() string { return Name }

// Version of the enricher.
func (*Enricher) Version() int { return 1 }

// Requirements: none — it reads the scan-root virtual filesystem, so it needs
// neither network nor direct host filesystem access and runs under any OS.
func (*Enricher) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// RequiredPlugins: none. It enriches deb packages if any are present.
func (*Enricher) RequiredPlugins() []string { return nil }

// Enrich reads each deb package's copyright file from the scan root and sets its
// Licenses. Per-file read failures are skipped — a missing or unreadable
// copyright must not fail the scan.
func (*Enricher) Enrich(_ context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	if input == nil || input.ScanRoot == nil || input.ScanRoot.FS == nil {
		return nil
	}
	fsys := input.ScanRoot.FS
	for _, p := range inv.Packages {
		if p == nil || len(p.Licenses) > 0 || p.Name == "" || p.PURLType != debPURLType {
			continue
		}
		f, err := fsys.Open("usr/share/doc/" + p.Name + "/copyright")
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxCopyrightBytes))
		_ = f.Close()
		if err != nil {
			continue
		}
		if lics := licensesFromCopyright(data); len(lics) > 0 {
			p.Licenses = lics
		}
	}
	return nil
}

// licensesFromCopyright extracts licences from a Debian copyright file, cheapest
// and most precise first:
//  1. structured DEP-5 "License:" fields (authoritative — carries "+" or-later);
//  2. references to /usr/share/common-licenses/<NAME> (the licence is named by
//     the path, so no text needs reading);
//  3. only if neither is present, the probabilistic full-text classifier.
//
// The classifier never overrides a structured result, and most copyrights are
// resolved by steps 1–2 without it.
func licensesFromCopyright(data []byte) []string {
	if lics := parseDEP5(data); len(lics) > 0 {
		return lics
	}
	if lics := commonLicensePointers(data); len(lics) > 0 {
		return lics
	}
	return license.Classify(data)
}

// commonLicenseRe captures the licence name from a /usr/share/common-licenses/
// reference, e.g. "…/common-licenses/GPL-2" -> "GPL-2".
var commonLicenseRe = regexp.MustCompile(`/usr/share/common-licenses/([0-9A-Za-z_.+-]*[0-9A-Za-z+])`)

// commonLicensePointers returns the SPDX licences a copyright references by path
// under /usr/share/common-licenses. Only versioned names map; the bare GPL /
// LGPL / GFDL symlinks are version-ambiguous and deliberately skipped rather
// than guess a version.
func commonLicensePointers(data []byte) []string {
	var out []string
	seen := make(map[string]bool)
	for _, m := range commonLicenseRe.FindAllSubmatch(data, -1) {
		id, ok := commonLicenseToSPDX[string(m[1])]
		if !ok || id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// commonLicenseToSPDX maps /usr/share/common-licenses/ filenames to SPDX ids.
// A bare path reference names the base licence only, so version-with-"+" nuance
// (which lives in the DEP-5 "License:" field, checked first) is not represented
// here. Bare "GPL"/"LGPL"/"GFDL" are omitted — they symlink to the newest
// version and naming a specific one would be a guess.
var commonLicenseToSPDX = map[string]string{
	"Apache-2.0": "Apache-2.0",
	"Artistic":   "Artistic-1.0",
	"BSD":        "BSD-3-Clause", // Debian's common-licenses/BSD is the 3-clause form
	"CC0-1.0":    "CC0-1.0",
	"GFDL-1.2":   "GFDL-1.2-only",
	"GFDL-1.3":   "GFDL-1.3-only",
	"GPL-1":      "GPL-1.0-only",
	"GPL-2":      "GPL-2.0-only",
	"GPL-3":      "GPL-3.0-only",
	"LGPL-2":     "LGPL-2.0-only",
	"LGPL-2.1":   "LGPL-2.1-only",
	"LGPL-3":     "LGPL-3.0-only",
	"MPL-1.1":    "MPL-1.1",
	"MPL-2.0":    "MPL-2.0",
}

// parseDEP5 extracts the SPDX licences declared in a DEP-5 copyright file. It
// reads the short name from each top-level "License:" field (both the per-Files
// paragraphs and the standalone licence paragraphs), maps Debian short names to
// SPDX, deduplicates, and preserves first-seen order. Returns nil for a free-text
// copyright with no machine-readable License field.
func parseDEP5(data []byte) []string {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	seen := make(map[string]bool)
	var out []string
	for sc.Scan() {
		line := sc.Text()
		// DEP-5 fields start at column 0; indented lines are field continuations
		// (e.g. the wrapped licence text) and must not be read as a License field.
		if !strings.HasPrefix(line, "License:") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(line, "License:"))
		id := debianToSPDX(val)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// debianToSPDX maps a DEP-5 licence short name to an SPDX identifier. Debian's
// "+" (or-later) and "Expat" spellings are not SPDX and are mapped explicitly;
// short names that are already valid SPDX (Apache-2.0, MIT, ISC, BSD-*, …) pass
// through unchanged for downstream normalization. Returns "" for values with no
// SPDX equivalent (e.g. public-domain), so the caller drops them.
func debianToSPDX(val string) string {
	if val == "" {
		return ""
	}
	if id, ok := debianShortNames[strings.ToLower(val)]; ok {
		return id
	}
	return val
}

var debianShortNames = map[string]string{
	"gpl-1":         "GPL-1.0-only",
	"gpl-1+":        "GPL-1.0-or-later",
	"gpl-2":         "GPL-2.0-only",
	"gpl-2+":        "GPL-2.0-or-later",
	"gpl-3":         "GPL-3.0-only",
	"gpl-3+":        "GPL-3.0-or-later",
	"lgpl-2":        "LGPL-2.0-only",
	"lgpl-2+":       "LGPL-2.0-or-later",
	"lgpl-2.1":      "LGPL-2.1-only",
	"lgpl-2.1+":     "LGPL-2.1-or-later",
	"lgpl-3":        "LGPL-3.0-only",
	"lgpl-3+":       "LGPL-3.0-or-later",
	"gfdl-1.2":      "GFDL-1.2-only",
	"gfdl-1.2+":     "GFDL-1.2-or-later",
	"gfdl-1.3":      "GFDL-1.3-only",
	"gfdl-1.3+":     "GFDL-1.3-or-later",
	"expat":         "MIT",
	"artistic":      "Artistic-1.0",
	"public-domain": "", // no SPDX equivalent — dropped
}
