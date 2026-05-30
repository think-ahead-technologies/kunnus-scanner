// ABOUTME: Offline scalibr enricher that recovers Debian/Ubuntu package licences from /usr/share/doc/<pkg>/copyright.
// ABOUTME: dpkg's status DB carries no licence (unlike apk/rpm); the licence lives in the DEP-5 copyright file.
package debiancopyright

import (
	"bufio"
	"context"
	"io"
	"strings"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name is the unique enricher name.
const Name = "kunnus/license/debian-copyright"

// debPURLType is the purl type dpkg assigns to Debian/Ubuntu packages.
const debPURLType = "deb"

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
		lics := licensesFromCopyright(f)
		_ = f.Close()
		if len(lics) > 0 {
			p.Licenses = lics
		}
	}
	return nil
}

// licensesFromCopyright extracts the SPDX licences declared in a DEP-5 copyright
// file. It reads the short name from each top-level "License:" field (both the
// per-Files paragraphs and the standalone licence paragraphs), maps Debian
// short names to SPDX, deduplicates, and preserves first-seen order. A free-text
// copyright with no License field yields nothing.
func licensesFromCopyright(r io.Reader) []string {
	sc := bufio.NewScanner(r)
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
