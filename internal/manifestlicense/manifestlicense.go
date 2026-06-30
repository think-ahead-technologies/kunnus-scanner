// ABOUTME: Offline scalibr enricher that recovers component licences from each installed package's own manifest.
// ABOUTME: scalibr's installed extractors (e.g. packagejson) read these manifests but drop the licence; this adds it back.
package manifestlicense

import (
	"context"
	"log/slog"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"

	"github.com/think-ahead/kunnus-scanner/internal/ecosystem"
)

// Name is the unique enricher name.
const Name = "kunnus/license/manifest"

var _ enricher.Enricher = (*Enricher)(nil)

// Enricher fills in component licences offline by re-reading each package's
// own manifest (e.g. node_modules/<pkg>/package.json) from the scan-root
// filesystem and parsing the licence field scalibr discards. It only touches
// packages from extractors that have a manifest parser (see
// ecosystem.ManifestLicenseParser), so lockfile-sourced packages — whose
// location is a shared lockfile, not their own manifest — are left alone.
//
// Parsing is delegated to ecosystem rather than done here because there are five
// manifest formats, each keyed by the scalibr extractor that owns it, so each
// parser lives next to its ecosystem's other knowledge. (debiancopyright, with a
// single format and no ecosystem home, parses inline instead — same principle,
// different N. See internal/license/doc.go for the whole picture.)
type Enricher struct{}

// New returns a manifest-license enricher.
func New() *Enricher { return &Enricher{} }

// Name of the enricher.
func (*Enricher) Name() string { return Name }

// Version of the enricher.
func (*Enricher) Version() int { return 1 }

// Requirements: none. It reads the scan-root virtual filesystem it is given, so
// it needs neither network nor direct host filesystem access, and runs under any
// OS — keeping it always-on and offline.
func (*Enricher) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// RequiredPlugins: none. It enriches whatever installed packages are present;
// absent the relevant extractors it simply finds nothing to do.
func (*Enricher) RequiredPlugins() []string { return nil }

// Enrich reads each licence-less package's manifest from the scan root and sets
// its Licenses. Packages that already carry a licence, lack a location, or come
// from an extractor without a manifest parser are skipped. Per-file read or
// parse failures are logged and skipped — one bad manifest must not fail the
// scan.
func (*Enricher) Enrich(_ context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	if input == nil || input.ScanRoot == nil || input.ScanRoot.FS == nil {
		return nil
	}
	fsys := input.ScanRoot.FS
	for _, p := range inv.Packages {
		if p == nil || len(p.Licenses) > 0 || p.Location.PathOrEmpty() == "" {
			continue
		}
		for _, pluginName := range p.Plugins {
			parser, ok := ecosystem.ManifestLicenseParser(pluginName)
			if !ok {
				continue
			}
			path := p.Location.PathOrEmpty()
			f, err := fsys.Open(path)
			if err != nil {
				slog.Debug("manifest license: open failed", "path", path, "err", err)
				break
			}
			lics, perr := parser(f)
			_ = f.Close()
			if perr != nil {
				slog.Warn("manifest license parser failed", "extractor", pluginName, "path", path, "err", perr)
				break
			}
			if len(lics) > 0 {
				p.Licenses = lics
			}
			break
		}
	}
	return nil
}
