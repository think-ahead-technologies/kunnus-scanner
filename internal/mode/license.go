// ABOUTME: Builds the optional deps.dev online licence enricher for modes that opt in.
// ABOUTME: Off by default — the only network-using plugin kunnus enables, and only on explicit request.
package mode

import (
	"fmt"

	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/depsdev"
	licenseenricher "github.com/google/osv-scalibr/enricher/license"
	"github.com/google/osv-scalibr/plugin"

	"github.com/think-ahead/kunnus-scanner/internal/manifestlicense"
	"github.com/think-ahead/kunnus-scanner/internal/version"
)

// AddManifestLicenses appends the offline manifest-license enricher to plugins.
// It is always on: it makes no network calls and only reads manifests already
// present in the scan root, recovering the licences scalibr's installed
// extractors (e.g. packagejson) read but discard. Modes that run installed
// language extractors (repo, container) add it; OS scans have no
// manifest-bearing extractors, so they do not.
func AddManifestLicenses(plugins []plugin.Plugin) []plugin.Plugin {
	return append(plugins, manifestlicense.New())
}

// DefaultLicenseAPI is the deps.dev gRPC endpoint used for online licence
// enrichment unless Overrides.LicenseAPIURL overrides it. It speaks the deps.dev
// Insights v3 API; a custom value must be a compatible gRPC service (for
// example a self-hosted deps.dev mirror), not an arbitrary HTTP URL.
const DefaultLicenseAPI = depsdev.DepsdevAPI

// OnlineLicenseEnricher returns the deps.dev licence enricher pointed at the
// configured endpoint when ov.OnlineLicenses is set, or (nil, nil) when it is
// not. Construction makes no network calls — the gRPC client dials lazily on
// first use — so it is safe to build during planning.
//
// Callers that add the returned plugin MUST also set the scan capabilities'
// Network to plugin.NetworkOnline; otherwise scalibr filters the enricher out
// (its requirement is NetworkOnline and the default scan environment is offline).
func OnlineLicenseEnricher(ov Overrides) (plugin.Plugin, error) {
	if !ov.OnlineLicenses {
		return nil, nil
	}
	addr := ov.LicenseAPIURL
	if addr == "" {
		addr = DefaultLicenseAPI
	}
	client, err := datasource.NewCachedInsightsClient(addr, "kunnus/"+version.Version)
	if err != nil {
		return nil, fmt.Errorf("connect licence API %q: %w", addr, err)
	}
	return licenseenricher.NewWithClient(client), nil
}

// AddOnlineLicenses appends the deps.dev licence enricher to plugins and widens
// caps to allow network access, when ov.OnlineLicenses is set. It is a no-op
// (returning plugins unchanged, caps untouched) otherwise — keeping the default
// scan fully offline. Every mode routes its plugin selection through here so the
// opt-in behaves identically across repo, os, and container scans.
func AddOnlineLicenses(plugins []plugin.Plugin, caps *plugin.Capabilities, ov Overrides) ([]plugin.Plugin, error) {
	enr, err := OnlineLicenseEnricher(ov)
	if err != nil {
		return nil, err
	}
	if enr == nil {
		return plugins, nil
	}
	caps.Network = plugin.NetworkOnline
	return append(plugins, enr), nil
}
