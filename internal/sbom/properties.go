// ABOUTME: Maps a scalibr Package to the BSI TR-03183-2 v2.1 component-properties set.
// ABOUTME: Each property classifies how the component was sourced and what shape it has.
package sbom

import "github.com/google/osv-scalibr/extractor"

// BSI property keys defined by TR-03183-2 v2.1 §5.2.2. Values are the JSON
// strings "true" or "false" — they're treated as text by both CDX and the
// sbomqs evaluator, so we encode them as strings rather than booleans.
const (
	bsiPropFilename   = "bsi:component:filename"
	bsiPropExecutable = "bsi:component:executable"
	bsiPropArchive    = "bsi:component:archive"
	bsiPropStructured = "bsi:component:structured"
)

// bsiProperties returns the property map BSI v2.1 expects for a single
// scalibr package. The filename key is omitted when no location is known —
// callers must not emit an empty filename property.
func bsiProperties(p *extractor.Package) map[string]string {
	out := map[string]string{
		bsiPropExecutable: "false",
		bsiPropArchive:    "false",
		bsiPropStructured: "false",
	}

	if len(p.Locations) > 0 && p.Locations[0] != "" {
		out[bsiPropFilename] = p.Locations[0]
	}

	for _, plugin := range p.Plugins {
		class := classifyPlugin(plugin)
		if class.executable {
			out[bsiPropExecutable] = "true"
		}
		if class.archive {
			out[bsiPropArchive] = "true"
		}
		if class.structured {
			out[bsiPropStructured] = "true"
		}
	}
	return out
}

// pluginClass captures the BSI form a given scalibr plugin produces:
//   - executable: extracted from a built binary (Go binary, .NET PE, etc.)
//   - archive:    extracted from a packed archive (JAR, NuGet .nupkg, MSI, …)
//   - structured: extracted from a structured manifest or DB (lockfiles,
//     dpkg/rpm databases, Windows registry, .csproj XML, …)
//
// A plugin can set multiple flags — a .deps.json sitting inside a published
// binary is both executable-sourced and structured, for example. The current
// classifier favours the simpler interpretation per plugin.
type pluginClass struct {
	executable bool
	archive    bool
	structured bool
}

func classifyPlugin(name string) pluginClass {
	switch name {
	// Built binaries that scalibr reads directly from disk.
	case "go/binary", "dotnet/pe", "os/kernel/vmlinuz":
		return pluginClass{executable: true}

	// Archives whose embedded manifest scalibr unpacks.
	case "java/archive":
		return pluginClass{archive: true}

	// macOS .app bundles are archives in spirit (directory archives).
	case "os/macapps":
		return pluginClass{archive: true, structured: true}

	// Standalone Windows registry extractors — structured metadata, no file.
	case "windows/ospackages", "windows/regosversion", "windows/regpatchlevel", "windows/dismpatch":
		return pluginClass{structured: true}
	}

	// Everything else (lockfiles, manifests, OS package databases) is
	// structured. Keeping this as the default avoids a sprawling allow-list
	// that drifts as scalibr adds extractors.
	return pluginClass{structured: true}
}
