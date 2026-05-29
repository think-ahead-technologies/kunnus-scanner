// ABOUTME: BSI component-property keys, classifier, and the applier shared by both enrichment stages.
// ABOUTME: Both per-component enrichment and root-component enrichment write these properties.
package sbom

import (
	"strconv"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/extractor"
)

// Layer-attribution property keys. Populated for container scans, where
// scalibr traces which image layer introduced each package. Absent for repo
// and OS scans, which have no layer dimension.
const (
	layerPropIndex       = "kunnus:layer:index"
	layerPropDiffID      = "kunnus:layer:diffid"
	layerPropCommand     = "kunnus:layer:command"
	layerPropInBaseImage = "kunnus:layer:in_base_image"
)

// layerProperties returns the layer-attribution properties for a package, or
// nil when the package carries no layer metadata (every non-container scan).
// The diffID and command keys are omitted when empty so we never emit blank
// property values.
func layerProperties(p *extractor.Package) map[string]string {
	lm := p.LayerMetadata
	if lm == nil {
		return nil
	}
	out := map[string]string{
		layerPropIndex:       strconv.Itoa(lm.Index),
		layerPropInBaseImage: strconv.FormatBool(lm.BaseImageIndex > 0),
	}
	if d := lm.DiffID.String(); d != "" {
		out[layerPropDiffID] = d
	}
	if lm.Command != "" {
		out[layerPropCommand] = lm.Command
	}
	return out
}

// BSI property keys. Values are the JSON strings "true" or "false" — they're
// treated as text by both CDX and the sbomqs evaluator, so we encode them as
// strings rather than booleans.
const (
	bsiPropFilename   = "bsi:component:filename"
	bsiPropExecutable = "bsi:component:executable"
	bsiPropArchive    = "bsi:component:archive"
	bsiPropStructured = "bsi:component:structured"
)

// bsiProperties returns the property map BSI expects for a single
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

// applyBSIProps writes the given property map onto the component, skipping
// any property name the component already carries (caller wins over default).
// A no-op when props is empty.
func applyBSIProps(c *cyclonedx.Component, props map[string]string) {
	if len(props) == 0 {
		return
	}
	existing := map[string]bool{}
	if c.Properties != nil {
		for _, p := range *c.Properties {
			existing[p.Name] = true
		}
	}
	additions := make([]cyclonedx.Property, 0, len(props))
	for name, value := range props {
		if existing[name] {
			continue
		}
		additions = append(additions, cyclonedx.Property{Name: name, Value: value})
	}
	if len(additions) == 0 {
		return
	}
	if c.Properties == nil {
		c.Properties = &additions
		return
	}
	combined := append(*c.Properties, additions...)
	c.Properties = &combined
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
