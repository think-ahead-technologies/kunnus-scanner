// ABOUTME: BSI component-property keys, classifier, and the applier shared by both enrichment stages.
// ABOUTME: Both per-component enrichment and root-component enrichment write these properties.
package sbom

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/extractor"
)

// Layer-attribution property keys. Populated for container scans, where
// scalibr traces which image layer introduced each package. Absent for repo
// and OS scans, which have no layer dimension.
//
// The singular index/diffid/command/in_base_image keys describe the introducing
// (lowest-index) layer. When a package occupies more than one layer, the plural
// indices/diffids keys carry the full set so attribution is not lost to the
// single-layer keys.
const (
	layerPropIndex       = "kunnus:layer:index"
	layerPropDiffID      = "kunnus:layer:diffid"
	layerPropCommand     = "kunnus:layer:command"
	layerPropInBaseImage = "kunnus:layer:in_base_image"
	layerPropIndices     = "kunnus:layer:indices"
	layerPropDiffIDs     = "kunnus:layer:diffids"
)

// layerProperties returns the layer-attribution properties aggregated across
// every package sharing a PURL, or nil when none carry layer metadata (every
// non-container scan). The singular keys describe the introducing layer (lowest
// index); when the package spans multiple layers, the plural keys list all of
// them so no layer is dropped. diffID and command keys are omitted when empty so
// we never emit blank property values.
func layerProperties(pkgs []*extractor.Package) map[string]string {
	var layers []*extractor.LayerMetadata
	for _, p := range pkgs {
		if p != nil && p.LayerMetadata != nil {
			layers = append(layers, p.LayerMetadata)
		}
	}
	if len(layers) == 0 {
		return nil
	}
	// Sort by layer index so the introducing layer is first and the aggregated
	// sets below are deterministic regardless of inventory order.
	slices.SortFunc(layers, func(a, b *extractor.LayerMetadata) int {
		return cmp.Compare(a.Index, b.Index)
	})

	intro := layers[0]
	out := map[string]string{
		layerPropIndex:       strconv.Itoa(intro.Index),
		layerPropInBaseImage: strconv.FormatBool(intro.BaseImageIndex > 0),
	}
	if d := intro.DiffID.String(); d != "" {
		out[layerPropDiffID] = d
	}
	if intro.Command != "" {
		out[layerPropCommand] = intro.Command
	}

	// Multi-layer: record the full set of layer indices and diffIDs. The
	// per-layer Command is intentionally not aggregated — it can contain commas
	// (breaking the comma-joined form) and is recoverable from the image config
	// via the diffID.
	indices := distinctSortedIndices(layers)
	if len(indices) > 1 {
		strIdx := make([]string, len(indices))
		for i, idx := range indices {
			strIdx[i] = strconv.Itoa(idx)
		}
		out[layerPropIndices] = strings.Join(strIdx, ",")

		var diffIDs []string
		for _, lm := range layers {
			if d := lm.DiffID.String(); d != "" && !slices.Contains(diffIDs, d) {
				diffIDs = append(diffIDs, d)
			}
		}
		if len(diffIDs) > 0 {
			out[layerPropDiffIDs] = strings.Join(diffIDs, ",")
		}
	}
	return out
}

// distinctSortedIndices returns the unique layer indices in ascending order.
// layers must already be sorted by Index (layerProperties guarantees this).
func distinctSortedIndices(layers []*extractor.LayerMetadata) []int {
	var out []int
	for _, lm := range layers {
		if len(out) == 0 || out[len(out)-1] != lm.Index {
			out = append(out, lm.Index)
		}
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

// bsiProperties returns the property map BSI expects, aggregated across every
// package sharing a PURL. The executable/archive/structured flags are OR'd over
// all of them — if any source is, say, an archive, the component is. The
// filename takes the first known location (the full set rides in the component's
// evidence occurrences); it is omitted when no package has a location, since
// callers must not emit an empty filename property.
func bsiProperties(pkgs []*extractor.Package) map[string]string {
	out := map[string]string{
		bsiPropExecutable: "false",
		bsiPropArchive:    "false",
		bsiPropStructured: "false",
	}

	for _, p := range pkgs {
		if p == nil {
			continue
		}
		if _, set := out[bsiPropFilename]; !set && p.Location.PathOrEmpty() != "" {
			out[bsiPropFilename] = p.Location.PathOrEmpty()
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
