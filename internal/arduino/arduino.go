// ABOUTME: Arduino extractor — surfaces vendored libraries (library.properties) and sketch-profile pins (sketch.yaml).
// ABOUTME: A kunnus filesystem.Extractor (no scalibr plugin exists for Arduino): libraries and platform cores -> pkg:generic packages.
package arduino

import (
	"bufio"
	"context"
	"io"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name is the scalibr plugin name for the Arduino extractor. It is a
// kunnus-native extractor appended directly by mode/repo (like modustoolbox),
// not a name in scalibr's registry.
const Name = "kunnus/arduino"

// The two component-bearing Arduino files: each vendored library carries its
// own library.properties metadata, and arduino-cli's sketch.yaml pins the
// libraries and platform cores a sketch builds against.
const (
	libraryPropertiesName = "library.properties"
	sketchYAMLName        = "sketch.yaml"
	sketchYMLName         = "sketch.yml"
)

// maxFileBytes bounds how much of a matched file we read. Both formats are a
// few hundred bytes in practice.
const maxFileBytes = 1 << 20 // 1 MiB

// Extractor surfaces Arduino components. A library.properties describes the
// vendored library it sits in (name + version — .gemspec-style installed
// state). A sketch.yaml profile pins libraries ("Name (version)") and platform
// cores ("vendor:arch (version)") — the core is a real dependency: it is the
// vendor's Arduino framework compiled into the firmware. A library's
// "depends=" field is deliberately not emitted: those transitive declarations
// usually duplicate libraries vendored (and therefore surfaced) right next to
// it, without version pins of their own.
type Extractor struct{}

// New returns an Arduino extractor.
func New() *Extractor { return &Extractor{} }

// Name returns the kunnus plugin name.
func (*Extractor) Name() string { return Name }

// Version is the plugin version, bumped on behavioural changes.
func (*Extractor) Version() int { return 0 }

// Requirements declares no special capabilities: the extractor reads file bytes
// through the scan input, so it works against a host filesystem or any abstract
// FS, on any OS.
func (*Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired reports whether path is an Arduino component source: a
// library.properties or a sketch.yaml/sketch.yml (matched case-insensitively).
func (*Extractor) FileRequired(api filesystem.FileAPI) bool {
	switch strings.ToLower(path.Base(api.Path())) {
	case libraryPropertiesName, sketchYAMLName, sketchYMLName:
		return true
	}
	return false
}

// Extract parses the matched file and emits one pkg:generic package per
// component. A malformed file yields no packages (and no error): a single bad
// manifest must not fail the scan.
func (*Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var specs []pkgSpec
	if strings.EqualFold(path.Base(input.Path), libraryPropertiesName) {
		if p := parseLibraryProperties(input.Reader); p != nil {
			specs = []pkgSpec{*p}
		}
	} else {
		specs = parseSketch(input.Reader)
	}
	pkgs := make([]*extractor.Package, 0, len(specs))
	for _, s := range specs {
		pkgs = append(pkgs, &extractor.Package{
			Name:     s.name,
			Version:  s.version,
			PURLType: "generic",
			Location: extractor.LocationFromPath(input.Path),
		})
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

// pkgSpec is one Arduino component: a library or platform core name and its
// version ("" when the file declares none).
type pkgSpec struct {
	name    string
	version string
}

// parseLibraryProperties reads the java-properties-style metadata of one
// vendored library and returns it as a component, or nil when no name is
// declared. Only name and version are read; the rest (author, sentence,
// architectures, depends) is either display metadata or deliberately skipped.
func parseLibraryProperties(r io.Reader) *pkgSpec {
	var spec pkgSpec
	sc := bufio.NewScanner(io.LimitReader(r, maxFileBytes))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "name":
			spec.name = strings.TrimSpace(value)
		case "version":
			spec.version = strings.TrimSpace(value)
		}
	}
	if spec.name == "" {
		return nil
	}
	return &spec
}

// sketchProject mirrors the sketch.yaml fields the parser reads: per-profile
// library and platform lists. Libraries are plain strings; platform entries
// are mappings carrying a "platform" key (plus index URLs we ignore).
type sketchProject struct {
	Profiles map[string]struct {
		Platforms []struct {
			Platform string `yaml:"platform"`
		} `yaml:"platforms"`
		Libraries []string `yaml:"libraries"`
	} `yaml:"profiles"`
}

// parseSketch reads every profile's pinned libraries and platform cores. Both
// use the "Name (version)" form — library names may contain spaces (registry
// display names), platform names are "vendor:arch". Entries collapse across
// profiles later, in the SBOM dedup stage.
func parseSketch(r io.Reader) []pkgSpec {
	data, err := io.ReadAll(io.LimitReader(r, maxFileBytes))
	if err != nil {
		return nil
	}
	var project sketchProject
	if err := yaml.Unmarshal(data, &project); err != nil {
		return nil
	}
	var specs []pkgSpec
	for _, profile := range project.Profiles {
		for _, lib := range profile.Libraries {
			if s := parsePinned(lib); s != nil {
				specs = append(specs, *s)
			}
		}
		for _, p := range profile.Platforms {
			if s := parsePinned(p.Platform); s != nil {
				specs = append(specs, *s)
			}
		}
	}
	return specs
}

// parsePinned parses sketch.yaml's "Name (version)" pin form; the version is
// optional. An empty name yields nil.
func parsePinned(s string) *pkgSpec {
	s = strings.TrimSpace(s)
	name, rest, found := strings.Cut(s, "(")
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	version := ""
	if found {
		version = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), ")"))
	}
	return &pkgSpec{name: name, version: version}
}
