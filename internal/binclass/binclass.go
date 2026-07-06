// ABOUTME: Binary-classifier extractor — identifies non-packaged executables by fingerprinting version strings in their bytes.
// ABOUTME: A scalibr filesystem.Extractor that catches software (e.g. memcached) compiled into an image outside any package manager.
package binclass

import (
	"bytes"
	"context"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name is the scalibr plugin name for the binary classifier.
const Name = "kunnus/binclass"

// elfMagic is the four-byte signature every ELF binary opens with. The
// classifier only fingerprints ELF executables: the catalog targets Linux
// binaries, and gating on the magic keeps a loose version regex from matching a
// data file that merely shares a binary's name (e.g. a text file called "jq").
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// maxScanBytes bounds how much of a matched file is read into memory before we
// give up looking for a version string. Classifier globs are narrow, so only a
// handful of files ever reach Extract; this guards against a pathological match
// on a huge file.
const maxScanBytes = 200 << 20 // 200 MiB

// Extractor identifies non-packaged binaries by matching their filename against
// a classifier glob and scanning their bytes for a version string. It is the
// kunnus analogue of syft's binary cataloger and the one path that surfaces
// software compiled into an image outside any package manager (apk/dpkg/rpm).
type Extractor struct {
	classifiers []classifier
}

// New returns an Extractor backed by the default classifier catalog.
func New() *Extractor { return &Extractor{classifiers: defaultCatalog()} }

// Name returns the scalibr plugin name.
func (*Extractor) Name() string { return Name }

// Version is the plugin version, bumped on behavioural changes.
func (*Extractor) Version() int { return 0 }

// Requirements declares no special capabilities: the extractor reads file bytes
// through the scan input, so it works against both a host filesystem and a
// container image's abstract FS, on any OS.
func (*Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired reports whether path matches any classifier's glob. Only matched
// files are handed to Extract, so the byte scan never runs on the whole tree.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	return e.match(api.Path()) != nil
}

// Extract scans the matched file's bytes for the classifier's version patterns
// (tried in order, first non-empty capture wins) and, on a hit, emits a single
// package named and PURL-typed per the catalog entry.
func (e *Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	c := e.match(input.Path)
	if c == nil {
		return inventory.Inventory{}, nil
	}
	// Read and verify the ELF magic before scanning the body, so a non-ELF file
	// that happens to match a glob is rejected without reading it in full.
	header := make([]byte, len(elfMagic))
	n, err := io.ReadFull(input.Reader, header)
	if err != nil || !bytes.Equal(header[:n], elfMagic) {
		return inventory.Inventory{}, nil
	}
	rest, err := io.ReadAll(io.LimitReader(input.Reader, maxScanBytes-int64(len(elfMagic))))
	if err != nil {
		return inventory.Inventory{}, err
	}
	version := c.extractVersion(input.Path, append(header, rest...))
	if version == "" {
		return inventory.Inventory{}, nil
	}
	purlType, name := splitPURLTemplate(c.purl)
	return inventory.Inventory{Packages: []*extractor.Package{{
		Name:     name,
		Version:  version,
		PURLType: purlType,
		Location: extractor.LocationFromPath(input.Path),
		Metadata: &Metadata{CPEs: c.cpes},
	}}}, nil
}

// Metadata carries the classifier-supplied CPE templates so a downstream CPE
// stage can attach them. (The catalog ships CPEs per syft; emitting them into
// the SBOM is wired separately from this prototype.)
type Metadata struct {
	CPEs []string
}

// IsProtoable marks Metadata as a scalibr package-metadata type.
func (*Metadata) IsProtoable() {}

// match returns the first classifier whose glob matches path, or nil.
func (e *Extractor) match(p string) *classifier {
	for i := range e.classifiers {
		if e.classifiers[i].matches(p) {
			return &e.classifiers[i]
		}
	}
	return nil
}

// extractVersion runs the classifier's content patterns, then its filename
// template (if any), over the file at path/data and returns the first non-empty
// "version" capture, or "" if none match.
func (c *classifier) extractVersion(path string, data []byte) string {
	for _, re := range c.res {
		m := re.FindSubmatch(data)
		if m == nil {
			continue
		}
		if i := re.SubexpIndex("version"); i > 0 && len(m[i]) > 0 {
			return string(m[i])
		}
	}
	if c.nameTmpl != nil {
		return c.nameTmpl.match(path, data)
	}
	return ""
}

// match extracts version hints from path with fileRe, renders them into a
// content regex via contentTmpl (escaping regex metacharacters in each hint, as
// the values are version substrings spliced into a pattern), and returns that
// pattern's "version" capture from data. Any failure yields "".
func (nt *nameTemplate) match(path string, data []byte) string {
	pm := nt.fileRe.FindStringSubmatch(path)
	if pm == nil {
		return ""
	}
	vals := make(map[string]string, len(pm))
	for i, name := range nt.fileRe.SubexpNames() {
		if name != "" {
			vals[name] = regexp.QuoteMeta(pm[i])
		}
	}
	var buf strings.Builder
	if err := nt.contentTmpl.Execute(&buf, vals); err != nil {
		return ""
	}
	re, err := regexp.Compile(buf.String())
	if err != nil {
		return ""
	}
	m := re.FindSubmatch(data)
	if m == nil {
		return ""
	}
	if i := re.SubexpIndex("version"); i > 0 && len(m[i]) > 0 {
		return string(m[i])
	}
	return ""
}

// splitPURLTemplate decomposes a "pkg:type/name@version" template into its PURL
// type and name (the name may carry a namespace, e.g. "github.com/.../consul";
// kunnus's purl-normalisation step decodes the embedded slashes on output).
func splitPURLTemplate(tmpl string) (purlType, name string) {
	s := strings.TrimPrefix(tmpl, "pkg:")
	s = strings.TrimSuffix(s, "@version")
	typ, rest, ok := strings.Cut(s, "/")
	if !ok {
		return "generic", s
	}
	return typ, rest
}

// globMatch reports whether a "**/<suffix>" glob matches path p. The "**/" head
// matches any leading directories; the suffix's segments are matched against
// p's trailing segments with path.Match (so "*", "?" and "[...]" work per
// segment). A suffix may itself contain "/" (e.g. "**/elixir/ebin/elixir.app").
func globMatch(glob, p string) bool {
	suffix := strings.TrimPrefix(glob, "**/")
	pat := strings.Split(suffix, "/")
	seg := strings.Split(p, "/")
	if len(pat) > len(seg) {
		return false
	}
	seg = seg[len(seg)-len(pat):]
	for i := range pat {
		ok, err := path.Match(pat[i], seg[i])
		if err != nil || !ok {
			return false
		}
	}
	return true
}
