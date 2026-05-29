// ABOUTME: pip requirements.txt parser — "name==version" pins plus --hash=sha256: annotations across continuation lines.
// ABOUTME: Only "==" pins carry an integrity guarantee; range specs and VCS/URL pins produce nothing.
package ecosystem

import (
	"bufio"
	"io"
	"strings"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

func parseRequirementsTxt(r io.Reader) (hashes.Map, error) {
	out := make(hashes.Map)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	var buf strings.Builder
	for scanner.Scan() {
		line := stripRequirementsComment(scanner.Text())
		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, `\`) {
			// Backslash line-continuation: stitch into the buffer and keep going.
			buf.WriteString(strings.TrimSuffix(trimmed, `\`))
			buf.WriteByte(' ')
			continue
		}
		buf.WriteString(line)
		logical := strings.TrimSpace(buf.String())
		buf.Reset()
		if logical == "" {
			continue
		}
		collectRequirementsLine(out, logical)
	}
	return out, scanner.Err()
}

// stripRequirementsComment removes pip's "#" trailing comments. pip treats
// "#" as a comment start when preceded by whitespace or at line start; a
// stricter parser is overkill — real lockfiles never embed "#" mid-token.
func stripRequirementsComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
}

// collectRequirementsLine reads one logical line (post-continuation join) and
// records every (name, version) → sha256 it can extract. Lines without "=="
// (editable installs, URL pins, options-only) contribute nothing.
func collectRequirementsLine(out hashes.Map, line string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}
	name, version, ok := parseRequirementsPin(fields[0])
	if !ok {
		return
	}
	purl := pypiPURL(name, version)
	for _, f := range fields[1:] {
		const hashOpt = "--hash="
		if !strings.HasPrefix(f, hashOpt) {
			continue
		}
		addPyPIFileHash(out, purl, f[len(hashOpt):])
	}
}

// parseRequirementsPin extracts (name, version) from "name[extras]==version"
// optionally followed by ";<env-markers>". Only "==" pins carry an integrity
// guarantee — range specifiers ("foo>=1.0") leave the version unresolved and
// can't form a stable PURL.
func parseRequirementsPin(spec string) (name, version string, ok bool) {
	if strings.HasPrefix(spec, "-") {
		// pip option (-r, -e, --index-url, ...) rather than a package spec.
		return "", "", false
	}
	if i := strings.Index(spec, ";"); i >= 0 {
		spec = spec[:i]
	}
	const op = "=="
	at := strings.Index(spec, op)
	if at <= 0 {
		return "", "", false
	}
	name = spec[:at]
	version = strings.TrimSpace(spec[at+len(op):])
	// Strip extras: "requests[security]" → "requests". The PURL identifies the
	// package, not the extras opted into at install time.
	if b := strings.Index(name, "["); b >= 0 {
		name = name[:b]
	}
	name = strings.TrimSpace(name)
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}
