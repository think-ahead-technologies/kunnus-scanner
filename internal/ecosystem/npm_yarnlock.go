// ABOUTME: yarn parser — yarn.lock SHA-512 hashes for both v1 and berry v2+ formats.
// ABOUTME: v1 uses "integrity sha512-<base64>"; berry uses "checksum: <hex sha512>".
package ecosystem

import (
	"bufio"
	"encoding/hex"
	"io"
	"strings"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

func parseYarnLock(r io.Reader) (hashes.Map, error) {
	out := make(hashes.Map)
	state := &yarnState{out: out}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		state.consume(scanner.Text())
	}
	state.flush()
	return out, scanner.Err()
}

// yarnState is a streaming line-by-line parser handling both v1 and berry.
// The two formats share the structure "block header, indented body"; the
// only differences are the body-line syntax and the integrity field name.
type yarnState struct {
	out hashes.Map

	// Currently-open block.
	header   string
	version  string
	checksum string // berry hex
	sri      string // v1 SRI value (sha512-base64)
	inBlock  bool
}

func (s *yarnState) consume(line string) {
	switch {
	case strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "":
		// Comment or blank line — between-block separator.
		s.flush()
		s.reset()
		return
	case !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t"):
		// New block header.
		s.flush()
		s.reset()
		s.header = strings.TrimSuffix(strings.TrimSpace(line), ":")
		s.inBlock = true
		return
	}

	if !s.inBlock {
		return
	}

	body := strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(body, "version "):
		// v1: version "4.17.21"
		s.version = unquote(strings.TrimPrefix(body, "version "))
	case strings.HasPrefix(body, "version: "):
		// berry: version: 4.17.21
		s.version = strings.TrimSpace(strings.TrimPrefix(body, "version:"))
	case strings.HasPrefix(body, "integrity "):
		// v1: integrity sha512-<base64>
		s.sri = strings.TrimSpace(strings.TrimPrefix(body, "integrity "))
	case strings.HasPrefix(body, "checksum: "):
		// berry: checksum: <hex>
		s.checksum = strings.TrimSpace(strings.TrimPrefix(body, "checksum:"))
	}
}

func (s *yarnState) flush() {
	if !s.inBlock || s.header == "" || s.version == "" {
		return
	}
	name := yarnNameFromHeader(s.header)
	if name == "" {
		return
	}

	if s.sri != "" {
		if digest, err := decodeSRI(s.sri); err == nil {
			s.out.Add(npmPURL(name, s.version), hashes.Hash{Algorithm: hashes.AlgSHA512, Hex: digest})
		}
	}
	if s.checksum != "" && isHex(s.checksum) && len(s.checksum) == 128 {
		s.out.Add(npmPURL(name, s.version), hashes.Hash{Algorithm: hashes.AlgSHA512, Hex: strings.ToLower(s.checksum)})
	}
}

func (s *yarnState) reset() {
	s.header, s.version, s.checksum, s.sri = "", "", "", ""
	s.inBlock = false
}

// yarnNameFromHeader returns the package name from a yarn.lock block header.
// v1 headers can be comma-separated specifiers (e.g.
// `"lodash@^4.0.0", "lodash@~4.17.0"`). Berry headers are typically single
// (e.g. `"lodash@npm:4.17.21"`). Both formats agree on "name@spec" — we
// take the FIRST specifier and discard the version portion via splitNpmSpec.
func yarnNameFromHeader(header string) string {
	header = strings.TrimSuffix(header, ":")
	if i := strings.Index(header, ","); i >= 0 {
		header = header[:i]
	}
	spec := unquote(strings.TrimSpace(header))
	name, _, ok := splitNpmSpec(spec)
	if !ok {
		return ""
	}
	return name
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}
