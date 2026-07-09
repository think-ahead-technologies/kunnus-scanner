// ABOUTME: Parser for pinned dependency declarations in CMake source — FetchContent_Declare, ExternalProject_Add, CPMAddPackage/CPMFindPackage.
// ABOUTME: Pure (stdlib + internal/hashes only, no scalibr) so both the internal/cmake extractor and the ecosystem hash parser derive identical purls from one grammar.
package cmakedecl

import (
	"encoding/hex"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// maxSourceBytes bounds how much CMake source Parse reads.
const maxSourceBytes = 4 << 20 // 4 MiB

// maxArgs caps the arguments collected per command invocation; a real declare
// has a handful, so anything past this is a pathological file, and the whole
// invocation is dropped rather than half-parsed.
const maxArgs = 256

// Decl is one pinned dependency declaration recovered from CMake source.
// PURLType is "github" (Name is the owner/repo namespaced form) or "generic".
// Version is the declared pin verbatim — a git tag, SHA, branch, or version
// string — or empty when the declare pins nothing literal. Hashes carries any
// URL_HASH digest declared alongside a tarball URL.
type Decl struct {
	PURLType string
	Name     string
	Version  string
	Hashes   []hashes.Hash
}

// commands is the set of dependency-declaring commands the scanner extracts.
// CMake command names are case-insensitive; keys are lowercase.
var commands = map[string]bool{
	"fetchcontent_declare": true,
	"externalproject_add":  true,
	"cpmaddpackage":        true,
	"cpmfindpackage":       true,
}

// Parse scans CMake source for the dependency-declaring commands and returns
// the declares whose identity is literal. This is deliberately not a CMake
// interpreter: any identity field containing a variable reference ("${...}")
// drops the declare (a variable pin field merely drops the version), which is
// both the correctness rule — we cannot evaluate variables — and the
// false-positive control for files like CPM.cmake itself, whose internal
// invocations are all variable-driven. Malformed source yields no declares.
func Parse(r io.Reader) []Decl {
	data, err := io.ReadAll(io.LimitReader(r, maxSourceBytes))
	if err != nil {
		return nil
	}
	var decls []Decl
	for _, inv := range scan(string(data)) {
		if d := interpret(inv); d != nil {
			decls = append(decls, *d)
		}
	}
	return decls
}

// invocation is one matched command call: the lowercased command name and its
// arguments with quotes removed.
type invocation struct {
	name string
	args []string
}

// scan walks the source once and collects the argument lists of the commands
// in the commands set. Line comments ("#"), bracket comments ("#[[ ... ]]"),
// and quoted strings are honoured, so a declare mentioned in a comment or a
// string literal never matches. An unterminated invocation is dropped.
func scan(src string) []invocation {
	var invs []invocation
	i, n := 0, len(src)
	for i < n {
		c := src[i]
		switch {
		case c == '#':
			i = skipComment(src, i)
		case c == '"':
			_, i = readQuoted(src, i)
		case isIdentStart(c):
			start := i
			for i < n && isIdent(src[i]) {
				i++
			}
			name := strings.ToLower(src[start:i])
			j := i
			for j < n && isSpace(src[j]) {
				j++
			}
			if j >= n || src[j] != '(' {
				continue
			}
			if !commands[name] {
				i = j + 1
				continue
			}
			args, end, ok := scanArgs(src, j+1)
			i = end
			if ok {
				invs = append(invs, invocation{name: name, args: args})
			}
		default:
			i++
		}
	}
	return invs
}

// scanArgs collects the arguments of one invocation starting just after its
// opening paren, returning the position just after the matching close paren.
// Nested parens (rare inside these commands, legal in CMake) are tracked but
// contribute no arguments.
func scanArgs(src string, i int) (args []string, end int, ok bool) {
	depth := 0
	n := len(src)
	for i < n && len(args) <= maxArgs {
		c := src[i]
		switch {
		case isSpace(c):
			i++
		case c == '#':
			i = skipComment(src, i)
		case c == '"':
			var arg string
			arg, i = readQuoted(src, i)
			if i > n {
				return nil, n, false
			}
			args = append(args, arg)
		case c == '(':
			depth++
			i++
		case c == ')':
			if depth == 0 {
				return args, i + 1, true
			}
			depth--
			i++
		default:
			start := i
			for i < n && !isSpace(src[i]) && !strings.ContainsRune(`()#"`, rune(src[i])) {
				i++
			}
			args = append(args, src[start:i])
		}
	}
	return nil, min(i, n), false // unterminated or pathological
}

// readQuoted reads a double-quoted string starting at the opening quote,
// returning its unescaped contents and the position after the closing quote
// (or past the end for an unterminated string).
func readQuoted(src string, i int) (string, int) {
	var sb strings.Builder
	i++ // opening quote
	n := len(src)
	for i < n && src[i] != '"' {
		if src[i] == '\\' && i+1 < n {
			sb.WriteByte(src[i+1])
			i += 2
			continue
		}
		sb.WriteByte(src[i])
		i++
	}
	return sb.String(), i + 1
}

// skipComment advances past a "#" comment: the bracket form "#[=*[ ... ]=*]"
// to its matching close, otherwise to the end of the line.
func skipComment(src string, i int) int {
	n := len(src)
	if j := i + 1; j < n && src[j] == '[' {
		k := j + 1
		eq := 0
		for k < n && src[k] == '=' {
			k++
			eq++
		}
		if k < n && src[k] == '[' {
			closer := "]" + strings.Repeat("=", eq) + "]"
			if idx := strings.Index(src[k+1:], closer); idx >= 0 {
				return k + 1 + idx + len(closer)
			}
			return n
		}
	}
	for i < n && src[i] != '\n' {
		i++
	}
	return i
}

func isSpace(c byte) bool      { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }
func isIdentStart(c byte) bool { return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isIdent(c byte) bool      { return isIdentStart(c) || (c >= '0' && c <= '9') }

// hasVar reports whether a value contains a CMake variable reference and is
// therefore not a literal we can trust.
func hasVar(s string) bool { return strings.Contains(s, "${") }

// interpret maps one matched invocation to a Decl, or nil when it pins nothing
// literal.
func interpret(inv invocation) *Decl {
	switch inv.name {
	case "fetchcontent_declare", "externalproject_add":
		return interpretDeclare(inv.args)
	case "cpmaddpackage", "cpmfindpackage":
		if len(inv.args) == 1 {
			return interpretCPMShorthand(inv.args[0])
		}
		return interpretCPMKeywords(inv.args)
	}
	return nil
}

// declareKeywords are the FetchContent_Declare / ExternalProject_Add keyword
// arguments the interpreter reads (CMake keywords are case-sensitive
// uppercase).
var declareKeywords = map[string]bool{
	"GIT_REPOSITORY": true, "GIT_TAG": true, "URL": true, "URL_HASH": true,
}

// interpretDeclare handles the shared FetchContent/ExternalProject grammar:
// a content name followed by keyword arguments. A git source is classified by
// host; a tarball URL yields a generic package named after the declare, with a
// best-effort version from the URL and any URL_HASH digest attached. A declare
// with neither source (SOURCE_DIR-only, or variable-driven) yields nothing.
func interpretDeclare(args []string) *Decl {
	if len(args) == 0 || hasVar(args[0]) {
		return nil
	}
	name := args[0]
	kv := keywordValues(args[1:], declareKeywords)
	if gitRepo := kv["GIT_REPOSITORY"]; gitRepo != "" && !hasVar(gitRepo) {
		purlType, pkgName := classifyRepoURL(gitRepo, name)
		tag := kv["GIT_TAG"]
		if hasVar(tag) {
			tag = ""
		}
		return &Decl{PURLType: purlType, Name: pkgName, Version: tag}
	}
	if tarball := kv["URL"]; tarball != "" && !hasVar(tarball) {
		d := &Decl{PURLType: "generic", Name: name, Version: versionFromURL(tarball)}
		if h, ok := parseURLHash(kv["URL_HASH"]); ok {
			d.Hashes = []hashes.Hash{h}
		}
		return d
	}
	return nil
}

// cpmKeywords are the CPMAddPackage/CPMFindPackage keyword arguments the
// interpreter reads.
var cpmKeywords = map[string]bool{
	"NAME": true, "VERSION": true, "GIT_TAG": true,
	"GITHUB_REPOSITORY": true, "GITLAB_REPOSITORY": true, "BITBUCKET_REPOSITORY": true,
	"GIT_REPOSITORY": true, "URL": true, "URL_HASH": true,
}

// interpretCPMShorthand handles CPM's single-argument form:
// "gh:owner/repo[#tag][@version]", "gl:"/"bb:" equivalents, or a full URL with
// the same optional suffixes. Both suffixes may appear together (seen in the
// wild: "gh:chriskohlhoff/asio#asio-1-18-1@1.18.1"); the "#tag" git ref is the
// exact pin and wins over the "@version" declaration.
func interpretCPMShorthand(s string) *Decl {
	if s == "" || hasVar(s) {
		return nil
	}
	var ref, declared string
	for {
		idx := strings.LastIndexAny(s, "@#")
		if idx < 0 || idx <= strings.LastIndexByte(s, '/') {
			break
		}
		if s[idx] == '#' {
			ref = s[idx+1:]
		} else if declared == "" {
			declared = s[idx+1:]
		}
		s = s[:idx]
	}
	version := ref
	if version == "" {
		version = declared
	}
	switch {
	case strings.HasPrefix(s, "gh:"):
		owner, repo, ok := strings.Cut(strings.TrimPrefix(s, "gh:"), "/")
		if !ok || owner == "" || repo == "" {
			return nil
		}
		return &Decl{PURLType: "github", Name: owner + "/" + repo, Version: version}
	case strings.HasPrefix(s, "gl:"), strings.HasPrefix(s, "bb:"):
		rest := s[3:]
		name := rest[strings.LastIndexByte(rest, '/')+1:]
		if name == "" {
			return nil
		}
		return &Decl{PURLType: "generic", Name: name, Version: version}
	case strings.Contains(s, "://"):
		purlType, name := classifyRepoURL(s, "")
		if name == "" {
			return nil
		}
		return &Decl{PURLType: purlType, Name: name, Version: version}
	}
	return nil
}

// interpretCPMKeywords handles CPM's keyword form. GIT_TAG beats VERSION as
// the pin (it is the exact one); identity comes from GITHUB_REPOSITORY, then
// GIT_REPOSITORY, then the GitLab/Bitbucket variants, then a tarball URL named
// by NAME. Variable-valued fields are treated as absent.
func interpretCPMKeywords(args []string) *Decl {
	kv := keywordValues(args, cpmKeywords)
	for k, v := range kv {
		if hasVar(v) {
			delete(kv, k)
		}
	}
	version := kv["GIT_TAG"]
	if version == "" {
		version = kv["VERSION"]
	}
	if gh := kv["GITHUB_REPOSITORY"]; gh != "" {
		owner, repo, ok := strings.Cut(gh, "/")
		if !ok || owner == "" || repo == "" {
			return nil
		}
		return &Decl{PURLType: "github", Name: owner + "/" + repo, Version: version}
	}
	if gitRepo := kv["GIT_REPOSITORY"]; gitRepo != "" {
		purlType, name := classifyRepoURL(gitRepo, kv["NAME"])
		if name == "" {
			return nil
		}
		return &Decl{PURLType: purlType, Name: name, Version: version}
	}
	for _, key := range []string{"GITLAB_REPOSITORY", "BITBUCKET_REPOSITORY"} {
		if repo := kv[key]; repo != "" {
			name := repo[strings.LastIndexByte(repo, '/')+1:]
			if name == "" {
				return nil
			}
			return &Decl{PURLType: "generic", Name: name, Version: version}
		}
	}
	if tarball := kv["URL"]; tarball != "" {
		name := kv["NAME"]
		if name == "" {
			return nil
		}
		if version == "" {
			version = versionFromURL(tarball)
		}
		d := &Decl{PURLType: "generic", Name: name, Version: version}
		if h, ok := parseURLHash(kv["URL_HASH"]); ok {
			d.Hashes = []hashes.Hash{h}
		}
		return d
	}
	return nil
}

// keywordValues walks an argument list and returns the value following each
// recognised keyword. Unrecognised arguments are skipped, so interleaved
// options (OPTIONS, DOWNLOAD_ONLY, ...) don't disturb the pairs we read.
func keywordValues(args []string, keys map[string]bool) map[string]string {
	kv := make(map[string]string)
	for i := 0; i < len(args); i++ {
		if keys[args[i]] && i+1 < len(args) {
			if _, seen := kv[args[i]]; !seen {
				kv[args[i]] = args[i+1]
			}
			i++
		}
	}
	return kv
}

// classifyRepoURL maps a git repository URL to a PURL type and package name:
// github.com URLs become pkg:github with the owner/repo namespaced name;
// anything else becomes pkg:generic named by the URL's last path segment
// (".git" trimmed), falling back to fallbackName. Mirrors the classification
// in the other native extractors (unification tracked in issue #47).
func classifyRepoURL(repoURL, fallbackName string) (purlType, name string) {
	u, err := url.Parse(repoURL)
	if err != nil {
		return "generic", fallbackName
	}
	var segs []string
	for _, seg := range strings.Split(u.Path, "/") {
		if seg != "" {
			segs = append(segs, seg)
		}
	}
	if len(segs) == 0 {
		return "generic", fallbackName
	}
	repo := strings.TrimSuffix(segs[len(segs)-1], ".git")
	if repo == "" {
		return "generic", fallbackName
	}
	if strings.EqualFold(u.Hostname(), "github.com") && len(segs) >= 2 {
		return "github", segs[len(segs)-2] + "/" + repo
	}
	return "generic", repo
}

// urlVersionRE extracts a dotted version (optionally v-prefixed) from a
// tarball filename, e.g. "zlib-1.3.1.tar.gz" or "v3.11.3.tar.gz".
var urlVersionRE = regexp.MustCompile(`v?(\d+(?:\.\d+)+)`)

// versionFromURL best-effort extracts a version from a tarball URL's last path
// segment. No match yields an empty version — better versionless than wrong.
func versionFromURL(tarball string) string {
	if i := strings.IndexByte(tarball, '?'); i >= 0 {
		tarball = tarball[:i]
	}
	seg := tarball[strings.LastIndexByte(tarball, '/')+1:]
	m := urlVersionRE.FindStringSubmatch(seg)
	if m == nil {
		return ""
	}
	return m[1]
}

// urlHashAlgorithms maps CMake URL_HASH algorithm tags (lowercased) to the
// internal algorithm plus the expected hex length; unsupported algorithms are
// dropped rather than mislabelled, mirroring sbom.algorithmToCDX.
var urlHashAlgorithms = map[string]struct {
	alg    hashes.Algorithm
	hexLen int
}{
	"sha512": {hashes.AlgSHA512, 128},
	"sha256": {hashes.AlgSHA256, 64},
	"sha1":   {hashes.AlgSHA1, 40},
	"md5":    {hashes.AlgMD5, 32},
}

// parseURLHash parses a CMake URL_HASH value ("<ALGO>=<hex>") into a Hash.
// Unsupported algorithms, wrong digest lengths, and non-hex values are
// rejected.
func parseURLHash(s string) (hashes.Hash, bool) {
	algo, digest, ok := strings.Cut(s, "=")
	if !ok {
		return hashes.Hash{}, false
	}
	spec, ok := urlHashAlgorithms[strings.ToLower(algo)]
	if !ok || len(digest) != spec.hexLen {
		return hashes.Hash{}, false
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return hashes.Hash{}, false
	}
	return hashes.Hash{Algorithm: spec.alg, Hex: strings.ToLower(digest)}, true
}
