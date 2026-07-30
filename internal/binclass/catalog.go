// ABOUTME: The binary-classifier catalog: filename globs + version-extraction regexes for non-packaged software.
// ABOUTME: The patterns are ported from anchore/syft's binary cataloger (Apache-2.0); see doc.go for what was simplified.
package binclass

import (
	"regexp"
	"text/template"
)

// classifier fingerprints one piece of software that ships as a bare binary.
// Files whose path matches any glob are scanned for a version: first by each
// content pattern in res, then, if set, by nameTmpl. The first non-empty
// "version" capture wins. purl is the "pkg:type/name@version" template and cpes
// are the CPE 2.3 templates carried for a downstream CPE stage.
type classifier struct {
	globs    []string
	purl     string
	res      []*regexp.Regexp
	nameTmpl *nameTemplate
	cpes     []string
}

// nameTemplate matches a version in two steps, for software whose binary carries
// only the major.minor in its filename and the full version, NUL-delimited, in
// its bytes (python: libpython3.14.so → "3.14" → \x003.14.5\x00). fileRe extracts
// named groups from the file path; those values render contentTmpl into a content
// regex whose "version" group is then matched against the bytes. Ported from
// syft's FileNameTemplateVersionMatcher (Apache-2.0).
type nameTemplate struct {
	fileRe      *regexp.Regexp
	contentTmpl *template.Template
}

// matches reports whether path matches any of the classifier's globs.
func (c *classifier) matches(p string) bool {
	for _, g := range c.globs {
		if globMatch(g, p) {
			return true
		}
	}
	return false
}

// list is a terse constructor for the glob/cpe string slices below.
func list(s ...string) []string { return s }

// mc builds a content-regex classifier, compiling each pattern at load time (a
// malformed pattern panics here, which the catalog-integrity test turns into a
// failure).
func mc(purl string, globs, cpes []string, patterns ...string) classifier {
	res := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		res[i] = regexp.MustCompile(p)
	}
	return classifier{globs: globs, purl: purl, res: res, cpes: cpes}
}

// mcTmpl builds a filename-template classifier: fileRegex extracts version hints
// from the path, contentTemplate renders into the content regex. Both are
// compiled at load time.
func mcTmpl(purl string, globs, cpes []string, fileRegex, contentTemplate string) classifier {
	return classifier{
		globs: globs,
		purl:  purl,
		cpes:  cpes,
		nameTmpl: &nameTemplate{
			fileRe:      regexp.MustCompile(fileRegex),
			contentTmpl: template.Must(template.New("content").Parse(contentTemplate)),
		},
	}
}

// defaultCatalog returns the built-in classifiers, ported from anchore/syft's
// binary cataloger (syft/pkg/cataloger/binary, Apache-2.0). Each entry's
// content-regex evidence is carried over verbatim; syft's cross-file fallbacks
// (shared-library lookups, sibling VERSION files, filename templates) and its
// Java JDK/JRE branching set are intentionally not ported here — see doc.go.
func defaultCatalog() []classifier {
	return []classifier{
		mc("pkg:generic/pypy@version", list("**/libpypy*.so*"), list(),
			`(?m)\[PyPy (?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		// python: the full version (NUL-delimited in the bytes) is keyed off the
		// major.minor in the filename. Ported from syft; its shared-library-lookup
		// fallback is omitted — the .so is matched directly by the libpython glob,
		// and a static build carries the version in the binary itself.
		mcTmpl("pkg:generic/python@version", list("**/libpython*.so*"),
			list("cpe:2.3:a:python_software_foundation:python:*:*:*:*:*:*:*:*", "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"),
			`(?:.*/|^)libpython(?P<version>[0-9]+(?:\.[0-9]+)+)[a-z]?\.so.*$`,
			`(?m)\x00(?P<version>{{ .version }}[-._a-zA-Z0-9]*)\x00`),
		mcTmpl("pkg:generic/python@version", list("**/python*"),
			list("cpe:2.3:a:python_software_foundation:python:*:*:*:*:*:*:*:*", "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"),
			`(?:.*/|^)python(?P<version>[0-9]+(?:\.[0-9]+)+)$`,
			`(?m)\x00(?P<version>{{ .version }}[-._a-zA-Z0-9]*)\x00`),
		mc("pkg:generic/go@version", list("**/go", "**/go.exe"), list("cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*"),
			`(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)?)\x00`),
		mc("pkg:generic/julia@version", list("**/libjulia-internal.so"), list("cpe:2.3:a:julialang:julia:*:*:*:*:*:*:*:*"),
			`(?m)__init__\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00verify`),
		mc("pkg:golang/helm.sh/helm@version", list("**/helm"), list("cpe:2.3:a:helm:helm:*:*:*:*:*:*:*:*"),
			`(?m)\x00v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`),
		mc("pkg:generic/redis@version", list("**/redis-server"), list("cpe:2.3:a:redislabs:redis:*:*:*:*:*:*:*:*", "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"),
			`[^\d](?P<version>\d+.\d+\.\d+)buildkitsandbox-\d+`,
			`[^\d](?P<version>[0-9]+\.[0-9]+\.[0-9]+)\w{12}-\d+`,
			`Redis version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		mc("pkg:generic/valkey@version", list("**/valkey-server"), list("cpe:2.3:a:lfprojects:valkey:*:*:*:*:*:*:*:*", "cpe:2.3:a:linuxfoundation:valkey:*:*:*:*:*:*:*:*", "cpe:2.3:a:valkey-io:valkey:*:*:*:*:*:*:*:*"),
			`[^\d](?P<version>\d+.\d+\.\d+)buildkitsandbox-\d+`),
		mc("pkg:generic/node@version", list("**/node"), list("cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"),
			`(?m)\x00(node )?v(?P<version>(0|4|5|6)\.[0-9]+\.[0-9]+)\x00`,
			`(?m)node\.js\/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		mc("pkg:generic/busybox@version", list("**/busybox"), list("cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*"),
			`(?m)BusyBox\s+v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		mc("pkg:generic/util-linux@version", list("**/getopt"), list("cpe:2.3:a:kernel:util-linux:*:*:*:*:*:*:*:*"),
			`\x00util-linux\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`),
		mc("pkg:generic/haproxy@version", list("**/haproxy"), list("cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*"),
			`(?m)version (?P<version>[0-9]+\.[0-9]+(\.|-dev|-rc)[0-9]+)(-[a-z0-9]{7})?, released 20`,
			`(?m)HA-Proxy version (?P<version>[0-9]+\.[0-9]+(\.|-dev)[0-9]+)`,
			`(?m)(?P<version>[0-9]+\.[0-9]+(\.|-dev)[0-9]+)-[0-9a-zA-Z]{7}.+HAProxy version`),
		mc("pkg:generic/perl@version", list("**/perl"), list("cpe:2.3:a:perl:perl:*:*:*:*:*:*:*:*"),
			`(?m)\/usr\/local\/lib\/perl\d\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		mc("pkg:generic/composer@version", list("**/composer*"), list("cpe:2.3:a:getcomposer:composer:*:*:*:*:*:*:*:*"),
			`(?m)'pretty_version'\s*=>\s*'(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)'`),
		mc("pkg:generic/httpd@version", list("**/httpd"), list("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
			`(?m)Apache\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		mc("pkg:generic/memcached@version", list("**/memcached"), list("cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*"),
			`(?m)memcached\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		mc("pkg:generic/traefik@version", list("**/traefik"), list("cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*"),
			`(?m)(\x00v?|\x{FFFD}.?)(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00`),
		mc("pkg:generic/arangodb@version", list("**/arangosh"), list("cpe:2.3:a:arangodb:arangodb:*:*:*:*:*:*:*:*"),
			`(?m)\x00*(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+)?)\s(enterprise\s)?\[linux\]`),
		mc("pkg:generic/postgresql@version", list("**/postgres"), list("cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"),
			`(?m)(\x00|\?)PostgreSQL (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
		mc("pkg:generic/mysql@version", list("**/mysql"), list("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"),
			`\x00(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)\x00+mysql`,
			`(?m).*/mysql-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
		mc("pkg:generic/percona-server@version", list("**/mysql"), list("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*", "cpe:2.3:a:percona:percona_server:*:*:*:*:*:*:*:*"),
			`(?m).*/percona-server-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
		mc("pkg:generic/percona-xtradb-cluster@version", list("**/mysql"), list("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*", "cpe:2.3:a:percona:percona_server:*:*:*:*:*:*:*:*", "cpe:2.3:a:percona:xtradb_cluster:*:*:*:*:*:*:*:*"),
			`(?m).*/Percona-XtraDB-Cluster-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
		mc("pkg:generic/percona-xtrabackup@version", list("**/xtrabackup"), list("cpe:2.3:a:percona:xtrabackup:*:*:*:*:*:*:*:*"),
			`(?m).*/percona-xtrabackup-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
		mc("pkg:generic/mariadb@version", list("**/mariadb", "**/mysql"), list("cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*"),
			`(?m)(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)-MariaDB`),
		mc("pkg:generic/rust@version", list("**/libstd-????????????????.so"), list("cpe:2.3:a:rust-lang:rust:*:*:*:*:*:*:*:*"),
			`(?m)(\x00)clang LLVM \(rustc version (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)) \(\w+ \d{4}\-\d{2}\-\d{2}\)`),
		mc("pkg:generic/rust@version", list("**/libstd-????????????????.dylib"), list("cpe:2.3:a:rust-lang:rust:*:*:*:*:*:*:*:*"),
			`(?m)c (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)) \(\w+ \d{4}\-\d{2}\-\d{2}\)`),
		mc("pkg:generic/ruby@version", list("**/ruby"), list("cpe:2.3:a:ruby-lang:ruby:*:*:*:*:*:*:*:*"),
			`(?m)ruby (?P<version>[0-9]+\.[0-9]+\.[0-9]+((p|preview|rc|dev)[0-9]*)?) `),
		mc("pkg:generic/erlang@version", list("**/erlexec"), list(`cpe:2.3:a:erlang:erlang\/otp:*:*:*:*:*:*:*:*`),
			`(?m)/src/otp_src_(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/`,
			`(?m)/usr/local/src/otp-(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/`),
		mc("pkg:generic/erlang@version", list("**/beam.smp"), list(`cpe:2.3:a:erlang:erlang\/otp:*:*:*:*:*:*:*:*`),
			`(?m)/src/otp_src_(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/`,
			`(?m)/usr/local/src/otp-(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/`,
			`\x00+(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)\x00+Erlang/OTP`,
			`(?s)Erlang/OTP.{1,150}\x00+(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)\x00+`),
		mc("pkg:generic/erlang@version", list("**/liberts_internal.a"), list(`cpe:2.3:a:erlang:erlang\/otp:*:*:*:*:*:*:*:*`),
			`(?m)/src/otp_src_(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/`,
			`(?m)/usr/local/src/otp-(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/`),
		mc("pkg:generic/swipl@version", list("**/swipl"), list(`cpe:2.3:a:erlang:erlang\/otp:*:*:*:*:*:*:*:*`),
			`(?m)swipl-(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\/`),
		mc("pkg:generic/dart@version", list("**/dart"), list("cpe:2.3:a:dart:dart_software_development_kit:*:*:*:*:*:*:*:*"),
			`(?m)\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+(\.[0-9]+)?\.beta)?) `),
		mc("pkg:generic/deno@version", list("**/deno"), list("cpe:2.3:a:deno:deno:*:*:*:*:*:*:*:*"),
			`Deno/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		mc("pkg:generic/haskell/ghc@version", list("**/ghc*"), list("cpe:2.3:a:haskell:ghc:*:*:*:*:*:*:*:*"),
			`(?m)\x00GHC (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`,
			`\x00libHSghc\-(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\-([a-zA-Z0-9]+\-)?ghc[0-9]+\.[0-9]+\.[0-9]+\.so\x00`),
		mc("pkg:generic/haskell/cabal@version", list("**/cabal"), list("cpe:2.3:a:haskell:cabal:*:*:*:*:*:*:*:*"),
			`(?m)\x00Cabal-(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)-`,
			`\x00.{0,50}cabal\-install\-(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)\-[a-zA-Z0-9]+\x00+`),
		mc("pkg:generic/haskell/stack@version", list("**/stack"), list("cpe:2.3:a:haskell:stack:*:*:*:*:*:*:*:*"),
			`(?m)Version\s*(?P<version>[0-9]+\.[0-9]+\.[0-9]+),\s*Git`),
		mc("pkg:golang/github.com/hashicorp/consul@version", list("**/consul"), list("cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*"),
			`CONSUL_VERSION: (?P<version>\d+\.\d+\.\d+)`,
			`GitDescribe=(?P<version>\d+\.\d+\.\d+)\"`,
			`\x00+v(?P<version>\d+\.\d+\.\d+)\x00+`),
		mc("pkg:golang/github.com/hashicorp/vault@version", list("**/vault"), list("cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*"),
			`(?m)revoke(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`,
			`state(?P<version>[0-9]+\.[0-9]+\.[0-9]+\-rc[0-9])`,
			`016x(?P<version>1.1[1,3,4].[0-9]{1,2})`,
			`\x00+(?P<version>1\.[0-9][0,1]?\.[0-9]+)\x00+`),
		mc("pkg:generic/nginx@version", list("**/nginx"), list("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"),
			`(?m)(\x00|\?)nginx version: [^\/]+\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:\+\d+)?(?:-\d+)?)`),
		mc("pkg:generic/bash@version", list("**/bash"), list("cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*"),
			`(?m)@\(#\)Bash version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\([0-9]\) [a-z0-9]+ GNU`),
		mc("pkg:generic/openssl@version", list("**/openssl"), list("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"),
			`\x00OpenSSL (?P<version>[0-9]+\.[0-9]+\.[0-9]+([a-z]+|-alpha[0-9]|-beta[0-9]|-rc[0-9])?)`),
		mc("pkg:generic/openldap@version", list("**/ldapsearch"), list("cpe:2.3:a:openldap:openldap:*:*:*:*:*:*:*:*"),
			`\$OpenLDAP:\sldapsearch\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		mc("pkg:generic/qtbase@version", list("**/libQt*Core.so*"), list("cpe:2.3:a:qt:qt:*:*:*:*:*:*:*:*", "cpe:2.3:a:qt:qtbase:*:*:*:*:*:*:*:*"),
			`\x00\x00Qt (?P<version>[0-9]+\.[0-9]+\.[0-9]+) \(`,
			`QtCore library version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		mc("pkg:generic/gcc@version", list("**/gcc"), list("cpe:2.3:a:gnu:gcc:*:*:*:*:*:*:*:*"),
			`GCC: \(GNU\) (?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		mc("pkg:github/fluent/fluent-bit@version", list("**/fluent-bit"), list("cpe:2.3:a:treasuredata:fluent_bit:*:*:*:*:*:*:*:*"),
			`\x00(\x00)?(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00(\x1b\[1m\x00|\x00|\x00\x00)?(%s)?Fluent`),
		mc("pkg:generic/wp-cli@version", list("**/wp"), list("cpe:2.3:a:wp-cli:wp-cli:*:*:*:*:*:*:*:*"),
			`(?m)wp-cli/wp-cli (?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		mc("pkg:generic/curl@version", list("**/curl"), list("cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"),
			`curl/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		mc("pkg:generic/lighttpd@version", list("**/lighttpd"), list("cpe:2.3:a:lighttpd:lighttpd:*:*:*:*:*:*:*:*"),
			`\x00lighttpd/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`),
		mc("pkg:generic/proftpd@version", list("**/proftpd"), list("cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*:*"),
			`\x00ProFTPD Version (?P<version>[0-9]+\.[0-9]+\.[0-9]+[a-z]?)\x00`),
		mc("pkg:generic/zstd@version", list("**/zstd"), list("cpe:2.3:a:facebook:zstandard:*:*:*:*:*:*:*:*"),
			`\x00v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`),
		mc("pkg:generic/xz@version", list("**/xz"), list("cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*"),
			`\x00xz \(XZ Utils\) (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`),
		mc("pkg:generic/gzip@version", list("**/gzip"), list("cpe:2.3:a:gnu:gzip:*:*:*:*:*:*:*:*"),
			`\x00(?P<version>[0-9]+\.[0-9]+)\x00`),
		mc("pkg:generic/sqlcipher@version", list("**/sqlcipher"), list("cpe:2.3:a:zetetic:sqlcipher:*:*:*:*:*:*:*:*"),
			`[^0-9]\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`),
		mc("pkg:generic/jq@version", list("**/jq"), list("cpe:2.3:a:jqlang:jq:*:*:*:*:*:*:*:*"),
			`\x00(?P<version>[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]+)?)\x00`),
		mc("pkg:generic/chrome@version", list("**/chrome"), list("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"),
			`\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\x00Default`),
		mc("pkg:generic/ffmpeg@version", list("**/ffmpeg"), list("cpe:2.3:a:ffmpeg:ffmpeg:*:*:*:*:*:*:*:*"),
			`(?m)%s version (?P<version>[0-9]+\.[0-9]+(\.[0-9]+)?)`),
		mc("pkg:generic/ffmpeg@version", list("**/libav*"), list("cpe:2.3:a:ffmpeg:ffmpeg:*:*:*:*:*:*:*:*"),
			`(?m)FFmpeg version (?P<version>[0-9]+\.[0-9]+(\.[0-9]+)?)`,
			`(?m)Lavc(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`,
			`(?m)Lavf(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		mc("pkg:generic/ffmpeg@version", list("**/libswresample*"), list("cpe:2.3:a:ffmpeg:ffmpeg:*:*:*:*:*:*:*:*"),
			`(?m)FFmpeg version (?P<version>[0-9]+\.[0-9]+(\.[0-9]+)?)`),
		mc("pkg:generic/elixir@version", list("**/elixir"), list("cpe:2.3:a:elixir-lang:elixir:*:*:*:*:*:*:*:*"),
			`(?m)ELIXIR_VERSION=(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		mc("pkg:generic/elixir@version", list("**/elixir/ebin/elixir.app"), list("cpe:2.3:a:elixir-lang:elixir:*:*:*:*:*:*:*:*"),
			`(?m)\{vsn,"(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9]+)?)"\}`),
		mc("pkg:generic/istio@version", list("**/pilot-discovery"), list("cpe:2.3:a:istio:istio:*:*:*:*:*:*:*:*"),
			`[0-9]+\.[0-9]+\.[0-9]+\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]+|-beta\.[0-9]+|-rc\.[0-9]+|-dev)?)\x00+`,
			`Clean\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]+|-beta\.[0-9]+|-rc\.[0-9]+|-dev)?)\x00+`,
			`Modified\x00+(?P<version>[0-9]+\.[0-9]+-dev)\x00+`,
			`(?s)(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]+|-beta\.[0-9]+|-rc\.[0-9]+|-dev)?)\x00+.{1,100}S?=v<y5`),
		mc("pkg:generic/istio@version", list("**/pilot-agent"), list("cpe:2.3:a:istio:istio:*:*:*:*:*:*:*:*"),
			`[0-9]+\.[0-9]+\.[0-9]+\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]+|-beta\.[0-9]+|-rc\.[0-9]+|-dev)?)\x00+`,
			`Clean\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]+|-beta\.[0-9]+|-rc\.[0-9]+|-dev)?)\x00+`,
			`Modified\x00+(?P<version>[0-9]+\.[0-9]+-dev)\x00+`,
			`(?s)(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]+|-beta\.[0-9]+|-rc\.[0-9]+|-dev)?)\x00+.{1,100}S?=v<y5`),
		mc("pkg:generic/grafana@version", list("**/grafana"), list("cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"),
			`\x00+(?P<version>[0-9]{2}\.[0-9]+\.[0-9]+\-[0-9]{6,})\x00+`,
			`\x00+release-(?P<version>[0-9]{2}\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+`,
			`(?s)\x00+go1\.[0-9]+\.[0-9]+\x00+(?P<version>[0-9]{2}\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+.{1,500}\+DT`,
			`(?P<version>[0-9]{2}\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+\$a`,
			`\x00.(?P<version>10\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00`,
			`(?s)(?P<version>[0-9]{2}\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+.{1,100}\x00go1\.[0-9]+\.[0-9]+\x00.{1,100}\+DT`,
			`(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+v[0-9]+\.[0-9]+\.x\x00+`,
			`HEAD\x00+.*\x00+(?P<version>[0-9]\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+`,
			`[a-z0-9]+\x00+(?P<version>[0-9]\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+\/usr\/local\/go`),
		mc("pkg:generic/grafana@version", list("**/grafana-server"), list("cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"),
			`[a-z0-9]+\x00+(?P<version>[0-9]\.[0-9]+\.[0-9]+(-beta[0-9]|-test)?)\x00+\/usr\/local\/go`,
			`HEAD\x00+.*\x00+(?P<version>[0-9]\.[0-9]+\.[0-9]+(-beta[0-9]|-test)?)\x00+`,
			`(?s)\x00+(?P<version>[0-9]\.[0-9]+\.[0-9]+(-beta[0-9]|-test)?)\x00+.*\x00+.{1,1000}\x00+\/u`),
		mc("pkg:generic/envoy@version", list("**/envoy"), list("cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*"),
			`(?s)\x00(?P<version>1\.3[0-9]\.[0-9]+(-dev)?)\x00.{0,1000}envoy_reloadable_features`,
			`(?s)\x00(?P<version>1\.34\.5)\x00.{0,200}envoy\.reloadable_features`,
			`(?s)envoy_quic_.{0,1000}\x00(?P<version>1\.2[0-9]\.[0-9]+(-dev)?)\x00`,
			`(?s)\x00(?P<version>1\.[12][0-9]\.[0-9]+(-dev)?)\x00.{0,1000}Unable to`,
			`(?s)\x00(?P<version>1\.2[0-9]\.[0-9]+(-dev)?)\x00.{0,580}ValidationError`,
			`(?s)\x00(?P<version>1\.1[0-9]\.[0-9]+(-dev)?)\x00.{0,1000}ValidationError`,
			`(?s)\[source/.{0,200}\x00(?P<version>1\.1[0-9]\.[0-9]+(-dev)?)\x00`,
			`(?s)\x00(?P<version>1\.[0-9]\.[0-9]+(-dev)?)\x00.{0,20}RELEASE`),
		mc("pkg:generic/mongodb@version", list("**/mongod"), list("cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"),
			`(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00tcmalloc`,
			`(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+heap_size`,
			`(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+cppdefines`),
	}
}
