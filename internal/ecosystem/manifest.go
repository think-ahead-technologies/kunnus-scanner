// ABOUTME: Per-installed-package manifest license parsers, keyed by the scalibr extractor that produced the package.
// ABOUTME: Unlike lockfile LicenseParsers (one file, many packages), these read a single package's own manifest.
package ecosystem

import (
	"bufio"
	"encoding/json"
	"io"
	"net/textproto"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
)

// manifestLicenseParsers maps a scalibr extractor name to the parser that reads
// licences from the per-package manifest that extractor consumes. Used for
// installed/container scans, where each package's manifest (e.g.
// node_modules/<pkg>/package.json) carries a licence that scalibr does not
// surface. Keyed by extractor because the package, not a marker filename,
// identifies which manifest to read.
var manifestLicenseParsers = map[string]func(io.Reader) ([]string, error){
	packagejson.Name: parsePackageJSONLicense,
	wheelegg.Name:    parseWheelMetadataLicense,
}

// ManifestLicenseParser returns the parser for the per-package manifest produced
// by the named extractor, or (nil, false) if that extractor's packages carry no
// parseable manifest licence.
func ManifestLicenseParser(extractorName string) (func(io.Reader) ([]string, error), bool) {
	p, ok := manifestLicenseParsers[extractorName]
	return p, ok
}

// parsePackageJSONLicense extracts licences from a package.json. It handles the
// modern "license" string (an SPDX id or expression), the legacy "license"
// object ({"type": ...}), and the legacy "licenses" array ([{"type": ...}]).
func parsePackageJSONLicense(r io.Reader) ([]string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var pj struct {
		License  json.RawMessage `json:"license"`
		Licenses json.RawMessage `json:"licenses"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		return nil, err
	}

	var out []string
	if len(pj.License) > 0 {
		var s string
		if json.Unmarshal(pj.License, &s) == nil && s != "" {
			out = append(out, s)
		} else {
			var obj struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(pj.License, &obj) == nil && obj.Type != "" {
				out = append(out, obj.Type)
			}
		}
	}
	if len(pj.Licenses) > 0 {
		var arr []struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(pj.Licenses, &arr) == nil {
			for _, l := range arr {
				if l.Type != "" {
					out = append(out, l.Type)
				}
			}
		}
	}
	return out, nil
}

// maxLicenseHeaderLen caps the legacy free-text "License" header we accept.
// Older wheels sometimes inline the entire licence text there; anything longer
// than a plausible identifier/expression is dropped rather than turned into a
// giant LicenseRef.
const maxLicenseHeaderLen = 100

// parseWheelMetadataLicense extracts licences from a Python dist-info METADATA or
// egg-info PKG-INFO file (RFC 822-style headers). In priority order:
//   - "License-Expression" (PEP 639) — already an SPDX expression;
//   - "License :: ..." trove classifiers — mapped to SPDX (see troveToSPDX);
//   - the legacy free-text "License" header — passed through for normalization.
func parseWheelMetadataLicense(r io.Reader) ([]string, error) {
	tp := textproto.NewReader(bufio.NewReader(r))
	hdr, err := tp.ReadMIMEHeader()
	// ReadMIMEHeader reports io.EOF when the file ends without a blank line after
	// the headers (common for METADATA with no body); the headers it parsed are
	// still valid, so only fail when nothing was read.
	if err != nil && len(hdr) == 0 {
		return nil, err
	}

	if exprs := hdr.Values("License-Expression"); len(exprs) > 0 {
		if v := strings.TrimSpace(exprs[0]); v != "" {
			return []string{v}, nil
		}
	}

	var out []string
	for _, c := range hdr.Values("Classifier") {
		if spdx, ok := troveToSPDX[strings.TrimSpace(c)]; ok {
			out = append(out, spdx)
		}
	}
	if len(out) > 0 {
		return out, nil
	}

	if lic := hdr.Values("License"); len(lic) > 0 {
		v := strings.TrimSpace(lic[0])
		if v != "" && len(v) <= maxLicenseHeaderLen {
			return []string{v}, nil
		}
	}
	return nil, nil
}

// troveToSPDX maps common PyPI "trove" license classifiers to SPDX identifiers.
// Only unambiguous mappings are listed; ambiguous classifiers (e.g. a bare
// "License :: OSI Approved") are omitted so we never assert a licence we cannot
// pin down. "BSD License" is mapped to the 3-clause variant, its overwhelmingly
// common meaning in the Python ecosystem.
var troveToSPDX = map[string]string{
	"License :: OSI Approved :: MIT License":                                             "MIT",
	"License :: OSI Approved :: Apache Software License":                                 "Apache-2.0",
	"License :: OSI Approved :: BSD License":                                             "BSD-3-Clause",
	"License :: OSI Approved :: ISC License (ISCL)":                                      "ISC",
	"License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)":                    "MPL-2.0",
	"License :: OSI Approved :: Python Software Foundation License":                      "PSF-2.0",
	"License :: OSI Approved :: The Unlicense (Unlicense)":                               "Unlicense",
	"License :: OSI Approved :: GNU General Public License v2 (GPLv2)":                   "GPL-2.0-only",
	"License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)":         "GPL-2.0-or-later",
	"License :: OSI Approved :: GNU General Public License v3 (GPLv3)":                   "GPL-3.0-only",
	"License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)":         "GPL-3.0-or-later",
	"License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)":           "LGPL-2.0-only",
	"License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
	"License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)":           "LGPL-3.0-only",
	"License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
}
