// ABOUTME: Extracts SHA-512 hashes from bun.lock (Bun's text lockfile format).
// ABOUTME: Format is JSONC with packages-as-tuples; integrity sits at index 3 of each tuple.
package hashes

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tidwall/jsonc"
)

// bunLockfile mirrors the subset of bun.lock we read. Bun's lockfile is JSONC
// (JSON with comments and trailing commas); we strip those via tidwall/jsonc
// before unmarshaling. The packages map's value is a heterogeneous tuple:
//
//	[ "<name>@<version>", "<resolution>", {<deps>}, "<integrity>" ]
//
// Some entries omit the trailing integrity (git deps, workspaces).
type bunLockfile struct {
	Packages map[string][]any `json:"packages"`
}

func parseBunLock(path string) (Map, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock bunLockfile
	if err := json.Unmarshal(jsonc.ToJSON(data), &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	out := make(Map)
	for _, tuple := range lock.Packages {
		if len(tuple) < 4 {
			continue
		}
		spec, ok := tuple[0].(string)
		if !ok || spec == "" {
			continue
		}
		integrity, ok := tuple[3].(string)
		if !ok || integrity == "" {
			continue
		}
		name, version, ok := bunSplitSpec(spec)
		if !ok {
			continue
		}
		digest, err := decodeSRI(integrity)
		if err != nil {
			continue
		}
		out[npmPURL(name, version)] = Hash{Algorithm: AlgSHA512, Hex: digest}
	}
	return out, nil
}

// bunSplitSpec parses a "name@version" specifier into its components. Scoped
// packages have two "@" characters ("@babel/core@7.0.0"); we split on the
// LAST "@" so scope-prefix and version-prefix don't conflict.
func bunSplitSpec(spec string) (string, string, bool) {
	at := -1
	for i := len(spec) - 1; i > 0; i-- {
		if spec[i] == '@' {
			at = i
			break
		}
	}
	if at <= 0 {
		return "", "", false
	}
	name := spec[:at]
	version := spec[at+1:]
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}
