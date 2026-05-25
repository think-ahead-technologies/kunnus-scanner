// ABOUTME: bun parser — bun.lock (JSONC) SHA-512 SRI extraction.
// ABOUTME: Format is JSONC with packages-as-tuples; integrity sits at index 3 of each tuple.
package ecosystem

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tidwall/jsonc"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
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

func parseBunLock(path string) (hashes.Map, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock bunLockfile
	if err := json.Unmarshal(jsonc.ToJSON(data), &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	out := make(hashes.Map)
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
		name, version, ok := splitNpmSpec(spec)
		if !ok {
			continue
		}
		digest, err := decodeSRI(integrity)
		if err != nil {
			continue
		}
		out.Add(npmPURL(name, version), hashes.Hash{Algorithm: hashes.AlgSHA512, Hex: digest})
	}
	return out, nil
}
