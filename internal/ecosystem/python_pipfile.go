// ABOUTME: Pipenv Pipfile.lock parser — JSON default/develop sections each carry hashes[] per package.
// ABOUTME: version is recorded as "==X.Y.Z"; the operator is stripped before building the PURL.
package ecosystem

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

type pipfileLockfile struct {
	Default map[string]pipfileEntry `json:"default"`
	Develop map[string]pipfileEntry `json:"develop"`
}

type pipfileEntry struct {
	Hashes  []string `json:"hashes"`
	Version string   `json:"version"`
}

func parsePipfileLock(r io.Reader) (hashes.Map, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	var lock pipfileLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}

	out := make(hashes.Map)
	for _, section := range []map[string]pipfileEntry{lock.Default, lock.Develop} {
		for name, entry := range section {
			version := strings.TrimPrefix(entry.Version, "==")
			if name == "" || version == "" || len(entry.Hashes) == 0 {
				continue
			}
			purl := pypiPURL(name, version)
			for _, sri := range entry.Hashes {
				addPyPIFileHash(out, purl, sri)
			}
		}
	}
	return out, nil
}
