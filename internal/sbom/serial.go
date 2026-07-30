// ABOUTME: Derives the SBOM serialNumber: a deterministic UUIDv8 from the series identity,
// ABOUTME: an explicit override, or a random UUIDv4 when no stable identity exists.
package sbom

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
)

// serialNamespace is the fixed UUID namespace for kunnus serial derivation:
// the name-based UUID of the kunnus.tech domain, so the namespace is
// re-derivable and verifiably ours rather than an opaque constant
// (d22e9dc1-292c-5b0d-a2d4-b10793fdb5ea, pinned by test). It must never
// change — a new namespace would silently split every existing document
// series.
var serialNamespace = uuid.NewSHA1(uuid.NameSpaceDNS, []byte("kunnus.tech"))

// serialScheme versions the derivation key layout. Bump it if the key inputs
// ever change, so documents from old and new schemes never merge into one
// series by accident.
const serialScheme = "v1"

// serialKeySep separates the key fields. The ASCII unit separator cannot
// appear in a mode name, component id, or version, so distinct field values
// can never collide into the same key.
const serialKeySep = "\x1f"

// deriveSerial returns the serialNumber for a document in the given series
// and whether that serial is deterministic (i.e. the document belongs to a
// series that future scans can rejoin). Precedence: the explicit override,
// then identity-based derivation, then a random UUID for documents with no
// stable identity.
func deriveSerial(s bom.Series) (serial string, deterministic bool, err error) {
	if s.Serial != "" {
		norm, err := NormalizeSerial(s.Serial)
		if err != nil {
			return "", false, err
		}
		return norm, true, nil
	}
	if s.ID == "" {
		return "urn:uuid:" + uuid.New().String(), false, nil
	}
	key := strings.Join([]string{serialScheme, s.Mode, s.ID, s.Version}, serialKeySep)
	// UUIDv8 (RFC 9562 custom) from a SHA-256 of namespace+key: deterministic
	// like a v5 without inheriting v5's SHA-1. NewHash truncates the digest to
	// 128 bits and stamps the version/variant bits.
	u := uuid.NewHash(sha256.New(), serialNamespace, []byte(key), 8)
	return "urn:uuid:" + u.String(), true, nil
}

// NormalizeSerial validates a user-supplied serial number and returns it in
// the urn:uuid form the CycloneDX schema requires. Accepts a bare UUID or an
// already-prefixed one. Exported so the command layer can reject a malformed
// --serial-number before the scan runs instead of after.
func NormalizeSerial(s string) (string, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return "", fmt.Errorf("serial number %q is not a UUID: %w", s, err)
	}
	return "urn:uuid:" + u.String(), nil
}

// bomVersion returns the document version for a series member: the generation
// timestamp in Unix epoch seconds (metadata.timestamp when parseable, now
// otherwise). Successive scans of one series thus get strictly increasing
// versions without the scanner having to know which revisions came before —
// consumers order series members by version, exactly as CycloneDX specifies.
func bomVersion(timestamp string, now time.Time) int {
	if t, err := time.Parse(time.RFC3339, timestamp); err == nil {
		return int(t.Unix())
	}
	return int(now.Unix())
}
