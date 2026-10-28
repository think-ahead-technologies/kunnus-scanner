// ABOUTME: Encoder is the struct form of Encode, satisfying the port internal/app declares.
// ABOUTME: The package function stays: it is what the encode tests and this type both call.
package sbom

import "io"

// Encoder adapts this package to the encoder port. It holds no state — the
// type exists so the use case can name what it depends on.
type Encoder struct{}

// Encode writes the CycloneDX document. See the package-level Encode.
func (Encoder) Encode(out io.Writer, opts Options) error { return Encode(out, opts) }
