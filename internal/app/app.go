// ABOUTME: The application service: plan a scan, run it, encode the SBOM. One use case, one call.
// ABOUTME: Takes a plain Request so the use case is invocable without a CLI — internal/command only translates flags.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/sbom"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
)

// Request is one SBOM generation, described in full. Every field is plain
// data or a port: nothing here knows where the values came from, which is
// what lets the use case run from a CLI, a test, or any future front end.
type Request struct {
	// Mode is the scan flavour to plan with (repo, os, container). Required.
	Mode mode.Mode

	// Target is what to scan: a filesystem path for the path-based modes, an
	// image reference for container.
	Target string

	// Overrides are the user's adjustments to what auto-detection chose.
	Overrides mode.Overrides

	// ComponentID and ComponentVersion refine the identity the mode derived
	// from the target. Non-empty values win, and they key the serial-number
	// series as well as the SBOM's root component, so the two cannot disagree.
	ComponentID      string
	ComponentVersion string

	// Author is the entity operating the scanner (CISA's SBOM Author element).
	// The zero value falls back to the kunnus creator identity, with a warning:
	// the scanner cannot know who runs it.
	Author bom.Author

	// SerialNumber is an explicit serialNumber override, bare or urn:uuid. It
	// is validated before the scan runs, so a malformed value fails fast rather
	// than after the expensive half of the work.
	SerialNumber string

	// Now and NewSerial are the encoder's clock and identity-less serial
	// source. Nil means the real ones; a caller pins them to make a document
	// reproducible.
	Now       func() time.Time
	NewSerial func() string
}

// Result reports what a completed generation produced beyond the document
// itself. A non-empty FailedPlugins means the scan finished and the SBOM was
// written, but some extractors failed — the caller decides what that is worth
// (the CLI turns it into a non-zero exit).
type Result struct {
	FailedPlugins []string
}

// GenerateSBOM plans the scan described by req, runs it, and writes the
// CycloneDX document to out.
//
// It returns an error only when no usable document was produced. A scan that
// completed with some extractors failing is a success here: the document is
// written and the failures are named in Result.FailedPlugins.
//
// Nothing is written to out unless encoding succeeds — but a failure partway
// through encoding can still have written bytes, so callers writing to a
// durable destination should stage through a sink they can abort (see
// internal/command).
func GenerateSBOM(ctx context.Context, out io.Writer, req Request) (*Result, error) {
	if req.Mode == nil {
		return nil, errors.New("no scan mode set on the request")
	}

	// Validate everything cheap before the expensive half: a malformed serial
	// must fail before the scan, not after it.
	serial := req.SerialNumber
	if serial != "" {
		var err error
		if serial, err = sbom.NormalizeSerial(serial); err != nil {
			return nil, &InvalidRequestError{Field: "SerialNumber", Err: err}
		}
	}

	// The scanner cannot know who operates it: unset, the document falls back
	// to the kunnus creator identity — correct when think-ahead runs the scan,
	// a placeholder for everyone else. Say so instead of guessing silently.
	if req.Author.IsZero() {
		slog.Warn("no author given; recording Kunnus as SBOM author — pass --author \"Name <email>\" to name your organization")
	}

	plan, err := req.Mode.Plan(ctx, req.Target, req.Overrides)
	if err != nil {
		return nil, fmt.Errorf("plan %s scan: %w", req.Mode.Name(), err)
	}

	result, err := runPlan(ctx, plan)
	if err != nil {
		return nil, fmt.Errorf("run %s scan: %w", req.Mode.Name(), err)
	}

	// Most digests are harvested during planning (plan.Hashes); a mode whose
	// digests depend on scan output (container apk checksums) supplies a
	// post-scan recovery hook instead. Merge the two so the encoder sees one map.
	hashMap := plan.Hashes
	if plan.PostScanHashes != nil {
		hashMap = mergeHashMaps(hashMap, plan.PostScanHashes(result.Inventory))
	}

	component := plan.Component
	if req.ComponentID != "" {
		component.ID = req.ComponentID
	}
	if req.ComponentVersion != "" {
		component.Version = req.ComponentVersion
	}

	err = sbom.Encode(out, sbom.Options{
		Inventory: result.Inventory,
		Component: component,
		Series: bom.Series{
			Mode:    req.Mode.Name(),
			ID:      component.ID,
			Version: component.Version,
			Serial:  serial,
		},
		Lifecycle: plan.Lifecycle,
		Author:    req.Author,
		Hashes:    hashMap,
		Licenses:  plan.Licenses,
		Graph:     plan.Graph,
		Extras:    plan.ExtraComponents,
		Owned:     plan.OwnedFiles,
		Now:       req.Now,
		NewSerial: req.NewSerial,
	})
	if err != nil {
		return nil, fmt.Errorf("encode sbom: %w", err)
	}

	return &Result{FailedPlugins: failedPlugins(result.PluginStatuses)}, nil
}

// runPlan dispatches to the matching scalibr scan: a container scan when the
// mode opened an image, otherwise a filesystem scan over the configured scan
// roots. Keeping the branch here lets internal/scan stay free of mode types.
func runPlan(ctx context.Context, plan *mode.Plan) (*scan.Result, error) {
	if plan.Image != nil {
		return scan.RunContainer(ctx, plan.Image, plan.Config)
	}
	return scan.Run(ctx, plan.Config)
}

// mergeHashMaps folds extra into base, tolerating nil on either side, and
// returns the combined map.
func mergeHashMaps(base, extra hashes.Map) hashes.Map {
	if len(extra) == 0 {
		return base
	}
	if base == nil {
		return extra
	}
	base.Merge(extra)
	return base
}
