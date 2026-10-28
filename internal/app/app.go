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

// Service is the use case with its driven ports bound. The zero value works
// and uses the production adapters, so a caller wanting the real thing need
// not name them; New is the same thing said explicitly.
type Service struct {
	Scanner Scanner
	Encoder Encoder
}

// New returns a Service wired to the production adapters.
func New() Service {
	return Service{Scanner: scan.Scanner{}, Encoder: sbom.Encoder{}}
}

// scanner returns the bound scanner, defaulting to the production adapter.
func (s Service) scanner() Scanner {
	if s.Scanner != nil {
		return s.Scanner
	}
	return scan.Scanner{}
}

// encoder returns the bound encoder, defaulting to the production adapter.
func (s Service) encoder() Encoder {
	if s.Encoder != nil {
		return s.Encoder
	}
	return sbom.Encoder{}
}

// Request is one SBOM generation. Every field is plain data or a port, so the
// use case runs from a CLI, a test, or any future front end alike.
type Request struct {
	// Mode is the scan flavour to plan with (repo, os, container). Required.
	Mode mode.Mode

	// Target is a filesystem path, or an image reference for container mode.
	Target string

	// Overrides are the user's adjustments to what auto-detection chose.
	Overrides mode.Overrides

	// ComponentID and ComponentVersion override the identity the mode derived.
	// They key the serial series and the root component both, so the two
	// cannot disagree.
	ComponentID      string
	ComponentVersion string

	// Author is the entity operating the scanner. Zero falls back to the
	// kunnus creator identity, with a warning.
	Author bom.Author

	// SerialNumber overrides serial derivation, bare or urn:uuid. Validated
	// before the scan runs.
	SerialNumber string

	// Now and NewSerial are the encoder's clock and identity-less serial
	// source. Nil means the real ones.
	Now       func() time.Time
	NewSerial func() string
}

// Result reports what a completed generation produced beyond the document. A
// non-empty FailedPlugins means the SBOM was written but some extractors
// failed; the caller decides what that is worth.
type Result struct {
	FailedPlugins []string
}

// GenerateSBOM plans the scan described by req, runs it through the bound
// ports, and writes the
// CycloneDX document to out. It errors only when no usable document was
// produced; a scan whose extractors partly failed still writes, and names them
// in Result.FailedPlugins.
//
// A failure partway through encoding can leave bytes on out, so callers writing
// somewhere durable should stage through a sink they can abort (internal/command).
func (s Service) GenerateSBOM(ctx context.Context, out io.Writer, req Request) (*Result, error) {
	if req.Mode == nil {
		return nil, errors.New("no scan mode set on the request")
	}

	// Validate the cheap things before the expensive half.
	serial := req.SerialNumber
	if serial != "" {
		var err error
		if serial, err = sbom.NormalizeSerial(serial); err != nil {
			return nil, &InvalidRequestError{Field: "SerialNumber", Err: err}
		}
	}

	// The scanner cannot know who operates it: unset, the document records the
	// kunnus identity, which is a placeholder for everyone else. Say so.
	if req.Author.IsZero() {
		slog.Warn("no author given; recording Kunnus as SBOM author — pass --author \"Name <email>\" to name your organization")
	}

	plan, err := req.Mode.Plan(ctx, req.Target, req.Overrides)
	if err != nil {
		return nil, fmt.Errorf("plan %s scan: %w", req.Mode.Name(), err)
	}

	result, err := s.runPlan(ctx, plan)
	if err != nil {
		return nil, fmt.Errorf("run %s scan: %w", req.Mode.Name(), err)
	}

	// Most digests come from planning; a mode whose digests depend on scan
	// output supplies a post-scan hook. Merge so the encoder sees one map.
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

	err = s.encoder().Encode(out, sbom.Options{
		Inventory: result.Inventory,
		Component: component,
		Series: bom.Series{
			Mode:    req.Mode.Name(),
			ID:      component.ID,
			Version: component.Version,
			Serial:  serial,
		},
		Lifecycle:  plan.Lifecycle,
		Author:     req.Author,
		Hashes:     hashMap,
		Licenses:   plan.Licenses,
		Graph:      plan.Graph,
		Extras:     plan.ExtraComponents,
		OwnedFiles: plan.OwnedFiles,
		Now:        req.Now,
		NewSerial:  req.NewSerial,
	})
	if err != nil {
		return nil, fmt.Errorf("encode sbom: %w", err)
	}

	return &Result{FailedPlugins: failedPlugins(result.PluginStatuses)}, nil
}

// runPlan dispatches to the matching scalibr scan: a container scan when the
// mode opened an image, a filesystem scan otherwise. Keeping the branch here
// lets internal/scan stay free of mode types.
func (s Service) runPlan(ctx context.Context, plan *mode.Plan) (*scan.Result, error) {
	if plan.Image != nil {
		return s.scanner().RunContainer(ctx, plan.Image, plan.Config)
	}
	return s.scanner().Run(ctx, plan.Config)
}

// mergeHashMaps folds extra into base, tolerating nil on either side.
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
