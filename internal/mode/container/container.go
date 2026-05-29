// ABOUTME: Container-image scan planner. A sibling to mode/repo and mode/os: it opens an image and builds the union scan config.
// ABOUTME: Containers are not path-based, so this does not implement mode.Mode — the command runs scan.RunContainer with the Plan.
package container

import (
	"context"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/artifact/image"
	scalibrimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/ecosystem"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/osfamily"
)

// Source selects how an image reference is resolved into an image to scan.
type Source string

const (
	// SourceAuto resolves to SourceTarball when ref is an existing file, else
	// SourceRemote.
	SourceAuto Source = "auto"
	// SourceRemote pulls the image from a registry by name (e.g. "alpine:3.18").
	SourceRemote Source = "remote"
	// SourceTarball reads a docker-save / OCI image tarball from disk.
	SourceTarball Source = "tarball"
	// SourceDocker loads the image from the local docker daemon by name.
	SourceDocker Source = "docker"
)

// Image-open limits. Containers can carry large blobs; the file cap keeps a
// single oversized file from dominating memory, and the symlink cap bounds
// chain resolution. These mirror scalibr's own conservative defaults.
const (
	maxFileBytes    = 1 << 30 // 1 GiB
	maxSymlinkDepth = 6
)

// Plan is everything the container pipeline needs: the opened image, the scan
// config, and the root component metadata. It is the container analog of
// mode.Plan, but carries the image because container scans run via
// scan.RunContainer rather than over a filesystem path.
type Plan struct {
	Image     image.Image
	Config    *scalibr.ScanConfig
	Component bom.ComponentInfo
}

// Open resolves ref into an image and builds the scan config. The caller scans
// it with scan.RunContainer(plan.Image, plan.Config). Overrides' EnablePlugins
// / DisablePlugins adjust the plugin selection; TargetOS and Ecosystems are
// ignored (containers are Linux and carry every ecosystem).
func Open(ctx context.Context, ref string, src Source, ov mode.Overrides) (*Plan, error) {
	if ref == "" {
		return nil, fmt.Errorf("image reference is required")
	}

	img, err := openImage(ctx, ref, resolveSource(ref, src))
	if err != nil {
		return nil, err
	}

	cfg, err := buildConfig(ov)
	if err != nil {
		return nil, err
	}

	return &Plan{
		Image:  img,
		Config: cfg,
		Component: bom.ComponentInfo{
			Name: ref,
			Type: bom.ComponentTypeContainer,
		},
	}, nil
}

// resolveSource turns SourceAuto into a concrete source: a tarball if ref names
// an existing regular file on disk, otherwise a remote registry name.
func resolveSource(ref string, src Source) Source {
	if src != SourceAuto {
		return src
	}
	if fi, err := os.Stat(ref); err == nil && fi.Mode().IsRegular() {
		return SourceTarball
	}
	return SourceRemote
}

func openImage(ctx context.Context, ref string, src Source) (*scalibrimage.Image, error) {
	cfg := &scalibrimage.Config{
		MaxFileBytes:    maxFileBytes,
		MaxSymlinkDepth: maxSymlinkDepth,
	}
	switch src {
	case SourceTarball:
		img, err := scalibrimage.FromTarball(ref, cfg)
		if err != nil {
			return nil, fmt.Errorf("open image tarball %q: %w", ref, err)
		}
		return img, nil
	case SourceDocker:
		img, err := scalibrimage.FromLocalDockerImage(ref, cfg)
		if err != nil {
			return nil, fmt.Errorf("load docker image %q: %w", ref, err)
		}
		return img, nil
	case SourceRemote:
		img, err := scalibrimage.FromRemoteName(ref, cfg, remote.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("pull image %q: %w", ref, err)
		}
		return img, nil
	default:
		return nil, fmt.Errorf("unknown image source %q", src)
	}
}

// buildConfig selects the union of every ecosystem's plugins and every Linux OS
// family's plugins, applies user overrides, and filters to what can run under
// Linux container capabilities. Per-extractor FileRequired decides what the
// image actually matches, so enabling the union is correct, not wasteful.
func buildConfig(ov mode.Overrides) (*scalibr.ScanConfig, error) {
	names := dedup(append(ecosystem.AllPlugins(), osfamily.LinuxPluginsFor(nil)...))
	names = mode.ApplyOverrides(names, ov)

	plugins, err := pl.FromNames(names, nil)
	if err != nil {
		return nil, fmt.Errorf("load plugins %v: %w", names, err)
	}

	caps := &plugin.Capabilities{OS: plugin.OSLinux}
	plugins = plugin.FilterByCapabilities(plugins, caps)
	if len(plugins) == 0 {
		return nil, fmt.Errorf("no extractors selected for container scan")
	}

	return &scalibr.ScanConfig{
		Plugins:      plugins,
		Capabilities: caps,
	}, nil
}

func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
