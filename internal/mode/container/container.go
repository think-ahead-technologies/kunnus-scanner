// ABOUTME: Container-image scan mode. Implements mode.Mode with an image reference as its target.
// ABOUTME: Opens the image, builds the installed-state union config, and signals a container scan via Plan.Image.
package container

import (
	"context"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	scalibr "github.com/google/osv-scalibr"
	scalibrimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"

	"github.com/think-ahead/kunnus-scanner/internal/apkchecksum"
	"github.com/think-ahead/kunnus-scanner/internal/binclass"
	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/ecosystem"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/osfamily"
	"github.com/think-ahead/kunnus-scanner/internal/ownership"
	"github.com/think-ahead/kunnus-scanner/internal/pluginset"
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

// Mode implements mode.Mode for container-image scans. Unlike the path-based
// modes its target is an image reference (a registry name, a tarball path, or a
// local docker image), and its Plan opens that image — for a remote reference,
// pulling it — so the runner can scan the image's layers via ScanContainer.
type Mode struct{}

// New returns a fresh container mode.
func New() *Mode { return &Mode{} }

// Name returns the user-facing name.
func (*Mode) Name() string { return "container" }

// Plan resolves target into an image and builds the installed-state union scan
// config. It sets Plan.Image so the runner dispatches to a container scan (via
// scalibr ScanContainer), and Plan.PostScanHashes so the apk pull-checksums
// scalibr drops are recovered once the inventory exists. Overrides' Source
// selects how the reference is resolved; EnablePlugins / DisablePlugins adjust
// the selection; TargetOS and Ecosystems are ignored (containers are Linux and
// carry every ecosystem).
func (*Mode) Plan(ctx context.Context, target string, ov mode.Overrides) (*mode.Plan, error) {
	if target == "" {
		return nil, fmt.Errorf("a container image reference or tarball path is required")
	}

	src := resolveSource(target, sourceFromOverrides(ov))
	img, err := openImage(ctx, target, src)
	if err != nil {
		return nil, fmt.Errorf("open image: %w", err)
	}

	cfg, err := buildConfig(ov)
	if err != nil {
		return nil, err
	}

	id, imgVersion := seriesIdentity(target, src)
	return &mode.Plan{
		Config: cfg,
		Image:  img,
		Component: bom.ComponentInfo{
			Name:    target,
			Version: imgVersion,
			ID:      id,
			Type:    bom.ComponentTypeContainer,
		},
		ExtraComponents: osComponent(img),
		// Read the image's dpkg/apk file ownership so the encoder can drop binary
		// classifier pkg:generic twins of packaged binaries (e.g. /usr/bin/xz
		// owned by xz-utils) by path rather than by name.
		OwnedFiles: ownership.Scan(img.FS()),
		// apk pull-checksums key off the scanned packages, so they can only be
		// recovered after the scan from the resulting inventory — the container
		// analog of repo mode's planning-time lockfile hash mining.
		PostScanHashes: func(inv inventory.Inventory) hashes.Map {
			return apkchecksum.Mine(inv, img.FS())
		},
	}, nil
}

// seriesIdentity derives the stable component identity for an image reference:
// the repository path without tag or digest, so successive builds of one image
// stay in one serial-number series, with the tag as the version when the
// reference carries one. A digest pins a single build — using it as the
// version would make every document a series of one, so digest references get
// no version. Tarball paths are local files, not stable identities.
func seriesIdentity(target string, src Source) (id, version string) {
	if src == SourceTarball {
		return "", ""
	}
	ref, err := name.ParseReference(target)
	if err != nil {
		return "", ""
	}
	id = ref.Context().Name()
	if tag, ok := ref.(name.Tag); ok {
		version = tag.TagStr()
	}
	return id, version
}

// sourceFromOverrides maps the user-facing Source override to a Source, treating
// an empty value as SourceAuto.
func sourceFromOverrides(ov mode.Overrides) Source {
	if ov.Source == "" {
		return SourceAuto
	}
	return Source(ov.Source)
}

// osComponent reads the image's /etc/os-release and returns the
// operating-system component, named by the distro ID with VERSION_ID as its
// version. Returns nil when the image declares no OS, so scratch and distroless
// images get no nameless component.
func osComponent(img *scalibrimage.Image) []bom.ExtraComponent {
	id, version, ok := osfamily.LinuxOSRelease(img.FS())
	if !ok {
		return nil
	}
	ref := "os:" + id
	if version != "" {
		ref += "@" + version
	}
	return []bom.ExtraComponent{{
		Name:    id,
		Version: version,
		Type:    bom.ComponentTypeOS,
		BomRef:  ref,
	}}
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

// buildConfig selects each ecosystem's installed-state extractor, every Linux
// OS family's plugins, and the embedded-SBOM extractors, applies user
// overrides, and filters to what can run under Linux container capabilities.
//
// Installed-only (not the lockfile extractors repo scans use) keeps the SBOM to
// what is actually present in the image rather than what a stray lockfile
// declares. The SBOM extractors additionally ingest any SBOM the image ships
// for itself (e.g. /usr/share/spdx/*.spdx.json) — a vendor's own SBOM is the
// authoritative record of the image's contents and often lists components that
// leave no other on-disk trace. Per-extractor FileRequired then decides what
// the image filesystem actually matches.
func buildConfig(ov mode.Overrides) (*scalibr.ScanConfig, error) {
	names := pluginset.Union(
		ecosystem.AllInstalledPlugins(),
		osfamily.ContainerLinuxPlugins(),
		[]string{cdx.Name, spdx.Name}, // SBOMs shipped inside the image
	)
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

	// The binary classifier is a kunnus extractor (not in scalibr's name
	// registry), so it is appended directly. It surfaces software compiled into
	// the image outside any package manager — the one class of component the
	// installed-state extractors above cannot see.
	plugins = append(plugins, binclass.New())

	plugins = mode.AddOfflineLicenseEnrichers(plugins)
	plugins, err = mode.AddOnlineLicenses(plugins, caps, ov)
	if err != nil {
		return nil, err
	}

	return &scalibr.ScanConfig{
		Plugins:      plugins,
		Capabilities: caps,
	}, nil
}
