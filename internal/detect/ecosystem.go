// ABOUTME: Walks a directory tree to recognise which language ecosystems are present.
// ABOUTME: Returns canonical ecosystem names that mode/repo maps to scalibr plugin sets.
package detect

import (
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"github.com/think-ahead/kunnus-scanner/internal/fswalk"
)

// Ecosystems walks scanRoot and returns the set of language ecosystems it found,
// inferred from manifest and lockfile names. The walk skips common heavy
// directories (.git, node_modules, vendor, target, dist, build) to keep
// detection fast on large monorepos.
func Ecosystems(scanRoot string) ([]string, error) {
	found := make(map[string]struct{})

	err := filepath.WalkDir(scanRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Permission errors on subtrees should not fail detection.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if fswalk.SkipDir(d.Name()) && path != scanRoot {
				return fs.SkipDir
			}
			return nil
		}
		if eco := ecosystemForFile(d.Name()); eco != "" {
			found[eco] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(found))
	for eco := range found {
		out = append(out, eco)
	}
	slices.Sort(out)
	return out, nil
}

// ecosystemForFile maps a filename to a canonical ecosystem name, or "" if unknown.
// File extensions are matched case-insensitively to handle Windows-extracted trees.
func ecosystemForFile(name string) string {
	lower := strings.ToLower(name)
	switch lower {
	case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lock":
		return "npm"
	case "go.mod", "go.sum":
		return "go"
	case "cargo.toml", "cargo.lock":
		return "cargo"
	case "packages.config", "packages.lock.json", "project.assets.json":
		return "dotnet"
	case "pom.xml":
		return "maven"
	case "build.gradle", "build.gradle.kts", "gradle.lockfile":
		return "gradle"
	case "pyproject.toml", "poetry.lock", "pdm.lock", "pipfile.lock", "requirements.txt", "setup.py", "uv.lock":
		return "python"
	case "conan.lock", "conanfile.txt", "conanfile.py":
		return "cpp"
	case "composer.json", "composer.lock":
		return "composer"
	case "gemfile", "gemfile.lock":
		return "ruby"
	case "package.resolved", "podfile.lock":
		return "swift"
	case "cabal.project.freeze", "stack.yaml.lock":
		return "haskell"
	case "renv.lock":
		return "r"
	}
	if strings.HasSuffix(lower, ".csproj") || strings.HasSuffix(lower, ".deps.json") {
		return "dotnet"
	}
	return ""
}
