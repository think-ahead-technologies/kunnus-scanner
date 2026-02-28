//go:build !windows

package sbom

// autoProjectName returns a project name derived from the first scanned directory.
func autoProjectName(dirs []string) string {
	return projectNameFromDir(dirs[0])
}
