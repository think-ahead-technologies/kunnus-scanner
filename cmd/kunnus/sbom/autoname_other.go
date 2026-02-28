// ABOUTME: Provides autoProjectName for non-Windows platforms.
// ABOUTME: Returns the base directory name of the first scanned directory for use in auto-generated filenames.

//go:build !windows

package sbom

// autoProjectName returns a project name derived from the first scanned directory.
func autoProjectName(dirs []string) string {
	return projectNameFromDir(dirs[0])
}
