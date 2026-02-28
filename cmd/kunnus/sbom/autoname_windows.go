// ABOUTME: Provides autoProjectName for Windows, using the machine hostname.
// ABOUTME: On Windows the technician scans the whole machine, so hostname is the natural project name.

//go:build windows

package sbom

import "os"

// autoProjectName returns the machine hostname for Windows scans.
// Falls back to the base directory name if the hostname cannot be determined.
func autoProjectName(dirs []string) string {
	if name, err := os.Hostname(); err == nil && name != "" {
		return name
	}

	return projectNameFromDir(dirs[0])
}
