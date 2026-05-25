// ABOUTME: Host introspection: which OS is the kunnus binary itself running on?
// ABOUTME: Returns canonical names matching mode.Overrides.TargetOS values.
package detect

import "runtime"

// Host returns the canonical OS name of the host running this binary.
// Values: "linux", "windows", "mac", or runtime.GOOS for everything else.
func Host() string {
	switch runtime.GOOS {
	case "darwin":
		return "mac"
	default:
		return runtime.GOOS
	}
}
