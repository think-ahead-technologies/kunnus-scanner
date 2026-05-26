// ABOUTME: Tests Host() returns a canonical OS name.
// ABOUTME: Just verifies the runtime.GOOS dispatch yields a value mode.Overrides accepts.
package detect_test

import (
	"slices"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/detect"
)

func TestHost_ReturnsCanonicalName(t *testing.T) {
	got := detect.Host()
	allowed := []string{"linux", "windows", "mac", "freebsd", "openbsd", "netbsd"}
	if !slices.Contains(allowed, got) {
		t.Errorf("Host() = %q, want one of %v", got, allowed)
	}
}
