// ABOUTME: Test setup for the kunnus sbom command tests.
// ABOUTME: Configures the testlogger and snapshot cleanup for the test suite.
package sbom_test

import (
	"log/slog"
	"testing"

	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(testlogger.New()))
	m.Run()
	testutility.CleanSnapshots(m)
}
