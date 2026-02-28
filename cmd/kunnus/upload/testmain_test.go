package upload_test

import (
	"log/slog"
	"testing"

	"github.com/google/osv-scanner/v2/internal/testlogger"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(testlogger.New()))
	m.Run()
}
