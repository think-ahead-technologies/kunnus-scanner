// ABOUTME: Adapter that lets osv-scalibr's log.Logger calls flow into our slog logger.
// ABOUTME: Required because scalibr defines its own logging interface upstream.
package log

import (
	"fmt"
	"log/slog"

	scalibrlog "github.com/google/osv-scalibr/log"
)

// ScalibrAdapter satisfies scalibr's log.Logger by forwarding every call into
// the wrapped *slog.Logger. Install it once at startup via scalibrlog.SetLogger.
type ScalibrAdapter struct {
	Logger *slog.Logger
}

var _ scalibrlog.Logger = (*ScalibrAdapter)(nil)

func (s *ScalibrAdapter) Errorf(format string, args ...any) {
	s.Logger.Error(fmt.Sprintf(format, args...))
}
func (s *ScalibrAdapter) Error(args ...any) { s.Logger.Error(fmt.Sprint(args...)) }

func (s *ScalibrAdapter) Warnf(format string, args ...any) {
	s.Logger.Warn(fmt.Sprintf(format, args...))
}
func (s *ScalibrAdapter) Warn(args ...any) { s.Logger.Warn(fmt.Sprint(args...)) }

func (s *ScalibrAdapter) Infof(format string, args ...any) {
	s.Logger.Info(fmt.Sprintf(format, args...))
}
func (s *ScalibrAdapter) Info(args ...any) { s.Logger.Info(fmt.Sprint(args...)) }

func (s *ScalibrAdapter) Debugf(format string, args ...any) {
	s.Logger.Debug(fmt.Sprintf(format, args...))
}
func (s *ScalibrAdapter) Debug(args ...any) { s.Logger.Debug(fmt.Sprint(args...)) }
