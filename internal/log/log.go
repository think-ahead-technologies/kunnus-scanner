// ABOUTME: Stdlib slog logger wired for kunnus: text handler to stderr, level-filtered.
// ABOUTME: Includes a ParseLevel helper for the CLI flag and the scalibr Logger adapter.
package log

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// New returns a logger that writes a text-formatted record per line to w,
// filtered to level and above. All operational output belongs on stderr;
// stdout is reserved for the SBOM payload.
func New(level slog.Leveler, w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

// ParseLevel maps a user-supplied --verbosity value to an slog.Level.
// Case-insensitive. Returns an error listing valid choices on miss.
func ParseLevel(text string) (slog.Level, error) {
	switch strings.ToLower(text) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid verbosity %q (want one of: debug, info, warn, error)", text)
	}
}

// Levels returns the accepted --verbosity values in increasing severity order,
// suitable for showing in CLI help.
func Levels() []string {
	return []string{"debug", "info", "warn", "error"}
}
