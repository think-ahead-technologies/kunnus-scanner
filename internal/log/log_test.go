// ABOUTME: Tests for the log package: level parsing, logger plumbing, scalibr adapter.
// ABOUTME: Real slog handlers, real byte buffers — no mocks.
package log

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
		err  bool
	}{
		{"debug", slog.LevelDebug, false},
		{"info", slog.LevelInfo, false},
		{"warn", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"DEBUG", slog.LevelDebug, false},
		{"Info", slog.LevelInfo, false},
		{"", 0, true},
		{"trace", 0, true},
		{"verbose", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseLevel(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("ParseLevel(%q) = %v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseLevel(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestNew_WritesAtOrAboveLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := New(slog.LevelWarn, &buf)

	logger.Debug("hidden debug")
	logger.Info("hidden info")
	logger.Warn("visible warn", "k", "v")
	logger.Error("visible error")

	out := buf.String()
	if strings.Contains(out, "hidden") {
		t.Errorf("level filter leaked sub-threshold records: %s", out)
	}
	if !strings.Contains(out, "visible warn") || !strings.Contains(out, "visible error") {
		t.Errorf("expected warn+error in output, got: %s", out)
	}
	if !strings.Contains(out, "k=v") {
		t.Errorf("expected structured attr k=v in output, got: %s", out)
	}
}

func TestNew_SupportsWithAttrs(t *testing.T) {
	// Upstream cmdlogger panics on WithAttrs; we must not.
	var buf bytes.Buffer
	logger := New(slog.LevelInfo, &buf).With("scan", "repo")
	logger.Info("hello")

	out := buf.String()
	if !strings.Contains(out, "scan=repo") || !strings.Contains(out, "hello") {
		t.Errorf("WithAttrs did not propagate: %s", out)
	}
}

func TestScalibrAdapter_RoutesLevels(t *testing.T) {
	var buf bytes.Buffer
	a := &ScalibrAdapter{Logger: New(slog.LevelDebug, &buf)}

	a.Debug("d1")
	a.Debugf("d%d", 2)
	a.Info("i1")
	a.Infof("i%d", 2)
	a.Warn("w1")
	a.Warnf("w%d", 2)
	a.Error("e1")
	a.Errorf("e%d", 2)

	out := buf.String()
	for _, want := range []string{"d1", "d2", "i1", "i2", "w1", "w2", "e1", "e2"} {
		if !strings.Contains(out, want) {
			t.Errorf("ScalibrAdapter dropped %q. output:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "level=DEBUG") || !strings.Contains(out, "level=ERROR") {
		t.Errorf("expected DEBUG and ERROR level markers, got:\n%s", out)
	}
}

func TestScalibrAdapter_ConcatsVariadicArgs(t *testing.T) {
	var buf bytes.Buffer
	a := &ScalibrAdapter{Logger: New(slog.LevelInfo, &buf)}
	a.Info("plugin ", "go/gomod", " disabled")

	if !strings.Contains(buf.String(), "plugin go/gomod disabled") {
		t.Errorf("variadic concat wrong: %s", buf.String())
	}
}
