package sbom_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/kunnus/sbom"
	"github.com/google/osv-scanner/v2/internal/cachedregexp"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/urfave/cli/v3"
)

var (
	// uuidV4Pattern matches UUID v4 strings for normalization.
	uuidV4Pattern = cachedregexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89ABab][0-9a-fA-F]{3}-[0-9a-fA-F]{12}`)
	// iso8601Pattern matches ISO 8601 timestamps for normalization.
	iso8601Pattern = cachedregexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`)
)

// normalizeUUIDs replaces each unique UUID with a stable placeholder to make
// snapshots reproducible across runs while preserving cross-reference relationships.
func normalizeUUIDs(input string) string {
	uuidMapping := map[string]int{}
	for _, id := range uuidV4Pattern.FindAllString(input, -1) {
		if _, ok := uuidMapping[id]; !ok {
			uuidMapping[id] = len(uuidMapping)
		}
	}

	return uuidV4Pattern.ReplaceAllStringFunc(input, func(id string) string {
		return fmt.Sprintf("uuid-placeholder-%d", uuidMapping[id])
	})
}

// normalizeTimestamps replaces ISO 8601 timestamps with a fixed placeholder.
func normalizeTimestamps(input string) string {
	return iso8601Pattern.ReplaceAllString(input, "<TIMESTAMP>")
}

// runAndNormalize runs the kunnus sbom command with the given args and returns
// normalized stdout, stderr, and exit code.
func runAndNormalize(t *testing.T, args []string) (string, string, int) {
	t.Helper()

	var outBuf, errBuf bytes.Buffer

	logger := cmdlogger.New(&outBuf, &errBuf)

	handler, ok := slog.Default().Handler().(*testlogger.Handler)
	if !ok {
		t.Fatal("test not initialized with testlogger - check TestMain")
	}
	handler.AddInstance(logger)
	defer handler.Delete()

	app := &cli.Command{
		Name:           "kunnus",
		DefaultCommand: "sbom",
		Writer:         &outBuf,
		ErrWriter:      &errBuf,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "verbosity", Value: "warn"},
			&cli.BoolFlag{Name: "quiet", Aliases: []string{"q"}},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			if lvl, err := cmdlogger.ParseLevel(cmd.String("verbosity")); err == nil {
				cmdlogger.SetLevel(lvl)
			}

			return ctx, nil
		},
		Commands: []*cli.Command{
			sbom.Command(&outBuf, &errBuf, nil),
		},
		ExitErrHandler: func(_ context.Context, _ *cli.Command, _ error) {},
	}

	err := app.Run(context.Background(), args)
	if err != nil {
		cmdlogger.Errorf("%v", err)
	}

	exitCode := 0
	if logger.HasErrored() {
		exitCode = 2
	}

	stdout := normalizeUUIDs(normalizeTimestamps(outBuf.String()))
	stderr := errBuf.String()

	return stdout, stderr, exitCode
}

func TestCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		exit int
	}{
		{
			name: "empty directory produces no-package warning",
			args: []string{"kunnus", "sbom", "./testdata/no-packages"},
			exit: 0,
		},
		{
			name: "explicit spdx-2-3 format",
			args: []string{"kunnus", "sbom", "--format=spdx-2-3", "./testdata/no-packages"},
			exit: 0,
		},
		{
			name: "cyclonedx-1-4 format",
			args: []string{"kunnus", "sbom", "--format=cyclonedx-1-4", "./testdata/no-packages"},
			exit: 0,
		},
		{
			name: "cyclonedx-1-5 format",
			args: []string{"kunnus", "sbom", "--format=cyclonedx-1-5", "./testdata/no-packages"},
			exit: 0,
		},
		{
			name: "unsupported format json is rejected",
			args: []string{"kunnus", "sbom", "--format=json", "./testdata/no-packages"},
			exit: 2,
		},
		{
			name: "unsupported format table is rejected",
			args: []string{"kunnus", "sbom", "--format=table", "./testdata/no-packages"},
			exit: 2,
		},
		{
			name: "no-recursive flag is accepted",
			args: []string{"kunnus", "sbom", "--no-recursive", "./testdata/no-packages"},
			exit: 0,
		},
		{
			name: "quiet flag suppresses summary on stderr",
			args: []string{"kunnus", "--quiet", "sbom", "./testdata/no-packages"},
			exit: 0,
		},
		{
			name: "include-os flag is accepted",
			args: []string{"kunnus", "sbom", "--include-os", "./testdata/no-packages"},
			exit: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stdout, stderr, exitCode := runAndNormalize(t, tc.args)

			if exitCode != tc.exit {
				t.Errorf("exit code: got %d, want %d\nstdout: %s\nstderr: %s", exitCode, tc.exit, stdout, stderr)
			}

			testutility.NewSnapshot().MatchText(t, stdout)
			testutility.NewSnapshot().WithWindowsReplacements(map[string]string{
				"CreateFile": "stat",
			}).MatchText(t, stderr)
		})
	}
}

func TestCommandOutputFlag(t *testing.T) {
	t.Parallel()

	outFile := filepath.Join(t.TempDir(), "sbom.spdx.json")

	_, stderr, exitCode := runAndNormalize(t, []string{
		"kunnus", "sbom", "--output", outFile, "./testdata/no-packages",
	})

	if exitCode != 0 {
		t.Errorf("exit code: got %d, want 0\nstderr: %s", exitCode, stderr)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("SBOM output file not created: %v", err)
	}

	if !strings.Contains(string(data), "spdxVersion") {
		t.Errorf("output file does not look like an SPDX document: %q", string(data))
	}

	if !strings.Contains(stderr, "Scanning") {
		t.Errorf("stderr: expected scan summary, got: %q", stderr)
	}
}
