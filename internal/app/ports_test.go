// ABOUTME: Contract tests for the driven ports: the service must use what it is given, and default when not.
// ABOUTME: The encoder seam also lets us assert the Options the use case assembles, which no document check can.
package app_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/app"
	"github.com/think-ahead/kunnus-scanner/internal/bom"
	repomode "github.com/think-ahead/kunnus-scanner/internal/mode/repo"
	"github.com/think-ahead/kunnus-scanner/internal/sbom"
)

// recordingEncoder captures the Options it is handed instead of encoding. It
// exists to prove the Encoder port is a real seam and to inspect what the use
// case assembles — not to stand in for the encoder in behavioural tests, which
// keep driving the real one.
type recordingEncoder struct {
	mu     sync.Mutex
	called bool
	opts   sbom.Options
}

func (e *recordingEncoder) Encode(out io.Writer, opts sbom.Options) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.called = true
	e.opts = opts
	_, err := io.WriteString(out, "{}")
	return err
}

func TestNew_WiresProductionAdapters(t *testing.T) {
	svc := app.New()
	if svc.Scanner == nil {
		t.Error("New() left Scanner nil")
	}
	if svc.Encoder == nil {
		t.Error("New() left Encoder nil")
	}
}

// The zero Service must still work: a caller that wants the production
// behaviour should not have to know the adapters' names.
func TestService_ZeroValueUsesProductionAdapters(t *testing.T) {
	var buf bytes.Buffer
	_, err := app.Service{}.GenerateSBOM(context.Background(), &buf, app.Request{
		Mode:   repomode.New(),
		Target: npmFixture(t),
	})
	if err != nil {
		t.Fatalf("GenerateSBOM on the zero Service: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("zero Service wrote no document")
	}
}

func TestService_UsesInjectedEncoder(t *testing.T) {
	enc := &recordingEncoder{}
	svc := app.Service{Encoder: enc}

	var buf bytes.Buffer
	_, err := svc.GenerateSBOM(context.Background(), &buf, app.Request{
		Mode:   repomode.New(),
		Target: npmFixture(t),
		Author: bom.Author{Name: "ACME GmbH"},
	})
	if err != nil {
		t.Fatalf("GenerateSBOM: %v", err)
	}

	if !enc.called {
		t.Fatal("the injected encoder was never called")
	}
	if buf.String() != "{}" {
		t.Errorf("output = %q, want the injected encoder's own bytes", buf.String())
	}

	// What the use case assembles from the plan — assertable directly now that
	// the encoder is a seam, rather than only inferable from the document.
	got := enc.opts
	if got.Lifecycle != bom.LifecyclePreBuild {
		t.Errorf("Lifecycle = %q, want the repo mode's pre-build", got.Lifecycle)
	}
	if got.Author.Name != "ACME GmbH" {
		t.Errorf("Author.Name = %q, want the request's", got.Author.Name)
	}
	if got.Series.Mode != "repo" {
		t.Errorf("Series.Mode = %q, want repo", got.Series.Mode)
	}
	if len(got.Inventory.Packages) == 0 {
		t.Error("Inventory reached the encoder empty")
	}
	if len(got.Hashes) == 0 {
		t.Error("Hashes reached the encoder empty; the npm fixture pins integrity digests")
	}
}

// An encoder failure must surface as an error, not a half-written document
// reported as success.
func TestService_EncoderErrorPropagates(t *testing.T) {
	svc := app.Service{Encoder: failingEncoder{}}

	var buf bytes.Buffer
	_, err := svc.GenerateSBOM(context.Background(), &buf, app.Request{
		Mode:   repomode.New(),
		Target: npmFixture(t),
	})
	if err == nil {
		t.Fatal("want the encoder's error back")
	}
}

type failingEncoder struct{}

func (failingEncoder) Encode(io.Writer, sbom.Options) error { return errors.New("encoder said no") }
