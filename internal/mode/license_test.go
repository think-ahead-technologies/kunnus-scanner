// ABOUTME: Tests the opt-in deps.dev licence enricher wiring (no network: construction and capability gating only).
// ABOUTME: Proves the enricher is added and survives capability filtering only when Network is widened to online.
package mode

import (
	"testing"

	licenseenricher "github.com/google/osv-scalibr/enricher/license"
	"github.com/google/osv-scalibr/plugin"
)

func TestOnlineLicenseEnricher_OffByDefault(t *testing.T) {
	enr, err := OnlineLicenseEnricher(Overrides{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enr != nil {
		t.Errorf("enricher = %v, want nil when OnlineLicenses is off", enr)
	}
}

func TestOnlineLicenseEnricher_On(t *testing.T) {
	enr, err := OnlineLicenseEnricher(Overrides{OnlineLicenses: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enr == nil {
		t.Fatal("enricher = nil, want the deps.dev enricher")
	}
	if enr.Name() != licenseenricher.Name {
		t.Errorf("enricher name = %q, want %q", enr.Name(), licenseenricher.Name)
	}
}

func TestOnlineLicenseEnricher_CustomURLInCode(t *testing.T) {
	// The endpoint is configurable in code via Overrides; construction is
	// network-free (lazy dial) so a custom address never errors here.
	enr, err := OnlineLicenseEnricher(Overrides{OnlineLicenses: true, LicenseAPIURL: "deps.dev.internal:443"})
	if err != nil {
		t.Fatalf("custom LicenseAPIURL errored: %v", err)
	}
	if enr == nil {
		t.Fatal("enricher = nil, want the deps.dev enricher with a custom endpoint")
	}
}

func TestAddOnlineLicenses_Off(t *testing.T) {
	caps := &plugin.Capabilities{OS: plugin.OSAny}
	in := []plugin.Plugin{}
	out, err := AddOnlineLicenses(in, caps, Overrides{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("plugins grew to %d, want 0 when off", len(out))
	}
	if caps.Network != plugin.NetworkAny {
		t.Errorf("caps.Network = %v, want unchanged (NetworkAny) when off", caps.Network)
	}
}

func TestAddOnlineLicenses_On_AddsEnricherAndWidensNetwork(t *testing.T) {
	caps := &plugin.Capabilities{OS: plugin.OSAny}
	out, err := AddOnlineLicenses(nil, caps, Overrides{OnlineLicenses: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 || out[0].Name() != licenseenricher.Name {
		t.Fatalf("plugins = %v, want exactly the deps.dev enricher", out)
	}
	if caps.Network != plugin.NetworkOnline {
		t.Errorf("caps.Network = %v, want NetworkOnline", caps.Network)
	}

	// The enricher requires network: it must survive capability filtering with
	// the widened caps, and be dropped without them. This validates the
	// capability flip without making any network call.
	if kept := plugin.FilterByCapabilities(out, caps); len(kept) != 1 {
		t.Errorf("enricher filtered out under online caps: kept %d, want 1", len(kept))
	}
	offline := &plugin.Capabilities{OS: plugin.OSAny, Network: plugin.NetworkOffline}
	if kept := plugin.FilterByCapabilities(out, offline); len(kept) != 0 {
		t.Errorf("enricher survived offline caps: kept %d, want 0", len(kept))
	}
}
