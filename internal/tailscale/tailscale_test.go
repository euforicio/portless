package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAllocateUsesDeterministicModeSpecificPorts(t *testing.T) {
	tests := []struct {
		mode     Mode
		occupied []uint16
		want     uint16
		wantErr  error
	}{
		{mode: Serve, want: 443},
		{mode: Serve, occupied: []uint16{443}, want: 8443},
		{mode: Serve, occupied: []uint16{443, 8443, 8444}, want: 8445},
		{mode: Funnel, want: 443},
		{mode: Funnel, occupied: []uint16{443}, want: 8443},
		{mode: Funnel, occupied: []uint16{443, 8443}, want: 10000},
		{mode: Funnel, occupied: []uint16{443, 8443, 10000}, wantErr: ErrNoPort},
		{mode: Mode("invalid"), wantErr: errors.New("invalid Tailscale exposure mode")},
	}
	for _, test := range tests {
		port, err := Allocate(test.mode, test.occupied)
		if port != test.want || (test.wantErr == nil) != (err == nil) ||
			(test.wantErr != nil && !strings.Contains(err.Error(), test.wantErr.Error())) {
			t.Errorf("Allocate(%s, %v) = %d, %v; want %d, %v", test.mode, test.occupied, port, err, test.want, test.wantErr)
		}
	}
}

func TestFunnelAllocationIntersectsDocumentedAndAuthorizedPorts(t *testing.T) {
	capabilities := map[string]json.RawMessage{
		"funnel": {},
		"https://tailscale.com/cap/funnel-ports?ports=400-9000,10000": {},
	}
	ports, ok := permittedFunnelPorts(capabilities)
	if !ok || !slices.Equal(ports, []uint16{443, 8443, 10000}) {
		t.Fatalf("permitted ports = %v, %t", ports, ok)
	}
	port, err := allocatePermittedFunnel([]uint16{443}, []uint16{443, 10000})
	if err != nil || port != 10000 {
		t.Fatalf("allocatePermittedFunnel = %d, %v", port, err)
	}
	if _, err := allocatePermittedFunnel([]uint16{443, 10000}, []uint16{443, 10000}); !errors.Is(err, ErrNoPort) {
		t.Fatalf("exhaustion error = %v", err)
	}
}

func TestParseServeStatusTracksAllOccupiedPortsAndExactRootOwner(t *testing.T) {
	value := []byte(`{
      "TCP":{"443":{"HTTPS":true},"8443":{"HTTPS":true},"9000":{"HTTPS":false}},
      "Web":{
        "node.example.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}},
        "node.example.ts.net:8443":{"Handlers":{"/other":{"Proxy":"http://127.0.0.1:4000"}}},
        "node.example.ts.net:9443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:5000"}}}
      },
      "AllowFunnel":{"node.example.ts.net:443":true}
    }`)
	registrations, ports, err := parseServeStatus(value, "node.example.ts.net")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ports, []uint16{443, 8443, 9000, 9443}) {
		t.Fatalf("used ports = %v", ports)
	}
	active, ok := registrations[443]
	if !ok || active.target != "http://127.0.0.1:3000" || !active.funnel {
		t.Fatalf("root registration = %#v, %t", active, ok)
	}
	if _, ok := registrations[8443]; ok {
		t.Fatal("non-root handler was claimed as an owned registration")
	}
}

func TestTargetAndPlanValidationFailClosed(t *testing.T) {
	for _, target := range []string{
		"", "http://localhost:3000", "http://127.0.0.1", "http://127.0.0.1:0",
		"http://127.0.0.1:3000/", "http://127.0.0.1:3000/path", "https://127.0.0.1:3000",
		"http://10.0.0.1:3000", "http://user@127.0.0.1:3000", "http://127.0.0.1:3000?x=1",
	} {
		if _, err := normalizeTarget(target); err == nil {
			t.Errorf("normalizeTarget accepted %q", target)
		}
	}
	if target, err := normalizeTarget("http://127.0.0.1:03000"); err != nil || target != "http://127.0.0.1:3000" {
		t.Fatalf("normalized target = %q, %v", target, err)
	}
	plan := Plan{
		Registration: Registration{Name: "app", Mode: Serve, Port: 443, Target: "http://127.0.0.1:3000", Host: "node.example.ts.net"},
		Register:     Command{Path: "/usr/local/bin/tailscale", Args: []string{"serve", "--bg", "--yes", "--https=443", "--set-path=/", "http://127.0.0.1:3000"}},
		Cleanup:      Command{Path: "/usr/local/bin/tailscale", Args: []string{"serve", "--yes", "--https=443", "--set-path=/", "off"}},
	}
	if err := validatePlan(plan); err != nil {
		t.Fatalf("valid plan: %v", err)
	}
	plan.Cleanup.Args = []string{"serve", "reset"}
	if err := validatePlan(plan); err == nil {
		t.Fatal("reset was accepted as exact cleanup")
	}
	plan = Plan{
		Registration: Registration{Name: "app", Mode: Funnel, Port: 8444, Target: "http://127.0.0.1:3000", Host: "node.example.ts.net"},
		Register:     Command{Path: "/usr/local/bin/tailscale", Args: []string{"funnel", "--bg", "--yes", "--https=8444", "--set-path=/", "http://127.0.0.1:3000"}},
		Cleanup:      Command{Path: "/usr/local/bin/tailscale", Args: []string{"funnel", "--yes", "--https=8444", "--set-path=/", "off"}},
	}
	if err := validatePlan(plan); err == nil {
		t.Fatal("unsupported Funnel port was accepted")
	}
}

func TestRealTailscaleReadOnlyPreflightAndPlan(t *testing.T) {
	if _, err := exec.LookPath(defaultExecutable); err != nil {
		t.Skipf("Tailscale CLI is unavailable: %v", err)
	}
	client := Client{Timeout: 10 * time.Second}
	snapshot, err := client.Check(t.Context(), Serve)
	if err != nil {
		t.Skipf("Tailscale is not connected with HTTPS enabled: %v", err)
	}
	if snapshot.Executable == "" || snapshot.Version == "" || snapshot.DNSName == "" || !snapshot.HTTPSCapable || !snapshot.MagicDNS {
		t.Fatalf("incomplete preflight: %#v", snapshot)
	}
	plan, err := client.BuildPlan(t.Context(), Request{Name: "read-only-probe", Mode: Serve, Target: "http://127.0.0.1:65534"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Register.String(), "--set-path=/") || !strings.HasSuffix(plan.Cleanup.String(), `"off"`) {
		t.Fatalf("unexpected plan: %s; %s", plan.Register.String(), plan.Cleanup.String())
	}
	if slices.Contains(snapshot.UsedPorts, plan.Registration.Port) {
		t.Fatalf("allocated occupied port %d from %v", plan.Registration.Port, snapshot.UsedPorts)
	}

	funnel, funnelErr := client.Check(t.Context(), Funnel)
	if funnelErr == nil && len(funnel.FunnelPorts) == 0 {
		t.Fatal("Funnel preflight passed without authorized ports")
	}
	if funnelErr != nil && !errors.Is(funnelErr, ErrHTTPSUnavailable) && !errors.Is(funnelErr, ErrUnavailable) {
		t.Fatalf("unexpected Funnel preflight error: %v", funnelErr)
	}
}

func TestReadOnlyRunnerBoundsRealChildProcess(t *testing.T) {
	client := Client{Timeout: 3 * time.Second}
	if _, err := client.run(context.Background(), "/usr/bin/yes"); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("unbounded output error = %v", err)
	}
	client.Timeout = 100 * time.Millisecond
	if _, err := client.run(context.Background(), "/bin/sleep", "5"); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout error = %v", err)
	}
}

func TestRealServeApplyAndExactCleanupOptIn(t *testing.T) {
	if os.Getenv("PORTLESS_TEST_TAILSCALE_MUTATION") != "1" {
		t.Skip("set PORTLESS_TEST_TAILSCALE_MUTATION=1 for real Serve mutation")
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := Client{Timeout: 15 * time.Second}
	plan, err := client.BuildPlan(t.Context(), Request{Name: "integration", Mode: Serve, Target: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Apply(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := client.Clean(cleanupContext, plan); err != nil {
			t.Errorf("Clean: %v", err)
		}
	})
}
