package mdns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCheckBuildsExplicitDNSServiceDiscoveryPlan(t *testing.T) {
	address := testLANAddresses(t)[0]
	preflight, err := Check(Config{Host: "Fieldnotes.Local.", Address: address, Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if preflight.Config.Host != "fieldnotes.local" || preflight.Config.Address != address.Unmap() {
		t.Fatalf("normalized config = %#v", preflight.Config)
	}
	want := []string{"-i", strconv.Itoa(preflight.Index), "-P", "fieldnotes", "_https._tcp", "local.", "443", "fieldnotes.local.", address.Unmap().String(), "path=/"}
	if strings.Join(preflight.Command.Args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("command args = %q, want %q", preflight.Command.Args, want)
	}
	if preflight.Command.Path != Executable || !strings.Contains(preflight.Command.String(), strconv.Quote("fieldnotes.local.")) {
		t.Fatalf("command is not auditable: %s", preflight.Command.String())
	}
}

func TestCheckRejectsUnsafeNamesAddressesAndPorts(t *testing.T) {
	validAddress := testLANAddresses(t)[0]
	tests := []Config{
		{Host: "fieldnotes.local", Address: validAddress},
		{Host: "fieldnotes.localhost", Address: validAddress, Port: 443},
		{Host: "a..b.local", Address: validAddress, Port: 443},
		{Host: "-bad.local", Address: validAddress, Port: 443},
		{Host: "bad name.local", Address: validAddress, Port: 443},
		{Host: "fieldnotes.local", Address: netip.MustParseAddr("127.0.0.1"), Port: 443},
		{Host: "fieldnotes.local", Address: netip.MustParseAddr("100.64.0.1"), Port: 443},
		{Host: "fieldnotes.local", Address: netip.MustParseAddr("192.168.255.254"), Port: 443},
		{Host: "fieldnotes.local", Address: validAddress, Port: 443, ReadyTimeout: -time.Second},
	}
	for _, config := range tests {
		if _, err := Check(config); err == nil {
			t.Errorf("Check accepted %#v", config)
		}
	}
}

func TestStartRefreshAndCloseRealDNSSDProcess(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("dns-sd integration requires macOS")
	}
	if _, err := os.Stat(Executable); err != nil {
		t.Skipf("dns-sd is unavailable: %v", err)
	}
	addresses := testLANAddresses(t)
	host := "portless-test-" + strconv.FormatInt(time.Now().UnixNano(), 36) + ".local"
	publisher, err := Start(t.Context(), Config{
		Host: host, Address: addresses[0], Port: 65432, ReadyTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Start real dns-sd: %v", err)
	}
	t.Cleanup(func() { _ = publisher.Close() })
	if publisher.Config().Host != host || publisher.Interface() == "" {
		t.Fatalf("publisher state = %#v on %q", publisher.Config(), publisher.Interface())
	}
	changed, err := publisher.Refresh(t.Context(), addresses[0])
	if err != nil || changed {
		t.Fatalf("same-address Refresh = %v, %v", changed, err)
	}
	if len(addresses) > 1 {
		refreshContext, cancel := context.WithTimeout(t.Context(), 12*time.Second)
		defer cancel()
		changed, err = publisher.Refresh(refreshContext, addresses[1])
		if err != nil || !changed {
			t.Fatalf("changed-address Refresh = %v, %v", changed, err)
		}
		if publisher.Config().Address != addresses[1] {
			t.Fatalf("refreshed address = %s, want %s", publisher.Config().Address, addresses[1])
		}
	}
	if err := publisher.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := publisher.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := publisher.Refresh(t.Context(), addresses[0]); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Refresh after Close error = %v", err)
	}
}

func TestStartHonorsCanceledContextBeforeSpawning(t *testing.T) {
	address := testLANAddresses(t)[0]
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Start(ctx, Config{Host: "portless-canceled.local", Address: address, Port: 443})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Start error = %v, want context canceled", err)
	}
}

func TestStopOwnedTerminatesOnlyExactRealDNSSDIdentity(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("dns-sd integration requires macOS")
	}
	if _, err := os.Stat(Executable); err != nil {
		t.Skipf("dns-sd is unavailable: %v", err)
	}
	address := testLANAddresses(t)[0]
	publisher, err := Start(t.Context(), Config{
		Host:    "portless-owned-" + strconv.FormatInt(time.Now().UnixNano(), 36) + ".local",
		Address: address, Port: 65431, Protocol: HTTP, ReadyTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := publisher.Identity()
	if err := StopOwned(identity); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Close(); err != nil {
		t.Fatal(err)
	}
	changed := identity
	changed.Start++
	if err := StopOwned(changed); err != nil {
		t.Fatalf("gone PID with stale identity should be harmless: %v", err)
	}
}

func testLANAddresses(t *testing.T) []netip.Addr {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var result []netip.Addr
	for _, networkInterface := range interfaces {
		required := net.FlagUp | net.FlagMulticast
		if networkInterface.Flags&required != required || networkInterface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		addresses, err := networkInterface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range addresses {
			prefix, err := netip.ParsePrefix(raw.String())
			if err != nil {
				continue
			}
			address := prefix.Addr().Unmap()
			if _, err := LANInterface(address); err == nil {
				result = append(result, address)
			}
		}
	}
	if len(result) == 0 {
		t.Skip("no eligible LAN address is currently assigned")
	}
	return result
}
