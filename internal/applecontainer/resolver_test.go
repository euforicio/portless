package applecontainer

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestResolveExecutesInspectAndParsesEndpoint(t *testing.T) {
	resolver := fixtureResolver(t, runningFixture("app", `[{"containerPort":8080,"count":1,"proto":"tcp"}]`))

	endpoint, err := resolver.Resolve(context.Background(), "app", 0, "http")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if endpoint.Container != "app" || endpoint.Network != "default" || endpoint.Address.String() != "192.168.64.2" || endpoint.Port != 8080 {
		t.Fatalf("unexpected endpoint: %#v", endpoint)
	}
	if len(endpoint.Addresses) != 2 || endpoint.Addresses[1].String() != "fd00::2" {
		t.Fatalf("unexpected addresses: %v", endpoint.Addresses)
	}
}

func TestResolveUsesConfiguredUnprivilegedLoginSession(t *testing.T) {
	directory := t.TempDir()
	fixturePath := filepath.Join(directory, "inspect.json")
	uidPath := filepath.Join(directory, "uid")
	if err := os.WriteFile(fixturePath, []byte(runningFixture("app", `[{"containerPort":8080,"count":1,"proto":"tcp"}]`)), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(directory, "container-fixture")
	script := fmt.Sprintf("#!/bin/sh\n/usr/bin/id -u > '%s'\nexec /bin/cat '%s'\n", uidPath, fixturePath)
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	credential := currentCredential(t)
	resolver := Resolver{Executable: executable, Credential: &credential}
	if _, err := resolver.Resolve(t.Context(), "app", 8080, "http"); err != nil {
		t.Fatal(err)
	}
	observed, err := os.ReadFile(uidPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(observed)) != strconv.FormatUint(uint64(credential.UID), 10) {
		t.Fatalf("inspector UID = %q, want %d", observed, credential.UID)
	}
}

func TestResolveAcceptsExplicitUnpublishedPort(t *testing.T) {
	resolver := fixtureResolver(t, runningFixture("app", `[]`))

	endpoint, err := resolver.Resolve(context.Background(), "app", 80, "http")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if endpoint.Port != 80 {
		t.Fatalf("port = %d, want 80", endpoint.Port)
	}
}

func TestResolveRejectsInvalidContainerStateAndPorts(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		requested uint16
		want      error
	}{
		{name: "stopped", fixture: stoppedFixture("app"), want: ErrNotRunning},
		{name: "missing port", fixture: runningFixture("app", `[]`), want: ErrMissingPort},
		{name: "ambiguous port", fixture: runningFixture("app", `[{"containerPort":80,"count":1,"proto":"tcp"},{"containerPort":443,"count":1,"proto":"tcp"}]`), want: ErrAmbiguousPort},
		{name: "udp selected", fixture: runningFixture("app", `[{"containerPort":53,"count":1,"proto":"udp"}]`), requested: 53, want: ErrUnsupportedProtocol},
		{name: "udp inference", fixture: runningFixture("app", `[{"containerPort":53,"count":1,"proto":"udp"}]`), want: ErrUnsupportedProtocol},
		{name: "invalid range", fixture: runningFixture("app", `[{"containerPort":65535,"count":2,"proto":"tcp"}]`), want: ErrInvalidMetadata},
		{name: "invalid count", fixture: runningFixture("app", `[{"containerPort":80,"count":0,"proto":"tcp"}]`), want: ErrInvalidMetadata},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := fixtureResolver(t, test.fixture)
			_, err := resolver.Resolve(context.Background(), "app", test.requested, "http")
			if !errors.Is(err, test.want) {
				t.Fatalf("Resolve error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestResolveBoundsAndSanitizesCommandFailures(t *testing.T) {
	directory := t.TempDir()
	executablePath := filepath.Join(directory, "container-fixture")
	script := "#!/bin/sh\necho 'TOKEN=do-not-return' >&2\nexit 7\n"
	if err := os.WriteFile(executablePath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := (Resolver{Executable: executablePath}).Resolve(context.Background(), "app", 80, "http")
	if err == nil || !strings.Contains(err.Error(), "status 7") {
		t.Fatalf("Resolve error = %v, want exit status", err)
	}
	if strings.Contains(err.Error(), "TOKEN") || strings.Contains(err.Error(), "do-not-return") {
		t.Fatalf("Resolve exposed command stderr: %v", err)
	}
}

func TestResolveTimesOutRealSubprocess(t *testing.T) {
	directory := t.TempDir()
	executablePath := filepath.Join(directory, "container-fixture")
	if err := os.WriteFile(executablePath, []byte("#!/bin/sh\nwhile :; do :; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := (Resolver{Executable: executablePath, Timeout: 20 * time.Millisecond}).Resolve(context.Background(), "app", 80, "http")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("Resolve error = %v, want timeout", err)
	}
}

func TestResolveRejectsMissingAddressAndUnexpectedIdentity(t *testing.T) {
	missingAddress := `[{"id":"app","configuration":{"id":"app","publishedPorts":[{"containerPort":80,"count":1,"proto":"tcp"}]},"status":{"state":"running","networks":[]}}]`
	resolver := fixtureResolver(t, missingAddress)
	if _, err := resolver.Resolve(context.Background(), "app", 0, "http"); !errors.Is(err, ErrMissingAddress) {
		t.Fatalf("missing address error = %v", err)
	}

	resolver = fixtureResolver(t, runningFixture("other", `[{"containerPort":80,"count":1,"proto":"tcp"}]`))
	if _, err := resolver.Resolve(context.Background(), "app", 0, "http"); err == nil {
		t.Fatal("Resolve accepted an unexpected identity")
	}
}

func TestEndpointDetectsAddressChange(t *testing.T) {
	previous := Endpoint{Container: "app", Network: "default", Protocol: "http", Address: netip.MustParseAddr("192.168.64.2"), Port: 80}
	current := previous
	current.Address = netip.MustParseAddr("192.168.64.9")
	if !current.AddressChanged(previous) {
		t.Fatal("address change was not detected")
	}
	if !current.RefreshRequired(previous) {
		t.Fatal("address change did not require refresh")
	}
	current = previous
	current.Network = "other"
	if !current.RefreshRequired(previous) {
		t.Fatal("network change did not require refresh")
	}
	current.Container = "other"
	if current.AddressChanged(previous) {
		t.Fatal("different owner reported as an address refresh")
	}
}

func TestRealAppleContainerInspect(t *testing.T) {
	containerID := os.Getenv("PORTLESS_TEST_CONTAINER")
	if containerID == "" {
		t.Skip("set PORTLESS_TEST_CONTAINER to exercise a real running Apple container")
	}
	portValue, err := strconv.ParseUint(os.Getenv("PORTLESS_TEST_CONTAINER_PORT"), 10, 16)
	if err != nil || portValue == 0 {
		t.Fatal("PORTLESS_TEST_CONTAINER_PORT must name the running container's TCP port")
	}
	credential := currentCredential(t)
	endpoint, err := (Resolver{Credential: &credential}).Resolve(context.Background(), containerID, uint16(portValue), "http")
	if err != nil {
		t.Fatalf("real Resolve: %v", err)
	}
	if endpoint.Container != containerID || !endpoint.Address.IsValid() {
		t.Fatalf("unexpected endpoint: %#v", endpoint)
	}
}

func currentCredential(t *testing.T) Credential {
	t.Helper()
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	groupValues, err := account.GroupIds()
	if err != nil {
		t.Fatal(err)
	}
	groups := make([]uint32, 0, len(groupValues))
	for _, value := range groupValues {
		group, parseErr := strconv.ParseUint(value, 10, 32)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		groups = append(groups, uint32(group))
	}
	return Credential{UID: uint32(uid), GID: uint32(gid), Groups: groups, Username: account.Username, HomeDir: account.HomeDir}
}

func fixtureResolver(t *testing.T, fixture string) Resolver {
	t.Helper()
	directory := t.TempDir()
	fixturePath := filepath.Join(directory, "inspect.json")
	if err := os.WriteFile(fixturePath, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	executablePath := filepath.Join(directory, "container-fixture")
	script := fmt.Sprintf("#!/bin/sh\n[ \"$1\" = inspect ] || exit 64\nexec /bin/cat %s\n", shellQuote(fixturePath))
	if err := os.WriteFile(executablePath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return Resolver{Executable: executablePath}
}

func runningFixture(id, ports string) string {
	return fmt.Sprintf(`[{"id":%[1]q,"configuration":{"id":%[1]q,"publishedPorts":%[2]s},"status":{"state":"running","networks":[{"network":"default","ipv4Address":"192.168.64.2/24","ipv6Address":"fd00::2/64"}]}}]`, id, ports)
}

func stoppedFixture(id string) string {
	return fmt.Sprintf(`[{"id":%[1]q,"configuration":{"id":%[1]q,"publishedPorts":[]},"status":{"state":"stopped","networks":[]}}]`, id)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
