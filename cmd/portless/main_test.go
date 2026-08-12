package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/euforicio/portless/internal/client"
	"github.com/euforicio/portless/internal/daemon"
	"github.com/euforicio/portless/internal/lan"
	"github.com/euforicio/portless/internal/mdns"
	"github.com/euforicio/portless/internal/runner"
	"github.com/euforicio/portless/internal/tailscale"
)

func TestPortlessRunHelper(t *testing.T) {
	if os.Getenv("GO_WANT_PORTLESS_RUN_HELPER") != "1" {
		return
	}
	values := map[string]string{
		"PORT": os.Getenv("PORT"), "HOST": os.Getenv("HOST"),
		"PORTLESS_URL": os.Getenv("PORTLESS_URL"),
	}
	data, _ := json.Marshal(values)
	_ = os.WriteFile(os.Args[len(os.Args)-1], data, 0o600)
	os.Exit(7)
}

func TestPortlessLANServerHelper(t *testing.T) {
	if os.Getenv("GO_WANT_PORTLESS_LAN_SERVER") != "1" {
		return
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", os.Getenv("PORT")))
	if err != nil {
		os.Exit(70)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, "lan-cli-ok") })}
	_ = server.Serve(listener)
	os.Exit(0)
}

func TestPortlessLANCrashSupervisorHelper(t *testing.T) {
	if os.Getenv("GO_WANT_PORTLESS_LAN_CRASH_SUPERVISOR") != "1" {
		return
	}
	code := run(context.Background(), []string{
		"run", "--name", "lan-crash", "--lan", "--ip", os.Getenv("PORTLESS_TEST_LAN_IP"), "--",
		os.Args[0], "-test.run=TestPortlessLANServerHelper",
	}, io.Discard, io.Discard)
	os.Exit(code)
}

func TestPortlessTakeoverSupervisorHelper(t *testing.T) {
	if os.Getenv("GO_WANT_PORTLESS_TAKEOVER_SUPERVISOR") != "1" {
		return
	}
	code := run(context.Background(), []string{
		"run", "--name", "stale", "--",
		os.Args[0], "-test.run=^TestPortlessLANServerHelper$",
	}, io.Discard, io.Discard)
	os.Exit(code)
}

func TestCommandSurfaceUsesRealManagementSocket(t *testing.T) {
	socketPath := startRuntime(t, "/usr/bin/false")
	t.Setenv("PORTLESS_SOCKET", socketPath)

	commands := [][]string{
		{"add", "App", "--port", "3000", "--pid", fmt.Sprint(os.Getpid())},
		{"remove", "app.localhost"},
		{"list"},
		{"status"},
		{"doctor"},
		{"refresh"},
	}
	for _, command := range commands {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := run(t.Context(), command, &stdout, &stderr); code != 0 {
			t.Fatalf("run(%v) = %d, stderr: %s", command, code, stderr.String())
		}
	}

}

func TestBuiltExecutableRunsDaemonAndOrdinaryCLI(t *testing.T) {
	directory := shortCommandTempDir(t)
	binary := filepath.Join(directory, "portless")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build portless: %v: %s", err, output)
	}
	stateDir := filepath.Join(directory, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "run", "management.sock")
	group, err := user.LookupGroupId(strconv.Itoa(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	process := exec.Command(binary,
		"daemon",
		"--state-dir", stateDir,
		"--management-socket", socket,
		"--management-group", group.Name,
		"--container-cli", "/usr/bin/false",
		"--http-listen", "127.0.0.1:0",
		"--https-listen", "127.0.0.1:0",
		"--refresh-interval", "-1s",
	)
	var daemonOutput bytes.Buffer
	process.Stdout = &daemonOutput
	process.Stderr = &daemonOutput
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if process.ProcessState == nil {
			_ = process.Process.Kill()
			_ = process.Wait()
		}
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		status := exec.Command(binary, "status")
		status.Env = append(os.Environ(), "PORTLESS_SOCKET="+socket)
		output, statusErr := status.CombinedOutput()
		if statusErr == nil && strings.HasPrefix(string(output), "running\n") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon did not become ready: %v: %s; daemon: %s", statusErr, output, daemonOutput.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := process.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatalf("daemon shutdown: %v: %s", err, daemonOutput.String())
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatalf("management socket remained after shutdown: %v", err)
	}
}

func TestAddAppleContainerSendsRefreshableOwner(t *testing.T) {
	executable := containerFixtureExecutable(t)
	socketPath := startRuntime(t, executable)
	t.Setenv("PORTLESS_SOCKET", socketPath)
	t.Setenv("PORTLESS_CONTAINER_CLI", executable)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(t.Context(), []string{"add", "fieldnotes", "--container", "fieldnotes", "--port", "80"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run = %d, stderr: %s", code, stderr.String())
	}
	response, err := (client.Client{SocketPath: socketPath}).Call(t.Context(), client.Request{Operation: client.OperationList})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Routes) != 1 {
		t.Fatalf("routes = %#v", response.Routes)
	}
	route := response.Routes[0]
	owner := route.Owner
	if owner.Kind != client.OwnerContainer || owner.Container != "fieldnotes" || owner.Network != "default" || owner.Refresh != client.RefreshContainerAddress {
		t.Fatalf("unexpected owner: %#v", owner)
	}
	if route.Host != "192.168.64.8" || route.Port != 80 {
		t.Fatalf("unexpected upstream: %#v", route)
	}
}

func TestAddRejectsUnsupportedInputsBeforeDial(t *testing.T) {
	t.Setenv("PORTLESS_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	for _, arguments := range [][]string{
		{"add", "two.labels", "--port", "3000"},
		{"add", "app", "--port", "3000", "--host", "0.0.0.0"},
		{"add", "app", "--port", "3000", "--protocol", "ftp"},
		{"add", "app"},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := run(t.Context(), arguments, &stdout, &stderr); code != 1 {
			t.Errorf("run(%v) = %d, want 1", arguments, code)
		}
	}
}

func TestStatusReportsStoppedWhenSocketIsAbsent(t *testing.T) {
	t.Setenv("PORTLESS_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run(t.Context(), []string{"status"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run = %d, stderr: %s", code, stderr.String())
	}
	if stdout.String() != "stopped\n" {
		t.Fatalf("stdout = %q, want stopped", stdout.String())
	}
}

func TestGenericRunRegistersCleansAndPreservesExitStatus(t *testing.T) {
	socketPath := startRuntime(t, "")
	t.Setenv("PORTLESS_SOCKET", socketPath)
	t.Setenv("PORTLESS_RUNNER_STATE", filepath.Join(t.TempDir(), "runner"))
	t.Setenv("GO_WANT_PORTLESS_RUN_HELPER", "1")
	outputPath := filepath.Join(t.TempDir(), "environment.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(t.Context(), []string{"run", "--name", "generic", "--", os.Args[0], "-test.run=TestPortlessRunHelper", "--", outputPath}, &stdout, &stderr)
	if code != 7 {
		t.Fatalf("run code = %d, want 7; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]string
	if err := json.Unmarshal(data, &values); err != nil {
		t.Fatal(err)
	}
	if values["PORT"] == "" || values["HOST"] != "127.0.0.1" || values["PORTLESS_URL"] != "https://generic.localhost" {
		t.Fatalf("managed environment = %#v", values)
	}
	response, err := (client.Client{SocketPath: socketPath}).Call(t.Context(), client.Request{Operation: client.OperationList})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Routes) != 0 {
		t.Fatalf("route cleanup left %#v", response.Routes)
	}
}

func TestGenericRunForceTakesOverExactOwnerAndCleans(t *testing.T) {
	socketPath := startRuntime(t, "")
	runnerDirectory := filepath.Join(t.TempDir(), "runner")
	t.Setenv("PORTLESS_SOCKET", socketPath)
	t.Setenv("PORTLESS_RUNNER_STATE", runnerDirectory)
	t.Setenv("GO_WANT_PORTLESS_LAN_SERVER", "1")

	manager, err := runner.Open(runnerDirectory)
	if err != nil {
		t.Fatal(err)
	}
	previous := startTakeoverProcess(t, manager, "takeover.localhost")
	management := client.Client{SocketPath: socketPath}
	previousRoute := registerTakeoverRoute(t, management, previous)

	previousWait := make(chan struct{})
	go func() {
		_, _ = previous.Wait()
		close(previousWait)
	}()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	go func() {
		done <- run(ctx, []string{
			"run", "--name", "takeover", "--force", "--",
			os.Args[0], "-test.run=^TestPortlessLANServerHelper$",
		}, &stdout, &stderr)
	}()

	current := waitForDifferentRouteOwner(t, management, previousRoute)
	select {
	case <-previousWait:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("taken-over process was not reaped")
	}
	previousAddress := net.JoinHostPort(previousRoute.Host, strconv.Itoa(int(previousRoute.Port)))
	if connection, err := net.DialTimeout("tcp", previousAddress, 200*time.Millisecond); err == nil {
		connection.Close()
		cancel()
		t.Fatalf("taken-over listener %s remained reachable", previousAddress)
	}
	currentAddress := "http://" + net.JoinHostPort(current.Host, strconv.Itoa(int(current.Port)))
	if err := waitForHTTPBody(currentAddress, "lan-cli-ok", 3*time.Second); err != nil {
		cancel()
		t.Fatalf("replacement endpoint: %v", err)
	}

	staleOwner := previousRoute.Owner
	staleReplacement := current
	staleReplacement.Port++
	staleReplacement.Owner = client.Owner{Kind: client.OwnerStatic, Refresh: client.RefreshNever}
	if _, err := management.Call(t.Context(), client.Request{
		Operation: client.OperationAdd, Route: &staleReplacement,
		Match: client.RouteMatchOwner, ExpectedOwner: &staleOwner,
	}); err == nil || !isRouteConflict(err) {
		cancel()
		t.Fatalf("stale owner compare-and-set error = %v", err)
	}
	if got := waitForRoute(t, management, current.Name); got != current {
		cancel()
		t.Fatalf("failed compare-and-set changed route: got %#v, want %#v", got, current)
	}

	cancel()
	if code := <-done; code != 143 {
		t.Fatalf("forced run exit = %d, stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	listed, err := management.Call(t.Context(), client.Request{Operation: client.OperationList})
	if err != nil || len(listed.Routes) != 0 {
		t.Fatalf("routes after replacement cleanup = %#v, %v", listed.Routes, err)
	}
	records, err := manager.Records()
	if err != nil || len(records) != 0 {
		t.Fatalf("runner state after replacement cleanup = %#v, %v", records, err)
	}
}

func TestForceRunnerTakeoverFailureAndProcessSafety(t *testing.T) {
	t.Run("missing route", func(t *testing.T) {
		management := client.Client{SocketPath: startRuntime(t, "")}
		manager, err := runner.Open(filepath.Join(t.TempDir(), "runner"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := forceRunnerTakeover(t.Context(), management, manager, "missing.localhost"); err == nil || !strings.Contains(err.Error(), "route is not registered") {
			t.Fatalf("missing route error = %v", err)
		}
	})

	t.Run("untracked unrelated process", func(t *testing.T) {
		management := client.Client{SocketPath: startRuntime(t, "")}
		manager, err := runner.Open(filepath.Join(t.TempDir(), "runner"))
		if err != nil {
			t.Fatal(err)
		}
		unrelated := exec.Command("/bin/sleep", "30")
		if err := unrelated.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = unrelated.Process.Kill()
			_ = unrelated.Wait()
		})
		route := client.Route{
			Name: "unrelated.localhost", Scheme: "http", Host: "127.0.0.1", Port: 43210,
			Owner: client.Owner{Kind: client.OwnerProcess, PID: unrelated.Process.Pid, Refresh: client.RefreshNever},
		}
		if _, err := management.Call(t.Context(), client.Request{Operation: client.OperationAdd, Route: &route, Match: client.RouteMatchAbsent}); err != nil {
			t.Fatal(err)
		}
		if _, err := forceRunnerTakeover(t.Context(), management, manager, route.Name); !errors.Is(err, runner.ErrNotTracked) {
			t.Fatalf("untracked takeover error = %v", err)
		}
		if err := unrelated.Process.Signal(syscall.Signal(0)); err != nil {
			t.Fatalf("untracked process was affected: %v", err)
		}
	})

	t.Run("current owner mismatch", func(t *testing.T) {
		management := client.Client{SocketPath: startRuntime(t, "")}
		manager, err := runner.Open(filepath.Join(t.TempDir(), "runner"))
		if err != nil {
			t.Fatal(err)
		}
		tracked := startTakeoverProcess(t, manager, "mismatch.localhost")
		route := client.Route{
			Name: tracked.Endpoint().Name, Scheme: "http", Host: tracked.Endpoint().Host, Port: tracked.Endpoint().Port,
			Owner: client.Owner{Kind: client.OwnerProcess, PID: os.Getpid(), Refresh: client.RefreshNever},
		}
		if _, err := management.Call(t.Context(), client.Request{Operation: client.OperationAdd, Route: &route, Match: client.RouteMatchAbsent}); err != nil {
			t.Fatal(err)
		}
		if _, err := forceRunnerTakeover(t.Context(), management, manager, route.Name); !errors.Is(err, runner.ErrIdentityMismatch) {
			t.Fatalf("identity mismatch error = %v", err)
		}
		if err := tracked.Signal(syscall.Signal(0)); err != nil {
			t.Fatalf("tracked process was affected: %v", err)
		}
	})

	t.Run("stale tracked process", func(t *testing.T) {
		socketPath := startRuntime(t, "")
		runnerDirectory := filepath.Join(t.TempDir(), "runner")
		t.Setenv("PORTLESS_SOCKET", socketPath)
		t.Setenv("PORTLESS_RUNNER_STATE", runnerDirectory)
		management := client.Client{SocketPath: socketPath}
		manager, err := runner.Open(runnerDirectory)
		if err != nil {
			t.Fatal(err)
		}
		supervisor := exec.Command(os.Args[0], "-test.run=^TestPortlessTakeoverSupervisorHelper$")
		supervisor.Env = append(os.Environ(),
			"GO_WANT_PORTLESS_TAKEOVER_SUPERVISOR=1",
			"GO_WANT_PORTLESS_LAN_SERVER=1",
			"PORTLESS_SOCKET="+socketPath,
			"PORTLESS_RUNNER_STATE="+runnerDirectory,
		)
		if err := supervisor.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if supervisor.ProcessState == nil {
				_ = supervisor.Process.Kill()
				_ = supervisor.Wait()
			}
		})
		route := waitForRoute(t, management, "stale.localhost")
		var record runner.Record
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			discovered, discoverErr := manager.Discover()
			if discoverErr == nil && len(discovered) == 1 {
				record = discovered[0].Record
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if record.Identity.PID == 0 {
			t.Fatal("stale fixture was not recorded")
		}
		if err := supervisor.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		_ = supervisor.Wait()
		if err := syscall.Kill(-record.ProcessGroup, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			t.Fatal(err)
		}
		deadline = time.Now().Add(5 * time.Second)
		staleObserved := false
		for time.Now().Before(deadline) {
			discovered, _ := manager.Discover()
			if len(discovered) == 1 && discovered[0].Status == runner.StatusStale {
				staleObserved = true
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !staleObserved {
			t.Fatal("runner state did not become stale")
		}
		if got, err := forceRunnerTakeover(t.Context(), management, manager, route.Name); err != nil || got != route {
			t.Fatalf("stale takeover = %#v, %v", got, err)
		}
		records, err := manager.Records()
		if err != nil || len(records) != 0 {
			t.Fatalf("state after stale takeover = %#v, %v", records, err)
		}
	})

	t.Run("management socket unavailable", func(t *testing.T) {
		manager, err := runner.Open(filepath.Join(t.TempDir(), "runner"))
		if err != nil {
			t.Fatal(err)
		}
		management := client.Client{SocketPath: filepath.Join(t.TempDir(), "missing.sock")}
		if _, err := forceRunnerTakeover(t.Context(), management, manager, "unavailable.localhost"); err == nil || !strings.Contains(err.Error(), "force requires an existing runner-owned route") {
			t.Fatalf("management failure = %v", err)
		}
	})
}

func TestGenericRunLANEndToEndAndSignalCleanup(t *testing.T) {
	addresses, err := mdns.EligibleAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) == 0 {
		t.Skip("no eligible assigned LAN address")
	}
	socketPath := startRuntime(t, "")
	t.Setenv("PORTLESS_SOCKET", socketPath)
	t.Setenv("PORTLESS_RUNNER_STATE", filepath.Join(t.TempDir(), "runner"))
	t.Setenv("GO_WANT_PORTLESS_LAN_SERVER", "1")
	readOutput, writeOutput, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readOutput.Close()
	var stderr bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"run", "--name", "lan-cli", "--lan", "--ip", addresses[0].Address.String(), "--", os.Args[0], "-test.run=TestPortlessLANServerHelper"}, writeOutput, &stderr)
		_ = writeOutput.Close()
	}()
	scanner := bufio.NewScanner(readOutput)
	var lanURL string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "http://lan-cli.local:") {
			lanURL = line
			break
		}
	}
	if lanURL == "" {
		cancel()
		t.Fatalf("LAN URL not printed: %v; stderr=%s", scanner.Err(), stderr.String())
	}
	parsed, err := url.Parse(lanURL)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(addresses[0].Address.String(), parsed.Port()))
	}
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	var response *http.Response
	for time.Now().Before(deadline) {
		response, err = httpClient.Get(lanURL)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "lan-cli-ok" {
		cancel()
		t.Fatalf("LAN body = %q", body)
	}
	var cleanOutput bytes.Buffer
	if code := run(t.Context(), []string{"clean", "--routes", "--yes"}, &cleanOutput, &stderr); code != 0 {
		cancel()
		t.Fatalf("clean code = %d, stdout=%s stderr=%s", code, cleanOutput.String(), stderr.String())
	}
	deadline = time.Now().Add(5 * time.Second)
	var exposures []ownedLAN
	for {
		exposures, err = ownedLANExposures()
		if err == nil && len(exposures) == 0 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("LAN state after clean = %#v, %v", exposures, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if response, requestErr := httpClient.Get(lanURL); requestErr == nil {
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			cancel()
			t.Fatalf("LAN after clean status = %d", response.StatusCode)
		}
	}
	cancel()
	if code := <-done; code != 143 {
		t.Fatalf("cancelled run code = %d, stderr=%s", code, stderr.String())
	}
	exposures, err = ownedLANExposures()
	if err != nil || len(exposures) != 0 {
		t.Fatalf("LAN state after signal = %#v, %v", exposures, err)
	}
	listed, err := (client.Client{SocketPath: socketPath}).Call(t.Context(), client.Request{Operation: client.OperationList})
	if err != nil || len(listed.Routes) != 0 {
		t.Fatalf("routes after signal = %#v, %v", listed.Routes, err)
	}
}

func TestGenericRunCleansLANWhenTailscaleSetupFails(t *testing.T) {
	addresses, err := mdns.EligibleAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) == 0 {
		t.Skip("no eligible assigned LAN address")
	}
	socketPath := startRuntime(t, "")
	t.Setenv("PORTLESS_SOCKET", socketPath)
	t.Setenv("PORTLESS_RUNNER_STATE", filepath.Join(t.TempDir(), "runner"))
	t.Setenv("GO_WANT_PORTLESS_LAN_SERVER", "1")
	t.Setenv("PATH", t.TempDir())

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(t.Context(), []string{
		"run", "--name", "lan-share-failure", "--lan", "--tailscale", "--ip", addresses[0].Address.String(), "--",
		os.Args[0], "-test.run=TestPortlessLANServerHelper",
	}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "configure Tailscale") {
		t.Fatalf("run code = %d, stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	exposures, err := ownedLANExposures()
	if err != nil || len(exposures) != 0 {
		t.Fatalf("LAN state after Tailscale failure = %#v, %v", exposures, err)
	}
	listed, err := (client.Client{SocketPath: socketPath}).Call(t.Context(), client.Request{Operation: client.OperationList})
	if err != nil || len(listed.Routes) != 0 {
		t.Fatalf("routes after Tailscale failure = %#v, %v", listed.Routes, err)
	}
}

func TestLANCrashReconcilesExactAdvertisementWithPrune(t *testing.T) {
	addresses, err := mdns.EligibleAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) == 0 {
		t.Skip("no eligible assigned LAN address")
	}
	socketPath := startRuntime(t, "")
	runnerDirectory := filepath.Join(t.TempDir(), "runner")
	t.Setenv("PORTLESS_SOCKET", socketPath)
	t.Setenv("PORTLESS_RUNNER_STATE", runnerDirectory)
	supervisor := exec.Command(os.Args[0], "-test.run=TestPortlessLANCrashSupervisorHelper")
	supervisor.Env = append(os.Environ(),
		"GO_WANT_PORTLESS_LAN_CRASH_SUPERVISOR=1", "GO_WANT_PORTLESS_LAN_SERVER=1",
		"PORTLESS_TEST_LAN_IP="+addresses[0].Address.String(),
	)
	if err := supervisor.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if supervisor.ProcessState == nil {
			_ = supervisor.Process.Kill()
			_ = supervisor.Wait()
		}
	}()
	manager, err := runner.Open(runnerDirectory)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	var record runner.Record
	var advertisement mdns.Identity
	for time.Now().Before(deadline) {
		discovered, discoverErr := manager.Discover()
		exposures, stateErr := ownedLANExposures()
		if discoverErr == nil && stateErr == nil && len(discovered) == 1 && len(exposures) == 1 && exposures[0].Registration.MDNS.PID > 0 {
			record = discovered[0].Record
			advertisement = exposures[0].Registration.MDNS
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if record.Identity.PID == 0 || advertisement.PID == 0 {
		t.Fatal("crash fixture did not become active")
	}
	if err := supervisor.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = supervisor.Wait()
	if err := syscall.Kill(-record.ProcessGroup, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		discovered, _ := manager.Discover()
		if len(discovered) == 1 && discovered[0].Status == runner.StatusStale {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"prune"}, &stdout, &stderr); code != 0 {
		t.Fatalf("prune code = %d, stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if err := mdns.StopOwned(advertisement); err != nil {
		t.Fatalf("owned advertisement remained after prune: %v", err)
	}
	exposures, err := ownedLANExposures()
	if err != nil || len(exposures) != 0 {
		t.Fatalf("LAN state after crash prune = %#v, %v", exposures, err)
	}
	listed, err := (client.Client{SocketPath: socketPath}).Call(t.Context(), client.Request{Operation: client.OperationList})
	if err != nil || len(listed.Routes) != 0 {
		t.Fatalf("routes after crash prune = %#v, %v", listed.Routes, err)
	}
}

func TestOwnedShareStateRoundTrip(t *testing.T) {
	t.Setenv("PORTLESS_RUNNER_STATE", filepath.Join(t.TempDir(), "runner"))
	identity := runner.Identity{PID: 42, Start: 99}
	plan := tailscale.Plan{Registration: tailscale.Registration{Name: "app", Mode: tailscale.Serve, Port: 443, Target: "http://127.0.0.1:3000", Host: "node.example.ts.net"}}
	if err := addOwnedShare(identity, plan); err != nil {
		t.Fatal(err)
	}
	shares, err := ownedShares()
	if err != nil || len(shares) != 1 || shares[0].Identity != identity || shares[0].Plan.Registration != plan.Registration {
		t.Fatalf("shares = %#v, err=%v", shares, err)
	}
	if err := removeOwnedShare(identity, plan); err != nil {
		t.Fatal(err)
	}
	shares, err = ownedShares()
	if err != nil || len(shares) != 0 {
		t.Fatalf("shares after remove = %#v, err=%v", shares, err)
	}
}

func TestOwnedLANStateRoundTrip(t *testing.T) {
	t.Setenv("PORTLESS_RUNNER_STATE", filepath.Join(t.TempDir(), "runner"))
	identity := runner.Identity{PID: 42, Start: 99}
	registration := lan.Registration{
		Name: "app.local", Target: "http://127.0.0.1:3000", Scheme: "http",
		Address: "192.168.1.20", Port: 54321, Interface: "en0", MDNS: mdns.Identity{PID: 43, Start: 100},
	}
	if err := updateOwnedLAN(identity, registration); err != nil {
		t.Fatal(err)
	}
	exposures, err := ownedLANExposures()
	if err != nil || len(exposures) != 1 || exposures[0].Identity != identity || exposures[0].Registration != registration {
		t.Fatalf("LAN exposures = %#v, err=%v", exposures, err)
	}
	if err := removeOwnedLAN(identity, registration.Name); err != nil {
		t.Fatal(err)
	}
	exposures, err = ownedLANExposures()
	if err != nil || len(exposures) != 0 {
		t.Fatalf("LAN after remove = %#v, err=%v", exposures, err)
	}
}

func TestLANFlagsRequireExplicitOptIn(t *testing.T) {
	for _, arguments := range [][]string{{"--https", "--", "true"}, {"--ip", "192.168.1.2", "--", "true"}} {
		if _, err := parseRunOptions(arguments, &bytes.Buffer{}, false); err == nil {
			t.Fatalf("parseRunOptions(%v) accepted implicit LAN", arguments)
		}
	}
	options, err := parseRunOptions([]string{"--lan", "--https", "--ip", "192.168.1.2", "--", "true"}, &bytes.Buffer{}, false)
	if err != nil || !options.lan || !options.https || options.ip != "192.168.1.2" {
		t.Fatalf("explicit LAN options = %#v, %v", options, err)
	}
}

func startTakeoverProcess(t *testing.T, manager *runner.Manager, name string) *runner.Process {
	t.Helper()
	process, err := manager.Start(context.Background(), runner.Spec{
		Name: name, Proxy: true,
		Command:     []string{os.Args[0], "-test.run=^TestPortlessLANServerHelper$"},
		Environment: map[string]string{"GO_WANT_PORTLESS_LAN_SERVER": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = process.Signal(syscall.SIGKILL)
		_, _ = process.Wait()
	})
	endpoint := process.Endpoint()
	address := "http://" + net.JoinHostPort(endpoint.Host, strconv.Itoa(int(endpoint.Port)))
	if err := waitForHTTPBody(address, "lan-cli-ok", 3*time.Second); err != nil {
		t.Fatalf("takeover process listener did not become ready: %v", err)
	}
	return process
}

func waitForHTTPBody(address, want string, timeout time.Duration) error {
	client := &http.Client{
		Timeout:   500 * time.Millisecond,
		Transport: &http.Transport{Proxy: nil},
	}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		response, err := client.Get(address)
		if err == nil {
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr == nil && string(body) == want {
				return nil
			}
			lastErr = fmt.Errorf("body = %q, read error = %v", body, readErr)
		} else {
			lastErr = err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return lastErr
}

func registerTakeoverRoute(t *testing.T, management client.Client, process *runner.Process) client.Route {
	t.Helper()
	endpoint := process.Endpoint()
	route := client.Route{
		Name: endpoint.Name, Scheme: "http", Host: endpoint.Host, Port: endpoint.Port,
		Owner: client.Owner{Kind: client.OwnerProcess, PID: process.PID(), Refresh: client.RefreshNever},
	}
	response, err := management.Call(t.Context(), client.Request{
		Operation: client.OperationAdd, Route: &route, Match: client.RouteMatchAbsent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Route == nil || response.Route.Owner.ProcessStart != process.Identity().Start {
		t.Fatalf("canonical runner route = %#v", response.Route)
	}
	return *response.Route
}

func waitForDifferentRouteOwner(t *testing.T, management client.Client, previous client.Route) client.Route {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, err := management.Call(t.Context(), client.Request{Operation: client.OperationList})
		if err == nil {
			for _, route := range response.Routes {
				if route.Name == previous.Name && route.Owner != previous.Owner {
					return route
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("replacement route did not become active")
	return client.Route{}
}

func waitForRoute(t *testing.T, management client.Client, name string) client.Route {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		response, err := management.Call(t.Context(), client.Request{Operation: client.OperationList})
		if err == nil {
			for _, route := range response.Routes {
				if route.Name == name {
					return route
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("route %s was not found", name)
	return client.Route{}
}

func isRouteConflict(err error) bool {
	var responseErr *client.ResponseError
	return errors.As(err, &responseErr) && responseErr.Code == "route_conflict"
}

func startRuntime(t *testing.T, containerCLI string) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "portless-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	stateDir := filepath.Join(directory, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "run", "management.sock")
	runtime, err := daemon.Start(t.Context(), daemon.Config{
		StateDir:         stateDir,
		ManagementSocket: socketPath,
		ManagementUID:    os.Geteuid(),
		ManagementGID:    os.Getegid(),
		HTTPListeners:    []string{"127.0.0.1:0"},
		HTTPSListeners:   []string{"127.0.0.1:0"},
		ContainerCLI:     containerCLI,
		RefreshInterval:  -1,
		ShutdownTimeout:  2 * time.Second,
		Version:          "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close(t.Context()) })
	return socketPath
}

func containerFixtureExecutable(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	fixturePath := filepath.Join(directory, "inspect.json")
	fixture := `[{"id":"fieldnotes","configuration":{"id":"fieldnotes","publishedPorts":[]},"status":{"state":"running","networks":[{"network":"default","ipv4Address":"192.168.64.8/24"}]}}]`
	if err := os.WriteFile(fixturePath, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	executablePath := filepath.Join(directory, "container-fixture")
	script := fmt.Sprintf("#!/bin/sh\n[ \"$1\" = inspect ] || exit 64\nexec /bin/cat '%s'\n", fixturePath)
	if err := os.WriteFile(executablePath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return executablePath
}

func shortCommandTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "portless-command-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}
