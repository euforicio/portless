package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/euforicio/portless/internal/client"
)

func TestStartRealProcessEnvironmentPortAndSignalForwarding(t *testing.T) {
	manager := openTestManager(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, []byte("test CA metadata\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	readyPath := filepath.Join(t.TempDir(), "ready.json")
	process, err := manager.Start(t.Context(), helperSpec("serve", readyPath, Spec{
		Name:             "generic-app",
		Proxy:            true,
		NodeExtraCACerts: caPath,
		Environment:      map[string]string{"CUSTOM_VALUE": "preserved"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = process.Signal(syscall.SIGKILL)
		_, _ = process.Wait()
	})

	endpoint := process.Endpoint()
	if endpoint.Name != "generic-app.localhost" || endpoint.Host != "127.0.0.1" || endpoint.Port == 0 || endpoint.URL != "https://generic-app.localhost" {
		t.Fatalf("endpoint = %#v", endpoint)
	}
	ready := waitForReady(t, readyPath)
	if ready["PORT"] != strconv.Itoa(int(endpoint.Port)) || ready["HOST"] != "127.0.0.1" || ready["PORTLESS_URL"] != endpoint.URL || ready["NODE_EXTRA_CA_CERTS"] != caPath || ready["CUSTOM_VALUE"] != "preserved" {
		t.Fatalf("child environment = %#v", ready)
	}

	connection, err := net.DialTimeout("tcp4", net.JoinHostPort(endpoint.Host, strconv.Itoa(int(endpoint.Port))), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, "ping\n"); err != nil {
		t.Fatal(err)
	}
	response, err := bufio.NewReader(connection).ReadString('\n')
	connection.Close()
	if err != nil || response != "pong\n" {
		t.Fatalf("real TCP response = %q, %v", response, err)
	}

	forwarded := make(chan os.Signal, 1)
	stop := process.Forward(forwarded)
	forwarded <- syscall.SIGUSR1
	result, err := process.Wait()
	stop()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || result.ExitCode != 17 || result.Signaled {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	records, err := manager.Records()
	if err != nil || len(records) != 0 {
		t.Fatalf("records after Wait = %#v, %v", records, err)
	}
}

func TestRunPreservesNonzeroExitStatus(t *testing.T) {
	manager := openTestManager(t)
	result, err := manager.Run(t.Context(), helperSpec("exit-7", "", Spec{Name: "failure", Proxy: false}), nil)
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || result.ExitCode != 7 || result.Signaled || result.Identity.PID <= 0 || result.Identity.Start <= 0 {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
}

func TestCancellationTerminatesProcessGroupAndPreservesSignal(t *testing.T) {
	manager := openTestManager(t)
	readyPath := filepath.Join(t.TempDir(), "cancel.json")
	ctx, cancel := context.WithCancel(context.Background())
	process, err := manager.Start(ctx, helperSpec("ignore-term", readyPath, Spec{
		Name: "cancelled", Proxy: true, StopTimeout: 30 * time.Millisecond,
	}))
	if err != nil {
		t.Fatal(err)
	}
	waitForReady(t, readyPath)
	cancel()
	result, err := process.Wait()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || result.ExitCode != -1 || !result.Signaled || result.Signal != syscall.SIGKILL {
		t.Fatalf("cancelled result = %#v, %v", result, err)
	}
}

func TestNonProxyDoesNotInjectManagedEnvironment(t *testing.T) {
	for _, key := range []string{"PORT", "HOST", "PORTLESS_URL", "NODE_EXTRA_CA_CERTS"} {
		t.Setenv(key, "")
	}
	manager := openTestManager(t)
	outputPath := filepath.Join(t.TempDir(), "environment.json")
	result, err := manager.Run(t.Context(), helperSpec("environment", outputPath, Spec{
		Name:  "no-proxy",
		Proxy: false,
	}), nil)
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("Run = %#v, %v", result, err)
	}
	environment := waitForReady(t, outputPath)
	for _, key := range []string{"PORT", "HOST", "PORTLESS_URL", "NODE_EXTRA_CA_CERTS"} {
		if environment[key] != "" {
			t.Fatalf("non-proxy child received %s=%q", key, environment[key])
		}
	}
}

func TestFixedPortAndBusyPort(t *testing.T) {
	manager := openTestManager(t)
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	busyPort := uint16(reservation.Addr().(*net.TCPAddr).Port)
	if _, err := manager.Start(t.Context(), helperSpec("serve", filepath.Join(t.TempDir(), "busy.json"), Spec{
		Name: "busy", Proxy: true, AppPort: busyPort,
	})); err == nil || !strings.Contains(err.Error(), "reserve loopback app port") {
		t.Fatalf("busy port error = %v", err)
	}
	reservation.Close()

	readyPath := filepath.Join(t.TempDir(), "fixed.json")
	process, err := manager.Start(t.Context(), helperSpec("serve", readyPath, Spec{
		Name: "fixed", Proxy: true, AppPort: busyPort,
	}))
	if err != nil {
		t.Fatal(err)
	}
	waitForReady(t, readyPath)
	if process.Endpoint().Port != busyPort {
		t.Fatalf("fixed port = %d; want %d", process.Endpoint().Port, busyPort)
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	result, err := process.Wait()
	if result.ExitCode != 23 || err == nil {
		t.Fatalf("fixed child result = %#v, %v", result, err)
	}
}

func TestForceTakeoverRequiresExactCurrentRoute(t *testing.T) {
	manager := openTestManager(t)
	readyPath := filepath.Join(t.TempDir(), "takeover.json")
	process, err := manager.Start(context.Background(), helperSpec("ignore-term", readyPath, Spec{
		Name: "takeover", Proxy: true, StopTimeout: time.Second,
	}))
	if err != nil {
		t.Fatal(err)
	}
	waitForReady(t, readyPath)
	records, err := manager.Records()
	if err != nil || len(records) != 1 {
		t.Fatalf("records = %#v, %v", records, err)
	}
	route := currentRoute(records[0])
	wrong := route
	wrong.Owner.ProcessStart++
	if err := manager.ForceTakeover(t.Context(), wrong, 50*time.Millisecond); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("wrong identity takeover error = %v", err)
	}
	if err := process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("wrong identity affected process: %v", err)
	}
	wrong = route
	wrong.Port++
	if err := manager.ForceTakeover(t.Context(), wrong, 50*time.Millisecond); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("wrong endpoint takeover error = %v", err)
	}

	waited := make(chan struct{})
	go func() {
		_, _ = process.Wait()
		close(waited)
	}()
	if err := manager.ForceTakeover(t.Context(), route, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("taken-over child was not reaped")
	}

	unrelated := exec.Command("/bin/sleep", "10")
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unrelated.Process.Kill()
		_ = unrelated.Wait()
	})
	unrelatedUID, unrelatedIdentity, _, err := inspectProcess(unrelated.Process.Pid)
	if err != nil || unrelatedUID != uint32(os.Geteuid()) {
		t.Fatal(err)
	}
	unrelatedRoute := route
	unrelatedRoute.Name = "unrelated.localhost"
	unrelatedRoute.Owner.PID = unrelatedIdentity.PID
	unrelatedRoute.Owner.ProcessStart = unrelatedIdentity.Start
	if err := manager.ForceTakeover(t.Context(), unrelatedRoute, time.Millisecond); !errors.Is(err, ErrNotTracked) {
		t.Fatalf("untracked takeover error = %v", err)
	}
	if err := unrelated.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("unrelated process was affected: %v", err)
	}
}

func TestDiscoverAndPruneDurableState(t *testing.T) {
	manager := openTestManager(t)
	child := exec.Command("/bin/sleep", "10")
	child.SysProcAttr = processGroupAttributes()
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	uid, identity, processGroup, err := inspectProcess(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	supervisorUID, supervisorIdentity, _, err := inspectProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	record := Record{
		Endpoint: Endpoint{Name: "durable.localhost", Proxy: true, Host: "127.0.0.1", Port: 43210, URL: "https://durable.localhost"},
		Identity: identity, ProcessGroup: processGroup, UID: uid,
		Supervisor: supervisorIdentity, SupervisorUID: supervisorUID,
		WorkingDirectory: t.TempDir(),
	}
	if err := manager.withStateLock(func(state *persistedState) error {
		state.Records = append(state.Records, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(filepath.Dir(manager.statePath))
	if err != nil {
		t.Fatal(err)
	}
	discovered, err := reopened.Discover()
	if err != nil || len(discovered) != 1 || discovered[0].Status != StatusActive {
		t.Fatalf("active discovery = %#v, %v", discovered, err)
	}
	if err := reopened.withStateLock(func(state *persistedState) error {
		state.Records[0].Supervisor = Identity{PID: 99999999, Start: 1}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	discovered, err = reopened.Discover()
	if err != nil || len(discovered) != 1 || discovered[0].Status != StatusOrphaned {
		t.Fatalf("orphan discovery = %#v, %v", discovered, err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	discovered, err = reopened.Discover()
	if err != nil || len(discovered) != 1 || discovered[0].Status != StatusStale {
		t.Fatalf("stale discovery = %#v, %v", discovered, err)
	}
	removed, err := reopened.Prune()
	if err != nil || len(removed) != 1 || removed[0].Identity != identity {
		t.Fatalf("Prune = %#v, %v", removed, err)
	}
	records, err := reopened.Records()
	if err != nil || len(records) != 0 {
		t.Fatalf("records after prune = %#v, %v", records, err)
	}
}

func TestStateAndSpecValidationFailClosed(t *testing.T) {
	if _, err := Open("relative"); err == nil {
		t.Fatal("Open accepted relative state directory")
	}
	unsafeDirectory := t.TempDir()
	if err := os.Chmod(unsafeDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(unsafeDirectory); err == nil {
		t.Fatal("Open accepted unsafe state directory")
	}
	manager := openTestManager(t)
	directoryInfo, err := os.Stat(manager.directory)
	if err != nil || directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("state directory mode = %v, %v", directoryInfo, err)
	}
	for _, path := range []string{manager.statePath, manager.lockPath} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("state file %s mode = %v, %v", path, info, err)
		}
	}
	invalidSpecs := []Spec{
		{Name: "bad/name", Command: []string{"true"}, Proxy: true},
		{Name: "managed", Command: []string{"true"}, Proxy: true, Environment: map[string]string{"PORT": "1234"}},
		{Name: "ca", Command: []string{"true"}, Proxy: false, NodeExtraCACerts: "/tmp/ca.pem"},
		{Name: "port", Command: []string{"true"}, Proxy: false, AppPort: 1234},
	}
	for _, spec := range invalidSpecs {
		if _, err := manager.Start(t.Context(), spec); err == nil {
			t.Fatalf("Start accepted invalid spec %#v", spec)
		}
	}

	statePath := manager.statePath
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte(`{"version":1,"records":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, statePath); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Records(); err == nil {
		t.Fatal("Records followed a state symlink")
	}
}

func TestRunnerHelperProcess(t *testing.T) {
	if os.Getenv("PORTLESS_RUNNER_HELPER") != "1" {
		return
	}
	action := os.Getenv("PORTLESS_RUNNER_ACTION")
	outputPath := os.Getenv("PORTLESS_RUNNER_OUTPUT")
	environment := map[string]string{
		"PORT":                os.Getenv("PORT"),
		"HOST":                os.Getenv("HOST"),
		"PORTLESS_URL":        os.Getenv("PORTLESS_URL"),
		"NODE_EXTRA_CA_CERTS": os.Getenv("NODE_EXTRA_CA_CERTS"),
		"CUSTOM_VALUE":        os.Getenv("CUSTOM_VALUE"),
	}
	switch action {
	case "exit-7":
		os.Exit(7)
	case "environment":
		writeHelperJSON(outputPath, environment)
		os.Exit(0)
	case "serve", "ignore-term":
		listener, err := net.Listen("tcp4", net.JoinHostPort(os.Getenv("HOST"), os.Getenv("PORT")))
		if err != nil {
			os.Exit(90)
		}
		defer listener.Close()
		writeHelperJSON(outputPath, environment)
		go func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer connection.Close()
					_, _ = bufio.NewReader(connection).ReadString('\n')
					_, _ = io.WriteString(connection, "pong\n")
				}()
			}
		}()
		signals := make(chan os.Signal, 1)
		if action == "ignore-term" {
			signal.Ignore(syscall.SIGTERM)
			signal.Notify(signals, syscall.SIGUSR1)
		} else {
			signal.Notify(signals, syscall.SIGTERM, syscall.SIGUSR1)
		}
		received := <-signals
		if received == syscall.SIGUSR1 {
			os.Exit(17)
		}
		os.Exit(23)
	default:
		fmt.Fprintln(os.Stderr, "unknown helper action")
		os.Exit(91)
	}
}

func openTestManager(t *testing.T) *Manager {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "state")
	manager, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func helperSpec(action, output string, spec Spec) Spec {
	spec.Command = []string{os.Args[0], "-test.run=^TestRunnerHelperProcess$"}
	if spec.Environment == nil {
		spec.Environment = make(map[string]string)
	}
	spec.Environment["PORTLESS_RUNNER_HELPER"] = "1"
	spec.Environment["PORTLESS_RUNNER_ACTION"] = action
	spec.Environment["PORTLESS_RUNNER_OUTPUT"] = output
	return spec
}

func waitForReady(t *testing.T, path string) map[string]string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			var value map[string]string
			if err := json.Unmarshal(data, &value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("helper process did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func writeHelperJSON(path string, value map[string]string) {
	file, err := os.CreateTemp(filepath.Dir(path), ".runner-helper-*")
	if err != nil {
		os.Exit(92)
	}
	temporaryPath := file.Name()
	if err := json.NewEncoder(file).Encode(value); err != nil {
		file.Close()
		os.Remove(temporaryPath)
		os.Exit(93)
	}
	if err := file.Close(); err != nil {
		os.Remove(temporaryPath)
		os.Exit(94)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		os.Remove(temporaryPath)
		os.Exit(95)
	}
}

func currentRoute(record Record) client.Route {
	return client.Route{
		Name:   record.Endpoint.Name,
		Scheme: "http",
		Host:   record.Endpoint.Host,
		Port:   record.Endpoint.Port,
		Owner: client.Owner{
			Kind:         client.OwnerProcess,
			PID:          record.Identity.PID,
			ProcessStart: record.Identity.Start,
			Refresh:      client.RefreshNever,
		},
	}
}
