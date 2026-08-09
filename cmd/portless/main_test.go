package main

import (
	"bytes"
	"fmt"
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
)

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
