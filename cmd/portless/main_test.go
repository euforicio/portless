package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/euforicio/portless/internal/client"
)

func TestCommandSurfaceUsesRealManagementSocket(t *testing.T) {
	socketPath, requests := startManagementServer(t, 7)
	t.Setenv("PORTLESS_SOCKET", socketPath)

	commands := [][]string{
		{"install"},
		{"add", "App", "--port", "3000", "--pid", fmt.Sprint(os.Getpid())},
		{"remove", "app.localhost"},
		{"list"},
		{"status"},
		{"doctor"},
		{"uninstall"},
	}
	for _, command := range commands {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := run(t.Context(), command, &stdout, &stderr); code != 0 {
			t.Fatalf("run(%v) = %d, stderr: %s", command, code, stderr.String())
		}
	}

	wantOperations := []client.Operation{
		client.OperationInstall,
		client.OperationAdd,
		client.OperationRemove,
		client.OperationList,
		client.OperationStatus,
		client.OperationDoctor,
		client.OperationUninstall,
	}
	for _, want := range wantOperations {
		request := <-requests
		if request.Operation != want {
			t.Fatalf("operation = %q, want %q", request.Operation, want)
		}
		if want == client.OperationAdd {
			if request.Route == nil || request.Route.Name != "app.localhost" || request.Route.Owner.Kind != client.OwnerProcess || request.Route.Owner.PID != os.Getpid() {
				t.Fatalf("unexpected add route: %#v", request.Route)
			}
		}
	}
}

func TestAddAppleContainerSendsRefreshableOwner(t *testing.T) {
	socketPath, requests := startManagementServer(t, 1)
	t.Setenv("PORTLESS_SOCKET", socketPath)
	t.Setenv("PORTLESS_CONTAINER_CLI", containerFixtureExecutable(t))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(t.Context(), []string{"add", "fieldnotes", "--container", "fieldnotes", "--port", "80"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run = %d, stderr: %s", code, stderr.String())
	}
	request := <-requests
	if request.Route == nil {
		t.Fatal("add request has no route")
	}
	owner := request.Route.Owner
	if owner.Kind != client.OwnerContainer || owner.Container != "fieldnotes" || owner.Network != "default" || owner.Refresh != client.RefreshContainerAddress {
		t.Fatalf("unexpected owner: %#v", owner)
	}
	if request.Route.Host != "192.168.64.8" || request.Route.Port != 80 {
		t.Fatalf("unexpected upstream: %#v", request.Route)
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

func startManagementServer(t *testing.T, calls int) (string, <-chan client.Request) {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "portless-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socketPath := filepath.Join(directory, "management.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(socketPath, 0o660); err != nil {
		t.Fatal(err)
	}

	requests := make(chan client.Request, calls)
	go func() {
		defer close(requests)
		for range calls {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			var request client.Request
			decodeErr := json.NewDecoder(connection).Decode(&request)
			if decodeErr == nil {
				requests <- request
				response := client.Response{Version: client.ProtocolVersion, ID: request.ID, OK: true}
				switch request.Operation {
				case client.OperationList:
					response.Routes = []client.Route{{
						Name: "app.localhost", Scheme: "http", Host: "127.0.0.1", Port: 3000,
						Owner: client.Owner{Kind: client.OwnerStatic, Refresh: client.RefreshNever},
					}}
				case client.OperationStatus:
					response.Status = &client.Status{Running: true, Version: "test", SocketPath: socketPath}
				case client.OperationDoctor:
					response.Diagnostics = []client.Diagnostic{{Name: "socket", Level: "ok", Message: "reachable"}}
				}
				_ = json.NewEncoder(connection).Encode(response)
			}
			_ = connection.Close()
		}
	}()
	return socketPath, requests
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
