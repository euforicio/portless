package client

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientCallUsesRealUnixSocket(t *testing.T) {
	socketPath := filepath.Join(shortTempDir(t), "management.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(socketPath, 0o660); err != nil {
		t.Fatal(err)
	}

	received := make(chan Request, 1)
	serverError := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverError <- err
			return
		}
		defer connection.Close()
		var request Request
		if err := json.NewDecoder(connection).Decode(&request); err != nil {
			serverError <- err
			return
		}
		received <- request
		serverError <- json.NewEncoder(connection).Encode(Response{
			Version: ProtocolVersion,
			ID:      request.ID,
			OK:      true,
			Status:  &Status{Running: true, Version: "test"},
		})
	}()

	response, err := (Client{SocketPath: socketPath, Timeout: time.Second}).Call(
		context.Background(), Request{Operation: OperationStatus},
	)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if response.Status == nil || !response.Status.Running {
		t.Fatalf("unexpected response: %#v", response)
	}
	request := <-received
	if request.Version != ProtocolVersion || request.ID == "" || request.Operation != OperationStatus {
		t.Fatalf("unexpected request: %#v", request)
	}
	if err := <-serverError; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestClientRejectsNonSocketPath(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := (Client{SocketPath: path}).Call(context.Background(), Request{Operation: OperationStatus})
	if err == nil || !strings.Contains(err.Error(), "not a Unix socket") {
		t.Fatalf("Call error = %v, want non-socket error", err)
	}
}

func TestClientRejectsMismatchedResponseID(t *testing.T) {
	socketPath := filepath.Join(shortTempDir(t), "management.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(socketPath, 0o660); err != nil {
		t.Fatal(err)
	}

	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		var request Request
		_ = json.NewDecoder(connection).Decode(&request)
		_ = json.NewEncoder(connection).Encode(Response{Version: ProtocolVersion, ID: "wrong", OK: true})
	}()

	_, err = (Client{SocketPath: socketPath, Timeout: time.Second}).Call(context.Background(), Request{Operation: OperationList})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Call error = %v, want ID mismatch", err)
	}
}

func TestClientCallTimesOutOnUnresponsiveSocket(t *testing.T) {
	socketPath := filepath.Join(shortTempDir(t), "management.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(socketPath, 0o660); err != nil {
		t.Fatal(err)
	}

	accepted := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		close(accepted)
		defer connection.Close()
		time.Sleep(100 * time.Millisecond)
	}()

	_, err = (Client{SocketPath: socketPath, Timeout: 20 * time.Millisecond}).Call(context.Background(), Request{Operation: OperationStatus})
	if err == nil || !strings.Contains(err.Error(), "read management response") {
		t.Fatalf("Call error = %v, want response timeout", err)
	}
	<-accepted
}

func TestClientRejectsMultipleResponses(t *testing.T) {
	socketPath := filepath.Join(shortTempDir(t), "management.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(socketPath, 0o660); err != nil {
		t.Fatal(err)
	}

	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		var request Request
		_ = json.NewDecoder(connection).Decode(&request)
		encoder := json.NewEncoder(connection)
		_ = encoder.Encode(Response{Version: ProtocolVersion, ID: request.ID, OK: true})
		_ = encoder.Encode(Response{Version: ProtocolVersion, ID: request.ID, OK: true})
	}()

	_, err = (Client{SocketPath: socketPath, Timeout: time.Second}).Call(context.Background(), Request{Operation: OperationList})
	if err == nil || !strings.Contains(err.Error(), "more than one response") {
		t.Fatalf("Call error = %v, want multiple-response error", err)
	}
}

func TestClientRejectsOversizedResponse(t *testing.T) {
	socketPath := filepath.Join(shortTempDir(t), "management.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(socketPath, 0o660); err != nil {
		t.Fatal(err)
	}

	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		var request Request
		_ = json.NewDecoder(connection).Decode(&request)
		_, _ = connection.Write(make([]byte, maxResponseBytes+1))
	}()

	_, err = (Client{SocketPath: socketPath, Timeout: time.Second}).Call(context.Background(), Request{Operation: OperationList})
	if err == nil || !strings.Contains(err.Error(), "exceeds size limit") {
		t.Fatalf("Call error = %v, want oversized-response error", err)
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "portless-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}
