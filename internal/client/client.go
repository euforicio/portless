package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	DefaultSocketPath = "/var/run/portless/management.sock"
	defaultTimeout    = 5 * time.Second
	maxResponseBytes  = 1 << 20
)

type Client struct {
	SocketPath string
	Timeout    time.Duration
}

type ResponseError struct {
	Code    string
	Message string
}

func (e *ResponseError) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

func (c Client) Call(ctx context.Context, request Request) (Response, error) {
	if request.Version == 0 {
		request.Version = ProtocolVersion
	}
	if request.ID == "" {
		id, err := requestID()
		if err != nil {
			return Response{}, fmt.Errorf("create request ID: %w", err)
		}
		request.ID = id
	}
	if err := request.Validate(); err != nil {
		return Response{}, fmt.Errorf("invalid request: %w", err)
	}

	socketPath := c.SocketPath
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	if err := validateSocket(socketPath); err != nil {
		return Response{}, err
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := net.Dialer{}
	connection, err := dialer.DialContext(callCtx, "unix", socketPath)
	if err != nil {
		return Response{}, fmt.Errorf("connect to management socket: %w", err)
	}
	defer connection.Close()
	if deadline, ok := callCtx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return Response{}, fmt.Errorf("set management socket deadline: %w", err)
		}
	}

	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return Response{}, fmt.Errorf("send management request: %w", err)
	}
	if unixConnection, ok := connection.(*net.UnixConn); ok {
		if err := unixConnection.CloseWrite(); err != nil {
			return Response{}, fmt.Errorf("finish management request: %w", err)
		}
	}

	responseData, err := io.ReadAll(io.LimitReader(connection, maxResponseBytes+1))
	if err != nil {
		return Response{}, fmt.Errorf("read management response: %w", err)
	}
	if len(responseData) > maxResponseBytes {
		return Response{}, errors.New("management response exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(responseData))
	decoder.DisallowUnknownFields()
	var response Response
	if err := decoder.Decode(&response); err != nil {
		return Response{}, fmt.Errorf("read management response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Response{}, errors.New("management server returned more than one response")
		}
		return Response{}, fmt.Errorf("read management response trailer: %w", err)
	}
	if response.Version != ProtocolVersion {
		return Response{}, fmt.Errorf("management server uses unsupported protocol version %d", response.Version)
	}
	if response.ID != request.ID {
		return Response{}, errors.New("management response request ID does not match")
	}
	if response.OK && response.Error != nil {
		return Response{}, errors.New("management response includes an error for a successful request")
	}
	if !response.OK {
		if response.Error == nil || response.Error.Code == "" || response.Error.Message == "" {
			return Response{}, errors.New("management response failed without a structured error")
		}
		return Response{}, &ResponseError{Code: response.Error.Code, Message: response.Error.Message}
	}
	return response, nil
}

func validateSocket(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("management socket path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect management socket: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return errors.New("management socket path is not a Unix socket")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("management socket ownership is unavailable")
	}
	if stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("management socket is owned by unexpected uid %d", stat.Uid)
	}
	if info.Mode().Perm()&0o002 != 0 {
		return errors.New("management socket must not be world-writable")
	}
	return nil
}

func requestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}
