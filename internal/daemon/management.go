package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/euforicio/portless/internal/client"
	"github.com/euforicio/portless/internal/pki"
	"github.com/euforicio/portless/internal/service"
)

const maxRequestBytes = 64 << 10

type operationError struct {
	code    string
	message string
}

func (e operationError) Error() string { return e.message }

func (r *Runtime) serveManagement() {
	for {
		connection, err := r.management.AcceptUnix()
		if err != nil {
			if r.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case r.serveErr <- fmt.Errorf("accept management connection: %w", err):
			default:
			}
			r.cancel()
			return
		}
		select {
		case r.managementSlots <- struct{}{}:
		default:
			_ = connection.Close()
			continue
		}
		r.managementConnections.add(connection)
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer func() { <-r.managementSlots }()
			defer r.managementConnections.remove(connection)
			defer connection.Close()
			r.handleManagement(connection)
		}()
	}
}

func (r *Runtime) handleManagement(connection *net.UnixConn) {
	deadline := time.Now().Add(r.config.ManagementTimeout)
	if err := connection.SetDeadline(deadline); err != nil {
		return
	}
	peer, err := service.Credentials(connection)
	if err != nil || !peer.Allowed(0, uint32(r.config.ManagementGID)) {
		return
	}

	frame, err := readRequestFrame(connection)
	if err != nil {
		_ = writeResponse(connection, client.Response{
			Version: client.ProtocolVersion,
			ID:      "invalid",
			OK:      false,
			Error:   &client.Problem{Code: "invalid_request", Message: err.Error()},
		})
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	var request client.Request
	if err := decoder.Decode(&request); err != nil {
		_ = writeResponse(connection, problemResponse(safeResponseID(request.ID), "invalid_request", "invalid management request"))
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		_ = writeResponse(connection, problemResponse(safeResponseID(request.ID), "invalid_request", "management request contains trailing data"))
		return
	}
	if err := request.Validate(); err != nil {
		_ = writeResponse(connection, problemResponse(safeResponseID(request.ID), "invalid_request", err.Error()))
		return
	}

	requestContext, cancel := context.WithDeadline(r.ctx, deadline)
	defer cancel()
	response, err := r.executeRequest(requestContext, peer, request)
	if err != nil {
		var operationErr operationError
		if errors.As(err, &operationErr) {
			response = problemResponse(request.ID, operationErr.code, operationErr.message)
		} else {
			if r.config.Logger != nil {
				r.config.Logger.Printf("management %s failed: %v", request.Operation, err)
			}
			response = problemResponse(request.ID, "internal", "operation failed")
		}
	}
	response.Version = client.ProtocolVersion
	response.ID = request.ID
	_ = writeResponse(connection, response)
}

func (r *Runtime) executeRequest(ctx context.Context, peer service.PeerCredentials, request client.Request) (client.Response, error) {
	success := client.Response{OK: true}
	switch request.Operation {
	case client.OperationAdd:
		registration := *request.Route
		switch registration.Owner.Kind {
		case client.OwnerProcess:
			if registration.Owner.ProcessStart != 0 {
				return client.Response{}, operationError{code: "invalid_request", message: "process start identity is daemon-owned"}
			}
			uid, identity, err := inspectProcess(registration.Owner.PID)
			if err != nil {
				return client.Response{}, operationError{code: "invalid_owner", message: "owning process is not running"}
			}
			if peer.UID != 0 && uid != peer.UID {
				return client.Response{}, operationError{code: "forbidden", message: "owning process belongs to another user"}
			}
			registration.Owner.ProcessStart = identity
		case client.OwnerContainer:
			if registration.Owner.InspectorUID != 0 {
				return client.Response{}, operationError{code: "invalid_request", message: "container inspector identity is daemon-owned"}
			}
			if peer.UID == 0 {
				return client.Response{}, operationError{code: "invalid_owner", message: "container routes must be registered by an unprivileged login user"}
			}
			resolver, err := r.containerResolver(peer.UID)
			if err != nil {
				return client.Response{}, operationError{code: "invalid_owner", message: err.Error()}
			}
			endpoint, err := resolver.Resolve(ctx, registration.Owner.Container, registration.Port, registration.Scheme)
			if err != nil {
				return client.Response{}, operationError{code: "invalid_owner", message: err.Error()}
			}
			if endpoint.Address.String() != registration.Host || endpoint.Network != registration.Owner.Network || endpoint.Container != registration.Owner.Container {
				return client.Response{}, operationError{code: "stale_metadata", message: "container metadata changed; retry add"}
			}
			registration.Host = endpoint.Address.String()
			registration.Port = endpoint.Port
			registration.Owner.Network = endpoint.Network
			registration.Owner.InspectorUID = peer.UID
		}
		if err := registration.Validate(); err != nil {
			return client.Response{}, operationError{code: "invalid_request", message: err.Error()}
		}
		if err := r.registry.set(registration, true); err != nil {
			return client.Response{}, err
		}
	case client.OperationRemove:
		if _, err := r.registry.remove(request.Name); err != nil {
			return client.Response{}, err
		}
	case client.OperationList:
		success.Routes = r.registry.list()
	case client.OperationStatus:
		success.Status = &client.Status{Running: true, Version: r.config.Version, SocketPath: r.config.ManagementSocket}
	case client.OperationDoctor:
		success.Diagnostics = r.doctor(ctx)
	case client.OperationRefresh:
		diagnostics, err := r.Refresh(ctx)
		if err != nil {
			return client.Response{}, err
		}
		success.Diagnostics = diagnostics
	case client.OperationInstall, client.OperationUninstall:
		return client.Response{}, operationError{code: "privilege_required", message: "service lifecycle operations must run through the privileged local CLI"}
	default:
		return client.Response{}, operationError{code: "invalid_request", message: "unsupported operation"}
	}
	return success, nil
}

func (r *Runtime) doctor(ctx context.Context) []client.Diagnostic {
	diagnostics := []client.Diagnostic{
		{Name: "daemon", Level: "ok", Message: "runtime is serving"},
		{Name: "management-socket", Level: "ok", Message: r.config.ManagementSocket},
		{Name: "routes", Level: "ok", Message: fmt.Sprintf("%d registrations", len(r.registry.list()))},
	}
	if info, err := os.Stat(r.config.ContainerCLI); err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		diagnostics = append(diagnostics, client.Diagnostic{Name: "apple-container", Level: "warning", Message: "container executable is unavailable"})
	} else {
		diagnostics = append(diagnostics, client.Diagnostic{Name: "apple-container", Level: "ok", Message: r.config.ContainerCLI})
	}
	trusted, err := pki.SystemTrusted(ctx, r.authority.RootCertificatePath())
	switch {
	case err != nil:
		diagnostics = append(diagnostics, client.Diagnostic{Name: "ca-trust", Level: "warning", Message: "could not inspect system trust"})
	case trusted:
		diagnostics = append(diagnostics, client.Diagnostic{Name: "ca-trust", Level: "ok", Message: "root certificate is trusted"})
	default:
		diagnostics = append(diagnostics, client.Diagnostic{Name: "ca-trust", Level: "warning", Message: "root certificate is not trusted"})
	}
	refreshDiagnostics, err := r.Refresh(ctx)
	if err != nil {
		diagnostics = append(diagnostics, client.Diagnostic{Name: "route-refresh", Level: "error", Message: "refresh failed"})
	} else {
		diagnostics = append(diagnostics, refreshDiagnostics...)
	}
	return diagnostics
}

func readRequestFrame(reader io.Reader) ([]byte, error) {
	limited := &io.LimitedReader{R: reader, N: maxRequestBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, errors.New("read management request")
	}
	if len(data) > maxRequestBytes {
		return nil, errors.New("management request exceeds size limit")
	}
	if len(data) < 2 || data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 || bytes.Contains(data, []byte{'\r'}) {
		return nil, errors.New("management request must be one newline-delimited JSON frame")
	}
	return data[:len(data)-1], nil
}

func writeResponse(writer io.Writer, response client.Response) error {
	return json.NewEncoder(writer).Encode(response)
}

func problemResponse(id, code, message string) client.Response {
	return client.Response{
		Version: client.ProtocolVersion,
		ID:      id,
		OK:      false,
		Error:   &client.Problem{Code: code, Message: message},
	}
}

func safeResponseID(id string) string {
	if len(id) == 0 || len(id) > 64 {
		return "invalid"
	}
	for _, character := range id {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("-_", character) {
			continue
		}
		return "invalid"
	}
	return id
}
