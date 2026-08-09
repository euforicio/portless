package daemon

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/euforicio/portless/internal/client"
	"github.com/euforicio/portless/internal/service"
)

func TestRuntimeEndToEndTLSHTTP2RedirectWebSocketAndPersistence(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/ws" {
			hijacker, ok := writer.(http.Hijacker)
			if !ok {
				t.Error("backend cannot hijack")
				return
			}
			connection, buffer, err := hijacker.Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer connection.Close()
			_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
			_ = buffer.Flush()
			_, _ = io.Copy(connection, connection)
			return
		}
		writer.Header().Set("X-Backend", "real")
		_, _ = io.WriteString(writer, "streamed response")
	}))
	defer backend.Close()
	backendAddress := strings.TrimPrefix(backend.URL, "http://")
	backendHost, backendPort, err := net.SplitHostPort(backendAddress)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(backendPort)

	config := integrationConfig(t)
	runtime, err := Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	management := client.Client{SocketPath: config.ManagementSocket, Timeout: time.Second}
	registration := client.Route{
		Name: "fieldnotes.localhost", Scheme: "http", Host: backendHost, Port: uint16(port),
		Owner: client.Owner{Kind: client.OwnerStatic, Refresh: client.RefreshNever},
	}
	if _, err := management.Call(t.Context(), client.Request{Operation: client.OperationAdd, Route: &registration}); err != nil {
		t.Fatal(err)
	}
	other := registration
	other.Name = "other.localhost"
	if _, err := management.Call(t.Context(), client.Request{Operation: client.OperationAdd, Route: &other}); err != nil {
		t.Fatal(err)
	}

	rootPool := rootPool(t, config.StateDir)
	transport := runtimeTransport(runtime.HTTPSAddresses()[0], rootPool)
	httpClient := &http.Client{Transport: transport}
	response, err := httpClient.Get("https://fieldnotes.localhost/stream")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "streamed response" || response.ProtoMajor != 2 {
		t.Fatalf("HTTPS response = %d %q %s", response.StatusCode, body, response.Proto)
	}
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 || len(response.TLS.PeerCertificates[0].DNSNames) != 1 || response.TLS.PeerCertificates[0].DNSNames[0] != "fieldnotes.localhost" {
		t.Fatalf("unexpected exact-host certificate: %#v", response.TLS)
	}

	redirectTransport := &http.Transport{DialContext: dialAddress(runtime.HTTPAddresses()[0])}
	redirectClient := &http.Client{
		Transport:     redirectTransport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, _ := http.NewRequest(http.MethodPost, "http://fieldnotes.localhost/path?q=1", strings.NewReader("body"))
	response, err = redirectClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusPermanentRedirect || response.Header.Get("Location") != "https://fieldnotes.localhost/path?q=1" {
		t.Fatalf("redirect = %d %q", response.StatusCode, response.Header.Get("Location"))
	}
	unknownRequest, _ := http.NewRequest(http.MethodGet, "http://unknown.localhost/", nil)
	unknownResponse, err := redirectClient.Do(unknownRequest)
	if err != nil {
		t.Fatal(err)
	}
	unknownResponse.Body.Close()
	if unknownResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown redirect status = %d", unknownResponse.StatusCode)
	}

	mismatchRequest, _ := http.NewRequest(http.MethodGet, "https://fieldnotes.localhost/", nil)
	mismatchRequest.Host = "other.localhost"
	mismatchResponse, err := httpClient.Do(mismatchRequest)
	if err != nil {
		t.Fatal(err)
	}
	mismatchResponse.Body.Close()
	if mismatchResponse.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("SNI/Host mismatch status = %d", mismatchResponse.StatusCode)
	}
	if connection, err := tls.Dial("tcp", runtime.HTTPSAddresses()[0], &tls.Config{RootCAs: rootPool, ServerName: "unknown.localhost"}); err == nil {
		connection.Close()
		t.Fatal("unknown SNI completed a TLS handshake")
	}

	websocket, err := tls.Dial("tcp", runtime.HTTPSAddresses()[0], &tls.Config{
		RootCAs: rootPool, ServerName: "fieldnotes.localhost", NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(websocket, "GET /ws?hot=1 HTTP/1.1\r\nHost: fieldnotes.localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGVzdA==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	reader := bufio.NewReader(websocket)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("WebSocket status = %q, %v", status, err)
	}
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		if line == "\r\n" {
			break
		}
	}
	frame := []byte{0x81, 0x02, 'h', 'i'}
	if _, err := websocket.Write(frame); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(frame))
	if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != string(frame) {
		t.Fatalf("WebSocket echo = %x, %v", echo, err)
	}
	if err := runtime.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = websocket.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := websocket.Read(make([]byte, 1)); err == nil {
		t.Fatal("hijacked WebSocket remained open after shutdown")
	}
	_ = websocket.Close()
	stateInfo, err := os.Lstat(filepath.Join(config.StateDir, stateFileName))
	if err != nil || stateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("route state mode = %v, %v", stateInfo, err)
	}

	restarted, err := Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close(t.Context())
	listed, err := (client.Client{SocketPath: config.ManagementSocket}).Call(t.Context(), client.Request{Operation: client.OperationList})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Routes) != 2 || listed.Routes[0].Name != "fieldnotes.localhost" {
		t.Fatalf("persisted routes = %#v", listed.Routes)
	}
}

func TestManagementStrictFramingLifecycleBoundaryAndProcessIdentity(t *testing.T) {
	config := integrationConfig(t)
	config.ManagementTimeout = 100 * time.Millisecond
	runtime, err := Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(t.Context())

	for _, frame := range [][]byte{
		[]byte(`{"version":1,"id":"unknown-field","operation":"list","extra":true}` + "\n"),
		[]byte(`{"version":1,"id":"two","operation":"list"}` + "\n" + `{"version":1,"id":"two","operation":"list"}` + "\n"),
		append(make([]byte, maxRequestBytes+1), '\n'),
	} {
		response := rawManagementCall(t, config.ManagementSocket, frame)
		if response.OK || response.Error == nil || response.Error.Code != "invalid_request" {
			t.Fatalf("strict response = %#v", response)
		}
	}

	management := client.Client{SocketPath: config.ManagementSocket, Timeout: time.Second}
	if _, err := management.Call(t.Context(), client.Request{Operation: client.OperationInstall}); err == nil || !strings.Contains(err.Error(), "privilege_required") {
		t.Fatalf("lifecycle request error = %v", err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer backend.Close()
	host, portText, _ := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	port, _ := strconv.Atoi(portText)
	registration := client.Route{
		Name: "owned.localhost", Scheme: "http", Host: host, Port: uint16(port),
		Owner: client.Owner{Kind: client.OwnerProcess, PID: os.Getpid(), Refresh: client.RefreshNever},
	}
	if _, err := management.Call(t.Context(), client.Request{Operation: client.OperationAdd, Route: &registration}); err != nil {
		t.Fatal(err)
	}
	listed, err := management.Call(t.Context(), client.Request{Operation: client.OperationList})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Routes) != 1 || listed.Routes[0].Owner.ProcessStart <= 0 {
		t.Fatalf("process identity was not persisted: %#v", listed.Routes)
	}
	child := exec.Command("/bin/sleep", "10")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	childRoute := registration
	childRoute.Name = "child.localhost"
	childRoute.Owner.PID = child.Process.Pid
	if _, err := management.Call(t.Context(), client.Request{Operation: client.OperationAdd, Route: &childRoute}); err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		t.Fatal(err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	if _, err := management.Call(t.Context(), client.Request{Operation: client.OperationRefresh}); err != nil {
		t.Fatal(err)
	}
	listed, err = management.Call(t.Context(), client.Request{Operation: client.OperationList})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Routes) != 1 || listed.Routes[0].Name != "owned.localhost" {
		t.Fatalf("exited child route remained: %#v", listed.Routes)
	}
	blocked, err := net.Dial("unix", config.ManagementSocket)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(blocked, `{"version":1`)
	shutdownContext, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	started := time.Now()
	if err := runtime.Close(shutdownContext); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) >= time.Second {
		t.Fatal("shutdown waited for a blocked management frame")
	}
	_ = blocked.Close()
}

func TestContainerRefreshMovesTrafficUsingRealInspectorProcess(t *testing.T) {
	addresses := privateLocalAddresses(t)
	if len(addresses) < 2 {
		t.Skip("two private local addresses are required for address-change traffic")
	}
	first, err := net.Listen("tcp", net.JoinHostPort(addresses[0].String(), "0"))
	if err != nil {
		t.Skipf("bind first private address: %v", err)
	}
	port := first.Addr().(*net.TCPAddr).Port
	second, err := net.Listen("tcp", net.JoinHostPort(addresses[1].String(), strconv.Itoa(port)))
	if err != nil {
		first.Close()
		t.Skipf("bind second private address on same port: %v", err)
	}
	serveBackend(t, first, "first")
	serveBackend(t, second, "second")

	directory := shortTempDir(t)
	fixture := filepath.Join(directory, "inspect.json")
	executable := filepath.Join(directory, "container-inspect")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n[ \"$1\" = inspect ] || exit 64\nexec /bin/cat \""+fixture+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeContainerState(t, fixture, addresses[0], port)

	config := integrationConfig(t)
	config.ContainerCLI = executable
	runtime, err := Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(t.Context())
	management := client.Client{SocketPath: config.ManagementSocket, Timeout: 2 * time.Second}
	registration := client.Route{
		Name: "container.localhost", Scheme: "http", Host: addresses[0].String(), Port: uint16(port),
		Owner: client.Owner{Kind: client.OwnerContainer, Container: "app", Network: "default", Refresh: client.RefreshContainerAddress},
	}
	requestOwned := registration
	requestOwned.Owner.InspectorUID = uint32(os.Geteuid())
	if _, err := management.Call(t.Context(), client.Request{Operation: client.OperationAdd, Route: &requestOwned}); err == nil || !strings.Contains(err.Error(), "daemon-owned") {
		t.Fatalf("request-supplied inspector error = %v", err)
	}
	if _, err := runtime.executeRequest(t.Context(), service.PeerCredentials{UID: 0}, client.Request{
		Version: client.ProtocolVersion, ID: "root-container", Operation: client.OperationAdd, Route: &registration,
	}); err == nil || !strings.Contains(err.Error(), "unprivileged login user") {
		t.Fatalf("root container registration error = %v", err)
	}
	stale := registration
	stale.Host = addresses[1].String()
	if _, err := management.Call(t.Context(), client.Request{Operation: client.OperationAdd, Route: &stale}); err == nil || !strings.Contains(err.Error(), "stale_metadata") {
		t.Fatalf("stale container metadata error = %v", err)
	}
	if _, err := management.Call(t.Context(), client.Request{Operation: client.OperationAdd, Route: &registration}); err != nil {
		t.Fatal(err)
	}
	rootPool := rootPool(t, config.StateDir)
	if got := fetchBody(t, runtime.HTTPSAddresses()[0], rootPool, "container.localhost"); got != "first" {
		t.Fatalf("initial backend = %q", got)
	}
	writeContainerState(t, fixture, addresses[1], port)
	if _, err := management.Call(t.Context(), client.Request{Operation: client.OperationRefresh}); err != nil {
		t.Fatal(err)
	}
	if got := fetchBody(t, runtime.HTTPSAddresses()[0], rootPool, "container.localhost"); got != "second" {
		t.Fatalf("refreshed backend = %q", got)
	}
	listed, err := management.Call(t.Context(), client.Request{Operation: client.OperationList})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Routes) != 1 || listed.Routes[0].Host != addresses[1].String() || listed.Routes[0].Owner.Container != "app" || listed.Routes[0].Owner.InspectorUID != uint32(os.Geteuid()) {
		t.Fatalf("refreshed registration = %#v", listed.Routes)
	}
}

func TestRuntimeRejectsUnsafeStateAndNonLoopbackListeners(t *testing.T) {
	config := integrationConfig(t)
	target := filepath.Join(filepath.Dir(config.StateDir), "target")
	if err := os.WriteFile(target, []byte(`{"version":1,"routes":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(config.StateDir, stateFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(t.Context(), config); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("unsafe state error = %v", err)
	}
	config = integrationConfig(t)
	config.HTTPSListeners = []string{"0.0.0.0:0"}
	if _, err := Start(t.Context(), config); err == nil || !strings.Contains(err.Error(), "not a literal loopback") {
		t.Fatalf("public listener error = %v", err)
	}
}

func integrationConfig(t *testing.T) Config {
	t.Helper()
	directory := shortTempDir(t)
	stateDir := filepath.Join(directory, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return Config{
		StateDir:         stateDir,
		ManagementSocket: filepath.Join(directory, "run", "management.sock"),
		ManagementUID:    os.Geteuid(),
		ManagementGID:    os.Getegid(),
		HTTPListeners:    []string{"127.0.0.1:0"},
		HTTPSListeners:   []string{"127.0.0.1:0"},
		ContainerCLI:     "/usr/bin/false",
		RefreshInterval:  -1,
		ShutdownTimeout:  2 * time.Second,
		Version:          "test",
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "portless-daemon-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func rootPool(t *testing.T, stateDir string) *x509.CertPool {
	t.Helper()
	certificate, err := os.ReadFile(filepath.Join(stateDir, "pki", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certificate) {
		t.Fatal("append root certificate")
	}
	return pool
}

func runtimeTransport(address string, roots *x509.CertPool) *http.Transport {
	return &http.Transport{
		DialContext:       dialAddress(address),
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}
}

func dialAddress(address string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
}

func rawManagementCall(t *testing.T, socket string, frame []byte) client.Response {
	t.Helper()
	connection, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(frame); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	if unix, ok := connection.(*net.UnixConn); ok {
		_ = unix.CloseWrite()
	}
	var response client.Response
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	connection.Close()
	return response
}

func privateLocalAddresses(t *testing.T) []netip.Addr {
	t.Helper()
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var result []netip.Addr
	for _, item := range interfaces {
		prefix, err := netip.ParsePrefix(item.String())
		if err != nil {
			continue
		}
		address := prefix.Addr().Unmap()
		if address.IsPrivate() && !address.IsLoopback() && address.Is4() {
			result = append(result, address)
		}
	}
	return result
}

func serveBackend(t *testing.T, listener net.Listener, body string) {
	t.Helper()
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, body) })}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})
}

func writeContainerState(t *testing.T, path string, address netip.Addr, port int) {
	t.Helper()
	contents := fmt.Sprintf(`[{"id":"app","configuration":{"id":"app","publishedPorts":[{"containerPort":%d,"count":1,"proto":"tcp"}]},"status":{"state":"running","networks":[{"network":"default","ipv4Address":"%s/24"}]}}]`, port, address)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func fetchBody(t *testing.T, runtimeAddress string, roots *x509.CertPool, host string) string {
	t.Helper()
	client := &http.Client{Transport: runtimeTransport(runtimeAddress, roots)}
	response, err := client.Get("https://" + host + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
