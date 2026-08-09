package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/euforicio/portless/internal/proxy"
	"github.com/euforicio/portless/internal/routes"
)

func TestRoutesHTTP11RequestsAndControlsForwardingHeaders(t *testing.T) {
	t.Parallel()

	type received struct {
		host       string
		requestURI string
		forwarded  string
		xff        string
		xfh        string
		xfp        string
		xfPrefix   string
		xRealIP    string
	}
	requests := make(chan received, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests <- received{
			host:       request.Host,
			requestURI: request.RequestURI,
			forwarded:  request.Header.Get("Forwarded"),
			xff:        request.Header.Get("X-Forwarded-For"),
			xfh:        request.Header.Get("X-Forwarded-Host"),
			xfp:        request.Header.Get("X-Forwarded-Proto"),
			xfPrefix:   request.Header.Get("X-Forwarded-Prefix"),
			xRealIP:    request.Header.Get("X-Real-IP"),
		}
		writer.Header().Set("Alt-Svc", `h3=":443"`)
		_, _ = io.WriteString(writer, "backend-a")
	}))
	t.Cleanup(backend.Close)

	table := routes.NewTable()
	mustSetRoute(t, table, "app.localhost", backend.URL)
	handler := mustNewProxy(t, table, proxy.Options{})
	frontend := httptest.NewServer(handler)
	t.Cleanup(frontend.Close)

	request, err := http.NewRequest(http.MethodGet, frontend.URL+"/assets%2Fhmr.js?x=1&x=2", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "APP.LOCALHOST:443"
	request.Header.Set("Forwarded", "for=attacker;proto=https")
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	request.Header.Set("X-Forwarded-Host", "attacker.example")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Prefix", "/attacker")
	request.Header.Set("X-Real-IP", "203.0.113.9")

	response, err := frontend.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "backend-a" {
		t.Fatalf("response = %d %q", response.StatusCode, body)
	}
	if response.Header.Get("Alt-Svc") != "" {
		t.Fatalf("proxy exposed backend Alt-Svc: %q", response.Header.Get("Alt-Svc"))
	}

	got := <-requests
	backendURL, _ := url.Parse(backend.URL)
	if got.host != backendURL.Host {
		t.Errorf("upstream Host = %q, want %q", got.host, backendURL.Host)
	}
	if got.requestURI != "/assets%2Fhmr.js?x=1&x=2" {
		t.Errorf("upstream RequestURI = %q", got.requestURI)
	}
	if got.forwarded != "" {
		t.Errorf("spoofed Forwarded header survived: %q", got.forwarded)
	}
	if got.xff != "127.0.0.1" {
		t.Errorf("X-Forwarded-For = %q, want trusted client address", got.xff)
	}
	if got.xfh != "app.localhost" {
		t.Errorf("X-Forwarded-Host = %q, want canonical route host", got.xfh)
	}
	if got.xfp != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want http", got.xfp)
	}
	if got.xfPrefix != "" || got.xRealIP != "" {
		t.Errorf("untrusted forwarding headers survived: prefix=%q real-ip=%q", got.xfPrefix, got.xRealIP)
	}
}

func TestRoutesDistinctHostsAndRejectsUnknownAuthority(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	backend := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			_, _ = io.WriteString(writer, name)
		}))
	}
	first := backend("first")
	second := backend("second")
	t.Cleanup(first.Close)
	t.Cleanup(second.Close)

	table := routes.NewTable()
	mustSetRoute(t, table, "first.localhost", first.URL)
	mustSetRoute(t, table, "second.localhost", second.URL)
	frontend := httptest.NewServer(mustNewProxy(t, table, proxy.Options{}))
	t.Cleanup(frontend.Close)

	for host, want := range map[string]string{
		"first.localhost":  "first",
		"second.localhost": "second",
	} {
		if got := requestBody(t, frontend.Client(), frontend.URL, host); got != want {
			t.Errorf("host %q routed to %q, want %q", host, got, want)
		}
	}

	for host, wantStatus := range map[string]int{
		"missing.localhost":       http.StatusNotFound,
		"first.localhost.example": http.StatusBadRequest,
		"user@first.localhost":    http.StatusBadRequest,
	} {
		response := makeRequest(t, frontend.Client(), frontend.URL, host, http.MethodGet)
		response.Body.Close()
		if response.StatusCode != wantStatus {
			t.Errorf("host %q status = %d, want %d", host, response.StatusCode, wantStatus)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("backend calls = %d, unknown hosts reached a backend", got)
	}
}

func TestRejectsConnectAndTerminatesARealProxyLoop(t *testing.T) {
	t.Parallel()

	table := routes.NewTable()
	frontend := httptest.NewServer(mustNewProxy(t, table, proxy.Options{}))
	t.Cleanup(frontend.Close)
	mustSetRoute(t, table, "loop.localhost", frontend.URL)

	response := makeRequest(t, frontend.Client(), frontend.URL, "loop.localhost", http.MethodGet)
	response.Body.Close()
	if response.StatusCode != http.StatusLoopDetected {
		t.Fatalf("loop response = %d, want 508", response.StatusCode)
	}

	response = makeRequest(t, frontend.Client(), frontend.URL, "loop.localhost", http.MethodConnect)
	response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("CONNECT response = %d, want 405", response.StatusCode)
	}
}

func TestRejectsNonOriginRequestTargetsBeforeRouting(t *testing.T) {
	t.Parallel()

	var backendCalls atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		backendCalls.Add(1)
	}))
	t.Cleanup(backend.Close)
	table := routes.NewTable()
	mustSetRoute(t, table, "target.localhost", backend.URL)
	frontend := httptest.NewServer(mustNewProxy(t, table, proxy.Options{}))
	t.Cleanup(frontend.Close)
	frontendURL, _ := url.Parse(frontend.URL)

	requests := []string{
		"GET http://target.localhost/path HTTP/1.1\r\nHost: target.localhost\r\nConnection: close\r\n\r\n",
		"GET foo:opaque HTTP/1.1\r\nHost: target.localhost\r\nConnection: close\r\n\r\n",
	}
	for _, request := range requests {
		if status := rawHTTPStatus(t, frontendURL.Host, request); status != http.StatusBadRequest {
			t.Errorf("non-origin request status = %d, want 400", status)
		}
	}
	if got := backendCalls.Load(); got != 0 {
		t.Fatalf("backend calls = %d, non-origin request reached upstream", got)
	}
}

func TestRewritesOnlyRedirectsForTheSelectedUpstream(t *testing.T) {
	t.Parallel()

	var backendURL string
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/matching":
			writer.Header().Set("Location", backendURL+"/login?next=%2Fapp#form")
		case "/network-path":
			parsed, _ := url.Parse(backendURL)
			writer.Header().Set("Location", "//"+parsed.Host+"/assets/app.js")
		case "/relative":
			writer.Header().Set("Location", "/login")
		case "/external":
			writer.Header().Set("Location", "https://example.com/login")
		}
		writer.WriteHeader(http.StatusFound)
	}))
	backendURL = backend.URL
	t.Cleanup(backend.Close)

	table := routes.NewTable()
	mustSetRoute(t, table, "redirect.localhost", backend.URL)
	frontend := httptest.NewServer(mustNewProxy(t, table, proxy.Options{}))
	t.Cleanup(frontend.Close)
	client := frontend.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	tests := []struct {
		path string
		want string
	}{
		{path: "/matching", want: "http://redirect.localhost/login?next=%2Fapp#form"},
		{path: "/network-path", want: "http://redirect.localhost/assets/app.js"},
		{path: "/relative", want: "/login"},
		{path: "/external", want: "https://example.com/login"},
	}
	for _, test := range tests {
		response := makeRequest(t, client, frontend.URL+test.path, "redirect.localhost", http.MethodGet)
		response.Body.Close()
		if response.StatusCode != http.StatusFound {
			t.Fatalf("%s status = %d, want 302", test.path, response.StatusCode)
		}
		if got := response.Header.Get("Location"); got != test.want {
			t.Errorf("%s Location = %q, want %q", test.path, got, test.want)
		}
	}
}

func TestFlushesStreamingResponses(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(writer, "data: first\n\n")
		writer.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(writer, "data: second\n\n")
	}))
	t.Cleanup(backend.Close)

	table := routes.NewTable()
	mustSetRoute(t, table, "stream.localhost", backend.URL)
	frontend := httptest.NewServer(mustNewProxy(t, table, proxy.Options{}))
	t.Cleanup(frontend.Close)

	request, err := http.NewRequest(http.MethodGet, frontend.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "stream.localhost"
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	response, err := frontend.Client().Do(request.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	reader := bufio.NewReader(response.Body)
	first, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if first != "data: first\n" {
		t.Fatalf("first streamed line = %q", first)
	}
	releaseOnce.Do(func() { close(release) })
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "\ndata: second\n\n" {
		t.Fatalf("remaining stream = %q", rest)
	}
}

func TestStreamsRequestBodies(t *testing.T) {
	t.Parallel()

	firstChunk := make(chan string, 1)
	received := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		buffer := make([]byte, 5)
		if _, err := io.ReadFull(request.Body, buffer); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		firstChunk <- string(buffer)
		rest, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		received <- string(buffer) + string(rest)
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(backend.Close)

	table := routes.NewTable()
	mustSetRoute(t, table, "upload.localhost", backend.URL)
	frontend := httptest.NewServer(mustNewProxy(t, table, proxy.Options{}))
	t.Cleanup(frontend.Close)

	bodyReader, bodyWriter := io.Pipe()
	request, err := http.NewRequest(http.MethodPost, frontend.URL+"/upload", bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "upload.localhost"
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	responseResult := make(chan *http.Response, 1)
	errorResult := make(chan error, 1)
	go func() {
		response, err := frontend.Client().Do(request.WithContext(ctx))
		if err != nil {
			errorResult <- err
			return
		}
		responseResult <- response
	}()

	if _, err := io.WriteString(bodyWriter, "first"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-firstChunk:
		if got != "first" {
			t.Fatalf("first upstream chunk = %q", got)
		}
	case <-ctx.Done():
		t.Fatal("upstream did not receive the first request chunk before EOF")
	}
	if _, err := io.WriteString(bodyWriter, "-second"); err != nil {
		t.Fatal(err)
	}
	if err := bodyWriter.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errorResult:
		t.Fatal(err)
	case response := <-responseResult:
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("response status = %d", response.StatusCode)
		}
	case <-ctx.Done():
		t.Fatal("streaming request did not complete")
	}
	if got := <-received; got != "first-second" {
		t.Fatalf("upstream request = %q", got)
	}
}

func TestPropagatesCancellationToUpstream(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	canceled := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
		close(canceled)
	}))
	t.Cleanup(backend.Close)

	table := routes.NewTable()
	mustSetRoute(t, table, "cancel.localhost", backend.URL)
	frontend := httptest.NewServer(mustNewProxy(t, table, proxy.Options{}))
	t.Cleanup(frontend.Close)

	ctx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, frontend.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "cancel.localhost"
	result := make(chan error, 1)
	go func() {
		response, err := frontend.Client().Do(request)
		if response != nil {
			response.Body.Close()
		}
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request did not start")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not observe cancellation")
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("client request unexpectedly succeeded after cancellation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client request did not return after cancellation")
	}
}

func TestRoutesInboundAndOutboundHTTP2(t *testing.T) {
	t.Parallel()

	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "%d %s", request.ProtoMajor, request.Header.Get("X-Forwarded-Proto"))
	}))
	backend.EnableHTTP2 = true
	backend.StartTLS()
	t.Cleanup(backend.Close)

	table := routes.NewTable()
	mustSetRoute(t, table, "h2.localhost", backend.URL)
	backendTransport := backend.Client().Transport.(*http.Transport).Clone()
	backendTransport.ForceAttemptHTTP2 = true
	t.Cleanup(backendTransport.CloseIdleConnections)
	handler := mustNewProxy(t, table, proxy.Options{Transport: backendTransport})

	frontend := httptest.NewUnstartedServer(handler)
	frontend.EnableHTTP2 = true
	frontend.StartTLS()
	t.Cleanup(frontend.Close)

	request, err := http.NewRequest(http.MethodGet, frontend.URL+"/h2", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "h2.localhost"
	response, err := frontend.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 2 {
		t.Fatalf("frontend protocol = %q, want HTTP/2", response.Proto)
	}
	if string(body) != "2 https" {
		t.Fatalf("backend result = %q, want HTTP/2 with forwarded https", body)
	}
}

func TestProxiesHTTP11WebSocketHMRFrames(t *testing.T) {
	t.Parallel()

	disconnected := make(chan struct{}, 2)
	backend := httptest.NewServer(webSocketEchoHandler(disconnected))
	t.Cleanup(backend.Close)

	table := routes.NewTable()
	mustSetRoute(t, table, "hmr.localhost", backend.URL)
	frontend := httptest.NewServer(mustNewProxy(t, table, proxy.Options{}))
	t.Cleanup(frontend.Close)
	frontendURL, _ := url.Parse(frontend.URL)

	t.Run("fragmentation and close", func(t *testing.T) {
		connection, reader := openWebSocket(t, frontendURL.Host, "hmr.localhost")
		defer connection.Close()
		setDeadline(t, connection)

		writeFrame(t, connection, false, 0x1, []byte(`{"type":"`), true)
		writeFrame(t, connection, true, 0x0, []byte(`update","path":"/app.js"}`), true)

		first := readFrame(t, reader)
		second := readFrame(t, reader)
		if first.fin || first.opcode != 0x1 || string(first.payload) != `{"type":"` {
			t.Fatalf("first echoed fragment = %#v", first)
		}
		if !second.fin || second.opcode != 0x0 || string(second.payload) != `update","path":"/app.js"}` {
			t.Fatalf("second echoed fragment = %#v", second)
		}

		closePayload := []byte{0x03, 0xe8}
		writeFrame(t, connection, true, 0x8, closePayload, true)
		closed := readFrame(t, reader)
		if !closed.fin || closed.opcode != 0x8 || !bytes.Equal(closed.payload, closePayload) {
			t.Fatalf("close frame = %#v", closed)
		}
		waitForDisconnect(t, disconnected)
	})

	t.Run("abrupt disconnect", func(t *testing.T) {
		connection, _ := openWebSocket(t, frontendURL.Host, "hmr.localhost")
		setDeadline(t, connection)
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
		waitForDisconnect(t, disconnected)
	})
}

func mustSetRoute(t *testing.T, table *routes.Table, host, upstream string) {
	t.Helper()
	if _, err := table.Set(host, upstream); err != nil {
		t.Fatalf("Set(%q, %q): %v", host, upstream, err)
	}
}

func mustNewProxy(t *testing.T, table *routes.Table, options proxy.Options) *proxy.Handler {
	t.Helper()
	handler, err := proxy.New(table, options)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func makeRequest(t *testing.T, client *http.Client, target, host, method string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = host
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func requestBody(t *testing.T, client *http.Client, target, host string) string {
	t.Helper()
	response := makeRequest(t, client, target, host, http.MethodGet)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func webSocketEchoHandler(disconnected chan<- struct{}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || !headerHasToken(request.Header, "Connection", "upgrade") ||
			!strings.EqualFold(request.Header.Get("Upgrade"), "websocket") ||
			request.URL.Path != "/hmr" || request.URL.Query().Get("token") != "dev-token" {
			http.Error(writer, "upgrade required", http.StatusBadRequest)
			return
		}

		connection, buffered, err := writer.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() {
			connection.Close()
			disconnected <- struct{}{}
		}()

		accept := webSocketAccept(request.Header.Get("Sec-WebSocket-Key"))
		fmt.Fprintf(buffered, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
		if err := buffered.Flush(); err != nil {
			return
		}

		reader := buffered.Reader
		for {
			frame, err := readRawFrame(reader)
			if err != nil {
				return
			}
			opcode := frame.opcode
			if opcode == 0x9 {
				opcode = 0xa
			}
			if err := writeRawFrame(connection, frame.fin, opcode, frame.payload, false); err != nil {
				return
			}
			if frame.opcode == 0x8 {
				return
			}
		}
	})
}

func headerHasToken(header http.Header, name, want string) bool {
	for value := range strings.SplitSeq(header.Get(name), ",") {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}

func webSocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func openWebSocket(t *testing.T, address, host string) (net.Conn, *bufio.Reader) {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	setDeadline(t, connection)
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	request := fmt.Sprintf("GET /hmr?token=dev-token HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n", host, key)
	if _, err := io.WriteString(connection, request); err != nil {
		connection.Close()
		t.Fatal(err)
	}

	reader := bufio.NewReader(connection)
	status, err := reader.ReadString('\n')
	if err != nil {
		connection.Close()
		t.Fatal(err)
	}
	if !strings.Contains(status, " 101 ") {
		connection.Close()
		t.Fatalf("upgrade status = %q", strings.TrimSpace(status))
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			connection.Close()
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	return connection, reader
}

func rawHTTPStatus(t *testing.T, address, request string) int {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	setDeadline(t, connection)
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	statusLine, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var protocol string
	var status int
	if _, err := fmt.Sscanf(statusLine, "%s %d", &protocol, &status); err != nil {
		t.Fatalf("parse status line %q: %v", statusLine, err)
	}
	return status
}

type wsFrame struct {
	fin     bool
	opcode  byte
	payload []byte
}

func readFrame(t *testing.T, reader *bufio.Reader) wsFrame {
	t.Helper()
	frame, err := readRawFrame(reader)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func readRawFrame(reader io.Reader) (wsFrame, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return wsFrame{}, err
	}
	frame := wsFrame{fin: header[0]&0x80 != 0, opcode: header[0] & 0x0f}
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return wsFrame{}, err
		}
		length = uint64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return wsFrame{}, err
		}
		length = binary.BigEndian.Uint64(extended[:])
	}
	if length > 1<<20 {
		return wsFrame{}, fmt.Errorf("test frame too large: %d", length)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return wsFrame{}, err
		}
	}
	frame.payload = make([]byte, length)
	if _, err := io.ReadFull(reader, frame.payload); err != nil {
		return wsFrame{}, err
	}
	if masked {
		for i := range frame.payload {
			frame.payload[i] ^= mask[i%len(mask)]
		}
	}
	return frame, nil
}

func writeFrame(t *testing.T, writer io.Writer, fin bool, opcode byte, payload []byte, masked bool) {
	t.Helper()
	if err := writeRawFrame(writer, fin, opcode, payload, masked); err != nil {
		t.Fatal(err)
	}
}

func writeRawFrame(writer io.Writer, fin bool, opcode byte, payload []byte, masked bool) error {
	first := opcode
	if fin {
		first |= 0x80
	}
	header := []byte{first}
	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}
	switch {
	case len(payload) < 126:
		header = append(header, maskBit|byte(len(payload)))
	case len(payload) <= 0xffff:
		header = append(header, maskBit|126, byte(len(payload)>>8), byte(len(payload)))
	default:
		header = append(header, maskBit|127)
		var extended [8]byte
		binary.BigEndian.PutUint64(extended[:], uint64(len(payload)))
		header = append(header, extended[:]...)
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	data := bytes.Clone(payload)
	if masked {
		mask := [4]byte{0x12, 0x34, 0x56, 0x78}
		if _, err := writer.Write(mask[:]); err != nil {
			return err
		}
		for i := range data {
			data[i] ^= mask[i%len(mask)]
		}
	}
	_, err := writer.Write(data)
	return err
}

func setDeadline(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
}

func waitForDisconnect(t *testing.T, disconnected <-chan struct{}) {
	t.Helper()
	select {
	case <-disconnected:
	case <-time.After(5 * time.Second):
		t.Fatal("backend did not observe WebSocket disconnect")
	}
}

func TestNewRejectsNilRouteTable(t *testing.T) {
	t.Parallel()
	if _, err := proxy.New(nil, proxy.Options{}); err == nil {
		t.Fatal("New() accepted a nil route table")
	}
}

func TestHTTPSUpstreamUsesConfiguredTrust(t *testing.T) {
	t.Parallel()

	backend := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "secure")
	}))
	t.Cleanup(backend.Close)
	table := routes.NewTable()
	mustSetRoute(t, table, "secure.localhost", backend.URL)

	trustedTransport := backend.Client().Transport.(*http.Transport).Clone()
	t.Cleanup(trustedTransport.CloseIdleConnections)
	frontend := httptest.NewServer(mustNewProxy(t, table, proxy.Options{Transport: trustedTransport}))
	t.Cleanup(frontend.Close)
	if got := requestBody(t, frontend.Client(), frontend.URL, "secure.localhost"); got != "secure" {
		t.Fatalf("HTTPS upstream body = %q", got)
	}
}
