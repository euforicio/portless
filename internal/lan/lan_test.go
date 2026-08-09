package lan

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/euforicio/portless/internal/mdns"
)

func TestRealHTTPListenerMDNSStreamingAndHostBoundary(t *testing.T) {
	address := testAddress(t)
	var authorized atomic.Bool
	authorized.Store(true)
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("first\n"))
		writer.(http.Flusher).Flush()
		_, _ = writer.Write([]byte("second\n"))
	}))
	t.Cleanup(backend.Close)

	service := startTestService(t, Request{Name: uniqueName(t), Target: backend.URL, PinnedIP: address, StateDir: t.TempDir(), Authorize: func(context.Context) bool { return authorized.Load() }})
	registration := service.Registration()
	client := lanClient(registration, nil)
	response, err := client.Get(registration.URL())
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "first\nsecond\n" {
		t.Fatalf("LAN response = status %d body %q err %v", response.StatusCode, body, err)
	}

	request, _ := http.NewRequest(http.MethodGet, "http://"+net.JoinHostPort(registration.Address, strconv.Itoa(int(registration.Port))), nil)
	request.Host = "unregistered.local"
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unregistered Host status = %d, want 404", response.StatusCode)
	}
	authorized.Store(false)
	response, err = client.Get(registration.URL())
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("removed route status = %d, want 404", response.StatusCode)
	}
}

func TestRealHTTPSExactCertificateAndHTTP2(t *testing.T) {
	address := testAddress(t)
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprint(writer, request.Proto)
	}))
	t.Cleanup(backend.Close)
	service := startTestService(t, Request{Name: uniqueName(t), Target: backend.URL, HTTPS: true, PinnedIP: address, StateDir: t.TempDir()})
	registration := service.Registration()

	roots := x509.NewCertPool()
	certificate, err := os.ReadFile(registration.CACertPath)
	if err != nil || !roots.AppendCertsFromPEM(certificate) {
		t.Fatalf("load LAN CA: %v", err)
	}
	client := lanClient(registration, roots)
	response, err := client.Get(registration.URL())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.ProtoMajor != 2 || string(body) != "HTTP/1.1" {
		t.Fatalf("HTTPS LAN protocol = %s backend %q", response.Proto, body)
	}
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 || response.TLS.PeerCertificates[0].VerifyHostname(registration.Name) != nil {
		t.Fatal("LAN leaf does not verify for the exact registered .local host")
	}

	untrusted := lanClient(registration, nil)
	if _, err := untrusted.Get(registration.URL()); err == nil {
		t.Fatal("HTTPS LAN unexpectedly trusted without the explicit LAN CA")
	}
}

func TestRealHTTP11UpgradeTunnel(t *testing.T) {
	address := testAddress(t)
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		hijacker := writer.(http.Hijacker)
		connection, buffer, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = buffer.Flush()
		_, _ = io.Copy(connection, connection)
	}))
	t.Cleanup(backend.Close)
	service := startTestService(t, Request{Name: uniqueName(t), Target: backend.URL, PinnedIP: address, StateDir: t.TempDir()})
	registration := service.Registration()
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(registration.Address, strconv.Itoa(int(registration.Port))), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(connection, "GET /socket HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", registration.Name)
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d", response.StatusCode)
	}
	payload := []byte("real-upgrade-payload")
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("upgrade echo = %q", got)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("hijacked LAN connection remained open after cleanup")
	}
}

func TestRealAddressRebindWhenTwoEligibleAddressesExist(t *testing.T) {
	addresses, err := mdns.EligibleAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) < 2 {
		t.Skip("address rebind requires two eligible assigned LAN addresses")
	}
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(backend.Close)
	service := startTestService(t, Request{Name: uniqueName(t), Target: backend.URL, PinnedIP: addresses[0].Address, StateDir: t.TempDir()})
	before := service.Registration()
	service.mu.Lock()
	service.request.PinnedIP = addresses[1].Address
	service.mu.Unlock()
	if err := service.refresh(); err != nil {
		t.Fatal(err)
	}
	after := service.Registration()
	if before.Address == after.Address || after.Address != addresses[1].Address.String() || before.Port != after.Port {
		t.Fatalf("rebind = %#v -> %#v", before, after)
	}
	response, err := lanClient(after, nil).Get(after.URL())
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("rebound status = %d", response.StatusCode)
	}
}

func startTestService(t *testing.T, request Request) *Service {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("LAN mDNS integration requires macOS")
	}
	if _, err := os.Stat(mdns.Executable); err != nil {
		t.Skipf("dns-sd unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	service, err := Start(ctx, request)
	if err != nil {
		t.Fatalf("start LAN service: %v", err)
	}
	t.Cleanup(func() {
		identity := service.Registration().MDNS
		if err := service.Close(); err != nil {
			t.Errorf("close LAN service: %v", err)
		}
		if err := mdns.StopOwned(identity); err != nil {
			t.Errorf("reconcile closed advertisement: %v", err)
		}
	})
	return service
}

func testAddress(t *testing.T) netip.Addr {
	t.Helper()
	addresses, err := mdns.EligibleAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) == 0 {
		t.Skip("no eligible assigned LAN address")
	}
	return addresses[0].Address
}

func uniqueName(t *testing.T) string {
	t.Helper()
	return "portless-lan-" + strings.ToLower(strconv.FormatInt(time.Now().UnixNano(), 36))
}

func lanClient(registration Registration, roots *x509.CertPool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ForceAttemptHTTP2 = true
	address := net.JoinHostPort(registration.Address, strconv.Itoa(int(registration.Port)))
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	if registration.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: registration.Name}
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}
