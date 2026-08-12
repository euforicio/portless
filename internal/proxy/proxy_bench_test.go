package proxy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/euforicio/portless/internal/proxy"
	"github.com/euforicio/portless/internal/routes"
)

const benchmarkResponse = "portless benchmark response"

func BenchmarkProxyRequests(b *testing.B) {
	b.Run("HTTP1.1", benchmarkProxyHTTP11)
	b.Run("HTTP2", benchmarkProxyHTTP2)
}

func benchmarkProxyHTTP11(b *testing.B) {
	backend := httptest.NewServer(benchmarkBackend(1))
	b.Cleanup(backend.Close)

	table := routes.NewTable()
	benchmarkSetRoute(b, table, "bench.localhost", backend.URL)
	handler := benchmarkNewProxy(b, table, proxy.Options{})
	b.Cleanup(handler.CloseIdleConnections)

	frontend := httptest.NewServer(handler)
	b.Cleanup(frontend.Close)
	client := frontend.Client()

	benchmarkRequest(b, client, frontend.URL, 1)
	b.ReportAllocs()
	b.SetBytes(int64(len(benchmarkResponse)))
	b.ResetTimer()
	for b.Loop() {
		benchmarkRequest(b, client, frontend.URL, 1)
	}
}

func benchmarkProxyHTTP2(b *testing.B) {
	backend := httptest.NewUnstartedServer(benchmarkBackend(2))
	backend.EnableHTTP2 = true
	backend.StartTLS()
	b.Cleanup(backend.Close)

	table := routes.NewTable()
	benchmarkSetRoute(b, table, "bench.localhost", backend.URL)
	backendTransport := backend.Client().Transport.(*http.Transport).Clone()
	backendTransport.ForceAttemptHTTP2 = true
	b.Cleanup(backendTransport.CloseIdleConnections)
	handler := benchmarkNewProxy(b, table, proxy.Options{Transport: backendTransport})

	frontend := httptest.NewUnstartedServer(handler)
	frontend.EnableHTTP2 = true
	frontend.StartTLS()
	b.Cleanup(frontend.Close)
	client := frontend.Client()

	benchmarkRequest(b, client, frontend.URL, 2)
	b.ReportAllocs()
	b.SetBytes(int64(len(benchmarkResponse)))
	b.ResetTimer()
	for b.Loop() {
		benchmarkRequest(b, client, frontend.URL, 2)
	}
}

func benchmarkBackend(protocolMajor int) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.ProtoMajor != protocolMajor {
			http.Error(writer, "unexpected upstream protocol", http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Length", strconv.Itoa(len(benchmarkResponse)))
		_, _ = io.WriteString(writer, benchmarkResponse)
	})
}

func benchmarkSetRoute(b *testing.B, table *routes.Table, host, upstream string) {
	b.Helper()
	if _, err := table.Set(host, upstream); err != nil {
		b.Fatal(err)
	}
}

func benchmarkNewProxy(b *testing.B, table *routes.Table, options proxy.Options) *proxy.Handler {
	b.Helper()
	handler, err := proxy.New(table, options)
	if err != nil {
		b.Fatal(err)
	}
	return handler
}

func benchmarkRequest(b *testing.B, client *http.Client, target string, protocolMajor int) {
	b.Helper()
	request, err := http.NewRequest(http.MethodGet, target+"/assets/app.js?benchmark=1", nil)
	if err != nil {
		b.Fatal(err)
	}
	request.Host = "bench.localhost"
	response, err := client.Do(request)
	if err != nil {
		b.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil {
		b.Fatal(readErr)
	}
	if closeErr != nil {
		b.Fatal(closeErr)
	}
	if response.StatusCode != http.StatusOK || response.ProtoMajor != protocolMajor || string(body) != benchmarkResponse {
		b.Fatalf("response = status %d, protocol %q, body %q", response.StatusCode, response.Proto, body)
	}
}
