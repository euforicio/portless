package profile_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/euforicio/portless/internal/pki"
	"github.com/euforicio/portless/internal/profile"
	"github.com/euforicio/portless/internal/routes"
)

func TestPlainHTTPProfileServesOnCustomLoopbackPort(t *testing.T) {
	t.Parallel()

	address := availableAddress(t)
	p, err := profile.New(profile.Config{Scheme: profile.HTTP, ListenAddress: address, TLD: "test"}, profile.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	if p.TLD() != ".test" || p.Scheme() != profile.HTTP || p.TLSConfig() != nil {
		t.Fatalf("unexpected profile: scheme=%q tld=%q tls=%v", p.Scheme(), p.TLD(), p.TLSConfig())
	}
	authority, err := p.PublicAuthority("APP.TEST")
	if err != nil {
		t.Fatal(err)
	}
	if authority != "app.test:"+portOf(t, address) {
		t.Fatalf("PublicAuthority() = %q", authority)
	}

	listener, err := p.Listen()
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "plain")
	})}
	serveResult := make(chan error, 1)
	go func() { serveResult <- p.Serve(server, listener) }()
	t.Cleanup(func() { closeServer(t, server, serveResult) })

	response, err := http.Get("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "plain" {
		t.Fatalf("response = %d %q", response.StatusCode, body)
	}
}

func TestCustomCertificateProfileServesRegisteredHTTP2Host(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath, keyPath, certificate := writeSelfSignedPair(t, dir, "custom", []string{"*.test", "*.app.test"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	table, err := routes.NewTableWithOptions(routes.Options{TLD: "test", WildcardFallback: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.Set("app.test", "http://127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	if _, err := table.Set("other.test", "http://127.0.0.1:8081"); err != nil {
		t.Fatal(err)
	}
	if _, err := table.Set("deep.test", "http://127.0.0.1:8082"); err != nil {
		t.Fatal(err)
	}
	address := availableAddress(t)
	p, err := profile.New(profile.Config{
		Scheme:           profile.HTTPS,
		ListenAddress:    address,
		TLD:              ".test",
		WildcardFallback: true,
		Certificates: profile.CertificateConfig{
			Mode: profile.CertificateFiles, CertFile: certPath, KeyFile: keyPath,
		},
	}, profile.Runtime{Routes: table})
	if err != nil {
		t.Fatal(err)
	}
	if !p.RouteOptions().WildcardFallback {
		t.Fatal("profile did not retain wildcard fallback policy")
	}
	listener, err := p.Listen()
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "%s %s", request.Proto, request.Host)
	})}
	serveResult := make(chan error, 1)
	go func() { serveResult <- p.Serve(server, listener) }()
	t.Cleanup(func() { closeServer(t, server, serveResult) })

	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	response, err := client.Get("https://child.app.test:" + portOf(t, listener.Addr().String()) + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.ProtoMajor != 2 || !strings.HasPrefix(string(body), "HTTP/2.0 child.app.test:") {
		t.Fatalf("response = %s %q", response.Proto, body)
	}
	mismatch, err := http.NewRequest(http.MethodGet, "https://app.test:"+portOf(t, listener.Addr().String())+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	mismatch.Host = "other.test"
	mismatchResponse, err := client.Do(mismatch)
	if err != nil {
		t.Fatal(err)
	}
	mismatchResponse.Body.Close()
	if mismatchResponse.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("SNI/Host mismatch status = %d, want 421", mismatchResponse.StatusCode)
	}

	if connection, dialErr := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		RootCAs: roots, ServerName: "missing.test", MinVersion: tls.VersionTLS12,
	}); dialErr == nil {
		connection.Close()
		t.Fatal("unregistered SNI completed a TLS handshake")
	}
	if connection, dialErr := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		RootCAs: roots, ServerName: "child.deep.test", MinVersion: tls.VersionTLS12,
	}); dialErr == nil {
		connection.Close()
		t.Fatal("registered fallback SNI outside certificate SANs completed a TLS handshake")
	}
}

func TestServeRejectsListenerOutsideProfile(t *testing.T) {
	t.Parallel()

	p, err := profile.New(profile.Config{Scheme: profile.HTTP, ListenAddress: availableAddress(t)}, profile.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := p.Serve(&http.Server{}, other); !errors.Is(err, profile.ErrInvalidListener) {
		t.Fatalf("Serve(other listener) error = %v, want ErrInvalidListener", err)
	}
}

func TestGeneratedLocalCAProfileServesRegisteredHost(t *testing.T) {
	t.Parallel()

	table, err := routes.NewTableWithOptions(routes.Options{TLD: "internal"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.Set("app.internal", "http://127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	authority, err := pki.Open(filepath.Join(t.TempDir(), "pki"), pki.Options{
		AllowedSuffix: ".internal",
		AllowHost: func(host string) bool {
			_, found := table.Lookup(host)
			return found
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := profile.New(profile.Config{
		Scheme: profile.HTTPS, ListenAddress: availableAddress(t), TLD: "internal",
		Certificates: profile.CertificateConfig{Mode: profile.GeneratedCertificates},
	}, profile.Runtime{
		Routes:         table,
		GetCertificate: authority.GetCertificate,
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := p.Listen()
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })}
	serveResult := make(chan error, 1)
	go func() { serveResult <- p.Serve(server, listener) }()
	t.Cleanup(func() { closeServer(t, server, serveResult) })

	root, err := authority.RootCertificate()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	connection, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		RootCAs: roots, ServerName: "app.internal", MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
}

func TestProfileRejectsUnsafeSettingsBeforeBinding(t *testing.T) {
	t.Parallel()

	validAddress := availableAddress(t)
	wildcardTable, err := routes.NewTableWithOptions(routes.Options{WildcardFallback: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		config  profile.Config
		runtime profile.Runtime
		want    error
	}{
		{name: "invalid scheme", config: profile.Config{Scheme: "tcp", ListenAddress: validAddress}, want: profile.ErrInvalidScheme},
		{name: "unspecified", config: profile.Config{Scheme: profile.HTTP, ListenAddress: "0.0.0.0:8080"}, want: profile.ErrInvalidListener},
		{name: "private address", config: profile.Config{Scheme: profile.HTTP, ListenAddress: "10.0.0.2:8080"}, want: profile.ErrInvalidListener},
		{name: "hostname", config: profile.Config{Scheme: profile.HTTP, ListenAddress: "localhost:8080"}, want: profile.ErrInvalidListener},
		{name: "zero port", config: profile.Config{Scheme: profile.HTTP, ListenAddress: "127.0.0.1:0"}, want: profile.ErrInvalidListener},
		{name: "invalid tld", config: profile.Config{Scheme: profile.HTTP, ListenAddress: validAddress, TLD: "dev.local"}, want: routes.ErrInvalidTLD},
		{name: "HTTP TLS settings", config: profile.Config{Scheme: profile.HTTP, ListenAddress: validAddress, Certificates: profile.CertificateConfig{Mode: profile.CertificateFiles}}, want: profile.ErrInvalidCertificate},
		{name: "HTTPS missing host policy", config: profile.Config{Scheme: profile.HTTPS, ListenAddress: validAddress, Certificates: profile.CertificateConfig{Mode: profile.GeneratedCertificates}}, want: profile.ErrInvalidCertificate},
		{name: "route policy mismatch", config: profile.Config{Scheme: profile.HTTPS, ListenAddress: validAddress, TLD: "test", Certificates: profile.CertificateConfig{Mode: profile.GeneratedCertificates}}, runtime: profile.Runtime{Routes: routes.NewTable(), GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }}, want: profile.ErrInvalidCertificate},
		{name: "generated wildcard", config: profile.Config{Scheme: profile.HTTPS, ListenAddress: validAddress, WildcardFallback: true, Certificates: profile.CertificateConfig{Mode: profile.GeneratedCertificates}}, runtime: profile.Runtime{Routes: wildcardTable, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }}, want: profile.ErrInvalidCertificate},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := profile.New(test.config, test.runtime); !errors.Is(err, test.want) {
				t.Fatalf("New() error = %v, want %v", err, test.want)
			}
		})
	}

	listener, err := net.Listen("tcp", validAddress)
	if err != nil {
		t.Fatalf("validation failure bound or consumed listener address: %v", err)
	}
	listener.Close()
}

func TestProfileRejectsInvalidCertificateFilesBeforeBinding(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath, keyPath, _ := writeSelfSignedPair(t, dir, "valid", []string{"*.test"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_, otherKey, _ := writeSelfSignedPair(t, dir, "other", []string{"*.test"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	expiredCert, expiredKey, _ := writeSelfSignedPair(t, dir, "expired", []string{"*.test"}, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	symlink := filepath.Join(dir, "certificate-link.pem")
	if err := os.Symlink(certPath, symlink); err != nil {
		t.Fatal(err)
	}

	table, err := routes.NewTableWithOptions(routes.Options{TLD: "test"})
	if err != nil {
		t.Fatal(err)
	}
	runtime := profile.Runtime{Routes: table}
	config := func(cert, key string) profile.Config {
		return profile.Config{Scheme: profile.HTTPS, ListenAddress: availableAddress(t), TLD: "test", Certificates: profile.CertificateConfig{Mode: profile.CertificateFiles, CertFile: cert, KeyFile: key}}
	}
	for _, test := range []struct{ name, cert, key string }{
		{name: "mismatched", cert: certPath, key: otherKey},
		{name: "expired", cert: expiredCert, key: expiredKey},
		{name: "symlink", cert: symlink, key: keyPath},
		{name: "relative", cert: filepath.Base(certPath), key: keyPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := profile.New(config(test.cert, test.key), runtime); !errors.Is(err, profile.ErrInvalidCertificate) {
				t.Fatalf("New() error = %v, want ErrInvalidCertificate", err)
			}
		})
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.New(config(certPath, keyPath), runtime); !errors.Is(err, profile.ErrInvalidCertificate) {
		t.Fatalf("unsafe key mode error = %v, want ErrInvalidCertificate", err)
	}
}

func writeSelfSignedPair(t *testing.T, dir, name string, dnsNames []string, notBefore, notAfter time.Time) (string, string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		DNSNames: dnsNames, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, name+"-cert.pem")
	keyPath := filepath.Join(dir, name+"-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, parsed
}

func availableAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func portOf(t *testing.T, address string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func closeServer(t *testing.T, server *http.Server, result <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Error(err)
	}
	select {
	case err := <-result:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve() error = %v", err)
		}
	case <-ctx.Done():
		t.Error("server did not stop")
	}
}
