package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestAuthorityCreatesSecureExactHostCertificates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	authority, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertMode(t, dir, 0o700)
	assertMode(t, filepath.Join(dir, rootBundleName), 0o600)
	assertMode(t, authority.RootCertificatePath(), 0o644)

	root, err := authority.RootCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if !root.IsCA || !root.BasicConstraintsValid || root.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatalf("invalid root constraints: %+v", root)
	}
	if key, ok := root.PublicKey.(*ecdsa.PublicKey); !ok || key.Curve.Params().Name != "P-256" {
		t.Fatalf("root key is not P-256: %T", root.PublicKey)
	}

	first, err := authority.Certificate("Fieldnotes.Localhost")
	if err != nil {
		t.Fatal(err)
	}
	second, err := authority.Certificate("fieldnotes.localhost")
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) != 0 {
		t.Fatal("cached certificate serial changed")
	}
	if len(first.Leaf.DNSNames) != 1 || first.Leaf.DNSNames[0] != "fieldnotes.localhost" {
		t.Fatalf("leaf SAN is not exact: %v", first.Leaf.DNSNames)
	}
	if first.Leaf.IsCA || len(first.Leaf.ExtKeyUsage) != 1 || first.Leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("invalid leaf constraints: %+v", first.Leaf)
	}
	if err := first.Leaf.CheckSignatureFrom(root); err != nil {
		t.Fatal(err)
	}
	assertMode(t, filepath.Join(dir, leafDirName, "fieldnotes.localhost.pem"), 0o600)

	for _, host := range []string{"", "localhost", "fieldnotes.localhost.", "127.0.0.1", "fieldnotes.localhost:443", "fieldnotes.example", "-bad.localhost"} {
		if _, err := authority.Certificate(host); err == nil {
			t.Errorf("Certificate(%q) unexpectedly succeeded", host)
		}
	}
}

func TestAuthorityPersistsAndRenewsLeafCertificates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	authority, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := authority.Certificate("api.localhost")
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := reopened.Certificate("api.localhost")
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Cmp(persisted.Leaf.SerialNumber) != 0 {
		t.Fatal("reopened authority did not reuse the on-disk leaf")
	}

	renewing, err := Open(filepath.Join(t.TempDir(), "renew"), Options{
		LeafValidity: 2 * time.Hour,
		RenewBefore:  3 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	oldLeaf, err := renewing.Certificate("api.localhost")
	if err != nil {
		t.Fatal(err)
	}
	newLeaf, err := renewing.Certificate("api.localhost")
	if err != nil {
		t.Fatal(err)
	}
	if oldLeaf.Leaf.SerialNumber.Cmp(newLeaf.Leaf.SerialNumber) == 0 {
		t.Fatal("leaf inside renewal window was not replaced")
	}
}

func TestAuthorityConcurrentIssuanceUsesOneLeaf(t *testing.T) {
	authority, err := Open(filepath.Join(t.TempDir(), "pki"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	const clients = 64
	serials := make(chan string, clients)
	errors := make(chan error, clients)
	var group sync.WaitGroup
	for range clients {
		group.Add(1)
		go func() {
			defer group.Done()
			cert, err := authority.Certificate("concurrent.localhost")
			if err != nil {
				errors <- err
				return
			}
			serials <- cert.Leaf.SerialNumber.String()
		}()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	close(serials)
	var first string
	for serial := range serials {
		if first == "" {
			first = serial
		}
		if serial != first {
			t.Fatalf("concurrent issuance returned %s and %s", first, serial)
		}
	}
}

func TestAuthorityServesRealTLSAndRejectsUnknownSNI(t *testing.T) {
	authority, err := Open(filepath.Join(t.TempDir(), "pki"), Options{
		AllowHost: func(host string) bool { return host == "fieldnotes.localhost" },
	})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	rootPEM, err := os.ReadFile(authority.RootCertificatePath())
	if err != nil {
		t.Fatal(err)
	}
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("failed to load root")
	}

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(base, &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: authority.GetCertificate})
	server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		io.WriteString(response, "secure")
	})}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(tlsListener) }()
	t.Cleanup(func() {
		server.Close()
		err := <-serveDone
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("TLS server: %v", err)
		}
	})

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, base.Addr().String())
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("https://fieldnotes.localhost/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "secure" {
		t.Fatalf("unexpected response %q", body)
	}

	if _, err := client.Get("https://unknown.localhost/"); err == nil {
		t.Fatal("unknown SNI unexpectedly completed a TLS handshake")
	}
}

func TestRootRotationIsPreparedBeforeActivation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	authority, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	oldFingerprint := authority.RootFingerprint()
	oldLeaf, err := authority.Certificate("rotate.localhost")
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := authority.PrepareRootRotation()
	if err != nil {
		t.Fatal(err)
	}
	if rotation.Fingerprint == oldFingerprint || authority.RootFingerprint() != oldFingerprint {
		t.Fatal("preparing rotation changed or reused the active root")
	}
	assertMode(t, rotation.CertificatePath, 0o644)
	if _, err := authority.ActivateRoot(oldFingerprint); err == nil {
		t.Fatal("activation accepted the wrong fingerprint")
	}
	previousPath, err := authority.ActivateRoot(rotation.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if authority.RootFingerprint() != rotation.Fingerprint {
		t.Fatal("candidate root was not activated")
	}
	assertMode(t, previousPath, 0o644)
	newRoot, err := authority.RootCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if oldLeaf.Leaf.CheckSignatureFrom(newRoot) == nil {
		t.Fatal("old leaf unexpectedly chains to the new root")
	}
	newLeaf, err := authority.Certificate("rotate.localhost")
	if err != nil {
		t.Fatal(err)
	}
	if err := newLeaf.Leaf.CheckSignatureFrom(newRoot); err != nil {
		t.Fatal(err)
	}
	if err := authority.FinalizeRootRotation(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(previousPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("previous root remains after finalize: %v", err)
	}
}

func TestAuthorityFailsClosedOnUnsafeOrSymlinkedFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	authority, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, rootBundleName), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, Options{}); err == nil {
		t.Fatal("over-permissive private root was accepted")
	}
	if err := os.Chmod(filepath.Join(dir, rootBundleName), 0o600); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(t.TempDir(), "leaf.pem")
	if err := os.WriteFile(target, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	leafPath := filepath.Join(dir, leafDirName, "linked.localhost.pem")
	if err := os.Symlink(target, leafPath); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Certificate("linked.localhost"); err == nil {
		t.Fatal("symlinked leaf path was accepted")
	}
}

func TestTrustCommandsAreExplicitAndDeterministic(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	commands, err := TrustCommands(TrustInstall, caPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"add-trusted-cert", "-d", "-r", "trustRoot", "-p", "ssl", "-k", SystemKeychain, caPath}
	if len(commands) != 1 || !equalStrings(commands[0].Args, want) {
		t.Fatalf("trust argv = %q, want %q", commands[0].Args, want)
	}
	remove, err := TrustCommands(TrustRemove, caPath)
	if err != nil || len(remove) != 1 || remove[0].Args[2] != caPath {
		t.Fatalf("remove command: %+v, %v", remove, err)
	}
	if _, err := TrustCommands(TrustInstall, "relative.pem"); err == nil {
		t.Fatal("relative CA path accepted")
	}
}

func TestSystemTrustInspectionUsesExactCertificate(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("system keychain inspection requires macOS")
	}
	authority, err := Open(filepath.Join(t.TempDir(), "pki"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	present, err := SystemTrusted(ctx, authority.RootCertificatePath())
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("fresh temporary root unexpectedly exists in the system keychain")
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode = %04o, want %04o", path, info.Mode().Perm(), want)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func parsePEMCertificate(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
