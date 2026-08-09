// Package profile validates one proxy listener's network, host, and TLS policy.
package profile

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/euforicio/portless/internal/routes"
)

var (
	ErrInvalidScheme      = errors.New("invalid profile scheme")
	ErrInvalidListener    = errors.New("invalid profile listener")
	ErrInvalidCertificate = errors.New("invalid profile certificate")
	ErrHostNotAllowed     = errors.New("profile host is not registered")
)

// Scheme is the public protocol served by a profile.
type Scheme string

const (
	HTTP  Scheme = "http"
	HTTPS Scheme = "https"
)

// CertificateMode selects the TLS certificate source.
type CertificateMode string

const (
	GeneratedCertificates CertificateMode = "local-ca"
	CertificateFiles      CertificateMode = "files"
)

// CertificateConfig selects either a generated local-CA provider or one
// pre-existing certificate and key pair.
type CertificateConfig struct {
	Mode     CertificateMode
	CertFile string
	KeyFile  string
}

// Config contains serializable settings for one public proxy listener.
type Config struct {
	Scheme           Scheme
	ListenAddress    string
	TLD              string
	WildcardFallback bool
	Certificates     CertificateConfig
}

// Runtime supplies process-local state that cannot be serialized. HTTPS
// profiles require the matching route table. Local-CA profiles also require
// GetCertificate.
type Runtime struct {
	Routes         *routes.Table
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// Profile is a fully validated listener configuration, safe for concurrent
// inspection. Construct it with New before binding any listener.
type Profile struct {
	scheme        Scheme
	listenAddress string
	tld           string
	routeOptions  routes.Options
	tlsConfig     *tls.Config
}

// DefaultConfig returns the current production-facing profile defaults.
func DefaultConfig() Config {
	return Config{
		Scheme:        HTTPS,
		ListenAddress: "127.0.0.1:443",
		TLD:           ".localhost",
		Certificates:  CertificateConfig{Mode: GeneratedCertificates},
	}
}

// New validates a complete profile, including its certificate source, before
// a listener can be opened.
func New(config Config, runtime Runtime) (*Profile, error) {
	if config.Scheme != HTTP && config.Scheme != HTTPS {
		return nil, ErrInvalidScheme
	}
	address, err := normalizeListener(config.ListenAddress)
	if err != nil {
		return nil, err
	}
	tld, err := routes.NormalizeTLD(config.TLD)
	if err != nil {
		return nil, err
	}

	profile := &Profile{
		scheme:        config.Scheme,
		listenAddress: address,
		tld:           tld,
		routeOptions: routes.Options{
			TLD:              tld,
			WildcardFallback: config.WildcardFallback,
		},
	}
	if config.Scheme == HTTP {
		if config.Certificates != (CertificateConfig{}) || runtime.GetCertificate != nil {
			return nil, fmt.Errorf("%w: HTTP profile contains TLS settings", ErrInvalidCertificate)
		}
		if runtime.Routes != nil && runtime.Routes.Options() != profile.routeOptions {
			return nil, fmt.Errorf("%w: route table policy differs from profile", ErrInvalidCertificate)
		}
		return profile, nil
	}
	if runtime.Routes == nil {
		return nil, fmt.Errorf("%w: HTTPS profile requires a route table", ErrInvalidCertificate)
	}
	if runtime.Routes.Options() != profile.routeOptions {
		return nil, fmt.Errorf("%w: route table policy differs from profile", ErrInvalidCertificate)
	}

	var certificate *tls.Certificate
	switch config.Certificates.Mode {
	case GeneratedCertificates:
		if config.Certificates.CertFile != "" || config.Certificates.KeyFile != "" || runtime.GetCertificate == nil {
			return nil, fmt.Errorf("%w: local-CA mode requires only a certificate provider", ErrInvalidCertificate)
		}
		if config.WildcardFallback {
			return nil, fmt.Errorf("%w: local-CA mode requires exact routing", ErrInvalidCertificate)
		}
	case CertificateFiles:
		if runtime.GetCertificate != nil {
			return nil, fmt.Errorf("%w: file mode cannot use a certificate provider", ErrInvalidCertificate)
		}
		loaded, loadErr := loadCertificate(config.Certificates.CertFile, config.Certificates.KeyFile, time.Now())
		if loadErr != nil {
			return nil, loadErr
		}
		certificate = &loaded
	default:
		return nil, fmt.Errorf("%w: unsupported mode %q", ErrInvalidCertificate, config.Certificates.Mode)
	}

	profile.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host, normalizeErr := routes.NormalizeAuthorityForTLD(hello.ServerName, tld)
			if normalizeErr != nil {
				return nil, ErrHostNotAllowed
			}
			if _, found := runtime.Routes.Resolve(host); !found {
				return nil, ErrHostNotAllowed
			}
			if certificate != nil {
				if verifyErr := certificate.Leaf.VerifyHostname(host); verifyErr != nil {
					return nil, fmt.Errorf("%w: certificate does not cover %q", ErrInvalidCertificate, host)
				}
				return certificate, nil
			}
			return runtime.GetCertificate(hello)
		},
	}
	return profile, nil
}

func normalizeListener(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return "", ErrInvalidListener
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil || parsed.Zone() != "" {
		return "", ErrInvalidListener
	}
	parsed = parsed.Unmap()
	if !parsed.IsLoopback() {
		return "", ErrInvalidListener
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return "", ErrInvalidListener
	}
	return net.JoinHostPort(parsed.String(), strconv.FormatUint(number, 10)), nil
}

func loadCertificate(certPath, keyPath string, now time.Time) (tls.Certificate, error) {
	if certPath == keyPath || certPath == "" || keyPath == "" {
		return tls.Certificate{}, fmt.Errorf("%w: certificate and key paths must be distinct", ErrInvalidCertificate)
	}
	if err := validatePath(certPath, false); err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: certificate path: %v", ErrInvalidCertificate, err)
	}
	if err := validatePath(keyPath, true); err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: key path: %v", ErrInvalidCertificate, err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: read certificate: %v", ErrInvalidCertificate, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: read key: %v", ErrInvalidCertificate, err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: load key pair: %v", ErrInvalidCertificate, err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: parse leaf: %v", ErrInvalidCertificate, err)
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.IsCA {
		return tls.Certificate{}, fmt.Errorf("%w: leaf is not a currently valid server certificate", ErrInvalidCertificate)
	}
	if len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) &&
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return tls.Certificate{}, fmt.Errorf("%w: leaf does not permit server authentication", ErrInvalidCertificate)
	}
	certificate.Leaf = leaf
	return certificate, nil
}

func validatePath(path string, private bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
		return errors.New("path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("path is not a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("file is writable by group or others")
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return errors.New("private key is accessible by group or others")
	}
	return nil
}

// Scheme returns the public listener protocol.
func (p *Profile) Scheme() Scheme { return p.scheme }

// ListenAddress returns the canonical numeric loopback listener address.
func (p *Profile) ListenAddress() string { return p.listenAddress }

// TLD returns the lowercase dot-prefixed route suffix.
func (p *Profile) TLD() string { return p.tld }

// PublicAuthority returns the canonical authority for a valid profile host,
// including a non-default listener port.
func (p *Profile) PublicAuthority(host string) (string, error) {
	normalized, err := routes.NormalizeAuthorityForTLD(host, p.tld)
	if err != nil {
		return "", err
	}
	_, port, _ := net.SplitHostPort(p.listenAddress)
	if (p.scheme == HTTP && port == "80") || (p.scheme == HTTPS && port == "443") {
		return normalized, nil
	}
	return net.JoinHostPort(normalized, port), nil
}

// Port returns the validated public listener port.
func (p *Profile) Port() uint16 {
	_, port, _ := net.SplitHostPort(p.listenAddress)
	number, _ := strconv.ParseUint(port, 10, 16)
	return uint16(number)
}

// Handler enforces TLS SNI and HTTP authority agreement for HTTPS profiles.
// Plain HTTP profiles return next unchanged.
func (p *Profile) Handler(next http.Handler) http.Handler {
	if next == nil {
		next = http.DefaultServeMux
	}
	if p.scheme == HTTP {
		return next
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || request.TLS.ServerName == "" {
			http.Error(writer, "TLS server name is required", http.StatusMisdirectedRequest)
			return
		}
		host, hostErr := routes.NormalizeAuthorityForTLD(request.Host, p.tld)
		serverName, sniErr := routes.NormalizeAuthorityForTLD(request.TLS.ServerName, p.tld)
		if hostErr != nil || sniErr != nil || host != serverName {
			http.Error(writer, "TLS server name and host differ", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// RouteOptions returns the matching route-table policy.
func (p *Profile) RouteOptions() routes.Options { return p.routeOptions }

// TLSConfig returns an independent TLS configuration. It is nil for HTTP.
func (p *Profile) TLSConfig() *tls.Config {
	if p.tlsConfig == nil {
		return nil
	}
	return p.tlsConfig.Clone()
}

// Listen binds the already-validated loopback address.
func (p *Profile) Listen() (net.Listener, error) {
	return net.Listen("tcp", p.listenAddress)
}

// Serve serves HTTP or HTTPS on a listener returned by Listen. HTTPS uses
// ServeTLS so the standard library configures ordinary HTTP/2 support.
func (p *Profile) Serve(server *http.Server, listener net.Listener) error {
	if server == nil || listener == nil {
		return errors.New("profile requires a server and listener")
	}
	if err := p.validateListener(listener); err != nil {
		return err
	}
	if p.scheme == HTTP {
		return server.Serve(listener)
	}
	server.TLSConfig = p.TLSConfig()
	handler := server.Handler
	if handler == nil {
		handler = http.DefaultServeMux
	}
	server.Handler = p.Handler(handler)
	return server.ServeTLS(listener, "", "")
}

func (p *Profile) validateListener(listener net.Listener) error {
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.Port != int(p.Port()) {
		return ErrInvalidListener
	}
	ip, ok := netip.AddrFromSlice(address.IP)
	if !ok || !ip.Unmap().IsLoopback() {
		return ErrInvalidListener
	}
	configuredHost, _, _ := net.SplitHostPort(p.listenAddress)
	configuredIP, _ := netip.ParseAddr(configuredHost)
	if ip.Unmap() != configuredIP.Unmap() {
		return ErrInvalidListener
	}
	return nil
}
