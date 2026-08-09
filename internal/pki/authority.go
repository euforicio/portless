package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	rootBundleName    = "root.pem"
	rootCertName      = "ca.pem"
	pendingBundleName = "pending-root.pem"
	pendingCertName   = "pending-ca.pem"
	previousCertName  = "previous-ca.pem"
	leafDirName       = "leaf"
)

// Options controls certificate lifetimes and the names accepted for issuance.
// Zero values select conservative local-development defaults.
type Options struct {
	AllowedSuffix  string
	RootCommonName string
	RootValidity   time.Duration
	LeafValidity   time.Duration
	RenewBefore    time.Duration
	// MaxLeafCertificates bounds the exact-host leaf cache in memory and on
	// disk. Zero preserves the existing unbounded behavior. A positive limit
	// is appropriate for authorities whose accepted host set can change, such
	// as an explicitly enabled LAN authority.
	MaxLeafCertificates int
	// AllowHost is called with the normalized exact hostname before issuance.
	// It should read a concurrency-safe route snapshot. Nil permits any valid
	// hostname under AllowedSuffix.
	AllowHost func(string) bool
}

// Authority owns a local root CA and exact-host leaf certificate cache.
type Authority struct {
	dir      string
	options  Options
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	rootPEM  []byte
	rootID   string
	leafBySN map[string]*tls.Certificate
	mu       sync.Mutex
}

// Rotation describes a prepared root that is not active yet. Callers can add
// CertificatePath to the trust store before activating the exact fingerprint.
type Rotation struct {
	Fingerprint     string
	CertificatePath string
	NotAfter        time.Time
}

// Open loads an existing authority or creates one when no CA files exist.
func Open(dir string, options Options) (*Authority, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("PKI directory must be absolute")
	}
	options, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	if err := ensurePrivateDir(filepath.Join(dir, leafDirName)); err != nil {
		return nil, err
	}

	a := &Authority{dir: dir, options: options, leafBySN: make(map[string]*tls.Certificate)}
	bundlePath := filepath.Join(dir, rootBundleName)
	bundle, err := os.ReadFile(bundlePath)
	switch {
	case err == nil:
		if err := checkRegularFile(bundlePath, 0o600); err != nil {
			return nil, err
		}
		if err := a.loadRoot(bundle); err != nil {
			return nil, fmt.Errorf("load root CA: %w", err)
		}
	case errors.Is(err, os.ErrNotExist):
		if _, statErr := os.Lstat(filepath.Join(dir, rootCertName)); statErr == nil {
			return nil, errors.New("public CA certificate exists without the private root bundle")
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		}
		if err := a.generateAndStoreRoot(time.Now()); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	if err := a.writePublicRoot(); err != nil {
		return nil, err
	}
	if err := a.enforceLeafBound(""); err != nil {
		return nil, err
	}
	return a, nil
}

// RootCertificate returns an independent parsed copy of the current root.
func (a *Authority) RootCertificate() (*x509.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return x509.ParseCertificate(bytes.Clone(a.root.Raw))
}

// RootCertificatePath is the public PEM file used for explicit trust changes.
func (a *Authority) RootCertificatePath() string {
	return filepath.Join(a.dir, rootCertName)
}

// RootFingerprint returns the root's SHA-256 fingerprint as lowercase hex.
func (a *Authority) RootFingerprint() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rootID
}

// RootNeedsRotation reports whether the root expires within renewBefore.
func (a *Authority) RootNeedsRotation(renewBefore time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return renewBefore >= 0 && !time.Now().Add(renewBefore).Before(a.root.NotAfter)
}

// PrepareRootRotation creates a candidate without changing the active issuer.
func (a *Authority) PrepareRootRotation() (Rotation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cert, _, certPEM, bundle, err := newRoot(a.options, time.Now())
	if err != nil {
		return Rotation{}, err
	}
	if err := atomicWrite(filepath.Join(a.dir, pendingBundleName), bundle, 0o600); err != nil {
		return Rotation{}, err
	}
	if err := atomicWrite(filepath.Join(a.dir, pendingCertName), certPEM, 0o644); err != nil {
		return Rotation{}, err
	}
	digest := sha256.Sum256(cert.Raw)
	return Rotation{
		Fingerprint:     hex.EncodeToString(digest[:]),
		CertificatePath: filepath.Join(a.dir, pendingCertName),
		NotAfter:        cert.NotAfter,
	}, nil
}

// ActivateRoot promotes only the prepared fingerprint. The old public root is
// retained so its exact trust entry can be removed after activation.
func (a *Authority) ActivateRoot(fingerprint string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	bundle, err := os.ReadFile(filepath.Join(a.dir, pendingBundleName))
	if err != nil {
		return "", fmt.Errorf("read pending root: %w", err)
	}
	cert, key, certPEM, err := parseRoot(bundle)
	if err != nil {
		return "", fmt.Errorf("parse pending root: %w", err)
	}
	if time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return "", errors.New("pending root certificate is not currently valid")
	}
	digest := sha256.Sum256(cert.Raw)
	if hex.EncodeToString(digest[:]) != strings.ToLower(fingerprint) {
		return "", errors.New("pending root fingerprint does not match")
	}
	previousPath := filepath.Join(a.dir, previousCertName)
	if err := atomicWrite(previousPath, a.rootPEM, 0o644); err != nil {
		return "", err
	}
	if err := atomicWrite(filepath.Join(a.dir, rootBundleName), bundle, 0o600); err != nil {
		return "", err
	}
	a.setRoot(cert, key, certPEM)
	if err := a.writePublicRoot(); err != nil {
		return "", err
	}
	if err := os.RemoveAll(filepath.Join(a.dir, leafDirName)); err != nil {
		return "", fmt.Errorf("remove old leaf certificates: %w", err)
	}
	if err := ensurePrivateDir(filepath.Join(a.dir, leafDirName)); err != nil {
		return "", err
	}
	a.leafBySN = make(map[string]*tls.Certificate)
	if err := os.Remove(filepath.Join(a.dir, pendingBundleName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Remove(filepath.Join(a.dir, pendingCertName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return previousPath, nil
}

// FinalizeRootRotation removes the retained old public root after its exact
// trust entry has been removed.
func (a *Authority) FinalizeRootRotation() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	err := os.Remove(filepath.Join(a.dir, previousCertName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// GetCertificate selects or creates only the exact normalized SNI hostname.
// There is deliberately no default certificate for empty or invalid SNI.
func (a *Authority) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil {
		return nil, errors.New("missing TLS client hello")
	}
	return a.Certificate(hello.ServerName)
}

// Certificate returns a cached exact-host leaf, renewing it before expiry.
func (a *Authority) Certificate(host string) (*tls.Certificate, error) {
	host, err := normalizeHost(host, a.options.AllowedSuffix)
	if err != nil {
		return nil, err
	}
	if a.options.AllowHost != nil && !a.options.AllowHost(host) {
		return nil, fmt.Errorf("hostname %q is not registered", host)
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	if now.Before(a.root.NotBefore) || !now.Before(a.root.NotAfter) {
		return nil, errors.New("root certificate is not currently valid")
	}
	if cert := a.leafBySN[host]; usableLeaf(cert, host, a.root, a.rootID, now, a.options.RenewBefore) {
		return cert, nil
	}
	path := filepath.Join(a.dir, leafDirName, host+".pem")
	if bundle, readErr := os.ReadFile(path); readErr == nil {
		if fileErr := checkRegularFile(path, 0o600); fileErr != nil {
			return nil, fileErr
		}
		if cert, parseErr := parseLeaf(bundle, host, a.root); parseErr == nil && usableLeaf(cert, host, a.root, a.rootID, now, a.options.RenewBefore) {
			a.leafBySN[host] = cert
			if err := a.enforceLeafBound(host); err != nil {
				delete(a.leafBySN, host)
				return nil, err
			}
			return cert, nil
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return nil, readErr
	}

	cert, bundle, err := a.generateLeaf(host, now)
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(path, bundle, 0o600); err != nil {
		return nil, fmt.Errorf("write leaf certificate: %w", err)
	}
	a.leafBySN[host] = cert
	if err := a.enforceLeafBound(host); err != nil {
		delete(a.leafBySN, host)
		removeErr := os.Remove(path)
		if removeErr == nil {
			removeErr = syncDirectory(filepath.Dir(path))
		}
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return nil, errors.Join(err, fmt.Errorf("remove unbounded leaf certificate: %w", removeErr))
		}
		return nil, err
	}
	return cert, nil
}

type leafCacheEntry struct {
	host    string
	path    string
	modTime time.Time
}

// enforceLeafBound reconciles the owned leaf directory with the configured
// limit. keepHost is evicted last so successful issuance never returns a
// certificate that the bounded cache immediately discarded.
func (a *Authority) enforceLeafBound(keepHost string) error {
	limit := a.options.MaxLeafCertificates
	if limit == 0 {
		return nil
	}
	dir := filepath.Join(a.dir, leafDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read leaf certificate cache: %w", err)
	}
	leaves := make([]leafCacheEntry, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(dir, name)
		if entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(name, ".pem") {
			return fmt.Errorf("unsafe entry in leaf certificate cache: %s", path)
		}
		host := strings.TrimSuffix(name, ".pem")
		normalized, normalizeErr := normalizeHost(host, a.options.AllowedSuffix)
		if normalizeErr != nil || normalized != host {
			return fmt.Errorf("unsafe entry in leaf certificate cache: %s", path)
		}
		if err := checkRegularFile(path, 0o600); err != nil {
			return fmt.Errorf("unsafe leaf certificate cache entry: %w", err)
		}
		bundle, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read leaf certificate cache entry %s: %w", path, err)
		}
		if _, err := parseLeaf(bundle, host, a.root); err != nil {
			return fmt.Errorf("invalid leaf certificate cache entry %s: %w", path, err)
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect leaf certificate cache entry %s: %w", path, err)
		}
		leaves = append(leaves, leafCacheEntry{host: host, path: path, modTime: info.ModTime()})
	}
	if len(leaves) <= limit {
		return nil
	}
	sort.Slice(leaves, func(i, j int) bool {
		if leaves[i].host == keepHost {
			return false
		}
		if leaves[j].host == keepHost {
			return true
		}
		if !leaves[i].modTime.Equal(leaves[j].modTime) {
			return leaves[i].modTime.Before(leaves[j].modTime)
		}
		return leaves[i].host < leaves[j].host
	})
	removeCount := len(leaves) - limit
	for _, leaf := range leaves[:removeCount] {
		if err := os.Remove(leaf.path); err != nil {
			return fmt.Errorf("evict leaf certificate %q: %w", leaf.host, err)
		}
		delete(a.leafBySN, leaf.host)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("persist leaf certificate eviction: %w", err)
	}
	return nil
}

func normalizeOptions(options Options) (Options, error) {
	if options.AllowedSuffix == "" {
		options.AllowedSuffix = ".localhost"
	}
	options.AllowedSuffix = strings.ToLower(options.AllowedSuffix)
	if !strings.HasPrefix(options.AllowedSuffix, ".") || len(options.AllowedSuffix) < 2 {
		return Options{}, errors.New("allowed suffix must begin with a dot")
	}
	if _, err := normalizeHost("portless"+options.AllowedSuffix, options.AllowedSuffix); err != nil {
		return Options{}, fmt.Errorf("invalid allowed suffix: %w", err)
	}
	if options.RootCommonName == "" {
		options.RootCommonName = "Portless Local Root CA"
	}
	if options.RootValidity == 0 {
		options.RootValidity = 10 * 365 * 24 * time.Hour
	}
	if options.LeafValidity == 0 {
		options.LeafValidity = 30 * 24 * time.Hour
	}
	if options.RenewBefore == 0 {
		options.RenewBefore = 7 * 24 * time.Hour
	}
	if options.RootValidity <= 0 || options.LeafValidity <= 0 || options.RenewBefore < 0 {
		return Options{}, errors.New("certificate lifetimes must be positive and renew-before non-negative")
	}
	if options.MaxLeafCertificates < 0 {
		return Options{}, errors.New("maximum leaf certificates must be non-negative")
	}
	if options.LeafValidity > options.RootValidity {
		return Options{}, errors.New("leaf validity cannot exceed root validity")
	}
	return options, nil
}

func normalizeHost(host, suffix string) (string, error) {
	if host == "" {
		return "", errors.New("SNI hostname is required")
	}
	if strings.TrimSpace(host) != host || strings.ContainsAny(host, ":/\\\x00") {
		return "", errors.New("invalid SNI hostname")
	}
	if strings.HasSuffix(host, ".") {
		return "", errors.New("SNI hostname must not have a trailing dot")
	}
	host = strings.ToLower(host)
	if len(host) > 253 || !strings.HasSuffix(host, suffix) || host == strings.TrimPrefix(suffix, ".") {
		return "", fmt.Errorf("hostname %q is outside %q", host, suffix)
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS label in %q", host)
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return "", fmt.Errorf("invalid DNS label in %q", host)
			}
		}
	}
	return host, nil
}

func (a *Authority) generateAndStoreRoot(now time.Time) error {
	cert, key, certPEM, bundle, err := newRoot(a.options, now)
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(a.dir, rootBundleName), bundle, 0o600); err != nil {
		return fmt.Errorf("write root bundle: %w", err)
	}
	a.setRoot(cert, key, certPEM)
	return nil
}

func newRoot(options Options, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate root key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: options.RootCommonName, Organization: []string{"Portless Local Development"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(options.RootValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create root certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	bundle := append(bytes.Clone(certPEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	return cert, key, certPEM, bundle, nil
}

func (a *Authority) loadRoot(bundle []byte) error {
	cert, key, certPEM, err := parseRoot(bundle)
	if err != nil {
		return err
	}
	if time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return errors.New("root certificate is not currently valid; rotate it explicitly")
	}
	a.setRoot(cert, key, certPEM)
	return nil
}

func parseRoot(bundle []byte) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	certBlock, rest := pem.Decode(bundle)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, nil, errors.New("root bundle has no certificate")
	}
	keyBlock, trailing := pem.Decode(rest)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(trailing)) != 0 {
		return nil, nil, nil, errors.New("root bundle has no valid private key")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, nil, nil, errors.New("root key is not ECDSA P-256")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, nil, errors.New("root certificate is not a valid CA")
	}
	public, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !public.Equal(&key.PublicKey) {
		return nil, nil, nil, errors.New("root certificate and private key do not match")
	}
	return cert, key, pem.EncodeToMemory(certBlock), nil
}

func (a *Authority) setRoot(cert *x509.Certificate, key *ecdsa.PrivateKey, certPEM []byte) {
	digest := sha256.Sum256(cert.Raw)
	a.root = cert
	a.rootKey = key
	a.rootPEM = bytes.Clone(certPEM)
	a.rootID = hex.EncodeToString(digest[:])
}

func (a *Authority) writePublicRoot() error {
	path := filepath.Join(a.dir, rootCertName)
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, a.rootPEM) {
		return checkRegularFile(path, 0o644)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicWrite(path, a.rootPEM, 0o644)
}

func (a *Authority) generateLeaf(host string, now time.Time) (*tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	notAfter := now.Add(a.options.LeafValidity)
	if notAfter.After(a.root.NotAfter) {
		notAfter = a.root.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-1 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.root, &key.PublicKey, a.rootKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	bundle := append(bytes.Clone(certPEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	cert, err := parseLeaf(bundle, host, a.root)
	return cert, bundle, err
}

func parseLeaf(bundle []byte, host string, root *x509.Certificate) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(bundle, bundle)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != host || leaf.VerifyHostname(host) != nil {
		return nil, errors.New("leaf certificate is not exact-host")
	}
	if err := leaf.CheckSignatureFrom(root); err != nil {
		return nil, err
	}
	cert.Leaf = leaf
	return &cert, nil
}

func usableLeaf(cert *tls.Certificate, host string, root *x509.Certificate, rootID string, now time.Time, renewBefore time.Duration) bool {
	if cert == nil || cert.Leaf == nil || cert.Leaf.VerifyHostname(host) != nil {
		return false
	}
	if now.Before(cert.Leaf.NotBefore) || !now.Add(renewBefore).Before(cert.Leaf.NotAfter) {
		return false
	}
	if cert.Leaf.CheckSignatureFrom(root) != nil {
		return false
	}
	digest := sha256.Sum256(root.Raw)
	return hex.EncodeToString(digest[:]) == rootID
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func ensurePrivateDir(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is not a real directory", path)
		}
		if info.Mode().Perm() != 0o700 {
			return fmt.Errorf("%s has unsafe mode %04o; want 0700", path, info.Mode().Perm())
		}
		if err := checkCurrentOwner(path, info); err != nil {
			return err
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Mkdir(path, 0o700)
}

func checkRegularFile(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if info.Mode().Perm() != mode {
		return fmt.Errorf("%s has unsafe mode %04o; want %04o", path, info.Mode().Perm(), mode)
	}
	if err := checkCurrentOwner(path, info); err != nil {
		return err
	}
	return nil
}

func checkCurrentOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect ownership of %s", path)
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is owned by UID %d; want %d", path, stat.Uid, os.Geteuid())
	}
	return nil
}

func atomicWrite(path string, contents []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".portless-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(contents); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("refusing to replace non-regular file %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func syncDirectory(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
