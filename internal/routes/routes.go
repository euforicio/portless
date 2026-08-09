// Package routes provides a concurrency-safe registry of validated proxy routes.
package routes

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
)

var (
	ErrInvalidHost     = errors.New("invalid route host")
	ErrInvalidUpstream = errors.New("invalid route upstream")
	ErrInvalidTLD      = errors.New("invalid route TLD")
)

const defaultTLD = ".localhost"

// Options defines the host namespace and lookup policy for a route table.
// The zero value selects exact-only .localhost routing.
type Options struct {
	TLD              string
	WildcardFallback bool
}

// Route is an immutable mapping from an exact validated host to an upstream.
// Routes must be created with NewRoute or NewRouteForTLD.
type Route struct {
	host     string
	upstream string
	target   url.URL
}

// NewRoute validates and normalizes a route. Upstreams are limited to HTTP(S)
// URLs with an explicit IP address and port on a local or private network.
func NewRoute(host, upstream string) (Route, error) {
	return NewRouteForTLD(host, upstream, defaultTLD)
}

// NewRouteForTLD validates and normalizes a route in the selected DNS suffix.
func NewRouteForTLD(host, upstream, tld string) (Route, error) {
	normalizedHost, err := NormalizeAuthorityForTLD(host, tld)
	if err != nil {
		return Route{}, err
	}

	target, canonical, err := parseUpstream(upstream)
	if err != nil {
		return Route{}, err
	}

	return Route{
		host:     normalizedHost,
		upstream: canonical,
		target:   target,
	}, nil
}

// Host returns the normalized route host.
func (r Route) Host() string { return r.host }

// Upstream returns the canonical upstream URL.
func (r Route) Upstream() string { return r.upstream }

// Target returns a copy of the parsed upstream URL.
func (r Route) Target() url.URL { return r.target }

func (r Route) valid() bool {
	return r.host != "" && r.upstream != "" && r.target.Scheme != "" && r.target.Host != ""
}

// NormalizeAuthority normalizes an HTTP Host or HTTP/2 :authority value to an
// exact .localhost route name. An optional numeric port is ignored for lookup.
func NormalizeAuthority(authority string) (string, error) {
	return NormalizeAuthorityForTLD(authority, defaultTLD)
}

// NormalizeAuthorityForTLD normalizes an HTTP Host or HTTP/2 :authority value
// within tld. An optional numeric port is ignored for lookup.
func NormalizeAuthorityForTLD(authority, tld string) (string, error) {
	suffix, err := NormalizeTLD(tld)
	if err != nil {
		return "", err
	}
	if authority == "" || strings.ContainsAny(authority, " \t\r\n/?#@\\") {
		return "", ErrInvalidHost
	}

	host := authority
	switch strings.Count(authority, ":") {
	case 0:
	case 1:
		var port string
		var err error
		host, port, err = net.SplitHostPort(authority)
		if err != nil || !validPort(port) {
			return "", ErrInvalidHost
		}
	default:
		return "", ErrInvalidHost
	}

	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if len(host) > 253 || !strings.HasSuffix(host, suffix) || host == strings.TrimPrefix(suffix, ".") {
		return "", ErrInvalidHost
	}

	for label := range strings.SplitSeq(host, ".") {
		if !validDNSLabel(label) {
			return "", ErrInvalidHost
		}
	}

	return host, nil
}

// NormalizeTLD validates and returns a lowercase, dot-prefixed DNS suffix.
// A profile TLD is one ASCII DNS label; route names must include at least one
// label before it.
func NormalizeTLD(tld string) (string, error) {
	if tld == "" {
		tld = defaultTLD
	}
	if strings.ContainsAny(tld, " \t\r\n/?#@\\:") {
		return "", ErrInvalidTLD
	}
	label := strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(tld, "."), "."))
	if !validDNSLabel(label) || strings.Contains(label, ".") {
		return "", ErrInvalidTLD
	}
	hasLetter := false
	for _, character := range label {
		if character >= 'a' && character <= 'z' {
			hasLetter = true
			break
		}
	}
	if !hasLetter {
		return "", ErrInvalidTLD
	}
	return "." + label, nil
}

func validDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func validPort(port string) bool {
	if port == "" {
		return false
	}
	for _, character := range port {
		if character < '0' || character > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n != 0
}

func parseUpstream(raw string) (url.URL, string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return url.URL{}, "", ErrInvalidUpstream
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return url.URL{}, "", ErrInvalidUpstream
	}

	host := u.Hostname()
	port := u.Port()
	if host == "" || !validPort(port) {
		return url.URL{}, "", ErrInvalidUpstream
	}
	portNumber, _ := strconv.ParseUint(port, 10, 16)
	port = strconv.FormatUint(portNumber, 10)

	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return url.URL{}, "", ErrInvalidUpstream
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsMulticast() || (!addr.IsLoopback() && !addr.IsPrivate()) {
		return url.URL{}, "", ErrInvalidUpstream
	}

	canonical := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(addr.String(), port))
	target := url.URL{Scheme: scheme, Host: net.JoinHostPort(addr.String(), port)}
	return target, canonical, nil
}

// Table stores routes. Every mutation becomes visible atomically to readers.
type Table struct {
	mu               sync.RWMutex
	routes           map[string]Route
	tld              string
	wildcardFallback bool
}

func NewTable() *Table {
	return &Table{routes: make(map[string]Route), tld: defaultTLD}
}

// NewTableWithOptions constructs a table with an explicit host namespace and
// fallback policy.
func NewTableWithOptions(options Options) (*Table, error) {
	tld, err := NormalizeTLD(options.TLD)
	if err != nil {
		return nil, err
	}
	return &Table{
		routes:           make(map[string]Route),
		tld:              tld,
		wildcardFallback: options.WildcardFallback,
	}, nil
}

// Set validates and atomically adds or replaces one route.
func (t *Table) Set(host, upstream string) (Route, error) {
	route, err := NewRouteForTLD(host, upstream, t.options().TLD)
	if err != nil {
		return Route{}, err
	}
	t.mu.Lock()
	if t.routes == nil {
		t.routes = make(map[string]Route)
	}
	t.routes[route.host] = route
	t.mu.Unlock()
	return route, nil
}

// Replace validates the complete snapshot and atomically replaces all routes.
func (t *Table) Replace(replacement []Route) error {
	next := make(map[string]Route, len(replacement))
	for _, route := range replacement {
		if !route.valid() {
			return ErrInvalidUpstream
		}
		if _, err := NormalizeAuthorityForTLD(route.host, t.options().TLD); err != nil {
			return err
		}
		if _, exists := next[route.host]; exists {
			return fmt.Errorf("%w: duplicate %q", ErrInvalidHost, route.host)
		}
		next[route.host] = route
	}

	t.mu.Lock()
	t.routes = next
	t.mu.Unlock()
	return nil
}

// Delete removes a route by normalized host or authority.
func (t *Table) Delete(authority string) bool {
	host, err := t.NormalizeAuthority(authority)
	if err != nil {
		return false
	}
	t.mu.Lock()
	_, existed := t.routes[host]
	delete(t.routes, host)
	t.mu.Unlock()
	return existed
}

// Lookup performs an exact normalized host lookup.
func (t *Table) Lookup(authority string) (Route, bool) {
	host, err := t.NormalizeAuthority(authority)
	if err != nil {
		return Route{}, false
	}
	t.mu.RLock()
	route, ok := t.routes[host]
	t.mu.RUnlock()
	return route, ok
}

// Resolve performs exact lookup first. When wildcard fallback is enabled it
// then checks each registered parent, from longest to shortest, without ever
// crossing the table's TLD boundary.
func (t *Table) Resolve(authority string) (Route, bool) {
	host, err := t.NormalizeAuthority(authority)
	if err != nil {
		return Route{}, false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()
	if route, ok := t.routes[host]; ok {
		return route, true
	}
	if !t.wildcardFallback {
		return Route{}, false
	}

	minimum := strings.TrimPrefix(t.tldValue(), ".")
	for candidate := host; ; {
		separator := strings.IndexByte(candidate, '.')
		if separator < 0 {
			return Route{}, false
		}
		candidate = candidate[separator+1:]
		if candidate == minimum {
			return Route{}, false
		}
		if route, ok := t.routes[candidate]; ok {
			return route, true
		}
	}
}

// NormalizeAuthority applies this table's configured TLD policy.
func (t *Table) NormalizeAuthority(authority string) (string, error) {
	return NormalizeAuthorityForTLD(authority, t.options().TLD)
}

// Options returns the immutable table policy.
func (t *Table) Options() Options { return t.options() }

func (t *Table) options() Options {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return Options{TLD: t.tldValue(), WildcardFallback: t.wildcardFallback}
}

func (t *Table) tldValue() string {
	if t.tld == "" {
		return defaultTLD
	}
	return t.tld
}

// List returns an immutable host-sorted route snapshot.
func (t *Table) List() []Route {
	t.mu.RLock()
	routes := make([]Route, 0, len(t.routes))
	for _, route := range t.routes {
		routes = append(routes, route)
	}
	t.mu.RUnlock()
	slices.SortFunc(routes, func(a, b Route) int { return strings.Compare(a.host, b.host) })
	return routes
}
