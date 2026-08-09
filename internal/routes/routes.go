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
)

// Route is an immutable mapping from an exact .localhost host to an upstream.
// Routes must be created with NewRoute.
type Route struct {
	host     string
	upstream string
	target   url.URL
}

// NewRoute validates and normalizes a route. Upstreams are limited to HTTP(S)
// URLs with an explicit IP address and port on a local or private network.
func NewRoute(host, upstream string) (Route, error) {
	normalizedHost, err := NormalizeAuthority(host)
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
	if len(host) > 253 || !strings.HasSuffix(host, ".localhost") {
		return "", ErrInvalidHost
	}

	for label := range strings.SplitSeq(host, ".") {
		if !validDNSLabel(label) {
			return "", ErrInvalidHost
		}
	}

	return host, nil
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
	mu     sync.RWMutex
	routes map[string]Route
}

func NewTable() *Table {
	return &Table{routes: make(map[string]Route)}
}

// Set validates and atomically adds or replaces one route.
func (t *Table) Set(host, upstream string) (Route, error) {
	route, err := NewRoute(host, upstream)
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
	host, err := NormalizeAuthority(authority)
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
	host, err := NormalizeAuthority(authority)
	if err != nil {
		return Route{}, false
	}
	t.mu.RLock()
	route, ok := t.routes[host]
	t.mu.RUnlock()
	return route, ok
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
