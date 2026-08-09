// Package daemon composes Portless's route, proxy, PKI, service, and container
// components into the production runtime.
package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/euforicio/portless/internal/applecontainer"
	"github.com/euforicio/portless/internal/client"
	"github.com/euforicio/portless/internal/pki"
	"github.com/euforicio/portless/internal/profile"
	"github.com/euforicio/portless/internal/proxy"
	"github.com/euforicio/portless/internal/routes"
	"github.com/euforicio/portless/internal/service"
)

const (
	defaultRefreshInterval = 5 * time.Second
	defaultShutdownTimeout = 10 * time.Second
)

// Config is the explicit daemon boundary. Production launchd configuration
// uses ports 80 and 443; integration tests use literal loopback port zero.
type Config struct {
	StateDir          string
	ManagementSocket  string
	ManagementUID     int
	ManagementGID     int
	HTTPListeners     []string
	HTTPSListeners    []string
	ContainerCLI      string
	RefreshInterval   time.Duration
	ShutdownTimeout   time.Duration
	ManagementTimeout time.Duration
	Version           string
	Logger            *log.Logger
	// Profile selects one custom public loopback listener. Nil preserves the
	// production-compatible dual-stack HTTP redirect and HTTPS listener set.
	Profile *profile.Config
	// ReconcileProfile permits an explicit service lifecycle operation to
	// replace persisted profile settings only when no routes are registered.
	ReconcileProfile bool
}

// Runtime owns every listener and background task for one daemon process.
type Runtime struct {
	config                Config
	ctx                   context.Context
	cancel                context.CancelFunc
	table                 *routes.Table
	registry              *registry
	authority             *pki.Authority
	proxy                 *proxy.Handler
	publicProfile         *profile.Profile
	management            *net.UnixListener
	servers               []*http.Server
	listeners             []net.Listener
	httpAddrs             []string
	httpsAddrs            []string
	listenerHandlers      []http.Handler
	listenerTLS           []*tls.Config
	profileListener       []bool
	serveErr              chan error
	connections           connectionTracker
	managementConnections connectionTracker
	managementSlots       chan struct{}
	wg                    sync.WaitGroup
	handlerWG             sync.WaitGroup
	closeOnce             sync.Once
	closeErr              error
}

type connectionTracker struct {
	mu    sync.Mutex
	items map[net.Conn]struct{}
}

func (t *connectionTracker) add(connection net.Conn) {
	t.mu.Lock()
	if t.items == nil {
		t.items = make(map[net.Conn]struct{})
	}
	t.items[connection] = struct{}{}
	t.mu.Unlock()
}

func (t *connectionTracker) remove(connection net.Conn) {
	t.mu.Lock()
	delete(t.items, connection)
	t.mu.Unlock()
}

func (t *connectionTracker) closeAll() {
	t.mu.Lock()
	connections := make([]net.Conn, 0, len(t.items))
	for connection := range t.items {
		connections = append(connections, connection)
	}
	t.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

// Start validates and binds the complete runtime before any serving goroutine
// is launched. A partial bind is always rolled back.
func Start(parent context.Context, config Config) (*Runtime, error) {
	if config.Profile == nil && filepath.IsAbs(config.StateDir) {
		persisted, found, loadErr := loadPersistedProfile(config.StateDir)
		if loadErr != nil {
			return nil, loadErr
		}
		if found && !persisted.Legacy {
			value := persisted.Config
			config.Profile = &value
			config.HTTPSListeners = nil
			if value.Scheme == profile.HTTP {
				config.HTTPListeners = nil
			}
		}
	}
	config, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	table := routes.NewTable()
	if config.Profile != nil {
		table, err = routes.NewTableWithOptions(routes.Options{TLD: config.Profile.TLD, WildcardFallback: config.Profile.WildcardFallback})
		if err != nil {
			cancel()
			return nil, err
		}
	}
	runtime := &Runtime{
		config:          config,
		ctx:             ctx,
		cancel:          cancel,
		table:           table,
		serveErr:        make(chan error, 1),
		managementSlots: make(chan struct{}, 64),
	}
	fail := func(cause error) (*Runtime, error) {
		cancel()
		for _, listener := range runtime.listeners {
			_ = listener.Close()
		}
		if runtime.management != nil {
			_ = runtime.management.Close()
		}
		return nil, cause
	}

	persistedProfileConfig := profile.DefaultConfig()
	if config.Profile != nil {
		persistedProfileConfig = *config.Profile
	}
	if err := reconcileProfile(config.StateDir, persistedProfileConfig, config.Profile == nil, config.ReconcileProfile); err != nil {
		return fail(err)
	}
	runtime.registry, err = openRegistry(config.StateDir, runtime.table)
	if err != nil {
		return fail(err)
	}
	needsAuthority := config.Profile == nil || (config.Profile.Scheme == profile.HTTPS && config.Profile.Certificates.Mode == profile.GeneratedCertificates)
	if needsAuthority {
		allowedSuffix := ""
		if config.Profile != nil {
			allowedSuffix = config.Profile.TLD
		}
		runtime.authority, err = pki.Open(filepath.Join(config.StateDir, "pki"), pki.Options{
			AllowedSuffix: allowedSuffix,
			AllowHost: func(host string) bool {
				_, found := runtime.table.Resolve(host)
				return found
			},
		})
		if err != nil {
			return fail(err)
		}
	}
	proxyOptions := proxy.Options{ErrorLog: config.Logger}
	if config.Profile != nil {
		_, port, _ := net.SplitHostPort(config.Profile.ListenAddress)
		parsedPort, _ := strconv.ParseUint(port, 10, 16)
		proxyOptions.PublicPort = uint16(parsedPort)
	}
	runtime.proxy, err = proxy.New(runtime.table, proxyOptions)
	if err != nil {
		return fail(err)
	}
	if config.Profile != nil {
		profileRuntime := profile.Runtime{Routes: runtime.table}
		if runtime.authority != nil {
			profileRuntime.GetCertificate = runtime.authority.GetCertificate
		}
		runtime.publicProfile, err = profile.New(*config.Profile, profileRuntime)
		if err != nil {
			return fail(err)
		}
	}
	if _, err := runtime.Refresh(ctx); err != nil {
		return fail(fmt.Errorf("initial route refresh: %w", err))
	}

	runtime.management, err = service.ListenManagement(service.SocketConfig{
		Path: config.ManagementSocket,
		UID:  config.ManagementUID,
		GID:  config.ManagementGID,
	})
	if err != nil {
		return fail(err)
	}
	for _, address := range config.HTTPListeners {
		listener, listenErr := net.Listen("tcp", address)
		if listenErr != nil {
			return fail(fmt.Errorf("listen HTTP on %s: %w", address, listenErr))
		}
		runtime.listeners = append(runtime.listeners, listener)
		runtime.httpAddrs = append(runtime.httpAddrs, listener.Addr().String())
		runtime.listenerHandlers = append(runtime.listenerHandlers, http.HandlerFunc(runtime.redirectHTTP))
		runtime.listenerTLS = append(runtime.listenerTLS, nil)
		runtime.profileListener = append(runtime.profileListener, false)
	}
	for _, address := range config.HTTPSListeners {
		listener, listenErr := net.Listen("tcp", address)
		if listenErr != nil {
			return fail(fmt.Errorf("listen HTTPS on %s: %w", address, listenErr))
		}
		runtime.listeners = append(runtime.listeners, listener)
		runtime.httpsAddrs = append(runtime.httpsAddrs, listener.Addr().String())
		runtime.listenerHandlers = append(runtime.listenerHandlers, http.HandlerFunc(runtime.serveHTTPS))
		runtime.listenerTLS = append(runtime.listenerTLS, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: runtime.authority.GetCertificate, NextProtos: []string{"h2", "http/1.1"}})
		runtime.profileListener = append(runtime.profileListener, false)
	}
	if runtime.publicProfile != nil {
		listener, listenErr := runtime.publicProfile.Listen()
		if listenErr != nil {
			return fail(fmt.Errorf("listen on profile %s: %w", runtime.publicProfile.ListenAddress(), listenErr))
		}
		runtime.listeners = append(runtime.listeners, listener)
		handler := runtime.publicProfile.Handler(runtime.proxy)
		runtime.listenerHandlers = append(runtime.listenerHandlers, handler)
		runtime.listenerTLS = append(runtime.listenerTLS, runtime.publicProfile.TLSConfig())
		runtime.profileListener = append(runtime.profileListener, true)
		if runtime.publicProfile.Scheme() == profile.HTTPS {
			runtime.httpsAddrs = append(runtime.httpsAddrs, listener.Addr().String())
		} else {
			runtime.httpAddrs = append(runtime.httpAddrs, listener.Addr().String())
		}
	}

	runtime.startServing()
	return runtime, nil
}

func (r *Runtime) startServing() {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.serveManagement()
	}()

	for index, listener := range r.listeners {
		tlsConfig := r.listenerTLS[index]
		isHTTPS := tlsConfig != nil
		handler := r.trackHandler(r.listenerHandlers[index])
		server := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    64 << 10,
			ConnState: func(connection net.Conn, state http.ConnState) {
				switch state {
				case http.StateNew, http.StateActive, http.StateIdle, http.StateHijacked:
					r.connections.add(connection)
				case http.StateClosed:
					r.connections.remove(connection)
				}
			},
		}
		if isHTTPS {
			server.TLSConfig = tlsConfig
		}
		r.servers = append(r.servers, server)
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			var err error
			if r.profileListener[index] {
				err = r.publicProfile.Serve(server, listener)
			} else if isHTTPS {
				err = server.ServeTLS(listener, "", "")
			} else {
				err = server.Serve(listener)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) && r.ctx.Err() == nil {
				select {
				case r.serveErr <- err:
				default:
				}
				r.cancel()
			}
		}()
	}

	if r.config.RefreshInterval > 0 {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			ticker := time.NewTicker(r.config.RefreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-r.ctx.Done():
					return
				case <-ticker.C:
					if _, err := r.Refresh(r.ctx); err != nil && r.config.Logger != nil {
						r.config.Logger.Printf("route refresh failed: %v", err)
					}
				}
			}
		}()
	}
}

// Wait runs coordinated shutdown after cancellation or the first unexpected
// serving error.
func (r *Runtime) Wait() error {
	var serveErr error
	select {
	case <-r.ctx.Done():
		select {
		case serveErr = <-r.serveErr:
		default:
		}
	case serveErr = <-r.serveErr:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), r.config.ShutdownTimeout)
	defer cancel()
	if err := r.Close(shutdownCtx); err != nil && serveErr == nil {
		serveErr = err
	}
	return serveErr
}

// Close stops management first, drains HTTP, then force-closes hijacked or
// blocked connections and waits for all runtime goroutines.
func (r *Runtime) Close(ctx context.Context) error {
	r.closeOnce.Do(func() {
		r.cancel()
		if r.management != nil {
			if err := r.management.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				r.closeErr = err
			}
		}
		r.managementConnections.closeAll()
		for _, server := range r.servers {
			if err := server.Shutdown(ctx); err != nil && r.closeErr == nil {
				r.closeErr = err
			}
		}
		if r.proxy != nil {
			r.proxy.CloseIdleConnections()
		}
		r.connections.closeAll()
		for _, listener := range r.listeners {
			_ = listener.Close()
		}
		done := make(chan struct{})
		go func() {
			r.handlerWG.Wait()
			r.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			if r.closeErr == nil {
				r.closeErr = ctx.Err()
			}
		}
	})
	return r.closeErr
}

// HTTPAddresses and HTTPSAddresses return bound listener snapshots.
func (r *Runtime) HTTPAddresses() []string  { return slices.Clone(r.httpAddrs) }
func (r *Runtime) HTTPSAddresses() []string { return slices.Clone(r.httpsAddrs) }

func (r *Runtime) trackHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		r.handlerWG.Add(1)
		defer r.handlerWG.Done()
		next.ServeHTTP(writer, request)
	})
}

func (r *Runtime) redirectHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodConnect {
		http.Error(writer, "CONNECT is not supported", http.StatusMethodNotAllowed)
		return
	}
	if request.URL == nil || request.URL.IsAbs() || request.URL.Opaque != "" || request.URL.User != nil {
		http.Error(writer, "invalid request target", http.StatusBadRequest)
		return
	}
	tld := ".localhost"
	scheme := "https"
	port := uint16(443)
	if r.publicProfile != nil {
		tld = r.publicProfile.TLD()
		scheme = string(r.publicProfile.Scheme())
		port = r.publicProfile.Port()
	}
	host, err := routes.NormalizeAuthorityForTLD(request.Host, tld)
	if err != nil {
		http.Error(writer, "invalid host", http.StatusBadRequest)
		return
	}
	if _, found := r.table.Resolve(host); !found {
		http.Error(writer, "unknown host", http.StatusNotFound)
		return
	}
	authority := host
	if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
		authority = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	target := scheme + "://" + authority + request.URL.RequestURI()
	http.Redirect(writer, request, target, http.StatusPermanentRedirect)
}

func (r *Runtime) serveHTTPS(writer http.ResponseWriter, request *http.Request) {
	if request.TLS == nil || request.TLS.ServerName == "" {
		http.Error(writer, "TLS server name is required", http.StatusMisdirectedRequest)
		return
	}
	tld := ".localhost"
	if r.publicProfile != nil {
		tld = r.publicProfile.TLD()
	}
	authority, err := routes.NormalizeAuthorityForTLD(request.Host, tld)
	serverName, sniErr := routes.NormalizeAuthorityForTLD(request.TLS.ServerName, tld)
	if err != nil || sniErr != nil || authority != serverName {
		http.Error(writer, "TLS server name and host differ", http.StatusMisdirectedRequest)
		return
	}
	r.proxy.ServeHTTP(writer, request)
}

// Refresh revalidates all dynamic owners and publishes one atomic active-table
// snapshot. Unverifiable containers are disabled but retained for recovery.
func (r *Runtime) Refresh(ctx context.Context) ([]client.Diagnostic, error) {
	registrations := r.registry.snapshot()
	results := make([]refreshResult, 0, len(registrations))
	diagnostics := make([]client.Diagnostic, 0)
	for _, registration := range registrations {
		switch registration.Owner.Kind {
		case client.OwnerStatic:
			results = append(results, refreshResult{before: registration, after: registration, active: true})
		case client.OwnerProcess:
			if !processIdentityMatches(registration.Owner) {
				results = append(results, refreshResult{before: registration, remove: true})
				diagnostics = append(diagnostics, client.Diagnostic{Name: registration.Name, Level: "warning", Message: "owning process exited or changed identity; route removed"})
			} else {
				results = append(results, refreshResult{before: registration, after: registration, active: true})
			}
		case client.OwnerContainer:
			resolver, err := r.containerResolver(registration.Owner.InspectorUID)
			if err != nil {
				results = append(results, refreshResult{before: registration, err: err})
				diagnostics = append(diagnostics, client.Diagnostic{Name: registration.Name, Level: "error", Message: "container route disabled: " + err.Error()})
				continue
			}
			endpoint, err := resolver.Resolve(ctx, registration.Owner.Container, registration.Port, registration.Scheme)
			if err != nil {
				results = append(results, refreshResult{before: registration, err: err})
				diagnostics = append(diagnostics, client.Diagnostic{Name: registration.Name, Level: "error", Message: "container route disabled: " + err.Error()})
				continue
			}
			updated := registration
			updated.Host = endpoint.Address.String()
			updated.Port = endpoint.Port
			updated.Owner.Container = endpoint.Container
			updated.Owner.Network = endpoint.Network
			if err := updated.Validate(); err != nil {
				results = append(results, refreshResult{before: registration, err: err})
				diagnostics = append(diagnostics, client.Diagnostic{Name: registration.Name, Level: "error", Message: "container route disabled: " + err.Error()})
				continue
			}
			results = append(results, refreshResult{before: registration, after: updated, active: true})
		}
	}
	if err := r.registry.applyRefresh(results); err != nil {
		return diagnostics, err
	}
	return diagnostics, nil
}

func (r *Runtime) containerResolver(uid uint32) (applecontainer.Resolver, error) {
	if r.config.ContainerCLI == "" {
		return applecontainer.Resolver{}, errors.New("Apple container adapter is not configured")
	}
	if uid == 0 {
		return applecontainer.Resolver{}, errors.New("container registration has no unprivileged inspector")
	}
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return applecontainer.Resolver{}, fmt.Errorf("look up container inspector UID %d: %w", uid, err)
	}
	accountUID, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uint32(accountUID) != uid {
		return applecontainer.Resolver{}, errors.New("container inspector identity changed")
	}
	accountGID, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return applecontainer.Resolver{}, errors.New("container inspector group is invalid")
	}
	groupValues, err := account.GroupIds()
	if err != nil {
		return applecontainer.Resolver{}, fmt.Errorf("look up container inspector groups: %w", err)
	}
	groups := make([]uint32, 0, len(groupValues))
	for _, value := range groupValues {
		group, parseErr := strconv.ParseUint(value, 10, 32)
		if parseErr != nil {
			return applecontainer.Resolver{}, errors.New("container inspector supplementary group is invalid")
		}
		groups = append(groups, uint32(group))
	}
	return applecontainer.Resolver{
		Executable: r.config.ContainerCLI,
		Credential: &applecontainer.Credential{
			UID: uid, GID: uint32(accountGID), Groups: groups, Username: account.Username, HomeDir: account.HomeDir,
		},
	}, nil
}

func normalizeConfig(config Config) (Config, error) {
	if !filepath.IsAbs(config.StateDir) || !filepath.IsAbs(config.ManagementSocket) {
		return Config{}, errors.New("state directory and management socket must be absolute")
	}
	if config.ManagementUID < 0 || config.ManagementGID < 0 {
		return Config{}, errors.New("management UID and GID must be non-negative")
	}
	if config.Profile == nil && (len(config.HTTPListeners) == 0 || len(config.HTTPSListeners) == 0) {
		return Config{}, errors.New("HTTP and HTTPS listeners are required")
	}
	if config.Profile != nil && len(config.HTTPSListeners) != 0 {
		return Config{}, errors.New("custom profile cannot be combined with legacy HTTPS listeners")
	}
	for _, address := range append(slices.Clone(config.HTTPListeners), config.HTTPSListeners...) {
		if err := validateLoopbackAddress(address); err != nil {
			return Config{}, err
		}
	}
	if config.ContainerCLI != "" && !filepath.IsAbs(config.ContainerCLI) {
		return Config{}, errors.New("Apple container executable must be absolute")
	}
	if config.RefreshInterval == 0 {
		config.RefreshInterval = defaultRefreshInterval
	}
	if config.ShutdownTimeout <= 0 {
		config.ShutdownTimeout = defaultShutdownTimeout
	}
	if config.ManagementTimeout <= 0 {
		config.ManagementTimeout = 5 * time.Second
	}
	if config.Logger == nil {
		config.Logger = log.New(io.Discard, "", 0)
	}
	return config, nil
}

func validateLoopbackAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listener %q", address)
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil || !parsed.IsLoopback() || parsed.Zone() != "" {
		return fmt.Errorf("listener %q is not a literal loopback address", address)
	}
	if port == "" {
		return fmt.Errorf("listener %q has no port", address)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("listener %q has an invalid port", address)
	}
	return nil
}
