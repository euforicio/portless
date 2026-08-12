// Package lan serves one explicitly requested route on one eligible LAN
// address. It is runtime agnostic: the upstream is an ordinary validated
// HTTP(S) IP-and-port URL.
package lan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/euforicio/portless/internal/mdns"
	"github.com/euforicio/portless/internal/pki"
	"github.com/euforicio/portless/internal/proxy"
	"github.com/euforicio/portless/internal/routes"
	"golang.org/x/sys/unix"
)

const (
	refreshInterval = 2 * time.Second
	shutdownTimeout = 3 * time.Second
	maxLANLeaves    = 256
)

type Request struct {
	Name      string
	Target    string
	HTTPS     bool
	PinnedIP  netip.Addr
	StateDir  string
	Logger    *log.Logger
	OnUpdate  func(Registration) error
	Authorize func(context.Context) bool
}

type Registration struct {
	Name       string        `json:"name"`
	Target     string        `json:"target"`
	Scheme     string        `json:"scheme"`
	Address    string        `json:"address"`
	Port       uint16        `json:"port"`
	PinnedIP   string        `json:"pinned_ip,omitempty"`
	Interface  string        `json:"interface"`
	MDNS       mdns.Identity `json:"mdns"`
	CACertPath string        `json:"ca_cert_path,omitempty"`
}

func (r Registration) URL() string {
	if r.Address == "" || r.Port == 0 {
		return ""
	}
	authority := r.Name
	if (r.Scheme == "http" && r.Port != 80) || (r.Scheme == "https" && r.Port != 443) {
		authority = net.JoinHostPort(r.Name, strconv.Itoa(int(r.Port)))
	}
	return r.Scheme + "://" + authority
}

func (r Registration) Validate() error {
	if r.Scheme != "http" && r.Scheme != "https" {
		return errors.New("invalid LAN registration scheme")
	}
	if _, err := routes.NewRouteForTLD(r.Name, r.Target, ".local"); err != nil {
		return fmt.Errorf("invalid LAN registration route: %w", err)
	}
	if r.Address == "" {
		if r.Port != 0 || r.Interface != "" || r.MDNS != (mdns.Identity{}) {
			return errors.New("inactive LAN registration contains listener state")
		}
	} else {
		address, err := netip.ParseAddr(r.Address)
		if err != nil || address.Unmap().String() != r.Address || r.Port == 0 || r.Interface == "" || r.MDNS.PID <= 0 || r.MDNS.Start <= 0 {
			return errors.New("invalid active LAN registration")
		}
	}
	if r.PinnedIP != "" {
		address, err := netip.ParseAddr(r.PinnedIP)
		if err != nil || address.Unmap().String() != r.PinnedIP {
			return errors.New("invalid pinned LAN address")
		}
	}
	if r.Scheme == "https" {
		if !filepath.IsAbs(r.CACertPath) {
			return errors.New("HTTPS LAN registration has no absolute CA certificate path")
		}
	} else if r.CACertPath != "" {
		return errors.New("HTTP LAN registration contains CA state")
	}
	return nil
}

type Service struct {
	mu        sync.Mutex
	request   Request
	host      string
	authority *pki.Authority
	active    *active
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	errors    chan error
	closeOnce sync.Once
}

type active struct {
	address     netip.Addr
	port        uint16
	iface       string
	listener    net.Listener
	server      *http.Server
	publisher   *mdns.Publisher
	proxy       *proxy.Handler
	connections sync.Map
}

func Start(parent context.Context, request Request) (*Service, error) {
	if !filepath.IsAbs(request.StateDir) {
		return nil, errors.New("LAN state directory must be absolute")
	}
	host, target, err := validateRequest(request)
	if err != nil {
		return nil, err
	}
	request.Target = target
	ctx, cancel := context.WithCancel(parent)
	service := &Service{request: request, host: host, ctx: ctx, cancel: cancel, done: make(chan struct{}), errors: make(chan error, 1)}
	if request.HTTPS {
		authority, err := service.openAuthority()
		if err != nil {
			cancel()
			return nil, err
		}
		service.authority = authority
	}
	address, err := selectAddress(request.PinnedIP)
	if err != nil {
		cancel()
		return nil, err
	}
	if err := service.activate(ctx, address, 0); err != nil {
		cancel()
		return nil, err
	}
	go service.monitor()
	return service, nil
}

func validateRequest(request Request) (string, string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(request.Name), "."))
	if name == "" || strings.HasSuffix(name, ".local") {
		return "", "", errors.New("LAN route name must omit .local")
	}
	host := name + ".local"
	if _, err := routes.NewRouteForTLD(host, request.Target, ".local"); err != nil {
		return "", "", fmt.Errorf("invalid LAN route: %w", err)
	}
	if request.PinnedIP.IsValid() {
		pinned := request.PinnedIP.Unmap()
		if pinned.Zone() != "" || pinned != request.PinnedIP.Unmap() {
			return "", "", errors.New("pinned LAN address must be canonical and unzoned")
		}
	}
	route, _ := routes.NewRouteForTLD(host, request.Target, ".local")
	return host, route.Upstream(), nil
}

func selectAddress(pinned netip.Addr) (netip.Addr, error) {
	if pinned.IsValid() {
		pinned = pinned.Unmap()
		if _, err := mdns.LANInterface(pinned); err != nil {
			return netip.Addr{}, err
		}
		return pinned, nil
	}
	addresses, err := mdns.EligibleAddresses()
	if err != nil {
		return netip.Addr{}, err
	}
	if len(addresses) == 0 {
		return netip.Addr{}, errors.New("no eligible LAN address is assigned")
	}
	return addresses[0].Address, nil
}

func (s *Service) openAuthority() (*pki.Authority, error) {
	if err := os.MkdirAll(s.request.StateDir, 0o700); err != nil {
		return nil, err
	}
	lock, err := openLock(filepath.Join(s.request.StateDir, "lan-pki.lock"))
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	return pki.Open(filepath.Join(s.request.StateDir, "lan-pki"), pki.Options{
		AllowedSuffix: ".local", RootCommonName: "Portless LAN Local CA", MaxLeafCertificates: maxLANLeaves,
		AllowHost: func(host string) bool { return host == s.host },
	})
}

func (s *Service) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	lock, err := openLock(filepath.Join(s.request.StateDir, "lan-pki.lock"))
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	return s.authority.GetCertificate(hello)
}

func openLock(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil {
		unix.Close(descriptor)
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || int(stat.Uid) != os.Geteuid() {
		unix.Close(descriptor)
		return nil, errors.New("LAN PKI lock must be an owned regular 0600 file")
	}
	return os.NewFile(uintptr(descriptor), path), nil
}

func (s *Service) activate(ctx context.Context, address netip.Addr, preferredPort uint16) error {
	bound, err := s.bind(address, preferredPort)
	if err != nil {
		return err
	}
	protocol := mdns.HTTP
	if s.request.HTTPS {
		protocol = mdns.HTTPS
	}
	publisher, err := mdns.Start(ctx, mdns.Config{Host: s.host, Address: address, Port: bound.port, Protocol: protocol})
	if err != nil {
		_ = closeActive(context.Background(), bound)
		return err
	}
	bound.publisher = publisher
	s.mu.Lock()
	s.active = bound
	registration := s.registrationLocked()
	s.mu.Unlock()
	if s.request.OnUpdate != nil {
		if err := s.request.OnUpdate(registration); err != nil {
			s.mu.Lock()
			s.active = nil
			s.mu.Unlock()
			_ = closeActive(context.Background(), bound)
			return fmt.Errorf("persist LAN ownership: %w", err)
		}
	}
	return nil
}

func (s *Service) bind(address netip.Addr, preferredPort uint16) (*active, error) {
	port := strconv.Itoa(int(preferredPort))
	listener, err := net.Listen("tcp", net.JoinHostPort(address.String(), port))
	if err != nil {
		return nil, fmt.Errorf("listen on LAN address %s: %w", address, err)
	}
	actualPort := uint16(listener.Addr().(*net.TCPAddr).Port)
	table, err := routes.NewTableWithOptions(routes.Options{TLD: ".local"})
	if err != nil {
		listener.Close()
		return nil, err
	}
	route, _ := routes.NewRouteForTLD(s.host, s.request.Target, ".local")
	if err := table.Replace([]routes.Route{route}); err != nil {
		listener.Close()
		return nil, err
	}
	proxyHandler, err := proxy.New(table, proxy.Options{PublicPort: actualPort, ErrorLog: s.request.Logger})
	if err != nil {
		listener.Close()
		return nil, err
	}
	var handler http.Handler
	authorized := func(request *http.Request) bool {
		return s.request.Authorize == nil || s.request.Authorize(request.Context())
	}
	if s.request.HTTPS {
		handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if !authorized(request) {
				http.Error(writer, "LAN route is no longer registered", http.StatusNotFound)
				return
			}
			if request.TLS == nil || request.TLS.ServerName == "" || !strings.EqualFold(strings.TrimSuffix(request.TLS.ServerName, "."), s.host) {
				http.Error(writer, "TLS server name and host differ", http.StatusMisdirectedRequest)
				return
			}
			proxyHandler.ServeHTTP(writer, request)
		})
	} else {
		handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if !authorized(request) {
				http.Error(writer, "LAN route is no longer registered", http.StatusNotFound)
				return
			}
			proxyHandler.ServeHTTP(writer, request)
		})
	}
	iface, _ := mdns.LANInterface(address)
	result := &active{address: address, port: actualPort, iface: iface, listener: listener, proxy: proxyHandler}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10,
		ConnState: func(connection net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew, http.StateActive, http.StateIdle, http.StateHijacked:
				result.connections.Store(connection, struct{}{})
			case http.StateClosed:
				result.connections.Delete(connection)
			}
		},
	}
	if s.request.HTTPS {
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.certificate, NextProtos: []string{"h2", "http/1.1"}}
	}
	result.server = server
	go func() {
		var serveErr error
		if s.request.HTTPS {
			serveErr = server.ServeTLS(listener, "", "")
		} else {
			serveErr = server.Serve(listener)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
			s.report(fmt.Errorf("LAN listener failed: %w", serveErr))
		}
	}()
	return result, nil
}

func (s *Service) monitor() {
	defer close(s.done)
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if err := s.refresh(); err != nil {
				s.report(err)
			}
		}
	}
}

func (s *Service) refresh() error {
	s.mu.Lock()
	authorize := s.request.Authorize
	pinnedIP := s.request.PinnedIP
	s.mu.Unlock()
	if authorize != nil && !authorize(s.ctx) {
		s.mu.Lock()
		current := s.active
		if current == nil {
			s.mu.Unlock()
			return nil
		}
		s.active = nil
		registration := s.registrationLocked()
		s.mu.Unlock()
		if current != nil {
			_ = closeActive(context.Background(), current)
			if s.request.OnUpdate != nil {
				_ = s.request.OnUpdate(registration)
			}
		}
		return errors.New("LAN route ownership changed; exposure withdrawn")
	}
	next, err := selectAddress(pinnedIP)
	s.mu.Lock()
	current := s.active
	s.mu.Unlock()
	if err != nil {
		if current != nil {
			s.mu.Lock()
			s.active = nil
			registration := s.registrationLocked()
			s.mu.Unlock()
			_ = closeActive(context.Background(), current)
			if s.request.OnUpdate != nil {
				if persistErr := s.request.OnUpdate(registration); persistErr != nil {
					return errors.Join(err, persistErr)
				}
			}
		}
		return fmt.Errorf("LAN address unavailable; exposure withdrawn: %w", err)
	}
	if current == nil {
		return s.activate(s.ctx, next, 0)
	}
	if current.address == next {
		return nil
	}
	replacement, err := s.bind(next, current.port)
	if err != nil {
		return err
	}
	if err := current.publisher.Close(); err != nil {
		_ = closeActive(context.Background(), replacement)
		return err
	}
	protocol := mdns.HTTP
	if s.request.HTTPS {
		protocol = mdns.HTTPS
	}
	replacement.publisher, err = mdns.Start(s.ctx, mdns.Config{Host: s.host, Address: next, Port: replacement.port, Protocol: protocol})
	if err != nil {
		rollback, rollbackErr := mdns.Start(s.ctx, mdns.Config{Host: s.host, Address: current.address, Port: current.port, Protocol: protocol})
		current.publisher = rollback
		_ = closeActive(context.Background(), replacement)
		if rollbackErr != nil {
			s.mu.Lock()
			s.active = nil
			registration := s.registrationLocked()
			s.mu.Unlock()
			_ = closeActive(context.Background(), current)
			if s.request.OnUpdate != nil {
				_ = s.request.OnUpdate(registration)
			}
			return errors.Join(fmt.Errorf("re-advertise LAN route: %w", err), fmt.Errorf("restore previous LAN advertisement: %w", rollbackErr))
		}
		return fmt.Errorf("re-advertise LAN route: %w", err)
	}
	s.mu.Lock()
	s.active = replacement
	registration := s.registrationLocked()
	s.mu.Unlock()
	_ = closeActive(context.Background(), current)
	if s.request.OnUpdate != nil {
		return s.request.OnUpdate(registration)
	}
	return nil
}

func (s *Service) Registration() Registration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registrationLocked()
}

func (s *Service) registrationLocked() Registration {
	result := Registration{Name: s.host, Target: s.request.Target, Scheme: "http"}
	if s.request.HTTPS {
		result.Scheme = "https"
		result.CACertPath = s.authority.RootCertificatePath()
	}
	if s.request.PinnedIP.IsValid() {
		result.PinnedIP = s.request.PinnedIP.Unmap().String()
	}
	if s.active != nil {
		result.Address = s.active.address.String()
		result.Port = s.active.port
		result.Interface = s.active.iface
		if s.active.publisher != nil {
			result.MDNS = s.active.publisher.Identity()
		}
	}
	return result
}

func (s *Service) Errors() <-chan error { return s.errors }

func (s *Service) report(err error) {
	select {
	case s.errors <- err:
	default:
	}
}

func (s *Service) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		<-s.done
		s.mu.Lock()
		current := s.active
		s.active = nil
		s.mu.Unlock()
		if current != nil {
			if err := closeActive(context.Background(), current); err != nil {
				s.report(err)
			}
		}
		close(s.errors)
	})
	select {
	case err, ok := <-s.errors:
		if ok {
			return err
		}
		return nil
	default:
		return nil
	}
}

func closeActive(parent context.Context, current *active) error {
	if current == nil {
		return nil
	}
	var result error
	if current.publisher != nil {
		result = current.publisher.Close()
	}
	ctx, cancel := context.WithTimeout(parent, shutdownTimeout)
	defer cancel()
	if err := current.server.Shutdown(ctx); err != nil {
		_ = current.server.Close()
		result = errors.Join(result, err)
	}
	current.connections.Range(func(connection, _ any) bool {
		_ = connection.(net.Conn).Close()
		return true
	})
	current.proxy.CloseIdleConnections()
	return result
}
