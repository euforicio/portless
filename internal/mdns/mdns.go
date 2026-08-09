// Package mdns publishes explicit HTTPS names on a local network through the
// macOS dns-sd utility. Publishing is always an explicit caller action.
package mdns

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	Executable          = "/usr/bin/dns-sd"
	defaultReadyTimeout = 5 * time.Second
	stopTimeout         = 2 * time.Second
)

var (
	ErrInvalidHost    = errors.New("invalid .local host")
	ErrInvalidAddress = errors.New("invalid LAN address")
	ErrNotRunning     = errors.New("mDNS advertisement is not running")
)

// Config describes one root-mounted HTTPS advertisement. Host must be one
// exact, single-label .local name and Address must currently belong to an up,
// multicast-capable, non-point-to-point interface.
type Config struct {
	Host         string
	Address      netip.Addr
	Port         uint16
	ReadyTimeout time.Duration
}

// Command is an auditable command plan. It never includes sudo.
type Command struct {
	Path string
	Args []string
}

func (c Command) String() string {
	parts := []string{c.Path}
	for _, argument := range c.Args {
		parts = append(parts, strconv.Quote(argument))
	}
	return strings.Join(parts, " ")
}

// Preflight is a read-only validation result.
type Preflight struct {
	Config    Config
	Interface string
	Command   Command
}

// Check validates an advertisement against the current network interfaces and
// returns the exact command that Start would execute.
func Check(config Config) (Preflight, error) {
	host, err := normalizeHost(config.Host)
	if err != nil {
		return Preflight{}, err
	}
	if config.Port == 0 {
		return Preflight{}, errors.New("mDNS advertisement port is required")
	}
	address := config.Address.Unmap()
	interfaceName, err := LANInterface(address)
	if err != nil {
		return Preflight{}, err
	}
	if config.ReadyTimeout < 0 {
		return Preflight{}, errors.New("mDNS readiness timeout cannot be negative")
	}
	config.Host = host
	config.Address = address
	instance := strings.TrimSuffix(host, ".local")
	command := Command{
		Path: Executable,
		Args: []string{
			"-P", instance, "_https._tcp", "local.",
			strconv.FormatUint(uint64(config.Port), 10), host + ".", address.String(), "path=/",
		},
	}
	return Preflight{Config: config, Interface: interfaceName, Command: command}, nil
}

// LANInterface returns the interface currently owning address. It rejects
// loopback, link-local, public, multicast, unspecified, and point-to-point
// addresses so VPN and tailnet addresses cannot accidentally become LAN mode.
func LANInterface(address netip.Addr) (string, error) {
	address = address.Unmap()
	if !address.IsValid() || address.Zone() != "" || !address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return "", fmt.Errorf("%w: %q is not private unicast", ErrInvalidAddress, address)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("list network interfaces: %w", err)
	}
	for _, networkInterface := range interfaces {
		required := net.FlagUp | net.FlagMulticast
		if networkInterface.Flags&required != required || networkInterface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		addresses, addressErr := networkInterface.Addrs()
		if addressErr != nil {
			return "", fmt.Errorf("list addresses for %s: %w", networkInterface.Name, addressErr)
		}
		for _, assigned := range addresses {
			prefix, parseErr := netip.ParsePrefix(assigned.String())
			if parseErr == nil && prefix.Addr().Unmap() == address {
				return networkInterface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("%w: %s is not assigned to an eligible interface", ErrInvalidAddress, address)
}

// Publisher owns one dns-sd child process.
type Publisher struct {
	mu            sync.Mutex
	config        Config
	interfaceName string
	command       Command
	process       *exec.Cmd
	done          chan error
	closed        bool
}

// Start runs the checked dns-sd plan and waits until both the hostname record
// and HTTPS service are active.
func Start(ctx context.Context, config Config) (*Publisher, error) {
	preflight, err := Check(config)
	if err != nil {
		return nil, err
	}
	return start(ctx, preflight)
}

func start(ctx context.Context, preflight Preflight) (*Publisher, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	command := exec.Command(preflight.Command.Path, preflight.Command.Args...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("capture dns-sd output: %w", err)
	}
	command.Stderr = command.Stdout
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start dns-sd: %w", err)
	}
	publisher := &Publisher{
		config: preflight.Config, interfaceName: preflight.Interface,
		command: preflight.Command, process: command, done: make(chan error, 1),
	}
	go func() { publisher.done <- command.Wait() }()

	timeout := preflight.Config.ReadyTimeout
	if timeout == 0 {
		timeout = defaultReadyTimeout
	}
	readyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := waitReady(readyCtx, stdout, publisher.done); err != nil {
		_ = publisher.stop()
		return nil, err
	}
	return publisher, nil
}

func waitReady(ctx context.Context, output io.Reader, done chan error) error {
	recordReady := false
	serviceReady := false
	lines := make(chan string)
	scanDone := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-ctx.Done():
				scanDone <- ctx.Err()
				return
			}
		}
		scanDone <- scanner.Err()
	}()
	for {
		select {
		case line := <-lines:
			if strings.Contains(line, "Name Conflict") {
				return errors.New("dns-sd reported a name conflict")
			}
			if strings.Contains(line, "Got a reply for record") && strings.Contains(line, "Name now registered and active") {
				recordReady = true
			}
			if strings.Contains(line, "Got a reply for service") && strings.Contains(line, "Name now registered and active") {
				serviceReady = true
			}
			if recordReady && serviceReady {
				return nil
			}
		case err := <-done:
			done <- err
			if err == nil {
				return errors.New("dns-sd exited before readiness")
			}
			return fmt.Errorf("dns-sd exited before readiness: %w", err)
		case err := <-scanDone:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				return fmt.Errorf("read dns-sd output: %w", err)
			}
			return errors.New("dns-sd output closed before readiness")
		case <-ctx.Done():
			return fmt.Errorf("wait for dns-sd readiness: %w", ctx.Err())
		}
	}
}

// Config returns the currently active normalized configuration.
func (p *Publisher) Config() Config {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.config
}

// Interface returns the current interface selected during the last preflight.
func (p *Publisher) Interface() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.interfaceName
}

// Command returns a copy of the active command plan.
func (p *Publisher) Command() Command {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Command{Path: p.command.Path, Args: append([]string(nil), p.command.Args...)}
}

// Refresh revalidates and, when the address changed, replaces the dns-sd child
// process. The old record is deterministically removed before the new one is
// registered, avoiding two processes claiming the same name.
func (p *Publisher) Refresh(ctx context.Context, address netip.Addr) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false, ErrNotRunning
	}
	next := p.config
	next.Address = address
	preflight, err := Check(next)
	if err != nil {
		return false, err
	}
	if preflight.Config.Address == p.config.Address {
		p.interfaceName = preflight.Interface
		return false, nil
	}
	if err := p.stop(); err != nil {
		p.closed = true
		return false, err
	}
	replacement, err := start(ctx, preflight)
	if err != nil {
		p.closed = true
		return false, err
	}
	p.config = replacement.config
	p.interfaceName = replacement.interfaceName
	p.command = replacement.command
	p.process = replacement.process
	p.done = replacement.done
	return true, nil
}

// Close removes the advertisement. It is safe to call more than once.
func (p *Publisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	return p.stop()
}

func (p *Publisher) stop() error {
	if p.process == nil || p.process.Process == nil {
		return nil
	}
	if err := p.process.Process.Signal(syscall.SIGTERM); errors.Is(err, os.ErrProcessDone) {
		waitErr := <-p.done
		if waitErr != nil {
			return fmt.Errorf("dns-sd stopped unexpectedly: %w", waitErr)
		}
		return nil
	} else if err != nil {
		select {
		case waitErr := <-p.done:
			return normalizeWait(waitErr)
		default:
			return fmt.Errorf("stop dns-sd: %w", err)
		}
	}
	timer := time.NewTimer(stopTimeout)
	defer timer.Stop()
	select {
	case err := <-p.done:
		return normalizeWait(err)
	case <-timer.C:
		if err := p.process.Process.Kill(); err != nil {
			return fmt.Errorf("kill dns-sd: %w", err)
		}
		return normalizeWait(<-p.done)
	}
}

func normalizeWait(err error) error {
	var exitError *exec.ExitError
	if err == nil || errors.As(err, &exitError) {
		return nil
	}
	return err
}

func normalizeHost(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	label, ok := strings.CutSuffix(host, ".local")
	if !ok || label == "" || strings.Contains(label, ".") || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return "", ErrInvalidHost
	}
	for _, character := range label {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return "", ErrInvalidHost
		}
	}
	return label + ".local", nil
}
