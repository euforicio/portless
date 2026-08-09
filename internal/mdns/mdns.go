// Package mdns publishes explicit HTTP or HTTPS names on a local network through the
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
	"slices"
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

type Protocol string

const (
	HTTP  Protocol = "http"
	HTTPS Protocol = "https"
)

// Config describes one root-mounted HTTP or HTTPS advertisement. Host must be
// one exact .local name and Address must currently belong to an up,
// multicast-capable, non-point-to-point interface.
type Config struct {
	Host         string
	Address      netip.Addr
	Port         uint16
	Protocol     Protocol
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
	Index     int
	Command   Command
}

type LANAddress struct {
	Address   netip.Addr
	Interface string
	Index     int
}

// EligibleAddresses returns the deterministic LAN selection set. Interface
// index is the primary stable order, IPv4 is preferred to ULA IPv6, then the
// canonical address bytes break ties.
func EligibleAddresses() ([]LANAddress, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}
	var result []LANAddress
	for _, networkInterface := range interfaces {
		required := net.FlagUp | net.FlagMulticast
		if networkInterface.Flags&required != required || networkInterface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		addresses, err := networkInterface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("list addresses for %s: %w", networkInterface.Name, err)
		}
		for _, raw := range addresses {
			prefix, err := netip.ParsePrefix(raw.String())
			if err != nil {
				continue
			}
			address := prefix.Addr().Unmap()
			if !address.IsValid() || address.Zone() != "" || !address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
				continue
			}
			result = append(result, LANAddress{Address: address, Interface: networkInterface.Name, Index: networkInterface.Index})
		}
	}
	slices.SortFunc(result, func(a, b LANAddress) int {
		if a.Index != b.Index {
			return a.Index - b.Index
		}
		if a.Address.Is4() != b.Address.Is4() {
			if a.Address.Is4() {
				return -1
			}
			return 1
		}
		return a.Address.Compare(b.Address)
	})
	return result, nil
}

// Identity is the kernel start identity of the owned dns-sd process. It is
// durable crash-reconciliation metadata; a PID alone is never sufficient.
type Identity struct {
	PID   int   `json:"pid"`
	Start int64 `json:"start"`
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
	networkInterface, err := lanInterface(address)
	if err != nil {
		return Preflight{}, err
	}
	if config.Protocol == "" {
		config.Protocol = HTTPS
	}
	if config.Protocol != HTTP && config.Protocol != HTTPS {
		return Preflight{}, errors.New("mDNS advertisement protocol must be http or https")
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
			"-i", strconv.Itoa(networkInterface.Index), "-P", instance, "_" + string(config.Protocol) + "._tcp", "local.",
			strconv.FormatUint(uint64(config.Port), 10), host + ".", address.String(), "path=/",
		},
	}
	return Preflight{Config: config, Interface: networkInterface.Name, Index: networkInterface.Index, Command: command}, nil
}

// LANInterface returns the interface currently owning address. It rejects
// loopback, link-local, public, multicast, unspecified, and point-to-point
// addresses so VPN and tailnet addresses cannot accidentally become LAN mode.
func LANInterface(address netip.Addr) (string, error) {
	networkInterface, err := lanInterface(address)
	if err != nil {
		return "", err
	}
	return networkInterface.Name, nil
}

func lanInterface(address netip.Addr) (net.Interface, error) {
	address = address.Unmap()
	if !address.IsValid() || address.Zone() != "" || !address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return net.Interface{}, fmt.Errorf("%w: %q is not private unicast", ErrInvalidAddress, address)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, fmt.Errorf("list network interfaces: %w", err)
	}
	for _, networkInterface := range interfaces {
		required := net.FlagUp | net.FlagMulticast
		if networkInterface.Flags&required != required || networkInterface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		addresses, addressErr := networkInterface.Addrs()
		if addressErr != nil {
			return net.Interface{}, fmt.Errorf("list addresses for %s: %w", networkInterface.Name, addressErr)
		}
		for _, assigned := range addresses {
			prefix, parseErr := netip.ParsePrefix(assigned.String())
			if parseErr == nil && prefix.Addr().Unmap() == address {
				return networkInterface, nil
			}
		}
	}
	return net.Interface{}, fmt.Errorf("%w: %s is not assigned to an eligible interface", ErrInvalidAddress, address)
}

// Publisher owns one dns-sd child process.
type Publisher struct {
	mu            sync.Mutex
	config        Config
	interfaceName string
	command       Command
	process       *exec.Cmd
	done          chan error
	identity      Identity
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
	command.Env = stableEnvironment()
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("capture dns-sd output: %w", err)
	}
	command.Stderr = command.Stdout
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start dns-sd: %w", err)
	}
	identity, err := inspectIdentity(command.Process.Pid)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, fmt.Errorf("inspect dns-sd identity: %w", err)
	}
	publisher := &Publisher{
		config: preflight.Config, interfaceName: preflight.Interface,
		command: preflight.Command, process: command, done: make(chan error, 1), identity: identity,
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
	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		recordReady := false
		serviceReady := false
		reported := false
		for scanner.Scan() {
			line := scanner.Text()
			if !reported && strings.Contains(line, "Name Conflict") {
				ready <- errors.New("dns-sd reported a name conflict")
				return
			}
			if strings.Contains(line, "Got a reply for record") && strings.Contains(line, "Name now registered and active") {
				recordReady = true
			}
			if strings.Contains(line, "Got a reply for service") && strings.Contains(line, "Name now registered and active") {
				serviceReady = true
			}
			if !reported && recordReady && serviceReady {
				reported = true
				ready <- nil
			}
		}
		if !reported {
			if err := scanner.Err(); err != nil {
				ready <- fmt.Errorf("read dns-sd output: %w", err)
			} else {
				ready <- errors.New("dns-sd output closed before readiness")
			}
		}
	}()
	select {
	case err := <-ready:
		return err
	case err := <-done:
		done <- err
		if err == nil {
			return errors.New("dns-sd exited before readiness")
		}
		return fmt.Errorf("dns-sd exited before readiness: %w", err)
	case <-ctx.Done():
		return fmt.Errorf("wait for dns-sd readiness: %w", ctx.Err())
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

func (p *Publisher) Identity() Identity {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.identity
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
	p.identity = replacement.identity
	return true, nil
}

// StopOwned terminates a previously persisted dns-sd process only when its
// current kernel start identity still matches. It is used after a supervisor
// crash and never searches for or affects unrelated dns-sd processes.
func StopOwned(identity Identity) error {
	if identity.PID <= 0 || identity.Start <= 0 {
		return nil
	}
	current, err := inspectIdentity(identity.PID)
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	if err != nil {
		return err
	}
	if current != identity {
		return errors.New("dns-sd process identity changed")
	}
	if err := syscall.Kill(identity.PID, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	deadline := time.Now().Add(stopTimeout)
	for time.Now().Before(deadline) {
		_, err := inspectIdentity(identity.PID)
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		if err != nil {
			return err
		}
		time.Sleep(25 * time.Millisecond)
	}
	current, err = inspectIdentity(identity.PID)
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	if err != nil || current != identity {
		return err
	}
	if err := syscall.Kill(identity.PID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	deadline = time.Now().Add(stopTimeout)
	for time.Now().Before(deadline) {
		_, err := inspectIdentity(identity.PID)
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		if err != nil {
			return err
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("owned dns-sd process did not exit after SIGKILL")
}

func stableEnvironment() []string {
	environment := make([]string, 0, len(os.Environ())+2)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "LANG=") || strings.HasPrefix(value, "LC_ALL=") {
			continue
		}
		environment = append(environment, value)
	}
	return append(environment, "LANG=C", "LC_ALL=C")
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
		return normalizeWait(waitErr)
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
	prefix, ok := strings.CutSuffix(host, ".local")
	if !ok || prefix == "" || len(host) > 253 {
		return "", ErrInvalidHost
	}
	for label := range strings.SplitSeq(prefix, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidHost
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", ErrInvalidHost
			}
		}
	}
	return prefix + ".local", nil
}
