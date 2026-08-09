package applecontainer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"time"
)

const (
	defaultExecutable = "container"
	defaultTimeout    = 5 * time.Second
	maxInspectBytes   = 8 << 20
)

var (
	ErrNotFound            = errors.New("container not found")
	ErrNotRunning          = errors.New("container is not running")
	ErrMissingPort         = errors.New("container has no declared TCP port")
	ErrAmbiguousPort       = errors.New("container has multiple declared TCP ports")
	ErrUnsupportedProtocol = errors.New("unsupported container port protocol")
	ErrMissingAddress      = errors.New("container has no reachable address")
	ErrInvalidMetadata     = errors.New("container returned invalid metadata")
)

type Resolver struct {
	Executable string
	Timeout    time.Duration
}

type Endpoint struct {
	Container string
	Network   string
	Protocol  string
	Address   netip.Addr
	Port      uint16
	Addresses []netip.Addr
}

func (e Endpoint) AddressChanged(previous Endpoint) bool {
	return e.Container == previous.Container &&
		e.Protocol == previous.Protocol &&
		e.Port == previous.Port &&
		e.Address != previous.Address
}

func (e Endpoint) RefreshRequired(previous Endpoint) bool {
	return e.Container == previous.Container &&
		e.Protocol == previous.Protocol &&
		e.Port == previous.Port &&
		(e.Network != previous.Network || e.Address != previous.Address)
}

func (r Resolver) Resolve(ctx context.Context, name string, requestedPort uint16, protocol string) (Endpoint, error) {
	if err := validateContainerID(name); err != nil {
		return Endpoint{}, err
	}
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol != "http" && protocol != "https" {
		return Endpoint{}, fmt.Errorf("%w: %q", ErrUnsupportedProtocol, protocol)
	}

	timeout := r.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	inspectCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	executable := r.Executable
	if executable == "" {
		executable = defaultExecutable
	}
	path, err := exec.LookPath(executable)
	if err != nil {
		return Endpoint{}, fmt.Errorf("find Apple container CLI: %w", err)
	}

	command := exec.CommandContext(inspectCtx, path, "inspect", name)
	stdout := boundedBuffer{limit: maxInspectBytes}
	command.Stdout = &stdout
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if errors.Is(inspectCtx.Err(), context.DeadlineExceeded) {
			return Endpoint{}, errors.New("Apple container inspection timed out")
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return Endpoint{}, fmt.Errorf("inspect Apple container %q: command exited with status %d", name, exitError.ExitCode())
		}
		return Endpoint{}, fmt.Errorf("inspect Apple container %q: %w", name, err)
	}
	if stdout.exceeded {
		return Endpoint{}, errors.New("Apple container inspection exceeded the size limit")
	}

	var records []inspectRecord
	decoder := json.NewDecoder(&stdout)
	if err := decoder.Decode(&records); err != nil {
		return Endpoint{}, fmt.Errorf("parse Apple container inspection: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Endpoint{}, errors.New("parse Apple container inspection: trailing data")
	}
	if len(records) == 0 {
		return Endpoint{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	if len(records) != 1 || records[0].ID != name || records[0].Configuration.ID != name {
		return Endpoint{}, errors.New("Apple container inspection returned an unexpected container")
	}
	record := records[0]
	if record.Status.State != "running" {
		return Endpoint{}, fmt.Errorf("%w: %q is %q", ErrNotRunning, name, record.Status.State)
	}

	port, err := selectPort(record.Configuration.PublishedPorts, requestedPort)
	if err != nil {
		return Endpoint{}, err
	}
	network, addresses, err := selectAddresses(record.Status.Networks)
	if err != nil {
		return Endpoint{}, err
	}

	return Endpoint{
		Container: name,
		Network:   network,
		Protocol:  protocol,
		Address:   addresses[0],
		Port:      port,
		Addresses: addresses,
	}, nil
}

type inspectRecord struct {
	ID            string        `json:"id"`
	Configuration configuration `json:"configuration"`
	Status        status        `json:"status"`
}

type configuration struct {
	ID             string          `json:"id"`
	PublishedPorts []publishedPort `json:"publishedPorts"`
}

type publishedPort struct {
	ContainerPort int    `json:"containerPort"`
	Count         int    `json:"count"`
	Protocol      string `json:"proto"`
}

type status struct {
	State    string          `json:"state"`
	Networks []networkStatus `json:"networks"`
}

type networkStatus struct {
	Network     string `json:"network"`
	IPv4Address string `json:"ipv4Address"`
	IPv6Address string `json:"ipv6Address"`
}

func selectPort(ports []publishedPort, requested uint16) (uint16, error) {
	var tcp []uint16
	hasOtherProtocol := false
	for _, port := range ports {
		count := port.Count
		if port.ContainerPort <= 0 || port.ContainerPort > 65535 || count > 65535-port.ContainerPort+1 {
			return 0, fmt.Errorf("%w: invalid published port range", ErrInvalidMetadata)
		}
		if count <= 0 {
			return 0, fmt.Errorf("%w: invalid published port count", ErrInvalidMetadata)
		}
		if !strings.EqualFold(port.Protocol, "tcp") {
			hasOtherProtocol = true
			continue
		}
		for value := port.ContainerPort; value < port.ContainerPort+count; value++ {
			tcp = append(tcp, uint16(value))
		}
	}
	slices.Sort(tcp)
	tcp = slices.Compact(tcp)

	if requested != 0 {
		if slices.Contains(tcp, requested) {
			return requested, nil
		}
		for _, port := range ports {
			count := max(port.Count, 1)
			if port.ContainerPort <= int(requested) && int(requested) < port.ContainerPort+count && !strings.EqualFold(port.Protocol, "tcp") {
				return 0, fmt.Errorf("%w: port %d is declared as %s", ErrUnsupportedProtocol, requested, port.Protocol)
			}
		}
		// An explicit port is an operator declaration for a directly reachable
		// container listener. Apple does not expose OCI EXPOSE metadata, and a
		// direct listener need not have a host-side publishedPorts entry.
		return requested, nil
	}
	if len(tcp) == 0 {
		if hasOtherProtocol {
			return 0, ErrUnsupportedProtocol
		}
		return 0, ErrMissingPort
	}
	if len(tcp) != 1 {
		return 0, fmt.Errorf("%w: specify --port", ErrAmbiguousPort)
	}
	return tcp[0], nil
}

func selectAddresses(networks []networkStatus) (string, []netip.Addr, error) {
	if len(networks) == 0 || networks[0].Network == "" {
		return "", nil, ErrMissingAddress
	}
	var ipv4 []netip.Addr
	var ipv6 []netip.Addr
	// Apple's published-port target is the first attached network. Retaining
	// that identity makes a later address refresh deterministic.
	for _, network := range networks[:1] {
		if address, ok := parseReachableAddress(network.IPv4Address); ok {
			ipv4 = append(ipv4, address)
		}
		if address, ok := parseReachableAddress(network.IPv6Address); ok {
			ipv6 = append(ipv6, address)
		}
	}
	ipv4 = compactAddresses(ipv4)
	ipv6 = compactAddresses(ipv6)
	if len(ipv4) == 0 && len(ipv6) == 0 {
		return "", nil, ErrMissingAddress
	}
	return networks[0].Network, append(ipv4, ipv6...), nil
}

func parseReachableAddress(value string) (netip.Addr, bool) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Addr{}, false
	}
	address := prefix.Addr().Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() || !address.IsPrivate() {
		return netip.Addr{}, false
	}
	return address, true
}

func compactAddresses(addresses []netip.Addr) []netip.Addr {
	slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(addresses)
}

func validateContainerID(value string) error {
	if len(value) == 0 || len(value) > 128 {
		return errors.New("container ID must be between 1 and 128 characters")
	}
	for i, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || ((char == '-' || char == '_' || char == '.') && i > 0) {
			continue
		}
		return fmt.Errorf("invalid container ID %q", value)
	}
	return nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	originalLength := len(value)
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.exceeded = true
		return originalLength, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		b.exceeded = true
	}
	_, _ = b.Buffer.Write(value)
	return originalLength, nil
}
