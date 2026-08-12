// Package tailscale plans and applies explicit Tailscale Serve and Funnel
// registrations. It never invokes sudo and never exposes anything unless the
// caller executes Apply.
package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	defaultExecutable = "tailscale"
	defaultTimeout    = 10 * time.Second
	maxOutputBytes    = 4 << 20
)

var (
	ErrUnavailable      = errors.New("tailscale is unavailable")
	ErrHTTPSUnavailable = errors.New("tailscale HTTPS is unavailable")
	ErrNoPort           = errors.New("no supported HTTPS port is available")
	ErrConflict         = errors.New("tailscale registration conflicts with current state")
	errOutputLimit      = errors.New("tailscale command output limit reached")
)

// Mode controls the exposure boundary.
type Mode string

const (
	Serve  Mode = "serve"
	Funnel Mode = "funnel"
)

// Client locates and invokes the official Tailscale CLI.
type Client struct {
	Executable string
	Timeout    time.Duration
}

// Request asks for one application at the root of its own HTTPS port.
// ReservedPorts includes ports selected by other not-yet-applied plans.
type Request struct {
	Name          string
	Mode          Mode
	Target        string
	ReservedPorts []uint16
}

// Command is an explicit, auditable CLI mutation. It never includes sudo.
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

// Registration is the normalized state owned by a Plan.
type Registration struct {
	Name   string
	Mode   Mode
	Port   uint16
	Target string
	Host   string
}

// Plan contains the exact registration and per-port cleanup commands.
type Plan struct {
	Registration Registration
	Register     Command
	Cleanup      Command
}

// Snapshot is the read-only result of checking the local Tailscale daemon.
type Snapshot struct {
	Executable    string
	Version       string
	DNSName       string
	UsedPorts     []uint16
	FunnelPorts   []uint16
	HTTPSCapable  bool
	MagicDNS      bool
	registrations map[uint16]activeRegistration
}

type activeRegistration struct {
	target string
	funnel bool
}

// Check performs only documented read-only CLI operations. It verifies a
// running daemon, MagicDNS, the HTTPS node capability, a certificate domain,
// a security-fixed modern CLI, and the selected mode's status command.
func (c Client) Check(ctx context.Context, mode Mode) (Snapshot, error) {
	return c.check(ctx, mode, true)
}

func (c Client) check(ctx context.Context, mode Mode, requireExposureCapability bool) (Snapshot, error) {
	if mode != Serve && mode != Funnel {
		return Snapshot{}, errors.New("invalid Tailscale exposure mode")
	}
	executable, err := c.executable()
	if err != nil {
		return Snapshot{}, err
	}
	versionOutput, err := c.readOnly(ctx, executable, "version", "--json")
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: version: %v", ErrUnavailable, err)
	}
	var versionStatus cliVersion
	if err := decodeOne(versionOutput, &versionStatus); err != nil {
		return Snapshot{}, fmt.Errorf("parse Tailscale version: %w", err)
	}
	version, err := parseVersion(versionStatus.MajorMinorPatch)
	if err != nil || version.less(semanticVersion{major: 1, minor: 98, patch: 9}) {
		return Snapshot{}, fmt.Errorf("%w: Tailscale v1.98.9 or newer is required", ErrUnavailable)
	}
	statusOutput, err := c.readOnly(ctx, executable, "status", "--json")
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: status: %v", ErrUnavailable, err)
	}
	var status daemonStatus
	if err := decodeOne(statusOutput, &status); err != nil {
		return Snapshot{}, fmt.Errorf("parse Tailscale status: %w", err)
	}
	if status.BackendState != "Running" || status.Self == nil || !status.Self.Online || status.Self.DNSName == "" {
		return Snapshot{}, fmt.Errorf("%w: daemon state is %q", ErrUnavailable, status.BackendState)
	}
	dnsOutput, err := c.readOnly(ctx, executable, "dns", "status", "--json")
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: DNS status: %v", ErrUnavailable, err)
	}
	var dns dnsStatus
	if err := decodeOne(dnsOutput, &dns); err != nil {
		return Snapshot{}, fmt.Errorf("parse Tailscale DNS status: %w", err)
	}
	dnsName := strings.TrimSuffix(status.Self.DNSName, ".")
	httpsCapability := hasCapability(status.Self.CapMap, "https")
	certificatePresent := slices.ContainsFunc(dns.CertDomains, func(domain string) bool {
		return strings.TrimSuffix(domain, ".") == dnsName
	})
	magicDNS := dns.TailscaleDNS && dns.CurrentTailnet.MagicDNSEnabled &&
		strings.TrimSuffix(dns.CurrentTailnet.SelfDNSName, ".") == dnsName && dns.CurrentTailnet.MagicDNSSuffix != ""
	if requireExposureCapability && (!magicDNS || !httpsCapability || !certificatePresent) {
		return Snapshot{}, fmt.Errorf("%w: MagicDNS=%t HTTPS-capability=%t certificate-domain=%t", ErrHTTPSUnavailable,
			magicDNS, httpsCapability, certificatePresent)
	}
	funnelPorts, funnelCapable := permittedFunnelPorts(status.Self.CapMap)
	if requireExposureCapability && mode == Funnel && !funnelCapable {
		return Snapshot{}, fmt.Errorf("%w: Funnel capabilities are not enabled for this node", ErrHTTPSUnavailable)
	}
	serveOutput, err := c.readOnly(ctx, executable, string(mode), "status", "--json")
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %s status: %v", ErrUnavailable, mode, err)
	}
	registrations, ports, err := parseServeStatus(serveOutput, dnsName)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		Executable: executable, Version: versionStatus.MajorMinorPatch,
		DNSName: dnsName, UsedPorts: ports, FunnelPorts: funnelPorts,
		HTTPSCapable: true, MagicDNS: true,
		registrations: registrations,
	}, nil
}

// BuildPlan performs a read-only preflight and allocates 443 first. Serve then
// uses every free port from 8443 upward; Funnel is restricted by Tailscale to
// 443, 8443, and 10000.
func (c Client) BuildPlan(ctx context.Context, request Request) (Plan, error) {
	name, err := normalizeName(request.Name)
	if err != nil {
		return Plan{}, err
	}
	target, err := normalizeTarget(request.Target)
	if err != nil {
		return Plan{}, err
	}
	snapshot, err := c.Check(ctx, request.Mode)
	if err != nil {
		return Plan{}, err
	}
	occupied := append(slices.Clone(snapshot.UsedPorts), request.ReservedPorts...)
	port, err := Allocate(request.Mode, occupied)
	if request.Mode == Funnel {
		port, err = allocatePermittedFunnel(occupied, snapshot.FunnelPorts)
	}
	if err != nil {
		return Plan{}, err
	}
	portFlag := "--https=" + strconv.FormatUint(uint64(port), 10)
	registration := Registration{Name: name, Mode: request.Mode, Port: port, Target: target, Host: snapshot.DNSName}
	return Plan{
		Registration: registration,
		Register:     Command{Path: snapshot.Executable, Args: []string{string(request.Mode), "--bg", "--yes", portFlag, "--set-path=/", target}},
		Cleanup:      Command{Path: snapshot.Executable, Args: []string{string(request.Mode), "--yes", portFlag, "--set-path=/", "off"}},
	}, nil
}

func allocatePermittedFunnel(occupied, permitted []uint16) (uint16, error) {
	used := make(map[uint16]struct{}, len(occupied))
	for _, port := range occupied {
		used[port] = struct{}{}
	}
	for _, port := range []uint16{443, 8443, 10000} {
		_, occupied := used[port]
		if !occupied && slices.Contains(permitted, port) {
			return port, nil
		}
	}
	return 0, ErrNoPort
}

// Allocate deterministically selects an HTTPS port without inspecting or
// mutating the system.
func Allocate(mode Mode, occupied []uint16) (uint16, error) {
	if mode != Serve && mode != Funnel {
		return 0, errors.New("invalid Tailscale exposure mode")
	}
	used := make(map[uint16]struct{}, len(occupied))
	for _, port := range occupied {
		if port != 0 {
			used[port] = struct{}{}
		}
	}
	available := func(port uint16) bool { _, exists := used[port]; return !exists }
	if available(443) {
		return 443, nil
	}
	switch mode {
	case Funnel:
		for _, port := range []uint16{8443, 10000} {
			if available(port) {
				return port, nil
			}
		}
	case Serve:
		for value := uint32(8443); value <= 65535; value++ {
			if available(uint16(value)) {
				return uint16(value), nil
			}
		}
	}
	return 0, ErrNoPort
}

// Apply is the explicit network-exposure mutation boundary. It rechecks that
// the allocated port remains unused, runs the exact plan, then verifies the
func (c Client) Apply(ctx context.Context, plan Plan) error {
	if err := validatePlan(plan); err != nil {
		return err
	}
	snapshot, err := c.Check(ctx, plan.Registration.Mode)
	if err != nil {
		return err
	}
	if snapshot.Executable != plan.Register.Path || snapshot.DNSName != plan.Registration.Host {
		return fmt.Errorf("%w: Tailscale identity changed since planning", ErrConflict)
	}
	if plan.Registration.Mode == Funnel && !slices.Contains(snapshot.FunnelPorts, plan.Registration.Port) {
		return fmt.Errorf("%w: Funnel port %d is no longer authorized", ErrConflict, plan.Registration.Port)
	}
	if slices.Contains(snapshot.UsedPorts, plan.Registration.Port) {
		return fmt.Errorf("%w: HTTPS port %d is now in use", ErrConflict, plan.Registration.Port)
	}
	if _, err := c.run(ctx, plan.Register.Path, plan.Register.Args...); err != nil {
		return fmt.Errorf("register Tailscale %s: %w", plan.Registration.Mode, err)
	}
	return c.verify(ctx, plan.Registration, true)
}

// Clean removes only the exact root-mounted registration represented by plan.
// It refuses to remove a port whose target or exposure mode changed.
func (c Client) Clean(ctx context.Context, plan Plan) error {
	if err := validatePlan(plan); err != nil {
		return err
	}
	snapshot, err := c.check(ctx, plan.Registration.Mode, false)
	if err != nil {
		return err
	}
	if snapshot.Executable != plan.Cleanup.Path || snapshot.DNSName != plan.Registration.Host {
		return fmt.Errorf("%w: Tailscale identity changed since planning", ErrConflict)
	}
	if err := verifySnapshot(snapshot, plan.Registration, true); err != nil {
		return err
	}
	if _, err := c.run(ctx, plan.Cleanup.Path, plan.Cleanup.Args...); err != nil {
		return fmt.Errorf("clean Tailscale %s: %w", plan.Registration.Mode, err)
	}
	return c.verify(ctx, plan.Registration, false)
}

func (c Client) verify(ctx context.Context, registration Registration, present bool) error {
	snapshot, err := c.check(ctx, registration.Mode, false)
	if err != nil {
		return err
	}
	return verifySnapshot(snapshot, registration, present)
}

func verifySnapshot(snapshot Snapshot, registration Registration, present bool) error {
	active, exists := snapshot.registrations[registration.Port]
	if !present {
		if exists {
			return fmt.Errorf("%w: HTTPS port %d remains configured", ErrConflict, registration.Port)
		}
		return nil
	}
	wantFunnel := registration.Mode == Funnel
	if !exists || active.target != registration.Target || active.funnel != wantFunnel {
		return fmt.Errorf("%w: HTTPS port %d does not match the planned root registration", ErrConflict, registration.Port)
	}
	return nil
}

func validatePlan(plan Plan) error {
	registration := plan.Registration
	if registration.Mode != Serve && registration.Mode != Funnel {
		return errors.New("invalid Tailscale plan mode")
	}
	if registration.Mode == Funnel && !slices.Contains([]uint16{443, 8443, 10000}, registration.Port) {
		return errors.New("invalid Tailscale Funnel port")
	}
	name, err := normalizeName(registration.Name)
	if err != nil || name != registration.Name {
		return errors.New("invalid Tailscale plan name")
	}
	target, err := normalizeTarget(registration.Target)
	if err != nil || target != registration.Target || registration.Port == 0 || registration.Host == "" {
		return errors.New("invalid Tailscale plan registration")
	}
	portFlag := "--https=" + strconv.FormatUint(uint64(registration.Port), 10)
	wantRegister := []string{string(registration.Mode), "--bg", "--yes", portFlag, "--set-path=/", target}
	wantCleanup := []string{string(registration.Mode), "--yes", portFlag, "--set-path=/", "off"}
	if plan.Register.Path == "" || plan.Cleanup.Path != plan.Register.Path || !filepath.IsAbs(plan.Register.Path) ||
		!slices.Equal(plan.Register.Args, wantRegister) || !slices.Equal(plan.Cleanup.Args, wantCleanup) {
		return errors.New("invalid Tailscale command plan")
	}
	return nil
}

func normalizeName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || len(name) > 63 || name[0] == '-' || name[len(name)-1] == '-' {
		return "", errors.New("invalid Tailscale application name")
	}
	for _, character := range name {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return "", errors.New("invalid Tailscale application name")
		}
	}
	return name, nil
}

func normalizeTarget(raw string) (string, error) {
	target, err := url.Parse(raw)
	if err != nil || target.Scheme != "http" || target.User != nil || target.Opaque != "" ||
		target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		return "", errors.New("tailscale target must be an HTTP loopback URL without a path")
	}
	address, err := netip.ParseAddr(target.Hostname())
	if err != nil || !address.IsLoopback() || address.Unmap() != netip.MustParseAddr("127.0.0.1") {
		return "", errors.New("tailscale target must use 127.0.0.1")
	}
	port, err := strconv.ParseUint(target.Port(), 10, 16)
	if err != nil || port == 0 {
		return "", errors.New("tailscale target requires a valid port")
	}
	return "http://127.0.0.1:" + strconv.FormatUint(port, 10), nil
}

func (c Client) executable() (string, error) {
	name := c.Executable
	if name == "" {
		name = defaultExecutable
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%w: find CLI: %v", ErrUnavailable, err)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve Tailscale CLI path: %w", err)
	}
	return path, nil
}

func (c Client) readOnly(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	return c.run(ctx, executable, arguments...)
}

func (c Client) run(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(commandContext, executable, arguments...)
	command.Stdin = strings.NewReader("")
	output := &boundedBuffer{limit: maxOutputBytes}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("capture Tailscale command output: %w", err)
	}
	command.Stderr = command.Stdout
	if err := command.Start(); err != nil {
		return nil, err
	}
	_, copyErr := io.Copy(output, stdout)
	if output.exceeded {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, errors.New("tailscale command output exceeded the size limit")
	}
	err = command.Wait()
	if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
		return nil, errors.New("tailscale command timed out")
	}
	if copyErr != nil {
		return nil, fmt.Errorf("read Tailscale command output: %w", copyErr)
	}
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return nil, fmt.Errorf("command exited with status %d", exitError.ExitCode())
		}
		return nil, err
	}
	return bytes.Clone(output.Bytes()), nil
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := b.limit - b.buffer.Len()
	if remaining <= 0 {
		b.exceeded = true
		return 0, errOutputLimit
	}
	if len(value) > remaining {
		b.exceeded = true
		_, _ = b.buffer.Write(value[:remaining])
		return 0, errOutputLimit
	}
	_, _ = b.buffer.Write(value)
	return original, nil
}

func (b *boundedBuffer) Bytes() []byte { return b.buffer.Bytes() }

type daemonStatus struct {
	BackendState string `json:"BackendState"`
	Self         *struct {
		DNSName string                     `json:"DNSName"`
		Online  bool                       `json:"Online"`
		CapMap  map[string]json.RawMessage `json:"CapMap"`
	} `json:"Self"`
}

type cliVersion struct {
	MajorMinorPatch string `json:"majorMinorPatch"`
}

type dnsStatus struct {
	TailscaleDNS   bool `json:"TailscaleDNS"`
	CurrentTailnet struct {
		MagicDNSEnabled bool   `json:"MagicDNSEnabled"`
		MagicDNSSuffix  string `json:"MagicDNSSuffix"`
		SelfDNSName     string `json:"SelfDNSName"`
	} `json:"CurrentTailnet"`
	CertDomains []string `json:"CertDomains"`
}

func hasCapability(capabilities map[string]json.RawMessage, name string) bool {
	_, exists := capabilities[name]
	return exists
}

func permittedFunnelPorts(capabilities map[string]json.RawMessage) ([]uint16, bool) {
	if !hasCapability(capabilities, "funnel") {
		return nil, false
	}
	const prefix = "https://tailscale.com/cap/funnel-ports?"
	permitted := make(map[uint16]struct{})
	for capability := range capabilities {
		if !strings.HasPrefix(capability, prefix) {
			continue
		}
		parsed, err := url.Parse(capability)
		if err != nil {
			continue
		}
		for token := range strings.SplitSeq(parsed.Query().Get("ports"), ",") {
			first, last := token, token
			if left, right, found := strings.Cut(token, "-"); found {
				first, last = left, right
			}
			start, startErr := strconv.ParseUint(first, 10, 16)
			end, endErr := strconv.ParseUint(last, 10, 16)
			if startErr != nil || endErr != nil || start == 0 || end < start {
				continue
			}
			for _, documented := range []uint16{443, 8443, 10000} {
				if uint64(documented) >= start && uint64(documented) <= end {
					permitted[documented] = struct{}{}
				}
			}
		}
	}
	ports := make([]uint16, 0, len(permitted))
	for port := range permitted {
		ports = append(ports, port)
	}
	slices.Sort(ports)
	return ports, len(ports) > 0
}

type serveStatus struct {
	TCP map[string]struct {
		HTTPS bool `json:"HTTPS"`
	} `json:"TCP"`
	Web map[string]struct {
		Handlers map[string]struct {
			Proxy string `json:"Proxy"`
		} `json:"Handlers"`
	} `json:"Web"`
	AllowFunnel map[string]bool `json:"AllowFunnel"`
}

func parseServeStatus(value []byte, dnsName string) (map[uint16]activeRegistration, []uint16, error) {
	var status serveStatus
	if err := decodeOne(value, &status); err != nil {
		return nil, nil, fmt.Errorf("parse Tailscale serve status: %w", err)
	}
	registrations := make(map[uint16]activeRegistration)
	used := make(map[uint16]struct{}, len(status.TCP)+len(status.Web))
	for rawPort, tcp := range status.TCP {
		port, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil || port == 0 {
			continue
		}
		portNumber := uint16(port)
		used[portNumber] = struct{}{}
		if !tcp.HTTPS {
			continue
		}
		key := dnsName + ":" + rawPort
		web, exists := status.Web[key]
		if !exists {
			continue
		}
		root, exists := web.Handlers["/"]
		if !exists || root.Proxy == "" {
			continue
		}
		registrations[portNumber] = activeRegistration{target: root.Proxy, funnel: status.AllowFunnel[key]}
	}
	for key := range status.Web {
		prefix := dnsName + ":"
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		port, err := strconv.ParseUint(strings.TrimPrefix(key, prefix), 10, 16)
		if err == nil && port != 0 {
			used[uint16(port)] = struct{}{}
		}
	}
	ports := make([]uint16, 0, len(used))
	for port := range used {
		ports = append(ports, port)
	}
	slices.Sort(ports)
	return registrations, ports, nil
}

func decodeOne(value []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

type semanticVersion struct{ major, minor, patch int }

func parseVersion(raw string) (semanticVersion, error) {
	raw = strings.TrimPrefix(raw, "v")
	raw, _, _ = strings.Cut(raw, "-")
	parts := strings.Split(raw, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return semanticVersion{}, errors.New("invalid version")
	}
	values := make([]int, 3)
	for index, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return semanticVersion{}, errors.New("invalid version")
		}
		values[index] = value
	}
	return semanticVersion{major: values[0], minor: values[1], patch: values[2]}, nil
}

func (v semanticVersion) less(other semanticVersion) bool {
	if v.major != other.major {
		return v.major < other.major
	}
	if v.minor != other.minor {
		return v.minor < other.minor
	}
	return v.patch < other.patch
}
