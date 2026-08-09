// Package runner starts and supervises framework-independent local processes
// under stable Portless route names.
package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/euforicio/portless/internal/client"
	"github.com/euforicio/portless/internal/projectconfig"
)

const defaultStopTimeout = 5 * time.Second

var (
	ErrAlreadyRunning   = errors.New("runner process is already running")
	ErrNotTracked       = errors.New("runner process is not tracked")
	ErrIdentityMismatch = errors.New("runner process identity does not match")
	ErrProcessGone      = errors.New("process does not exist")
)

// Identity is the PID plus kernel process-start identity used by process-owned
// routes. A PID without Start is never sufficient to authorize a signal.
type Identity struct {
	PID   int   `json:"pid"`
	Start int64 `json:"start"`
}

// Endpoint describes the environment and loopback endpoint assigned to a run.
type Endpoint struct {
	Name  string `json:"name"`
	Proxy bool   `json:"proxy"`
	Host  string `json:"host,omitempty"`
	Port  uint16 `json:"port,omitempty"`
	URL   string `json:"url,omitempty"`
}

// Spec describes one direct child-process execution.
type Spec struct {
	Name             string
	TLD              string
	PublicURL        string
	Command          []string
	WorkingDirectory string
	Environment      map[string]string
	AppPort          uint16
	Proxy            bool
	NodeExtraCACerts string
	StopTimeout      time.Duration
	Stdin            io.Reader
	Stdout           io.Writer
	Stderr           io.Writer
}

// Result preserves the child's exact exit status.
type Result struct {
	Identity Identity
	ExitCode int
	Signaled bool
	Signal   syscall.Signal
}

// Process is one supervised real child process.
type Process struct {
	manager     *Manager
	command     *exec.Cmd
	record      Record
	stopTimeout time.Duration
	done        chan struct{}
	waitOnce    sync.Once
	waitResult  Result
	waitErr     error
}

// Start launches a direct argv command after reserving its loopback port and
// records its exact kernel identity before returning.
func (manager *Manager) Start(ctx context.Context, spec Spec) (*Process, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	validated, err := validateSpec(spec)
	if err != nil {
		return nil, err
	}

	var process *Process
	err = manager.withStateLock(func(state *persistedState) error {
		if existing, ok := findRecord(state.Records, validated.endpoint.Name); ok {
			alive, err := probeRecord(existing)
			if err != nil {
				return fmt.Errorf("inspect existing runner process: %w", err)
			}
			if alive {
				return fmt.Errorf("%w: %s is owned by PID %d", ErrAlreadyRunning, existing.Endpoint.Name, existing.Identity.PID)
			}
			state.Records = deleteRecord(state.Records, existing.Endpoint.Name, existing.Identity)
		}

		reservation, port, err := reserveLoopbackPort(validated.spec.AppPort, validated.spec.Proxy)
		if err != nil {
			return err
		}
		if reservation != nil {
			defer reservation.Close()
		}
		validated.endpoint.Port = port
		if validated.spec.Proxy {
			validated.endpoint.Host = "127.0.0.1"
			validated.endpoint.URL = validated.spec.PublicURL
			if validated.endpoint.URL == "" {
				validated.endpoint.URL = "https://" + validated.endpoint.Name
			}
		}

		command := exec.Command(validated.spec.Command[0], validated.spec.Command[1:]...)
		command.Dir = validated.spec.WorkingDirectory
		command.Env = buildEnvironment(os.Environ(), validated.spec.Environment, validated.endpoint, validated.spec.NodeExtraCACerts)
		command.Stdin = validated.spec.Stdin
		command.Stdout = validated.spec.Stdout
		command.Stderr = validated.spec.Stderr
		command.SysProcAttr = processGroupAttributes()

		// A generic child cannot inherit and bind the same TCP listener. Keep the
		// reservation until the last possible moment, then execute immediately.
		if reservation != nil {
			if err := reservation.Close(); err != nil {
				return fmt.Errorf("release loopback port reservation: %w", err)
			}
			reservation = nil
		}
		if err := command.Start(); err != nil {
			return fmt.Errorf("start command: %w", err)
		}

		uid, identity, processGroup, err := inspectProcess(command.Process.Pid)
		if err != nil || processGroup != command.Process.Pid {
			_ = command.Process.Kill()
			_ = command.Wait()
			if err != nil {
				return fmt.Errorf("inspect started process: %w", err)
			}
			return errors.New("started process does not own its process group")
		}
		supervisorUID, supervisorIdentity, _, err := inspectProcess(os.Getpid())
		if err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return fmt.Errorf("inspect runner supervisor: %w", err)
		}
		record := Record{
			Endpoint:         validated.endpoint,
			Identity:         identity,
			ProcessGroup:     processGroup,
			UID:              uid,
			Supervisor:       supervisorIdentity,
			SupervisorUID:    supervisorUID,
			WorkingDirectory: validated.spec.WorkingDirectory,
		}
		state.Records = append(state.Records, record)
		if err := validateState(*state); err != nil {
			_ = signalRecord(record, syscall.SIGKILL)
			_ = command.Wait()
			return err
		}
		process = &Process{
			manager:     manager,
			command:     command,
			record:      record,
			stopTimeout: validated.spec.StopTimeout,
			done:        make(chan struct{}),
		}
		return nil
	})
	if err != nil {
		if process != nil {
			if signalErr := signalRecord(process.record, syscall.SIGKILL); signalErr != nil {
				// This is still our unreaped direct child, so its PID cannot be
				// reused. Fall back to the process handle if it changed groups.
				_ = process.command.Process.Kill()
			}
			_ = process.command.Wait()
		}
		return nil, err
	}

	go process.stopOnCancellation(ctx)
	return process, nil
}

// Run starts a child, forwards signals received on signals, and waits for its
// exact exit status. A non-zero exit returns the underlying *exec.ExitError.
func (manager *Manager) Run(ctx context.Context, spec Spec, signals <-chan os.Signal) (Result, error) {
	process, err := manager.Start(ctx, spec)
	if err != nil {
		return Result{}, err
	}
	stopForwarding := process.Forward(signals)
	defer stopForwarding()
	return process.Wait()
}

// Identity returns the exact process identity used for route ownership.
func (process *Process) Identity() Identity { return process.record.Identity }

// Endpoint returns the assigned stable name and loopback endpoint.
func (process *Process) Endpoint() Endpoint { return process.record.Endpoint }

// PID returns the child process ID.
func (process *Process) PID() int { return process.record.Identity.PID }

// Signal forwards one Unix signal to the verified runner-owned process group.
func (process *Process) Signal(signal os.Signal) error {
	unixSignal, ok := signal.(syscall.Signal)
	if !ok {
		return fmt.Errorf("unsupported signal %T", signal)
	}
	return signalRecord(process.record, unixSignal)
}

// Forward begins forwarding signals until Wait completes or the returned stop
// function is called. A nil channel is a no-op.
func (process *Process) Forward(signals <-chan os.Signal) func() {
	stop := make(chan struct{})
	var once sync.Once
	if signals != nil {
		go func() {
			for {
				select {
				case signal, ok := <-signals:
					if !ok {
						return
					}
					_ = process.Signal(signal)
				case <-process.done:
					return
				case <-stop:
					return
				}
			}
		}()
	}
	return func() { once.Do(func() { close(stop) }) }
}

// Wait reaps the process, removes only its matching durable record, and
// returns an exact exit code and terminating signal.
func (process *Process) Wait() (Result, error) {
	process.waitOnce.Do(func() {
		process.waitErr = process.command.Wait()
		state := process.command.ProcessState
		process.waitResult = Result{Identity: process.record.Identity, ExitCode: -1}
		if state != nil {
			process.waitResult.ExitCode = state.ExitCode()
			if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				process.waitResult.Signaled = true
				process.waitResult.Signal = status.Signal()
			}
		}
		_ = process.manager.removeMatching(process.record.Endpoint.Name, process.record.Identity)
		close(process.done)
	})
	<-process.done
	return process.waitResult, process.waitErr
}

func (process *Process) stopOnCancellation(ctx context.Context) {
	select {
	case <-ctx.Done():
		_ = signalRecord(process.record, syscall.SIGTERM)
		timer := time.NewTimer(process.stopTimeout)
		defer timer.Stop()
		select {
		case <-process.done:
			return
		case <-timer.C:
			_ = signalRecord(process.record, syscall.SIGKILL)
		}
	case <-process.done:
	}
}

type validatedSpec struct {
	spec     Spec
	endpoint Endpoint
}

func validateSpec(spec Spec) (validatedSpec, error) {
	name, err := client.NormalizeNameForTLD(spec.Name, spec.TLD)
	if err != nil {
		return validatedSpec{}, fmt.Errorf("invalid runner name: %w", err)
	}
	if len(spec.Command) == 0 || spec.Command[0] == "" {
		return validatedSpec{}, errors.New("runner command must contain an executable")
	}
	if len(spec.Command) > 256 {
		return validatedSpec{}, errors.New("runner command has too many arguments")
	}
	for index, argument := range spec.Command {
		if strings.IndexByte(argument, 0) >= 0 || len(argument) > 32<<10 {
			return validatedSpec{}, fmt.Errorf("runner command argument %d is invalid", index)
		}
	}
	if spec.WorkingDirectory == "" {
		spec.WorkingDirectory, err = os.Getwd()
		if err != nil {
			return validatedSpec{}, err
		}
	}
	spec.WorkingDirectory, err = filepath.Abs(spec.WorkingDirectory)
	if err != nil {
		return validatedSpec{}, err
	}
	spec.WorkingDirectory, err = filepath.EvalSymlinks(spec.WorkingDirectory)
	if err != nil {
		return validatedSpec{}, fmt.Errorf("resolve runner working directory: %w", err)
	}
	info, err := os.Stat(spec.WorkingDirectory)
	if err != nil || !info.IsDir() {
		return validatedSpec{}, errors.New("runner working directory must be a real directory")
	}
	if !spec.Proxy && spec.AppPort != 0 {
		return validatedSpec{}, errors.New("fixed app port requires proxy to be enabled")
	}
	if spec.PublicURL != "" {
		if !spec.Proxy {
			return validatedSpec{}, errors.New("public URL requires proxy to be enabled")
		}
		parsed, parseErr := url.Parse(spec.PublicURL)
		if parseErr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Hostname() != name || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return validatedSpec{}, errors.New("public URL must be an HTTP(S) origin for the runner name")
		}
		if parsed.Port() != "" {
			if value, portErr := strconv.ParseUint(parsed.Port(), 10, 16); portErr != nil || value == 0 {
				return validatedSpec{}, errors.New("public URL has an invalid port")
			}
		}
	}
	if len(spec.Environment) > 256 {
		return validatedSpec{}, errors.New("runner environment has too many entries")
	}
	for key, value := range spec.Environment {
		if err := projectconfig.ValidateEnvironmentKey(key); err != nil {
			return validatedSpec{}, err
		}
		if key == "PORT" || key == "HOST" || key == "PORTLESS_URL" || key == "NODE_EXTRA_CA_CERTS" {
			return validatedSpec{}, fmt.Errorf("environment key %q is managed by the runner", key)
		}
		if strings.IndexByte(value, 0) >= 0 || len(value) > 32<<10 {
			return validatedSpec{}, fmt.Errorf("environment value for %q is invalid", key)
		}
	}
	if spec.NodeExtraCACerts != "" {
		if !spec.Proxy {
			return validatedSpec{}, errors.New("NODE_EXTRA_CA_CERTS requires proxy to be enabled")
		}
		if !filepath.IsAbs(spec.NodeExtraCACerts) {
			return validatedSpec{}, errors.New("NODE_EXTRA_CA_CERTS path must be absolute")
		}
		info, err := os.Lstat(spec.NodeExtraCACerts)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return validatedSpec{}, errors.New("NODE_EXTRA_CA_CERTS path must be a regular file, not a symlink")
		}
	}
	if spec.StopTimeout <= 0 {
		spec.StopTimeout = defaultStopTimeout
	}
	return validatedSpec{spec: spec, endpoint: Endpoint{Name: name, Proxy: spec.Proxy}}, nil
}

func reserveLoopbackPort(requested uint16, proxy bool) (net.Listener, uint16, error) {
	if !proxy {
		return nil, 0, nil
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(requested))))
	if err != nil {
		return nil, 0, fmt.Errorf("reserve loopback app port: %w", err)
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.IP.String() != "127.0.0.1" || address.Port <= 0 || address.Port > 65535 {
		listener.Close()
		return nil, 0, errors.New("listener returned an invalid loopback port")
	}
	return listener, uint16(address.Port), nil
}

func buildEnvironment(base []string, configured map[string]string, endpoint Endpoint, nodeExtraCACerts string) []string {
	values := make(map[string]string, len(base)+len(configured)+4)
	for _, entry := range base {
		if key, value, ok := strings.Cut(entry, "="); ok && key != "" {
			values[key] = value
		}
	}
	for key, value := range configured {
		values[key] = value
	}
	if endpoint.Proxy {
		values["PORT"] = strconv.Itoa(int(endpoint.Port))
		values["HOST"] = endpoint.Host
		values["PORTLESS_URL"] = endpoint.URL
	}
	if nodeExtraCACerts != "" {
		values["NODE_EXTRA_CA_CERTS"] = nodeExtraCACerts
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+values[key])
	}
	return environment
}
