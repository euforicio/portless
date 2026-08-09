package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/euforicio/portless/internal/applecontainer"
	"github.com/euforicio/portless/internal/client"
	"github.com/euforicio/portless/internal/daemon"
	"github.com/euforicio/portless/internal/pki"
	"github.com/euforicio/portless/internal/service"
)

const version = "0.0.0-dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	operation := args[0]
	arguments := args[1:]
	if operation == "version" {
		if len(arguments) != 0 {
			fmt.Fprintln(stderr, "portless: version does not accept arguments")
			return 2
		}
		fmt.Fprintln(stdout, version)
		return 0
	}
	if operation == "help" || operation == "-h" || operation == "--help" {
		printUsage(stdout)
		return 0
	}

	management := client.Client{SocketPath: socketPath()}
	var err error
	switch operation {
	case "install":
		err = install(ctx, arguments, false, stdout, stderr)
	case "upgrade":
		err = install(ctx, arguments, true, stdout, stderr)
	case "daemon":
		err = runDaemon(ctx, arguments, stderr)
	case "add":
		err = add(ctx, management, arguments, stdout, stderr)
	case "remove":
		err = remove(ctx, management, arguments, stdout)
	case "list":
		err = list(ctx, management, arguments, stdout)
	case "status":
		err = status(ctx, management, arguments, stdout)
	case "doctor":
		err = doctor(ctx, management, arguments, stdout)
	case "refresh":
		err = refresh(ctx, management, arguments, stdout)
	case "uninstall":
		err = uninstall(ctx, arguments, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "portless: unknown command %q\n", operation)
		printUsage(stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "portless: %v\n", err)
		return 1
	}
	return 0
}

func install(ctx context.Context, args []string, upgrade bool, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	flags.SetOutput(stderr)
	managementGroup := flags.String("management-group", "admin", "local group allowed to manage routes")
	containerCLI := flags.String("container-cli", "", "absolute Apple container executable")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected install argument %q", flags.Arg(0))
	}
	if os.Geteuid() != 0 {
		return errors.New("service installation requires root; run this command through an explicit privileged shell")
	}
	config, err := service.DefaultConfig(*managementGroup)
	if err != nil {
		return err
	}
	if *containerCLI != "" {
		if !filepath.IsAbs(*containerCLI) {
			return errors.New("--container-cli must be absolute")
		}
		config.ContainerExecutable = *containerCLI
	}
	source, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current executable: %w", err)
	}
	installer := service.Installer{Config: config}
	var report service.Report
	if upgrade {
		report, err = installer.Upgrade(source)
	} else {
		report, err = installer.Install(source)
	}
	if err != nil {
		return fmt.Errorf("write service artifacts: %w", err)
	}
	authority, err := pki.Open(filepath.Join(config.StateDir, "pki"), pki.Options{})
	if err != nil {
		return fmt.Errorf("open local authority: %w", err)
	}
	if err := pki.ApplyTrust(ctx, pki.TrustInstall, authority.RootCertificatePath()); err != nil {
		return fmt.Errorf("install local CA trust: %w", err)
	}
	loaded, err := config.Loaded(ctx)
	if err != nil {
		return fmt.Errorf("inspect launchd service: %w", err)
	}
	if report.HasChanges() || !loaded {
		action := service.ActionInstall
		if upgrade {
			action = service.ActionUpgrade
		}
		commands, err := config.Commands(action)
		if err != nil {
			return err
		}
		if err := service.ApplyCommands(ctx, commands); err != nil {
			return fmt.Errorf("start launchd service: %w", err)
		}
	}
	if err := waitForDaemon(ctx, config.ManagementSocket); err != nil {
		return err
	}
	operation := "install"
	if upgrade {
		operation = "upgrade"
	}
	fmt.Fprintf(stdout, "%s complete\n", operation)
	return nil
}

func uninstall(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	flags.SetOutput(stderr)
	managementGroup := flags.String("management-group", "admin", "installed management group")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected uninstall argument %q", flags.Arg(0))
	}
	if os.Geteuid() != 0 {
		return errors.New("service removal requires root; run this command through an explicit privileged shell")
	}
	config, err := service.DefaultConfig(*managementGroup)
	if err != nil {
		return err
	}
	commands, err := config.Commands(service.ActionUninstall)
	if err != nil {
		return err
	}
	if err := service.ApplyCommands(ctx, commands); err != nil {
		return fmt.Errorf("stop launchd service: %w", err)
	}
	caPath := filepath.Join(config.StateDir, "pki", "ca.pem")
	if _, err := os.Lstat(caPath); err == nil {
		if err := pki.ApplyTrust(ctx, pki.TrustRemove, caPath); err != nil {
			return fmt.Errorf("remove local CA trust: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := (service.Installer{Config: config}).Uninstall(); err != nil {
		return fmt.Errorf("remove service artifacts: %w", err)
	}
	fmt.Fprintln(stdout, "uninstall complete; state and certificates retained")
	return nil
}

func waitForDaemon(ctx context.Context, path string) error {
	deadline := time.Now().Add(10 * time.Second)
	management := client.Client{SocketPath: path, Timeout: time.Second}
	for {
		if _, err := management.Call(ctx, client.Request{Operation: client.OperationStatus}); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("launchd service did not become ready")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func runDaemon(ctx context.Context, args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("daemon", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDir := flags.String("state-dir", "", "absolute daemon state directory")
	managementSocket := flags.String("management-socket", "", "absolute management socket")
	managementGroup := flags.String("management-group", "admin", "management group")
	containerCLI := flags.String("container-cli", "", "absolute Apple container executable")
	refreshInterval := flags.Duration("refresh-interval", 5*time.Second, "owner refresh interval")
	var httpListeners stringList
	var httpsListeners stringList
	flags.Var(&httpListeners, "http-listen", "literal loopback HTTP listener")
	flags.Var(&httpsListeners, "https-listen", "literal loopback HTTPS listener")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected daemon argument %q", flags.Arg(0))
	}
	base, err := service.DefaultConfig(*managementGroup)
	if err != nil {
		return err
	}
	if *stateDir == "" {
		*stateDir = base.StateDir
	}
	if *managementSocket == "" {
		*managementSocket = base.ManagementSocket
	}
	if *containerCLI == "" {
		*containerCLI = base.ContainerExecutable
	}
	if len(httpListeners) == 0 {
		httpListeners = base.HTTPListeners
	}
	if len(httpsListeners) == 0 {
		httpsListeners = base.HTTPSListeners
	}
	group, err := user.LookupGroup(*managementGroup)
	if err != nil {
		return fmt.Errorf("look up management group: %w", err)
	}
	managementGID, err := strconv.Atoi(group.Gid)
	if err != nil {
		return errors.New("management group has invalid GID")
	}
	runtime, err := daemon.Start(ctx, daemon.Config{
		StateDir:         *stateDir,
		ManagementSocket: *managementSocket,
		ManagementUID:    os.Geteuid(),
		ManagementGID:    managementGID,
		HTTPListeners:    httpListeners,
		HTTPSListeners:   httpsListeners,
		ContainerCLI:     *containerCLI,
		RefreshInterval:  *refreshInterval,
		Version:          version,
	})
	if err != nil {
		return err
	}
	return runtime.Wait()
}

func add(ctx context.Context, management client.Client, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: portless add NAME --port PORT [--pid PID] [--protocol http|https]\n       portless add NAME --container ID [--port PORT] [--protocol http|https]")
	}
	name, err := client.NormalizeName(args[0])
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("add", flag.ContinueOnError)
	flags.SetOutput(stderr)
	containerID := flags.String("container", "", "Apple container ID")
	portValue := flags.Uint("port", 0, "upstream TCP port")
	protocol := flags.String("protocol", "http", "upstream protocol (http or https)")
	host := flags.String("host", "127.0.0.1", "static loopback upstream address")
	pid := flags.Int("pid", 0, "own the route with a local process")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected add argument %q", flags.Arg(0))
	}
	if *portValue > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	upstreamProtocol := strings.ToLower(strings.TrimSpace(*protocol))
	if upstreamProtocol != "http" && upstreamProtocol != "https" {
		return fmt.Errorf("unsupported protocol %q", *protocol)
	}

	route := client.Route{Name: name, Scheme: upstreamProtocol}
	if *containerID != "" {
		if *pid != 0 || *host != "127.0.0.1" {
			return errors.New("--container cannot be combined with --pid or --host")
		}
		resolver := applecontainer.Resolver{Executable: os.Getenv("PORTLESS_CONTAINER_CLI")}
		endpoint, err := resolver.Resolve(ctx, *containerID, uint16(*portValue), upstreamProtocol)
		if err != nil {
			return err
		}
		route.Host = endpoint.Address.String()
		route.Port = endpoint.Port
		route.Owner = client.Owner{
			Kind:      client.OwnerContainer,
			Container: endpoint.Container,
			Network:   endpoint.Network,
			Refresh:   client.RefreshContainerAddress,
		}
	} else {
		if *portValue == 0 {
			return errors.New("--port is required for a local route")
		}
		address, err := netip.ParseAddr(*host)
		if err != nil || !address.IsLoopback() {
			return errors.New("--host must be a loopback IP address")
		}
		route.Host = address.Unmap().String()
		route.Port = uint16(*portValue)
		if *pid < 0 {
			return errors.New("--pid must be a positive process ID")
		}
		if *pid > 0 {
			route.Owner = client.Owner{Kind: client.OwnerProcess, PID: *pid, Refresh: client.RefreshNever}
		} else {
			route.Owner = client.Owner{Kind: client.OwnerStatic, Refresh: client.RefreshNever}
		}
	}
	if err := route.Validate(); err != nil {
		return err
	}

	_, err = management.Call(ctx, client.Request{Operation: client.OperationAdd, Route: &route})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "https://%s\n", route.Name)
	return nil
}

func remove(ctx context.Context, management client.Client, args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: portless remove NAME")
	}
	name, err := client.NormalizeName(args[0])
	if err != nil {
		return err
	}
	_, err = management.Call(ctx, client.Request{Operation: client.OperationRemove, Name: name})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "removed %s\n", name)
	return nil
}

func list(ctx context.Context, management client.Client, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: portless list")
	}
	response, err := management.Call(ctx, client.Request{Operation: client.OperationList})
	if err != nil {
		return err
	}
	writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	defer writer.Flush()
	fmt.Fprintln(writer, "NAME\tOWNER\tUPSTREAM\tREFRESH")
	for _, route := range response.Routes {
		owner := string(route.Owner.Kind)
		if route.Owner.Kind == client.OwnerProcess {
			owner += ":" + strconv.Itoa(route.Owner.PID)
		}
		if route.Owner.Kind == client.OwnerContainer {
			owner += ":" + route.Owner.Container + "/" + route.Owner.Network
		}
		upstream := route.Scheme + "://" + net.JoinHostPort(route.Host, strconv.Itoa(int(route.Port)))
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", route.Name, owner, upstream, route.Owner.Refresh)
	}
	return nil
}

func status(ctx context.Context, management client.Client, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: portless status")
	}
	response, err := management.Call(ctx, client.Request{Operation: client.OperationStatus})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(stdout, "stopped")
			return nil
		}
		return err
	}
	if response.Status == nil {
		return errors.New("management server returned no status")
	}
	state := "stopped"
	if response.Status.Running {
		state = "running"
	}
	fmt.Fprintln(stdout, state)
	if response.Status.Version != "" {
		fmt.Fprintf(stdout, "version: %s\n", response.Status.Version)
	}
	if response.Status.SocketPath != "" {
		fmt.Fprintf(stdout, "socket: %s\n", response.Status.SocketPath)
	}
	return nil
}

func doctor(ctx context.Context, management client.Client, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: portless doctor")
	}
	response, err := management.Call(ctx, client.Request{Operation: client.OperationDoctor})
	if err != nil {
		return err
	}
	if len(response.Diagnostics) == 0 {
		fmt.Fprintln(stdout, "ok")
		return nil
	}
	failed := false
	for _, diagnostic := range response.Diagnostics {
		fmt.Fprintf(stdout, "%s\t%s\t%s\n", diagnostic.Level, diagnostic.Name, diagnostic.Message)
		if diagnostic.Level == "error" {
			failed = true
		}
	}
	if failed {
		return errors.New("one or more checks failed")
	}
	return nil
}

func refresh(ctx context.Context, management client.Client, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: portless refresh")
	}
	response, err := management.Call(ctx, client.Request{Operation: client.OperationRefresh})
	if err != nil {
		return err
	}
	if len(response.Diagnostics) == 0 {
		fmt.Fprintln(stdout, "refresh complete")
		return nil
	}
	failed := false
	for _, diagnostic := range response.Diagnostics {
		fmt.Fprintf(stdout, "%s\t%s\t%s\n", diagnostic.Level, diagnostic.Name, diagnostic.Message)
		if diagnostic.Level == "error" {
			failed = true
		}
	}
	if failed {
		return errors.New("one or more routes could not be refreshed")
	}
	return nil
}

func socketPath() string {
	if value := os.Getenv("PORTLESS_SOCKET"); value != "" {
		return value
	}
	return client.DefaultSocketPath
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: portless <command> [options]")
	fmt.Fprintln(output, "commands: install, upgrade, add, remove, list, status, doctor, refresh, uninstall, version")
}
