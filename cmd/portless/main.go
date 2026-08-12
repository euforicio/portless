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
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/euforicio/portless/internal/applecontainer"
	"github.com/euforicio/portless/internal/client"
	"github.com/euforicio/portless/internal/daemon"
	"github.com/euforicio/portless/internal/pki"
	"github.com/euforicio/portless/internal/profile"
	"github.com/euforicio/portless/internal/service"
)

var version = "0.0.0-dev"

const publicCACertificatePath = "/usr/local/share/portless/ca.pem"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		err := runProject(ctx, client.Client{SocketPath: socketPath()}, nil, stdout, stderr, false)
		return reportRunError(err, stderr)
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
	case "init":
		err = initCommand(ctx, management, arguments, stdout, stderr)
	case "install":
		err = install(ctx, arguments, false, stdout, stderr)
	case "upgrade":
		err = install(ctx, arguments, true, stdout, stderr)
	case "daemon":
		err = runDaemon(ctx, arguments, stderr)
	case "run":
		err = runProject(ctx, management, arguments, stdout, stderr, false)
	case "add":
		err = add(ctx, management, arguments, stdout, stderr)
	case "alias":
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
	case "proxy":
		err = proxyCommand(ctx, management, arguments, stdout, stderr)
	case "service":
		err = serviceCommand(ctx, management, arguments, stdout, stderr)
	case "trust":
		err = trustCommand(ctx, arguments, stdout, stderr)
	case "hosts":
		err = hostsCommand(ctx, management, arguments, stdout, stderr)
	case "prune":
		err = pruneCommand(ctx, management, arguments, stdout)
	case "clean":
		err = cleanCommand(ctx, management, arguments, stdout, stderr)
	case "uninstall":
		err = uninstall(ctx, arguments, stdout, stderr)
	default:
		err = runProject(ctx, management, args, stdout, stderr, true)
	}
	return reportRunError(err, stderr)
}

func reportRunError(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	var exit commandExitError
	if errors.As(err, &exit) {
		return exit.code
	}
	fmt.Fprintf(stderr, "portless: %v\n", err)
	return 1
}

func install(ctx context.Context, args []string, upgrade bool, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	flags.SetOutput(stderr)
	managementGroup := flags.String("management-group", "admin", "local group allowed to manage routes")
	containerCLI := flags.String("container-cli", "", "absolute Apple container executable")
	profileFlags := registerProfileFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected install argument %q", flags.Arg(0))
	}
	selectedProfile, _, err := profileFlags.config()
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("service installation requires root; run this command through an explicit privileged shell")
	}
	config, err := service.DefaultConfig(*managementGroup)
	if err != nil {
		return err
	}
	config.Profile = selectedProfile
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
	needsGeneratedCA := selectedProfile == nil || (selectedProfile.Scheme == profile.HTTPS && selectedProfile.Certificates.Mode == profile.GeneratedCertificates)
	if needsGeneratedCA {
		authority, err := pki.Open(filepath.Join(config.StateDir, "pki"), pki.Options{})
		if err != nil {
			return fmt.Errorf("open local authority: %w", err)
		}
		if err := pki.ApplyTrust(ctx, pki.TrustInstall, authority.RootCertificatePath()); err != nil {
			return fmt.Errorf("install local CA trust: %w", err)
		}
		if err := installPublicCA(authority.RootCertificatePath()); err != nil {
			return fmt.Errorf("install public CA metadata: %w", err)
		}
	} else {
		caPath := filepath.Join(config.StateDir, "pki", "ca.pem")
		if _, statErr := os.Lstat(caPath); statErr == nil {
			if err := pki.ApplyTrust(ctx, pki.TrustRemove, caPath); err != nil {
				return fmt.Errorf("remove unused local CA trust: %w", err)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		if err := removePublicCA(); err != nil {
			return fmt.Errorf("remove unused public CA metadata: %w", err)
		}
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
	if err := removePublicCA(); err != nil {
		return fmt.Errorf("remove public CA metadata: %w", err)
	}
	fmt.Fprintln(stdout, "uninstall complete; state and certificates retained")
	return nil
}

func installPublicCA(source string) error {
	directory := filepath.Dir(publicCACertificatePath)
	for _, parent := range []string{"/usr/local", "/usr/local/share"} {
		if err := validateRootDirectory(parent); err != nil {
			return err
		}
	}
	if info, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(directory, 0o755); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || fileUID(info) != 0 {
		return errors.New("public CA directory is unsafe")
	}
	if info, err := os.Lstat(publicCACertificatePath); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || fileUID(info) != 0 {
			return errors.New("public CA destination is unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".ca-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, publicCACertificatePath); err != nil {
		return err
	}
	parent, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func removePublicCA() error {
	info, err := os.Lstat(publicCACertificatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || fileUID(info) != 0 {
		return errors.New("refusing to remove unsafe public CA path")
	}
	return os.Remove(publicCACertificatePath)
}

func validateRootDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || fileUID(info) != 0 {
		return fmt.Errorf("unsafe root directory %s", path)
	}
	return nil
}

func fileUID(info os.FileInfo) uint32 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Uid
	}
	return ^uint32(0)
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
	profileScheme := flags.String("scheme", "", "custom profile scheme (http or https)")
	profileListen := flags.String("listen", "", "custom profile loopback listener")
	profileTLD := flags.String("tld", "", "custom profile DNS suffix")
	profileCert := flags.String("cert", "", "custom TLS certificate file")
	profileKey := flags.String("key", "", "custom TLS private key file")
	profileWildcard := flags.Bool("wildcard", false, "enable registered-parent fallback")
	reconcileProfile := flags.Bool("reconcile-profile", false, "replace persisted profile when no routes exist")
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
	httpListenersExplicit := len(httpListeners) != 0
	if len(httpListeners) == 0 {
		httpListeners = base.HTTPListeners
	}
	customProfile := *profileScheme != "" || *profileListen != "" || *profileTLD != "" || *profileCert != "" || *profileKey != "" || *profileWildcard
	if len(httpsListeners) == 0 && !customProfile {
		httpsListeners = base.HTTPSListeners
	}
	var selectedProfile *profile.Config
	if customProfile {
		scheme := profile.HTTPS
		if *profileScheme != "" {
			scheme = profile.Scheme(strings.ToLower(*profileScheme))
		}
		listen := *profileListen
		if listen == "" {
			listen = "127.0.0.1:443"
			if scheme == profile.HTTP {
				listen = "127.0.0.1:80"
			}
		}
		tld := *profileTLD
		if tld == "" {
			tld = ".localhost"
		}
		certificates := profile.CertificateConfig{}
		if scheme == profile.HTTPS {
			certificates.Mode = profile.GeneratedCertificates
			if *profileCert != "" || *profileKey != "" {
				certificates = profile.CertificateConfig{Mode: profile.CertificateFiles, CertFile: *profileCert, KeyFile: *profileKey}
			}
		}
		value := profile.Config{Scheme: scheme, ListenAddress: listen, TLD: tld, WildcardFallback: *profileWildcard, Certificates: certificates}
		selectedProfile = &value
		// A custom profile is the sole public listener unless explicit redirect
		// listeners were supplied.
		if !httpListenersExplicit {
			httpListeners = nil
		}
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
		Profile:          selectedProfile,
		ReconcileProfile: *reconcileProfile,
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
	profileStatus, err := managementStatus(ctx, management)
	if err != nil {
		return err
	}
	name, err := client.NormalizeNameForTLD(args[0], profileStatus.TLD)
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
	force := flags.Bool("force", false, "replace an existing route explicitly")
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
		if err != nil || (!address.IsLoopback() && (!address.IsPrivate() || address.IsLinkLocalUnicast())) {
			return errors.New("--host must be a loopback or private unicast IP address")
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

	match := client.RouteMatchAbsent
	if *force {
		match = client.RouteMatchAny
	}
	_, err = management.Call(ctx, client.Request{Operation: client.OperationAdd, Route: &route, Match: match})
	if err != nil {
		return err
	}
	publicURL, _ := publicRouteURL(profileStatus, route.Name)
	fmt.Fprintln(stdout, publicURL)
	return nil
}

func remove(ctx context.Context, management client.Client, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: portless remove NAME [--force]")
	}
	profileStatus, err := managementStatus(ctx, management)
	if err != nil {
		return err
	}
	name, err := client.NormalizeNameForTLD(args[0], profileStatus.TLD)
	if err != nil {
		return err
	}
	force := false
	for _, argument := range args[1:] {
		if argument != "--force" || force {
			return errors.New("usage: portless remove NAME [--force]")
		}
		force = true
	}
	request := client.Request{Operation: client.OperationRemove, Name: name, Match: client.RouteMatchAny}
	if !force {
		current, currentErr := currentRoute(ctx, management, name)
		if currentErr != nil {
			return currentErr
		}
		request.Match = client.RouteMatchOwner
		request.ExpectedOwner = &current.Owner
	}
	_, err = management.Call(ctx, request)
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
	profileStatus, statusErr := managementStatus(ctx, management)
	if statusErr != nil {
		return statusErr
	}
	shares, shareErr := ownedShares()
	if shareErr != nil {
		return shareErr
	}
	sharedURLs := make(map[string]string, len(shares))
	lanExposures, lanErr := ownedLANExposures()
	if lanErr != nil {
		return lanErr
	}
	for _, exposure := range lanExposures {
		label := strings.TrimSuffix(exposure.Registration.Name, ".local")
		if lanURL := exposure.Registration.URL(); lanURL != "" {
			sharedURLs[label] = lanURL
		}
	}
	for _, share := range shares {
		authority := share.Plan.Registration.Host
		if share.Plan.Registration.Port != 443 {
			authority = net.JoinHostPort(authority, strconv.Itoa(int(share.Plan.Registration.Port)))
		}
		value := "https://" + authority
		if existing := sharedURLs[share.Plan.Registration.Name]; existing != "" {
			value = existing + ", " + value
		}
		sharedURLs[share.Plan.Registration.Name] = value
	}
	fmt.Fprintln(writer, "NAME\tURL\tSHARED\tOWNER\tUPSTREAM\tREFRESH")
	for _, route := range response.Routes {
		owner := string(route.Owner.Kind)
		if route.Owner.Kind == client.OwnerProcess {
			owner += ":" + strconv.Itoa(route.Owner.PID)
		}
		if route.Owner.Kind == client.OwnerContainer {
			owner += ":" + route.Owner.Container + "/" + route.Owner.Network
		}
		upstream := route.Scheme + "://" + net.JoinHostPort(route.Host, strconv.Itoa(int(route.Port)))
		publicURL, _ := publicRouteURL(profileStatus, route.Name)
		label := strings.SplitN(route.Name, ".", 2)[0]
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\n", route.Name, publicURL, sharedURLs[label], owner, upstream, route.Owner.Refresh)
	}
	return nil
}

func managementStatus(ctx context.Context, management client.Client) (client.Status, error) {
	response, err := management.Call(ctx, client.Request{Operation: client.OperationStatus})
	path := management.SocketPath
	if path == "" {
		path = client.DefaultSocketPath
	}
	if err != nil && runtime.GOOS == "darwin" && path == client.DefaultSocketPath {
		command := exec.CommandContext(ctx, "/bin/launchctl", "kickstart", "system/"+service.DefaultLabel)
		if startErr := command.Run(); startErr == nil {
			if waitErr := waitForDaemon(ctx, path); waitErr == nil {
				response, err = management.Call(ctx, client.Request{Operation: client.OperationStatus})
			}
		}
	}
	if err != nil {
		return client.Status{}, err
	}
	if response.Status == nil || response.Status.TLD == "" || response.Status.Scheme == "" || response.Status.ListenAddress == "" {
		return client.Status{}, errors.New("management server returned an incomplete proxy profile")
	}
	return *response.Status, nil
}

func publicRouteURL(status client.Status, name string) (string, error) {
	_, port, err := net.SplitHostPort(status.ListenAddress)
	if err != nil {
		return "", errors.New("management server returned an invalid profile listener")
	}
	authority := name
	if (status.Scheme == "https" && port != "443") || (status.Scheme == "http" && port != "80") {
		authority = net.JoinHostPort(name, port)
	}
	return status.Scheme + "://" + authority, nil
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
	fmt.Fprintln(output, "       portless NAME COMMAND [ARGS...]")
	fmt.Fprintln(output, "commands: init, run, alias, add, remove, list, proxy, service, trust, hosts, prune, clean, doctor, version")
}
