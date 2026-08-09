package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/euforicio/portless/internal/client"
	"github.com/euforicio/portless/internal/hosts"
	"github.com/euforicio/portless/internal/mdns"
	"github.com/euforicio/portless/internal/pki"
	"github.com/euforicio/portless/internal/profile"
	"github.com/euforicio/portless/internal/routes"
	"github.com/euforicio/portless/internal/runner"
	"github.com/euforicio/portless/internal/service"
	"github.com/euforicio/portless/internal/tailscale"
)

func initCommand(ctx context.Context, management client.Client, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	group := flags.String("management-group", "admin", "local group allowed to manage routes")
	profileFlags := registerProfileFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected init argument %q", flags.Arg(0))
	}
	selectedProfile, profileArguments, err := profileFlags.config()
	if err != nil {
		return err
	}
	if selectedProfile == nil {
		active, found := activeNonDefaultProfile(ctx, management)
		if !found && runtime.GOOS == "darwin" {
			start := exec.CommandContext(ctx, "/bin/launchctl", "kickstart", "system/"+service.DefaultLabel)
			if start.Run() == nil {
				_ = waitForDaemon(ctx, management.SocketPath)
				active, found = activeNonDefaultProfile(ctx, management)
			}
		}
		if found {
			selectedProfile = &active
			profileArguments = profileCommandArguments(active)
		}
	}
	if runtime.GOOS != "darwin" {
		return errors.New("init is supported only on macOS")
	}
	managementGroup, err := user.LookupGroup(*group)
	if err != nil {
		return fmt.Errorf("preflight management group: %w", err)
	}
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("preflight current user: %w", err)
	}
	groupIDs, err := currentUser.GroupIds()
	if err != nil {
		return fmt.Errorf("preflight user groups: %w", err)
	}
	if os.Geteuid() != 0 && !slices.Contains(groupIDs, managementGroup.Gid) {
		return fmt.Errorf("current user is not a member of management group %q", *group)
	}
	if selectedProfile != nil {
		if err := validateSelectedProfile(*selectedProfile); err != nil {
			return fmt.Errorf("preflight proxy profile: %w", err)
		}
	}
	optionalToolPreflight(stderr)
	if selectedProfile != nil {
		if err := preflightProfileChange(ctx, management, *selectedProfile); err != nil {
			return err
		}
	}
	artifactsCurrent, artifactDetail := installationMatches(*group, selectedProfile)
	if healthy, detail := daemonHealthy(ctx, management); healthy && artifactsCurrent {
		fmt.Fprintf(stdout, "portless is ready (%s)\n", detail)
		return nil
	}
	start := exec.CommandContext(ctx, "/bin/launchctl", "kickstart", "system/"+service.DefaultLabel)
	if start.Run() == nil {
		_ = waitForDaemon(ctx, management.SocketPath)
		artifactsCurrent, artifactDetail = installationMatches(*group, selectedProfile)
		if healthy, detail := daemonHealthy(ctx, management); healthy && artifactsCurrent {
			fmt.Fprintf(stdout, "portless is ready (%s)\n", detail)
			return nil
		}
	}
	if artifactDetail != "" {
		fmt.Fprintf(stderr, "preflight: %s\n", artifactDetail)
	}
	if err := validateFixedExecutable("/usr/bin/sudo"); err != nil {
		return fmt.Errorf("preflight privilege helper: %w", err)
	}
	for _, address := range []string{"127.0.0.1:80", "127.0.0.1:443"} {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			fmt.Fprintf(stderr, "preflight: %s is currently occupied; installation will verify service ownership\n", address)
		}
	}
	source, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current executable: %w", err)
	}
	privilegedArguments := []string{"--", source, "upgrade", "--management-group", *group}
	privilegedArguments = append(privilegedArguments, profileArguments...)
	command := exec.CommandContext(ctx, "/usr/bin/sudo", privilegedArguments...)
	command.Stdin = os.Stdin
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("privileged reconciliation: %w", err)
	}
	if current, detail := installationMatches(*group, selectedProfile); !current {
		return fmt.Errorf("post-install artifact verification failed: %s", detail)
	}
	if healthy, detail := daemonHealthy(ctx, management); !healthy {
		return fmt.Errorf("post-install doctor failed: %s", detail)
	}
	fmt.Fprintln(stdout, "portless is ready")
	return nil
}

func validateSelectedProfile(config profile.Config) error {
	table, err := routes.NewTableWithOptions(routes.Options{TLD: config.TLD, WildcardFallback: config.WildcardFallback})
	if err != nil {
		return err
	}
	runtimeConfig := profile.Runtime{Routes: table}
	if config.Scheme == profile.HTTPS && config.Certificates.Mode == profile.GeneratedCertificates {
		runtimeConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }
	}
	_, err = profile.New(config, runtimeConfig)
	return err
}

func activeNonDefaultProfile(ctx context.Context, management client.Client) (profile.Config, bool) {
	response, err := management.Call(ctx, client.Request{Operation: client.OperationStatus})
	if err != nil || response.Status == nil {
		return profile.Config{}, false
	}
	status := response.Status
	if status.Scheme == "https" && status.ListenAddress == "127.0.0.1:443" && status.TLD == ".localhost" && !status.WildcardFallback && status.CertificateMode == string(profile.GeneratedCertificates) {
		return profile.Config{}, false
	}
	config := profile.Config{
		Scheme: profile.Scheme(status.Scheme), ListenAddress: status.ListenAddress,
		TLD: status.TLD, WildcardFallback: status.WildcardFallback,
		Certificates: profile.CertificateConfig{
			Mode: profile.CertificateMode(status.CertificateMode), CertFile: status.CertificateFile, KeyFile: status.KeyFile,
		},
	}
	return config, true
}

func profileCommandArguments(config profile.Config) []string {
	arguments := []string{"--scheme", string(config.Scheme), "--listen", config.ListenAddress, "--tld", config.TLD}
	if config.WildcardFallback {
		arguments = append(arguments, "--wildcard")
	}
	if config.Certificates.Mode == profile.CertificateFiles {
		arguments = append(arguments, "--cert", config.Certificates.CertFile, "--key", config.Certificates.KeyFile)
	}
	return arguments
}

func optionalToolPreflight(stderr io.Writer) {
	if err := validateFixedExecutable("/usr/bin/dns-sd"); err != nil {
		fmt.Fprintf(stderr, "preflight: optional LAN publisher unavailable: %v\n", err)
	}
	if _, err := exec.LookPath("tailscale"); err != nil {
		fmt.Fprintln(stderr, "preflight: optional Tailscale CLI is unavailable")
	}
}

func daemonHealthy(ctx context.Context, management client.Client) (bool, string) {
	response, err := management.Call(ctx, client.Request{Operation: client.OperationStatus})
	if err != nil || response.Status == nil || !response.Status.Running {
		if err != nil {
			return false, err.Error()
		}
		return false, "daemon is not running"
	}
	if response.Status.Version != version {
		return false, "installed binary needs upgrade"
	}
	doctor, err := management.Call(ctx, client.Request{Operation: client.OperationDoctor})
	if err != nil {
		return false, err.Error()
	}
	for _, diagnostic := range doctor.Diagnostics {
		if diagnostic.Level == "error" || (diagnostic.Name == "ca-trust" && diagnostic.Level != "ok") {
			return false, diagnostic.Name + ": " + diagnostic.Message
		}
	}
	return true, response.Status.Version
}

func installationMatches(group string, selectedProfile *profile.Config) (bool, string) {
	config, err := service.DefaultConfig(group)
	if err != nil {
		return false, err.Error()
	}
	config.Profile = selectedProfile
	states, err := (service.Installer{Config: config}).Status()
	if err != nil {
		return false, err.Error()
	}
	source, err := os.Executable()
	if err != nil {
		return false, err.Error()
	}
	file, err := os.Open(source)
	if err != nil {
		return false, err.Error()
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return false, copyErr.Error()
	}
	if closeErr != nil {
		return false, closeErr.Error()
	}
	sourceDigest := hex.EncodeToString(hash.Sum(nil))
	for _, state := range states {
		switch state.Path {
		case config.Executable:
			if !state.Exists || state.SHA256 != sourceDigest || state.Mode != 0o755 || state.UID != 0 || state.GID != 0 {
				return false, "installed binary differs from the current executable"
			}
		case config.PlistPath:
			matches := state.Exists && state.Mode == 0o644 && state.UID == 0 && state.GID == 0
			if selectedProfile != nil {
				matches = matches && state.Match
			}
			if !matches {
				return false, "LaunchDaemon manifest requires reconciliation"
			}
		}
	}
	return true, ""
}

func preflightProfileChange(ctx context.Context, management client.Client, selected profile.Config) error {
	response, err := management.Call(ctx, client.Request{Operation: client.OperationStatus})
	if err != nil || response.Status == nil {
		return nil
	}
	tld, err := routes.NormalizeTLD(selected.TLD)
	if err != nil {
		return err
	}
	current := response.Status
	if current.Scheme == string(selected.Scheme) && current.ListenAddress == selected.ListenAddress && current.TLD == tld && current.WildcardFallback == selected.WildcardFallback &&
		current.CertificateMode == string(selected.Certificates.Mode) && current.CertificateFile == selected.Certificates.CertFile && current.KeyFile == selected.Certificates.KeyFile {
		return nil
	}
	routesResponse, err := management.Call(ctx, client.Request{Operation: client.OperationList})
	if err != nil {
		return err
	}
	if len(routesResponse.Routes) != 0 {
		return errors.New("profile change requires removing all registered routes first")
	}
	return nil
}

type commandProfileFlags struct {
	scheme   *string
	listen   *string
	tld      *string
	cert     *string
	key      *string
	wildcard *bool
}

func registerProfileFlags(flags *flag.FlagSet) commandProfileFlags {
	return commandProfileFlags{
		scheme:   flags.String("scheme", "", "proxy profile scheme (http or https)"),
		listen:   flags.String("listen", "", "proxy profile loopback listener"),
		tld:      flags.String("tld", "", "proxy profile DNS suffix"),
		cert:     flags.String("cert", "", "custom TLS certificate file"),
		key:      flags.String("key", "", "custom TLS private key file"),
		wildcard: flags.Bool("wildcard", false, "enable registered-parent fallback"),
	}
}

func (values commandProfileFlags) config() (*profile.Config, []string, error) {
	configured := *values.scheme != "" || *values.listen != "" || *values.tld != "" || *values.cert != "" || *values.key != "" || *values.wildcard
	if !configured {
		return nil, nil, nil
	}
	scheme := profile.HTTPS
	if *values.scheme != "" {
		scheme = profile.Scheme(strings.ToLower(*values.scheme))
	}
	listen := *values.listen
	if listen == "" {
		listen = "127.0.0.1:443"
		if scheme == profile.HTTP {
			listen = "127.0.0.1:80"
		}
	}
	tld := *values.tld
	if tld == "" {
		tld = ".localhost"
	}
	certificates := profile.CertificateConfig{}
	if scheme == profile.HTTPS {
		certificates.Mode = profile.GeneratedCertificates
		if *values.cert != "" || *values.key != "" {
			if *values.cert == "" || *values.key == "" {
				return nil, nil, errors.New("--cert and --key must be supplied together")
			}
			certificates = profile.CertificateConfig{Mode: profile.CertificateFiles, CertFile: *values.cert, KeyFile: *values.key}
		}
	} else if *values.cert != "" || *values.key != "" {
		return nil, nil, errors.New("plain HTTP profiles cannot use certificate files")
	}
	config := &profile.Config{Scheme: scheme, ListenAddress: listen, TLD: tld, WildcardFallback: *values.wildcard, Certificates: certificates}
	arguments := profileCommandArguments(*config)
	return config, arguments, nil
}

func validateFixedExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", path)
	}
	return nil
}

func proxyCommand(ctx context.Context, management client.Client, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: portless proxy start|stop|status [options]")
	}
	switch args[0] {
	case "status":
		return status(ctx, management, args[1:], stdout)
	case "start":
		foreground := false
		daemonArguments := make([]string, 0, len(args)-1)
		for _, argument := range args[1:] {
			if argument == "--foreground" {
				foreground = true
				continue
			}
			daemonArguments = append(daemonArguments, argument)
		}
		if foreground {
			return runDaemon(ctx, daemonArguments, stderr)
		}
		if len(daemonArguments) != 0 {
			return errors.New("custom profile flags require --foreground; persist them through service installation for background use")
		}
		if healthy, _ := daemonHealthy(ctx, management); healthy {
			fmt.Fprintln(stdout, "proxy is running")
			return nil
		}
		command := exec.CommandContext(ctx, "/bin/launchctl", "kickstart", "system/"+service.DefaultLabel)
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("start installed proxy (run portless init if needed): %w: %s", err, strings.TrimSpace(string(output)))
		}
		return waitForDaemon(ctx, management.SocketPath)
	case "stop":
		if len(args) != 1 {
			return errors.New("usage: portless proxy stop")
		}
		command := exec.CommandContext(ctx, "/bin/launchctl", "kill", "SIGTERM", "system/"+service.DefaultLabel)
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("stop installed proxy: %w: %s", err, strings.TrimSpace(string(output)))
		}
		fmt.Fprintln(stdout, "proxy stop requested")
		return nil
	default:
		return fmt.Errorf("unknown proxy command %q", args[0])
	}
}

func serviceCommand(ctx context.Context, management client.Client, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: portless service install|status|uninstall")
	}
	switch args[0] {
	case "install":
		return initCommand(ctx, management, args[1:], stdout, stderr)
	case "status":
		return status(ctx, management, args[1:], stdout)
	case "uninstall":
		if os.Geteuid() == 0 {
			return uninstall(ctx, args[1:], stdout, stderr)
		}
		source, err := os.Executable()
		if err != nil {
			return err
		}
		arguments := append([]string{"--", source, "uninstall"}, args[1:]...)
		command := exec.CommandContext(ctx, "/usr/bin/sudo", arguments...)
		command.Stdin, command.Stdout, command.Stderr = os.Stdin, stdout, stderr
		return command.Run()
	default:
		return fmt.Errorf("unknown service command %q", args[0])
	}
}

func trustCommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("trust", flag.ContinueOnError)
	flags.SetOutput(stderr)
	action := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = args[0], args[1:]
	}
	group := flags.String("management-group", "admin", "installed management group")
	if err := flags.Parse(args); err != nil {
		return err
	}
	config, err := service.DefaultConfig(*group)
	if err != nil {
		return err
	}
	caPath := filepath.Join(config.StateDir, "pki", "ca.pem")
	switch action {
	case "status":
		if _, err := os.Lstat(publicCACertificatePath); errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(stdout, "local CA not configured")
			return nil
		} else if err != nil {
			return err
		}
		trusted, err := pki.SystemTrusted(ctx, publicCACertificatePath)
		if err != nil {
			return err
		}
		if trusted {
			fmt.Fprintln(stdout, "trusted")
		} else {
			fmt.Fprintln(stdout, "not trusted")
		}
		return nil
	case "install", "remove":
		if os.Geteuid() != 0 {
			return errors.New("trust mutation is privileged; use portless init or an explicit root shell")
		}
		trustAction := pki.TrustInstall
		if action == "remove" {
			trustAction = pki.TrustRemove
		}
		if err := pki.ApplyTrust(ctx, trustAction, caPath); err != nil {
			return err
		}
		if action == "install" {
			return installPublicCA(caPath)
		}
		return removePublicCA()
	default:
		return fmt.Errorf("unknown trust action %q", action)
	}
}

func hostsCommand(ctx context.Context, management client.Client, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: portless hosts sync|clean [--apply]")
	}
	flags := flag.NewFlagSet("hosts "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	apply := flags.Bool("apply", false, "apply the privileged plan")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	configuration := hosts.DefaultConfig()
	var plan hosts.Plan
	var err error
	switch args[0] {
	case "sync":
		response, callErr := management.Call(ctx, client.Request{Operation: client.OperationList})
		if callErr != nil {
			return callErr
		}
		names := make([]string, 0, len(response.Routes))
		for _, route := range response.Routes {
			names = append(names, route.Name)
		}
		plan, err = configuration.SynchronizePlan(names)
	case "clean":
		plan, err = configuration.CleanPlan()
	default:
		return fmt.Errorf("unknown hosts action %q", args[0])
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s: %d -> %d bytes changed=%t\n", plan.Path, plan.BeforeBytes, plan.AfterBytes, plan.Changed)
	if !*apply || !plan.Changed {
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("hosts --apply is privileged; review the plan, then run it from an explicit root shell")
	}
	_, err = configuration.Apply(plan)
	return err
}

func pruneCommand(ctx context.Context, management client.Client, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: portless prune")
	}
	manager, err := runner.Open(runnerStateDirectory())
	if err != nil {
		return err
	}
	removed, err := manager.Prune()
	if err != nil {
		return err
	}
	shares, err := ownedShares()
	if err != nil {
		return err
	}
	cleanedShares := 0
	lanExposures, err := ownedLANExposures()
	if err != nil {
		return err
	}
	cleanedLAN := 0
	sharingClient := tailscale.Client{}
	for _, stale := range removed {
		for _, exposure := range lanExposures {
			if exposure.Identity != stale.Identity {
				continue
			}
			if err := mdns.StopOwned(exposure.Registration.MDNS); err != nil {
				return fmt.Errorf("clean stale LAN advertisement %s: %w", exposure.Registration.Name, err)
			}
			if err := removeOwnedLAN(exposure.Identity, exposure.Registration.Name); err != nil {
				return err
			}
			cleanedLAN++
		}
		for _, share := range shares {
			if share.Identity != stale.Identity {
				continue
			}
			if err := sharingClient.Clean(ctx, share.Plan); err != nil {
				return fmt.Errorf("clean stale Tailscale share %s: %w", share.Plan.Registration.Name, err)
			}
			if err := removeOwnedShare(share.Identity, share.Plan); err != nil {
				return err
			}
			cleanedShares++
		}
	}
	for _, record := range removed {
		if route, routeErr := currentRoute(ctx, management, record.Endpoint.Name); routeErr == nil && route.Owner.Kind == client.OwnerProcess && route.Owner.PID == record.Identity.PID && route.Owner.ProcessStart == record.Identity.Start {
			_ = cleanupRoute(ctx, management, route)
		}
	}
	fmt.Fprintf(stdout, "pruned %d stale runner records, %d LAN exposures, and %d Tailscale shares\n", len(removed), cleanedLAN, cleanedShares)
	return nil
}

func cleanCommand(ctx context.Context, management client.Client, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("clean", flag.ContinueOnError)
	flags.SetOutput(stderr)
	routesFlag := flags.Bool("routes", false, "remove all registered routes")
	yes := flags.Bool("yes", false, "confirm destructive route removal")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*routesFlag {
		return pruneCommand(ctx, management, nil, stdout)
	}
	if !*yes {
		return errors.New("clean --routes requires --yes")
	}
	response, err := management.Call(ctx, client.Request{Operation: client.OperationList})
	if err != nil {
		return err
	}
	shares, err := ownedShares()
	if err != nil {
		return err
	}
	sharingClient := tailscale.Client{}
	lanExposures, err := ownedLANExposures()
	if err != nil {
		return err
	}
	for _, exposure := range lanExposures {
		if err := mdns.StopOwned(exposure.Registration.MDNS); err != nil {
			return fmt.Errorf("clean LAN advertisement %s: %w", exposure.Registration.Name, err)
		}
		if err := removeOwnedLAN(exposure.Identity, exposure.Registration.Name); err != nil {
			return err
		}
	}
	for _, share := range shares {
		if err := sharingClient.Clean(ctx, share.Plan); err != nil {
			return fmt.Errorf("clean Tailscale share %s: %w", share.Plan.Registration.Name, err)
		}
		if err := removeOwnedShare(share.Identity, share.Plan); err != nil {
			return err
		}
	}
	for _, route := range response.Routes {
		if err := cleanupRoute(ctx, management, route); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "removed %d routes, %d LAN exposures, and %d Tailscale shares\n", len(response.Routes), len(lanExposures), len(shares))
	return nil
}
