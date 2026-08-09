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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/euforicio/portless/internal/client"
	"github.com/euforicio/portless/internal/lan"
	"github.com/euforicio/portless/internal/projectconfig"
	"github.com/euforicio/portless/internal/runner"
	"github.com/euforicio/portless/internal/tailscale"
)

type commandExitError struct {
	code int
}

type synchronizedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *synchronizedWriter) Write(value []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(value)
}

func (e commandExitError) Error() string { return fmt.Sprintf("command exited with status %d", e.code) }

type runOptions struct {
	name      string
	appPort   uint
	force     bool
	lan       bool
	https     bool
	ip        string
	tailscale bool
	funnel    bool
	command   []string
	shorthand bool
}

func runProject(ctx context.Context, management client.Client, args []string, stdout, stderr io.Writer, shorthand bool) error {
	stdout = &synchronizedWriter{writer: stdout}
	stderr = &synchronizedWriter{writer: stderr}
	options, err := parseRunOptions(args, stderr, shorthand)
	if err != nil {
		return err
	}

	workingDirectory, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve working directory: %w", err)
	}
	configuration, found, err := loadProjectConfiguration(workingDirectory)
	if err != nil {
		return err
	}
	command := options.command
	if len(command) == 0 && found {
		command = configuration.Command
	}
	if len(command) == 0 {
		return errors.New("no command supplied and no portless.json command found")
	}
	name, err := projectconfig.ResolveName(options.name, configuration.Name, workingDirectory)
	if err != nil {
		return err
	}
	proxyEnabled := true
	appPort := uint16(0)
	environment := map[string]string(nil)
	if found {
		proxyEnabled = configuration.Proxy
		appPort = configuration.AppPort
		environment = configuration.Environment
	}
	if options.appPort > 65535 {
		return errors.New("--app-port must be between 1 and 65535")
	}
	if options.appPort != 0 {
		proxyEnabled = true
		appPort = uint16(options.appPort)
	}
	if !proxyEnabled && options.force {
		return errors.New("--force requires proxy routing")
	}
	if !proxyEnabled && (options.lan || options.tailscale || options.funnel) {
		return errors.New("sharing flags require proxy routing")
	}
	profileStatus := client.Status{Scheme: "https", ListenAddress: "127.0.0.1:443", TLD: ".localhost"}
	publicURL := ""
	if proxyEnabled {
		status, statusErr := managementStatus(ctx, management)
		if statusErr != nil {
			return fmt.Errorf("proxy is unavailable; run portless init: %w", statusErr)
		}
		profileStatus = status
		label := strings.SplitN(name, ".", 2)[0]
		name, err = client.NormalizeNameForTLD(label, profileStatus.TLD)
		if err != nil {
			return err
		}
		_, publicPort, splitErr := net.SplitHostPort(profileStatus.ListenAddress)
		if splitErr != nil {
			return errors.New("daemon returned an invalid profile listener")
		}
		authority := name
		if (profileStatus.Scheme == "https" && publicPort != "443") || (profileStatus.Scheme == "http" && publicPort != "80") {
			authority = net.JoinHostPort(name, publicPort)
		}
		publicURL = profileStatus.Scheme + "://" + authority
	}

	manager, err := runner.Open(runnerStateDirectory())
	if err != nil {
		return fmt.Errorf("open runner state: %w", err)
	}
	var takeoverExpected *client.Route
	if options.force {
		expected, takeoverErr := forceRunnerTakeover(ctx, management, manager, name)
		if takeoverErr != nil {
			return takeoverErr
		}
		takeoverExpected = &expected
	}
	process, err := manager.Start(ctx, runner.Spec{
		Name:             name,
		TLD:              profileStatus.TLD,
		PublicURL:        publicURL,
		Command:          command,
		WorkingDirectory: workingDirectory,
		Environment:      environment,
		AppPort:          appPort,
		Proxy:            proxyEnabled,
		NodeExtraCACerts: readableCACertificate(),
		Stdin:            os.Stdin,
		Stdout:           stdout,
		Stderr:           stderr,
	})
	if err != nil {
		return err
	}

	var registered client.Route
	var sharingClient tailscale.Client
	var sharingPlan *tailscale.Plan
	var lanService *lan.Service
	if proxyEnabled {
		endpoint := process.Endpoint()
		requested := client.Route{
			Name: name, Scheme: "http", Host: endpoint.Host, Port: endpoint.Port,
			Owner: client.Owner{Kind: client.OwnerProcess, PID: process.PID(), Refresh: client.RefreshNever},
		}
		addRequest := client.Request{Operation: client.OperationAdd, Route: &requested, Match: client.RouteMatchAbsent}
		if takeoverExpected != nil {
			owner := takeoverExpected.Owner
			addRequest.Match = client.RouteMatchOwner
			addRequest.ExpectedOwner = &owner
		}
		added, err := management.Call(ctx, addRequest)
		if err != nil {
			_ = process.Signal(syscall.SIGTERM)
			_, _ = process.Wait()
			return fmt.Errorf("register process route: %w", err)
		}
		if added.Route == nil {
			_ = process.Signal(syscall.SIGTERM)
			_, _ = process.Wait()
			return errors.New("management server did not return the canonical process route")
		}
		registered = *added.Route
		fmt.Fprintln(stdout, process.Endpoint().URL)
		if options.lan {
			lanTarget := "http://" + net.JoinHostPort(endpoint.Host, strconv.Itoa(int(endpoint.Port)))
			var pinnedIP netip.Addr
			if options.ip != "" {
				pinnedIP, err = netip.ParseAddr(options.ip)
				if err != nil || pinnedIP.Unmap().String() != options.ip {
					_ = cleanupRoute(context.WithoutCancel(ctx), management, registered)
					_ = process.Signal(syscall.SIGTERM)
					_, _ = process.Wait()
					return errors.New("--ip must be a canonical literal LAN address")
				}
			}
			lanName := strings.TrimSuffix(name, profileStatus.TLD)
			lanService, err = lan.Start(ctx, lan.Request{
				Name: lanName, Target: lanTarget, HTTPS: options.https, PinnedIP: pinnedIP,
				StateDir: runnerStateDirectory(),
				Authorize: func(checkContext context.Context) bool {
					current, currentErr := currentRoute(checkContext, management, registered.Name)
					return currentErr == nil && current == registered
				},
				OnUpdate: func(registration lan.Registration) error {
					current, currentErr := currentRoute(context.WithoutCancel(ctx), management, registered.Name)
					if currentErr != nil || current != registered {
						return nil
					}
					return updateOwnedLAN(process.Identity(), registration)
				},
			})
			if err != nil {
				_ = cleanupRoute(context.WithoutCancel(ctx), management, registered)
				_ = process.Signal(syscall.SIGTERM)
				_, _ = process.Wait()
				return fmt.Errorf("configure LAN exposure: %w", err)
			}
			registration := lanService.Registration()
			fmt.Fprintln(stdout, registration.URL())
			fmt.Fprintf(stderr, "portless: LAN exposure is reachable by subnet peers and has no access control\n")
			if options.https {
				fmt.Fprintf(stderr, "portless: other devices do not automatically trust this CA; explicitly install %s on each client you choose to trust\n", registration.CACertPath)
			}
			go func() {
				for lanErr := range lanService.Errors() {
					fmt.Fprintf(stderr, "portless: LAN exposure warning: %v\n", lanErr)
				}
			}()
		}
		if options.tailscale || options.funnel {
			mode := tailscale.Serve
			if options.funnel {
				mode = tailscale.Funnel
			}
			plan, shareErr := sharingClient.BuildPlan(ctx, tailscale.Request{
				Name: strings.SplitN(name, ".", 2)[0], Mode: mode,
				Target: "http://" + net.JoinHostPort(endpoint.Host, strconv.Itoa(int(endpoint.Port))),
			})
			if shareErr == nil {
				shareErr = sharingClient.Apply(ctx, plan)
			}
			if shareErr == nil {
				shareErr = addOwnedShare(process.Identity(), plan)
				if shareErr != nil {
					cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
					_ = sharingClient.Clean(cleanupContext, plan)
					cancel()
				}
			}
			if shareErr != nil {
				_ = cleanupRoute(context.WithoutCancel(ctx), management, registered)
				_ = process.Signal(syscall.SIGTERM)
				_, _ = process.Wait()
				return fmt.Errorf("configure Tailscale %s: %w", mode, shareErr)
			}
			sharingPlan = &plan
			sharedAuthority := plan.Registration.Host
			if plan.Registration.Port != 443 {
				sharedAuthority = net.JoinHostPort(sharedAuthority, strconv.Itoa(int(plan.Registration.Port)))
			}
			fmt.Fprintln(stdout, "https://"+sharedAuthority)
		}
	}

	result, waitErr := process.Wait()
	if lanService != nil {
		registration := lanService.Registration()
		if lanErr := lanService.Close(); lanErr != nil {
			fmt.Fprintf(stderr, "portless: LAN cleanup deferred: %v\n", lanErr)
		} else if stateErr := removeOwnedLAN(process.Identity(), registration.Name); stateErr != nil {
			fmt.Fprintf(stderr, "portless: LAN state cleanup deferred: %v\n", stateErr)
		}
	}
	if sharingPlan != nil {
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		if shareErr := sharingClient.Clean(cleanupContext, *sharingPlan); shareErr != nil {
			fmt.Fprintf(stderr, "portless: Tailscale cleanup deferred: %v\n", shareErr)
		} else if stateErr := removeOwnedShare(process.Identity(), *sharingPlan); stateErr != nil {
			fmt.Fprintf(stderr, "portless: share state cleanup deferred: %v\n", stateErr)
		}
		cancel()
	}
	if proxyEnabled {
		if removeErr := cleanupRoute(context.WithoutCancel(ctx), management, registered); removeErr != nil {
			fmt.Fprintf(stderr, "portless: route cleanup deferred: %v\n", removeErr)
		}
	}
	if result.Signaled {
		return commandExitError{code: 128 + int(result.Signal)}
	}
	if result.ExitCode != 0 {
		return commandExitError{code: result.ExitCode}
	}
	return waitErr
}

func parseRunOptions(args []string, stderr io.Writer, shorthand bool) (runOptions, error) {
	var options runOptions
	options.shorthand = shorthand
	if shorthand {
		if len(args) < 2 {
			return options, errors.New("usage: portless NAME COMMAND [ARGS...]")
		}
		options.name = args[0]
		options.command = append([]string(nil), args[1:]...)
		return options, nil
	}
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.name, "name", "", "stable Portless route name")
	flags.UintVar(&options.appPort, "app-port", 0, "fixed application TCP port")
	flags.BoolVar(&options.force, "force", false, "replace an exact runner-owned process")
	flags.BoolVar(&options.lan, "lan", false, "explicitly publish on the local network")
	flags.BoolVar(&options.https, "https", false, "serve an explicitly enabled LAN route with exact-host HTTPS")
	flags.StringVar(&options.ip, "ip", "", "pin an explicitly enabled LAN route to one eligible address")
	flags.BoolVar(&options.tailscale, "tailscale", false, "explicitly publish with Tailscale Serve")
	flags.BoolVar(&options.funnel, "funnel", false, "explicitly publish with Tailscale Funnel")
	if err := flags.Parse(args); err != nil {
		return options, err
	}
	options.command = append([]string(nil), flags.Args()...)
	if len(options.command) > 0 && options.command[0] == "--" {
		options.command = options.command[1:]
	}
	if options.tailscale && options.funnel {
		return options, errors.New("--tailscale and --funnel are mutually exclusive")
	}
	if !options.lan && (options.https || options.ip != "") {
		return options, errors.New("--https and --ip require --lan")
	}
	return options, nil
}

func loadProjectConfiguration(directory string) (projectconfig.Config, bool, error) {
	path, found, err := projectconfig.Find(directory)
	if err != nil || !found {
		return projectconfig.Config{}, found, err
	}
	configuration, err := projectconfig.Load(path)
	return configuration, true, err
}

func runnerStateDirectory() string {
	if value := os.Getenv("PORTLESS_RUNNER_STATE"); value != "" {
		return value
	}
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "Portless", "runner")
}

func readableCACertificate() string {
	path := os.Getenv("PORTLESS_CA_CERT")
	if path == "" {
		path = publicCACertificatePath
	}
	if !filepath.IsAbs(path) {
		return ""
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ""
	}
	return path
}

func currentRoute(ctx context.Context, management client.Client, name string) (client.Route, error) {
	response, err := management.Call(ctx, client.Request{Operation: client.OperationList})
	if err != nil {
		return client.Route{}, err
	}
	for _, route := range response.Routes {
		if route.Name == name {
			return route, nil
		}
	}
	return client.Route{}, errors.New("route is not registered")
}

func forceRunnerTakeover(ctx context.Context, management client.Client, manager *runner.Manager, name string) (client.Route, error) {
	route, err := currentRoute(ctx, management, name)
	if err != nil {
		return client.Route{}, fmt.Errorf("force requires an existing runner-owned route: %w", err)
	}
	if err := manager.ForceTakeover(ctx, route, 5*time.Second); err != nil {
		return client.Route{}, fmt.Errorf("force takeover: %w", err)
	}
	return route, nil
}

func cleanupRoute(ctx context.Context, management client.Client, expected client.Route) error {
	if expected.Name == "" {
		return nil
	}
	owner := expected.Owner
	_, err := management.Call(ctx, client.Request{
		Operation: client.OperationRemove, Name: expected.Name,
		Match: client.RouteMatchOwner, ExpectedOwner: &owner,
	})
	return err
}
