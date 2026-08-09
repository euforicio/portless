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
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/euforicio/portless/internal/applecontainer"
	"github.com/euforicio/portless/internal/client"
)

const version = "0.0.0-dev"

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
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
		err = callEmpty(ctx, management, client.OperationInstall, arguments, stdout)
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
	case "uninstall":
		err = callEmpty(ctx, management, client.OperationUninstall, arguments, stdout)
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

func callEmpty(ctx context.Context, management client.Client, operation client.Operation, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: portless %s", operation)
	}
	_, err := management.Call(ctx, client.Request{Operation: operation})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s complete\n", operation)
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
	fmt.Fprintln(output, "commands: install, add, remove, list, status, doctor, uninstall, version")
}
