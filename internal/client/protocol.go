package client

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const ProtocolVersion = 1

type Operation string

const (
	OperationInstall   Operation = "install"
	OperationAdd       Operation = "add"
	OperationRemove    Operation = "remove"
	OperationList      Operation = "list"
	OperationStatus    Operation = "status"
	OperationDoctor    Operation = "doctor"
	OperationRefresh   Operation = "refresh"
	OperationUninstall Operation = "uninstall"
)

type OwnerKind string

const (
	OwnerStatic    OwnerKind = "static"
	OwnerProcess   OwnerKind = "process"
	OwnerContainer OwnerKind = "container"
)

type RefreshPolicy string

const (
	RefreshNever            RefreshPolicy = "never"
	RefreshContainerAddress RefreshPolicy = "container-address"
)

type Request struct {
	Version   int       `json:"version"`
	ID        string    `json:"id"`
	Operation Operation `json:"operation"`
	Route     *Route    `json:"route,omitempty"`
	Name      string    `json:"name,omitempty"`
}

type Response struct {
	Version     int          `json:"version"`
	ID          string       `json:"id"`
	OK          bool         `json:"ok"`
	Error       *Problem     `json:"error,omitempty"`
	Routes      []Route      `json:"routes,omitempty"`
	Status      *Status      `json:"status,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

type Problem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Route struct {
	Name   string `json:"name"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   uint16 `json:"port"`
	Owner  Owner  `json:"owner"`
}

type Owner struct {
	Kind         OwnerKind     `json:"kind"`
	PID          int           `json:"pid,omitempty"`
	ProcessStart int64         `json:"process_start,omitempty"`
	InspectorUID uint32        `json:"inspector_uid,omitempty"`
	Container    string        `json:"container,omitempty"`
	Network      string        `json:"network,omitempty"`
	Refresh      RefreshPolicy `json:"refresh"`
}

type Status struct {
	Running    bool   `json:"running"`
	Version    string `json:"version,omitempty"`
	SocketPath string `json:"socket_path,omitempty"`
}

type Diagnostic struct {
	Name    string `json:"name"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

func (r Request) Validate() error {
	if r.Version != ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %d", r.Version)
	}
	if err := validateID(r.ID); err != nil {
		return err
	}

	switch r.Operation {
	case OperationAdd:
		if r.Route == nil {
			return errors.New("add request requires a route")
		}
		if r.Name != "" {
			return errors.New("add request must not include name")
		}
		return r.Route.Validate()
	case OperationRemove:
		if r.Route != nil {
			return errors.New("remove request must not include a route")
		}
		name, err := NormalizeName(r.Name)
		if err != nil {
			return err
		}
		if name != r.Name {
			return errors.New("remove request name is not canonical")
		}
	case OperationInstall, OperationList, OperationStatus, OperationDoctor, OperationRefresh, OperationUninstall:
		if r.Route != nil || r.Name != "" {
			return fmt.Errorf("%s request must not include route data", r.Operation)
		}
	default:
		return fmt.Errorf("unsupported operation %q", r.Operation)
	}
	return nil
}

func (r Route) Validate() error {
	name, err := NormalizeName(r.Name)
	if err != nil {
		return err
	}
	if name != r.Name {
		return errors.New("route name is not canonical")
	}
	if r.Scheme != "http" && r.Scheme != "https" {
		return fmt.Errorf("unsupported route protocol %q", r.Scheme)
	}
	address, err := netip.ParseAddr(r.Host)
	if err != nil || !address.IsValid() || address.Zone() != "" || address.String() != r.Host || address.IsUnspecified() || address.IsMulticast() {
		return fmt.Errorf("invalid route host %q", r.Host)
	}
	if r.Port == 0 {
		return errors.New("route port must be between 1 and 65535")
	}

	switch r.Owner.Kind {
	case OwnerStatic:
		if !address.IsLoopback() {
			return errors.New("static routes must target a loopback address")
		}
		if r.Owner.PID != 0 || r.Owner.ProcessStart != 0 || r.Owner.InspectorUID != 0 || r.Owner.Container != "" || r.Owner.Network != "" || r.Owner.Refresh != RefreshNever {
			return errors.New("static route has invalid ownership metadata")
		}
	case OwnerProcess:
		if !address.IsLoopback() {
			return errors.New("process routes must target a loopback address")
		}
		if r.Owner.PID <= 0 || r.Owner.ProcessStart < 0 || r.Owner.InspectorUID != 0 || r.Owner.Container != "" || r.Owner.Network != "" || r.Owner.Refresh != RefreshNever {
			return errors.New("process route has invalid ownership metadata")
		}
	case OwnerContainer:
		if address.IsLoopback() || address.IsLinkLocalUnicast() || !address.IsPrivate() {
			return errors.New("container routes must target a reachable container address")
		}
		if r.Owner.PID != 0 || r.Owner.ProcessStart != 0 || validateOwnerToken(r.Owner.Container) != nil || validateOwnerToken(r.Owner.Network) != nil || r.Owner.Refresh != RefreshContainerAddress {
			return errors.New("container route has invalid ownership metadata")
		}
	default:
		return fmt.Errorf("unsupported route owner %q", r.Owner.Kind)
	}
	return nil
}

func validateOwnerToken(value string) error {
	if len(value) == 0 || len(value) > 128 {
		return errors.New("owner identifier must be between 1 and 128 characters")
	}
	for i, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || ((char == '-' || char == '_' || char == '.') && i > 0) {
			continue
		}
		return errors.New("owner identifier contains invalid characters")
	}
	return nil
}

func NormalizeName(input string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(input))
	name = strings.TrimSuffix(name, ".")
	if strings.HasSuffix(name, ".localhost") {
		name = strings.TrimSuffix(name, ".localhost")
	}
	if len(name) == 0 || len(name) > 63 {
		return "", errors.New("route name must be a DNS label between 1 and 63 characters")
	}
	for i, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || (char == '-' && i > 0 && i < len(name)-1) {
			continue
		}
		return "", fmt.Errorf("invalid route name %q", input)
	}
	return name + ".localhost", nil
}

func validateID(id string) error {
	if len(id) == 0 || len(id) > 64 {
		return errors.New("request ID must be between 1 and 64 characters")
	}
	for _, char := range id {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return errors.New("request ID contains invalid characters")
	}
	return nil
}
