package client

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/euforicio/portless/internal/routes"
)

const ProtocolVersion = 2

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

type RouteMatch string

const (
	RouteMatchAbsent RouteMatch = "absent"
	RouteMatchAny    RouteMatch = "any"
	RouteMatchOwner  RouteMatch = "owner"
)

type Request struct {
	Version       int        `json:"version"`
	ID            string     `json:"id"`
	Operation     Operation  `json:"operation"`
	Route         *Route     `json:"route,omitempty"`
	Name          string     `json:"name,omitempty"`
	Match         RouteMatch `json:"match,omitempty"`
	ExpectedOwner *Owner     `json:"expected_owner,omitempty"`
}

type Response struct {
	Version     int          `json:"version"`
	ID          string       `json:"id"`
	OK          bool         `json:"ok"`
	Error       *Problem     `json:"error,omitempty"`
	Routes      []Route      `json:"routes,omitempty"`
	Status      *Status      `json:"status,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
	Route       *Route       `json:"route,omitempty"`
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
	Running          bool   `json:"running"`
	Version          string `json:"version,omitempty"`
	SocketPath       string `json:"socket_path,omitempty"`
	Scheme           string `json:"scheme,omitempty"`
	ListenAddress    string `json:"listen_address,omitempty"`
	TLD              string `json:"tld,omitempty"`
	WildcardFallback bool   `json:"wildcard_fallback,omitempty"`
	CertificateMode  string `json:"certificate_mode,omitempty"`
	CertificateFile  string `json:"certificate_file,omitempty"`
	KeyFile          string `json:"key_file,omitempty"`
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
		if err := r.Route.validateForTLD(""); err != nil {
			return err
		}
		return r.validateMutationMatch(true)
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
		return r.validateMutationMatch(false)
	case OperationInstall, OperationList, OperationStatus, OperationDoctor, OperationRefresh, OperationUninstall:
		if r.Route != nil || r.Name != "" || r.Match != "" || r.ExpectedOwner != nil {
			return fmt.Errorf("%s request must not include route data", r.Operation)
		}
	default:
		return fmt.Errorf("unsupported operation %q", r.Operation)
	}
	return nil
}

func (r Request) validateMutationMatch(allowAbsent bool) error {
	switch r.Match {
	case RouteMatchAbsent:
		if !allowAbsent {
			return errors.New("remove request cannot require an absent route")
		}
		if r.ExpectedOwner != nil {
			return errors.New("absent route match must not include an expected owner")
		}
	case RouteMatchAny:
		if r.ExpectedOwner != nil {
			return errors.New("any route match must not include an expected owner")
		}
	case RouteMatchOwner:
		if r.ExpectedOwner == nil {
			return errors.New("owner route match requires an expected owner")
		}
		if err := r.ExpectedOwner.validateExpected(); err != nil {
			return fmt.Errorf("invalid expected owner: %w", err)
		}
	default:
		return fmt.Errorf("unsupported route match %q", r.Match)
	}
	return nil
}

func (r Route) Validate() error {
	return r.ValidateForTLD(".localhost")
}

// ValidateForTLD validates a route against the daemon's active DNS namespace.
func (r Route) ValidateForTLD(tld string) error {
	return r.validateForTLD(tld)
}

func (r Route) validateForTLD(tld string) error {
	if tld == "" {
		index := strings.LastIndexByte(r.Name, '.')
		if index <= 0 {
			return errors.New("route name must include a DNS suffix")
		}
		tld = r.Name[index:]
	}
	name, err := routes.NormalizeAuthorityForTLD(r.Name, tld)
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
		if !address.IsLoopback() && (!address.IsPrivate() || address.IsLinkLocalUnicast()) {
			return errors.New("static routes must target a loopback or private unicast address")
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

func (o Owner) validateExpected() error {
	switch o.Kind {
	case OwnerStatic:
		if o.PID != 0 || o.ProcessStart != 0 || o.InspectorUID != 0 || o.Container != "" || o.Network != "" || o.Refresh != RefreshNever {
			return errors.New("static owner has invalid ownership metadata")
		}
	case OwnerProcess:
		if o.PID <= 0 || o.ProcessStart <= 0 || o.InspectorUID != 0 || o.Container != "" || o.Network != "" || o.Refresh != RefreshNever {
			return errors.New("process owner requires an exact process identity")
		}
	case OwnerContainer:
		if o.PID != 0 || o.ProcessStart != 0 || o.InspectorUID == 0 || validateOwnerToken(o.Container) != nil || validateOwnerToken(o.Network) != nil || o.Refresh != RefreshContainerAddress {
			return errors.New("container owner requires an exact inspector identity")
		}
	default:
		return fmt.Errorf("unsupported route owner %q", o.Kind)
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
	return NormalizeNameForTLD(input, ".localhost")
}

// NormalizeNameForTLD accepts one label or a complete name under tld.
func NormalizeNameForTLD(input, tld string) (string, error) {
	suffix, err := routes.NormalizeTLD(tld)
	if err != nil {
		return "", err
	}
	name := strings.ToLower(strings.TrimSpace(input))
	name = strings.TrimSuffix(name, ".")
	if strings.HasSuffix(name, suffix) {
		return routes.NormalizeAuthorityForTLD(name, suffix)
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
	return name + suffix, nil
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
