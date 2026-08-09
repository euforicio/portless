package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/euforicio/portless/internal/client"
	"github.com/euforicio/portless/internal/routes"
)

const (
	stateVersion     = 1
	stateFileName    = "routes.json"
	maxStateBytes    = 4 << 20
	maxRegistrations = 1024
)

type persistedState struct {
	Version int            `json:"version"`
	Routes  []client.Route `json:"routes"`
}

type registry struct {
	mu      sync.Mutex
	path    string
	table   *routes.Table
	records map[string]client.Route
	active  map[string]bool
}

func openRegistry(stateDir string, table *routes.Table) (*registry, error) {
	if table == nil {
		return nil, errors.New("route table is required")
	}
	if err := ensurePrivateStateDir(stateDir); err != nil {
		return nil, err
	}
	r := &registry{
		path:    filepath.Join(stateDir, stateFileName),
		table:   table,
		records: make(map[string]client.Route),
		active:  make(map[string]bool),
	}
	state, err := readState(r.path)
	if err != nil {
		return nil, err
	}
	for _, registration := range state.Routes {
		if err := registration.Validate(); err != nil {
			return nil, fmt.Errorf("invalid persisted route %q: %w", registration.Name, err)
		}
		if _, exists := r.records[registration.Name]; exists {
			return nil, fmt.Errorf("duplicate persisted route %q", registration.Name)
		}
		r.records[registration.Name] = registration
		if registration.Owner.Kind == client.OwnerStatic || (registration.Owner.Kind == client.OwnerProcess && processIdentityMatches(registration.Owner)) {
			r.active[registration.Name] = true
		}
	}
	if err := r.rebuildLocked(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *registry) set(registration client.Route, active bool) error {
	if err := registration.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.records[registration.Name]; !exists && len(r.records) >= maxRegistrations {
		return fmt.Errorf("route limit of %d reached", maxRegistrations)
	}
	next := cloneRecords(r.records)
	next[registration.Name] = registration
	nextActive := cloneActive(r.active)
	nextActive[registration.Name] = active
	return r.commitLocked(next, nextActive)
}

func (r *registry) remove(name string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.records[name]; !exists {
		return false, nil
	}
	next := cloneRecords(r.records)
	delete(next, name)
	nextActive := cloneActive(r.active)
	delete(nextActive, name)
	if r.active[name] {
		intermediate := cloneActive(r.active)
		delete(intermediate, name)
		proxyRoutes, err := buildProxyRoutes(r.records, intermediate)
		if err != nil {
			return true, err
		}
		if err := r.table.Replace(proxyRoutes); err != nil {
			return true, err
		}
		r.active = intermediate
	}
	return true, r.commitLocked(next, nextActive)
}

func (r *registry) list() []client.Route {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]client.Route, 0, len(r.records))
	for _, registration := range r.records {
		result = append(result, registration)
	}
	slices.SortFunc(result, func(a, b client.Route) int { return strings.Compare(a.Name, b.Name) })
	return result
}

func (r *registry) snapshot() []client.Route {
	return r.list()
}

type refreshResult struct {
	before client.Route
	after  client.Route
	active bool
	err    error
	remove bool
}

func (r *registry) applyRefresh(results []refreshResult) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	next := cloneRecords(r.records)
	nextActive := cloneActive(r.active)
	changed := false
	unsafeNames := make(map[string]bool)
	for _, result := range results {
		current, exists := next[result.before.Name]
		if !exists || current != result.before {
			continue
		}
		if result.remove {
			unsafeNames[result.before.Name] = nextActive[result.before.Name]
			delete(next, result.before.Name)
			delete(nextActive, result.before.Name)
			changed = true
			continue
		}
		if result.err != nil {
			if nextActive[result.before.Name] {
				unsafeNames[result.before.Name] = true
				delete(nextActive, result.before.Name)
				changed = true
			}
			continue
		}
		if current != result.after {
			if nextActive[result.before.Name] {
				unsafeNames[result.before.Name] = true
			}
			next[result.before.Name] = result.after
			changed = true
		}
		if nextActive[result.before.Name] != result.active {
			nextActive[result.before.Name] = result.active
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if len(unsafeNames) != 0 {
		intermediate := cloneActive(r.active)
		for name := range unsafeNames {
			delete(intermediate, name)
		}
		proxyRoutes, err := buildProxyRoutes(r.records, intermediate)
		if err != nil {
			return err
		}
		if err := r.table.Replace(proxyRoutes); err != nil {
			return err
		}
		r.active = intermediate
	}
	return r.commitLocked(next, nextActive)
}

func (r *registry) commitLocked(records map[string]client.Route, active map[string]bool) error {
	proxyRoutes, err := buildProxyRoutes(records, active)
	if err != nil {
		return err
	}
	if err := writeState(r.path, records); err != nil {
		return err
	}
	if err := r.table.Replace(proxyRoutes); err != nil {
		return err
	}
	r.records = records
	r.active = active
	return nil
}

func (r *registry) rebuildLocked() error {
	proxyRoutes, err := buildProxyRoutes(r.records, r.active)
	if err != nil {
		return err
	}
	return r.table.Replace(proxyRoutes)
}

func buildProxyRoutes(records map[string]client.Route, active map[string]bool) ([]routes.Route, error) {
	result := make([]routes.Route, 0, len(records))
	for name, registration := range records {
		if !active[name] {
			continue
		}
		upstream := registration.Scheme + "://" + net.JoinHostPort(registration.Host, strconv.Itoa(int(registration.Port)))
		route, err := routes.NewRoute(registration.Name, upstream)
		if err != nil {
			return nil, fmt.Errorf("build proxy route %q: %w", registration.Name, err)
		}
		result = append(result, route)
	}
	return result, nil
}

func readState(path string) (persistedState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return persistedState{Version: stateVersion}, nil
	}
	if err != nil {
		return persistedState{}, err
	}
	if len(data) > maxStateBytes {
		return persistedState{}, errors.New("route state exceeds size limit")
	}
	if err := checkOwnedRegular(path, 0o600); err != nil {
		return persistedState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state persistedState
	if err := decoder.Decode(&state); err != nil {
		return persistedState{}, fmt.Errorf("decode route state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return persistedState{}, errors.New("route state contains trailing data")
	}
	if state.Version != stateVersion {
		return persistedState{}, fmt.Errorf("unsupported route state version %d", state.Version)
	}
	if len(state.Routes) > maxRegistrations {
		return persistedState{}, errors.New("route state contains too many registrations")
	}
	return state, nil
}

func writeState(path string, records map[string]client.Route) error {
	state := persistedState{Version: stateVersion, Routes: make([]client.Route, 0, len(records))}
	for _, registration := range records {
		state.Routes = append(state.Routes, registration)
	}
	slices.SortFunc(state.Routes, func(a, b client.Route) int { return strings.Compare(a.Name, b.Name) })
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxStateBytes {
		return errors.New("route state exceeds size limit")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to replace non-regular route state %s", path)
		}
		if err := checkOwnedRegular(path, 0o600); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".routes-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
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
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func ensurePrivateStateDir(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("state directory must be absolute")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory must be a real directory")
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("state directory has unsafe mode %04o; want 0700", info.Mode().Perm())
	}
	uid, _, err := ownership(info)
	if err != nil {
		return err
	}
	if uid != os.Geteuid() {
		return fmt.Errorf("state directory is owned by UID %d; want %d", uid, os.Geteuid())
	}
	return nil
}

func checkOwnedRegular(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if info.Mode().Perm() != mode {
		return fmt.Errorf("%s has unsafe mode %04o; want %04o", path, info.Mode().Perm(), mode)
	}
	uid, _, err := ownership(info)
	if err != nil {
		return err
	}
	if uid != os.Geteuid() {
		return fmt.Errorf("%s is owned by UID %d; want %d", path, uid, os.Geteuid())
	}
	return nil
}

func ownership(info os.FileInfo) (int, int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("file ownership is unavailable")
	}
	return int(stat.Uid), int(stat.Gid), nil
}

func processAlive(pid int) bool {
	if pid == 0 {
		return true
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func processIdentityMatches(owner client.Owner) bool {
	if owner.PID <= 0 || owner.ProcessStart <= 0 || !processAlive(owner.PID) {
		return false
	}
	_, start, err := inspectProcess(owner.PID)
	return err == nil && start == owner.ProcessStart
}

func cloneRecords(source map[string]client.Route) map[string]client.Route {
	result := make(map[string]client.Route, len(source))
	for name, registration := range source {
		result[name] = registration
	}
	return result
}

func cloneActive(source map[string]bool) map[string]bool {
	result := make(map[string]bool, len(source))
	for name, active := range source {
		result[name] = active
	}
	return result
}
