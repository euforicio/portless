package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/euforicio/portless/internal/client"
	"golang.org/x/sys/unix"
)

const (
	stateVersion  = 1
	stateFileName = "runner.json"
	lockFileName  = "runner.lock"
	maxStateBytes = 1 << 20
	maxRecords    = 1024
)

// Record is validated durable metadata for one runner-started process.
type Record struct {
	Endpoint         Endpoint `json:"endpoint"`
	Identity         Identity `json:"identity"`
	ProcessGroup     int      `json:"process_group"`
	UID              uint32   `json:"uid"`
	Supervisor       Identity `json:"supervisor"`
	SupervisorUID    uint32   `json:"supervisor_uid"`
	WorkingDirectory string   `json:"working_directory"`
}

// ProcessStatus classifies durable records without signaling them.
type ProcessStatus string

const (
	StatusActive   ProcessStatus = "active"
	StatusOrphaned ProcessStatus = "orphaned"
	StatusStale    ProcessStatus = "stale"
)

// Discovery pairs a durable record with its current kernel-observed status.
type Discovery struct {
	Record Record
	Status ProcessStatus
}

type persistedState struct {
	Version int      `json:"version"`
	Records []Record `json:"records"`
}

// Manager owns a private durable runner registry.
type Manager struct {
	directory string
	statePath string
	lockPath  string
}

// Open validates or creates a private runner state directory. Durable state is
// process metadata only; it cannot authorize takeover without a matching route
// identity supplied to ForceTakeover.
func Open(stateDirectory string) (*Manager, error) {
	if !filepath.IsAbs(stateDirectory) {
		return nil, errors.New("runner state directory must be absolute")
	}
	if err := ensurePrivateDirectory(stateDirectory); err != nil {
		return nil, err
	}
	manager := &Manager{
		directory: stateDirectory,
		statePath: filepath.Join(stateDirectory, stateFileName),
		lockPath:  filepath.Join(stateDirectory, lockFileName),
	}
	if err := manager.withStateLock(func(*persistedState) error { return nil }); err != nil {
		return nil, err
	}
	return manager, nil
}

// Records returns a name-sorted validated state snapshot.
func (manager *Manager) Records() ([]Record, error) {
	var result []Record
	err := manager.withStateLock(func(state *persistedState) error {
		result = append([]Record(nil), state.Records...)
		return nil
	})
	return result, err
}

// Discover distinguishes actively supervised children, live orphaned children,
// and stale records. Unknown kernel inspection failures are returned.
func (manager *Manager) Discover() ([]Discovery, error) {
	records, err := manager.Records()
	if err != nil {
		return nil, err
	}
	result := make([]Discovery, 0, len(records))
	for _, record := range records {
		childAlive, err := probeRecord(record)
		if err != nil {
			return nil, fmt.Errorf("inspect child %d: %w", record.Identity.PID, err)
		}
		status := StatusStale
		if childAlive {
			supervised, err := supervisorAlive(record)
			if err != nil {
				return nil, fmt.Errorf("inspect supervisor %d: %w", record.Supervisor.PID, err)
			}
			if supervised {
				status = StatusActive
			} else {
				status = StatusOrphaned
			}
		}
		result = append(result, Discovery{Record: record, Status: status})
	}
	return result, nil
}

// Prune removes stale records whose exact process identity no longer exists.
// It never signals a process or removes a live orphan.
func (manager *Manager) Prune() ([]Record, error) {
	var removed []Record
	err := manager.withStateLock(func(state *persistedState) error {
		retained := state.Records[:0]
		for _, record := range state.Records {
			alive, err := probeRecord(record)
			if err != nil {
				return fmt.Errorf("inspect runner process %d: %w", record.Identity.PID, err)
			}
			if alive {
				retained = append(retained, record)
			} else {
				removed = append(removed, record)
			}
		}
		state.Records = retained
		return nil
	})
	return removed, err
}

// ForceTakeover terminates a runner-owned process only when expected exactly
// matches both the durable record and the live kernel identity. The expected
// identity must come from the current process-owned route, not runner state.
func (manager *Manager) ForceTakeover(ctx context.Context, route client.Route, grace time.Duration) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if err := route.Validate(); err != nil || route.Owner.Kind != client.OwnerProcess || route.Owner.ProcessStart <= 0 {
		return fmt.Errorf("%w: current process-owned route is required", ErrIdentityMismatch)
	}
	canonical := route.Name
	expected := Identity{PID: route.Owner.PID, Start: route.Owner.ProcessStart}
	var record Record
	err := manager.withStateLock(func(state *persistedState) error {
		found, ok := findRecord(state.Records, canonical)
		if !ok {
			return ErrNotTracked
		}
		if found.Identity != expected {
			return ErrIdentityMismatch
		}
		if !found.Endpoint.Proxy || found.Endpoint.Host != route.Host || found.Endpoint.Port != route.Port {
			return ErrIdentityMismatch
		}
		record = found
		return nil
	})
	if err != nil {
		return err
	}

	alive, err := probeRecord(record)
	if err != nil {
		return err
	}
	if !alive {
		return manager.removeMatching(canonical, expected)
	}
	if err := signalRecord(record, syscall.SIGTERM); err != nil {
		if errors.Is(err, ErrIdentityMismatch) {
			return err
		}
		alive, probeErr := probeRecord(record)
		if probeErr != nil {
			return probeErr
		}
		if !alive {
			return manager.removeMatching(canonical, expected)
		}
		return err
	}
	if grace <= 0 {
		grace = defaultStopTimeout
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	killed := false
	for {
		alive, probeErr := probeRecord(record)
		if probeErr != nil {
			return probeErr
		}
		if !alive {
			return manager.removeMatching(canonical, expected)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if !killed {
				if err := signalRecord(record, syscall.SIGKILL); err != nil {
					if errors.Is(err, os.ErrProcessDone) {
						return manager.removeMatching(canonical, expected)
					}
					return err
				}
				killed = true
			}
		case <-ticker.C:
		}
	}
}

func (manager *Manager) removeMatching(name string, identity Identity) error {
	return manager.withStateLock(func(state *persistedState) error {
		state.Records = deleteRecord(state.Records, name, identity)
		return nil
	})
}

func (manager *Manager) withStateLock(operation func(*persistedState) error) error {
	lock, err := openLockFile(manager.lockPath)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock runner state: %w", err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)

	state, err := readState(manager.statePath)
	if err != nil {
		return err
	}
	before, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := operation(&state); err != nil {
		return err
	}
	if err := validateState(state); err != nil {
		return err
	}
	slices.SortFunc(state.Records, func(a, b Record) int { return strings.Compare(a.Endpoint.Name, b.Endpoint.Name) })
	after, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if bytes.Equal(before, after) && fileExists(manager.statePath) {
		return nil
	}
	return writeState(manager.statePath, state)
}

func openLockFile(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil {
		if err := validateOwnedFile(info, path, 0o600); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	descriptor, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open runner lock: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if err := validateOwnedFile(info, path, 0o600); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func readState(path string) (persistedState, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return persistedState{Version: stateVersion}, nil
	}
	if err != nil {
		return persistedState{}, fmt.Errorf("open runner state: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return persistedState{}, err
	}
	if err := validateOwnedFile(info, path, 0o600); err != nil {
		return persistedState{}, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil {
		return persistedState{}, err
	}
	if len(data) > maxStateBytes {
		return persistedState{}, errors.New("runner state exceeds size limit")
	}
	if err := rejectDuplicateStateKeys(data); err != nil {
		return persistedState{}, fmt.Errorf("decode runner state: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state persistedState
	if err := decoder.Decode(&state); err != nil {
		return persistedState{}, fmt.Errorf("decode runner state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return persistedState{}, errors.New("runner state contains trailing data")
	}
	if err := validateState(state); err != nil {
		return persistedState{}, err
	}
	return state, nil
}

func rejectDuplicateStateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var readValue func() error
	readValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("runner state object key must be a string")
				}
				if seen[key] {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = true
				if err := readValue(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := readValue(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected runner state JSON delimiter")
		}
	}
	return readValue()
}

func writeState(path string, state persistedState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxStateBytes {
		return errors.New("runner state exceeds size limit")
	}
	if info, err := os.Lstat(path); err == nil {
		if err := validateOwnedFile(info, path, 0o600); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".runner-*")
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

func validateState(state persistedState) error {
	if state.Version != stateVersion {
		return fmt.Errorf("unsupported runner state version %d", state.Version)
	}
	if len(state.Records) > maxRecords {
		return errors.New("runner state contains too many records")
	}
	seen := make(map[string]bool, len(state.Records))
	for _, record := range state.Records {
		canonical, err := client.NormalizeName(record.Endpoint.Name)
		if err != nil || canonical != record.Endpoint.Name {
			return fmt.Errorf("invalid runner record name %q", record.Endpoint.Name)
		}
		if seen[canonical] {
			return fmt.Errorf("duplicate runner record %q", canonical)
		}
		seen[canonical] = true
		if record.Identity.PID <= 0 || record.Identity.Start <= 0 || record.ProcessGroup != record.Identity.PID {
			return fmt.Errorf("invalid process identity for %q", canonical)
		}
		if record.UID != uint32(os.Geteuid()) {
			return fmt.Errorf("runner record %q belongs to unexpected UID %d", canonical, record.UID)
		}
		if record.Supervisor.PID <= 0 || record.Supervisor.Start <= 0 || record.SupervisorUID != uint32(os.Geteuid()) {
			return fmt.Errorf("invalid supervisor identity for %q", canonical)
		}
		if !filepath.IsAbs(record.WorkingDirectory) {
			return fmt.Errorf("runner record %q has a relative working directory", canonical)
		}
		if record.Endpoint.Proxy {
			if record.Endpoint.Host != "127.0.0.1" || record.Endpoint.Port == 0 || record.Endpoint.URL != "https://"+canonical {
				return fmt.Errorf("runner record %q has an invalid endpoint", canonical)
			}
		} else if record.Endpoint.Host != "" || record.Endpoint.Port != 0 || record.Endpoint.URL != "" {
			return fmt.Errorf("non-proxy runner record %q has proxy metadata", canonical)
		}
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
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
		return errors.New("runner state directory must be a real directory")
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("runner state directory has unsafe mode %04o; want 0700", info.Mode().Perm())
	}
	uid, err := fileUID(info)
	if err != nil {
		return err
	}
	if uid != uint32(os.Geteuid()) {
		return fmt.Errorf("runner state directory is owned by UID %d; want %d", uid, os.Geteuid())
	}
	return nil
}

func validateOwnedFile(info os.FileInfo, path string, mode os.FileMode) error {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must be a regular file, not a symlink", path)
	}
	if info.Mode().Perm() != mode {
		return fmt.Errorf("%s has unsafe mode %04o; want %04o", path, info.Mode().Perm(), mode)
	}
	uid, err := fileUID(info)
	if err != nil {
		return err
	}
	if uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s is owned by UID %d; want %d", path, uid, os.Geteuid())
	}
	return nil
}

func fileUID(info os.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("file ownership is unavailable")
	}
	return stat.Uid, nil
}

func findRecord(records []Record, name string) (Record, bool) {
	for _, record := range records {
		if record.Endpoint.Name == name {
			return record, true
		}
	}
	return Record{}, false
}

func deleteRecord(records []Record, name string, identity Identity) []Record {
	result := records[:0]
	for _, record := range records {
		if record.Endpoint.Name == name && record.Identity == identity {
			continue
		}
		result = append(result, record)
	}
	return result
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
