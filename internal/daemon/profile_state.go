package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/euforicio/portless/internal/profile"
	"github.com/euforicio/portless/internal/routes"
)

const (
	profileStateVersion = 1
	profileStateName    = "profile.json"
	maxProfileBytes     = 64 << 10
)

type persistedProfile struct {
	Version int            `json:"version"`
	Config  profile.Config `json:"config"`
	Legacy  bool           `json:"legacy,omitempty"`
}

// reconcileProfile pins a state directory to one validated public profile.
// A daemon never silently reinterprets durable routes under another TLD,
// listener, scheme, wildcard policy, or certificate source.
func reconcileProfile(stateDir string, config profile.Config, legacy, allowReplace bool) error {
	tld, err := routes.NormalizeTLD(config.TLD)
	if err != nil {
		return err
	}
	config.TLD = tld
	state := persistedProfile{Version: profileStateVersion, Config: config, Legacy: legacy}
	path := filepath.Join(stateDir, profileStateName)
	data, err := os.ReadFile(path)
	if err == nil {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return statErr
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			return errors.New("profile state must be a regular 0600 file")
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
			return errors.New("profile state has an unexpected owner")
		}
		if len(data) > maxProfileBytes {
			return errors.New("profile state exceeds size limit")
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		var existing persistedProfile
		if err := decoder.Decode(&existing); err != nil {
			return fmt.Errorf("decode profile state: %w", err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return errors.New("profile state contains trailing data")
		}
		if existing.Version != profileStateVersion {
			return fmt.Errorf("unsupported profile state version %d", existing.Version)
		}
		if !reflect.DeepEqual(existing, state) {
			if !allowReplace {
				return errors.New("active proxy profile differs from persisted state")
			}
			routeState, routeErr := readState(filepath.Join(stateDir, stateFileName))
			if routeErr != nil {
				return routeErr
			}
			if len(routeState.Routes) != 0 {
				return errors.New("cannot replace the active proxy profile while routes are registered")
			}
		} else {
			return nil
		}
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	temporary, err := os.CreateTemp(stateDir, ".profile-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
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
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	directory, err := os.Open(stateDir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func loadPersistedProfile(stateDir string) (persistedProfile, bool, error) {
	path := filepath.Join(stateDir, profileStateName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return persistedProfile{}, false, nil
	}
	if err != nil {
		return persistedProfile{}, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return persistedProfile{}, false, errors.New("profile state must be a regular 0600 file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return persistedProfile{}, false, errors.New("profile state has an unexpected owner")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return persistedProfile{}, false, err
	}
	if len(data) > maxProfileBytes {
		return persistedProfile{}, false, errors.New("profile state exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state persistedProfile
	if err := decoder.Decode(&state); err != nil {
		return persistedProfile{}, false, fmt.Errorf("decode profile state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return persistedProfile{}, false, errors.New("profile state contains trailing data")
	}
	if state.Version != profileStateVersion {
		return persistedProfile{}, false, fmt.Errorf("unsupported profile state version %d", state.Version)
	}
	return state, true, nil
}
