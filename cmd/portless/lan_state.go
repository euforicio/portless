package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/euforicio/portless/internal/lan"
	"github.com/euforicio/portless/internal/runner"
	"golang.org/x/sys/unix"
)

const lanStateVersion = 1

type ownedLAN struct {
	Identity     runner.Identity  `json:"identity"`
	Registration lan.Registration `json:"registration"`
}

type durableLANState struct {
	Version int        `json:"version"`
	LAN     []ownedLAN `json:"lan"`
}

func updateOwnedLAN(identity runner.Identity, registration lan.Registration) error {
	if identity.PID <= 0 || identity.Start <= 0 {
		return errors.New("LAN ownership requires a process identity")
	}
	if err := registration.Validate(); err != nil {
		return err
	}
	return mutateLANState(func(state *durableLANState) error {
		for index, existing := range state.LAN {
			if existing.Registration.Name != registration.Name {
				continue
			}
			if existing.Identity != identity {
				return errors.New("a durable LAN exposure already exists for this name")
			}
			state.LAN[index].Registration = registration
			return nil
		}
		state.LAN = append(state.LAN, ownedLAN{Identity: identity, Registration: registration})
		slices.SortFunc(state.LAN, func(a, b ownedLAN) int {
			if a.Registration.Name < b.Registration.Name {
				return -1
			}
			if a.Registration.Name > b.Registration.Name {
				return 1
			}
			return 0
		})
		return nil
	})
}

func removeOwnedLAN(identity runner.Identity, name string) error {
	return mutateLANState(func(state *durableLANState) error {
		retained := state.LAN[:0]
		for _, exposure := range state.LAN {
			if exposure.Identity == identity && exposure.Registration.Name == name {
				continue
			}
			retained = append(retained, exposure)
		}
		state.LAN = retained
		return nil
	})
}

func ownedLANExposures() ([]ownedLAN, error) {
	state, err := readLANState(filepath.Join(runnerStateDirectory(), "lan.json"))
	if err != nil {
		return nil, err
	}
	return slices.Clone(state.LAN), nil
}

func mutateLANState(operation func(*durableLANState) error) error {
	directory := runnerStateDirectory()
	if _, err := runner.Open(directory); err != nil {
		return err
	}
	lock, err := openLANLock(filepath.Join(directory, "lan.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	path := filepath.Join(directory, "lan.json")
	state, err := readLANState(path)
	if err != nil {
		return err
	}
	if err := operation(&state); err != nil {
		return err
	}
	return writeLANState(path, state)
}

func openLANLock(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil {
		unix.Close(descriptor)
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || int(stat.Uid) != os.Geteuid() {
		unix.Close(descriptor)
		return nil, errors.New("LAN state lock must be an owned regular 0600 file")
	}
	return os.NewFile(uintptr(descriptor), path), nil
}

func readLANState(path string) (durableLANState, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return durableLANState{Version: lanStateVersion}, nil
	}
	if err != nil {
		return durableLANState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return durableLANState{}, errors.New("LAN state must be a regular 0600 file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return durableLANState{}, errors.New("LAN state has an unexpected owner")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return durableLANState{}, err
	}
	if len(data) > 1<<20 {
		return durableLANState{}, errors.New("LAN state exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state durableLANState
	if err := decoder.Decode(&state); err != nil {
		return durableLANState{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return durableLANState{}, errors.New("LAN state contains trailing data")
	}
	if state.Version != lanStateVersion || len(state.LAN) > 256 {
		return durableLANState{}, errors.New("unsupported or oversized LAN state")
	}
	seen := make(map[string]bool, len(state.LAN))
	for _, exposure := range state.LAN {
		if exposure.Identity.PID <= 0 || exposure.Identity.Start <= 0 || seen[exposure.Registration.Name] {
			return durableLANState{}, errors.New("invalid LAN ownership state")
		}
		if err := exposure.Registration.Validate(); err != nil {
			return durableLANState{}, err
		}
		seen[exposure.Registration.Name] = true
	}
	return state, nil
}

func writeLANState(path string, state durableLANState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".lan-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
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
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
