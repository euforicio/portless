package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/euforicio/portless/internal/runner"
	"github.com/euforicio/portless/internal/tailscale"
	"golang.org/x/sys/unix"
)

const shareStateVersion = 1

type ownedShare struct {
	Identity runner.Identity `json:"identity"`
	Plan     tailscale.Plan  `json:"plan"`
}

type shareState struct {
	Version int          `json:"version"`
	Shares  []ownedShare `json:"shares"`
}

func addOwnedShare(identity runner.Identity, plan tailscale.Plan) error {
	return mutateShareState(func(state *shareState) error {
		for _, share := range state.Shares {
			if share.Plan.Registration.Name == plan.Registration.Name {
				return errors.New("a durable share already exists for this name")
			}
		}
		state.Shares = append(state.Shares, ownedShare{Identity: identity, Plan: plan})
		slices.SortFunc(state.Shares, func(a, b ownedShare) int {
			if a.Plan.Registration.Name < b.Plan.Registration.Name {
				return -1
			}
			if a.Plan.Registration.Name > b.Plan.Registration.Name {
				return 1
			}
			return 0
		})
		return nil
	})
}

func removeOwnedShare(identity runner.Identity, plan tailscale.Plan) error {
	return mutateShareState(func(state *shareState) error {
		retained := state.Shares[:0]
		for _, share := range state.Shares {
			if share.Identity == identity && share.Plan.Registration == plan.Registration {
				continue
			}
			retained = append(retained, share)
		}
		state.Shares = retained
		return nil
	})
}

func ownedShares() ([]ownedShare, error) {
	state, err := readShareState(filepath.Join(runnerStateDirectory(), "shares.json"))
	if err != nil {
		return nil, err
	}
	return append([]ownedShare(nil), state.Shares...), nil
}

func mutateShareState(operation func(*shareState) error) error {
	return withShareState(operation, true)
}

func withShareState(operation func(*shareState) error, write bool) error {
	directory := runnerStateDirectory()
	if _, err := runner.Open(directory); err != nil {
		return err
	}
	lockPath := filepath.Join(directory, "shares.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	path := filepath.Join(directory, "shares.json")
	state, err := readShareState(path)
	if err != nil {
		return err
	}
	if err := operation(&state); err != nil {
		return err
	}
	if !write {
		return nil
	}
	return writeShareState(path, state)
}

func readShareState(path string) (shareState, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return shareState{Version: shareStateVersion}, nil
	}
	if err != nil {
		return shareState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return shareState{}, errors.New("share state must be a regular 0600 file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return shareState{}, err
	}
	if len(data) > 1<<20 {
		return shareState{}, errors.New("share state exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state shareState
	if err := decoder.Decode(&state); err != nil {
		return shareState{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return shareState{}, errors.New("share state contains trailing data")
	}
	if state.Version != shareStateVersion || len(state.Shares) > 1024 {
		return shareState{}, errors.New("unsupported or oversized share state")
	}
	return state, nil
}

func writeShareState(path string, state shareState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".shares-*")
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
