package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// ArtifactState is an auditable snapshot of one owned installation artifact.
type ArtifactState struct {
	Path   string
	Exists bool
	Mode   fs.FileMode
	UID    int
	GID    int
	Size   int64
	SHA256 string
	Match  bool
}

// Report records every created, updated, unchanged, or removed artifact.
type Report struct {
	Action  Action
	Changed []string
	State   []ArtifactState
}

func (r Report) HasChanges() bool { return len(r.Changed) != 0 }

// Installer creates only the filesystem artifacts owned by Portless. It never
// invokes sudo, launchctl, or security; those privileged commands are explicit
// plans applied by the installation command.
type Installer struct {
	Config Config
}

func (i Installer) Install(sourceExecutable string) (Report, error) {
	return i.writeArtifacts(ActionInstall, sourceExecutable)
}

func (i Installer) Upgrade(sourceExecutable string) (Report, error) {
	return i.writeArtifacts(ActionUpgrade, sourceExecutable)
}

func (i Installer) writeArtifacts(action Action, sourceExecutable string) (Report, error) {
	if err := i.Config.validate(); err != nil {
		return Report{}, err
	}
	source, err := os.Open(sourceExecutable)
	if err != nil {
		return Report{}, err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return Report{}, err
	}
	if !info.Mode().IsRegular() {
		return Report{}, errors.New("source executable must be a regular file")
	}
	binary, err := io.ReadAll(source)
	if err != nil {
		return Report{}, err
	}
	plist, err := i.Config.Plist()
	if err != nil {
		return Report{}, err
	}

	report := Report{Action: action}
	dirs := []struct {
		path    string
		mode    fs.FileMode
		uid     int
		gid     int
		enforce bool
	}{
		{filepath.Dir(i.Config.Executable), 0o755, i.Config.UID, i.Config.GID, false},
		{filepath.Dir(i.Config.PlistPath), 0o755, i.Config.UID, i.Config.GID, false},
		{i.Config.StateDir, 0o700, i.Config.UID, i.Config.GID, true},
		{i.Config.RuntimeDir, 0o750, i.Config.UID, i.Config.ManagementGID, true},
		{filepath.Dir(i.Config.StdoutPath), 0o750, i.Config.UID, i.Config.GID, true},
		{filepath.Dir(i.Config.StderrPath), 0o750, i.Config.UID, i.Config.GID, true},
	}
	seen := make(map[string]bool)
	for _, dir := range dirs {
		if seen[dir.path] {
			continue
		}
		seen[dir.path] = true
		changed, err := ensureDir(dir.path, dir.mode, dir.uid, dir.gid, dir.enforce)
		if err != nil {
			return Report{}, err
		}
		if changed {
			report.Changed = append(report.Changed, dir.path)
		}
	}
	for _, artifact := range []struct {
		path string
		data []byte
		mode fs.FileMode
	}{
		{i.Config.Executable, binary, 0o755},
		{i.Config.PlistPath, plist, 0o644},
	} {
		changed, err := writeOwnedFile(artifact.path, artifact.data, artifact.mode, i.Config.UID, i.Config.GID)
		if err != nil {
			return Report{}, err
		}
		if changed {
			report.Changed = append(report.Changed, artifact.path)
		}
	}
	sort.Strings(report.Changed)
	report.State, err = i.Status()
	return report, err
}

// Status reads the binary and plist without contacting launchd.
func (i Installer) Status() ([]ArtifactState, error) {
	if err := i.Config.validate(); err != nil {
		return nil, err
	}
	plist, err := i.Config.Plist()
	if err != nil {
		return nil, err
	}
	desired := map[string]struct {
		data []byte
		mode fs.FileMode
	}{
		i.Config.PlistPath: {plist, 0o644},
	}
	states := make([]ArtifactState, 0, 2)
	for _, path := range []string{i.Config.Executable, i.Config.PlistPath} {
		state, err := inspectArtifact(path)
		if err != nil {
			return nil, err
		}
		if want, ok := desired[path]; ok && state.Exists {
			digest := sha256.Sum256(want.data)
			state.Match = state.SHA256 == hex.EncodeToString(digest[:]) && state.Mode == want.mode
		}
		states = append(states, state)
	}
	return states, nil
}

// Uninstall removes the launchd plist and installed binary idempotently. State,
// certificates, and logs are retained for recovery unless PurgeData is called.
func (i Installer) Uninstall() (Report, error) {
	if err := i.Config.validate(); err != nil {
		return Report{}, err
	}
	report := Report{Action: ActionUninstall}
	for _, artifact := range []struct {
		path string
		uid  int
		gid  int
	}{
		{i.Config.PlistPath, i.Config.UID, i.Config.GID},
		{i.Config.Executable, i.Config.UID, i.Config.GID},
		{i.Config.ManagementSocket, i.Config.UID, i.Config.ManagementGID},
	} {
		removed, err := removeOwnedPath(artifact.path, artifact.uid, artifact.gid)
		if err != nil {
			return Report{}, err
		}
		if removed {
			report.Changed = append(report.Changed, artifact.path)
		}
	}
	sort.Strings(report.Changed)
	state, err := i.Status()
	report.State = state
	return report, err
}

// PurgeData is deliberately separate from uninstall because it destroys the
// CA and route state. The caller must present this as an explicit choice.
func (i Installer) PurgeData() ([]string, error) {
	if err := i.Config.validate(); err != nil {
		return nil, err
	}
	removed := make([]string, 0, 2)
	for _, artifact := range []struct {
		path string
		uid  int
		gid  int
	}{
		{i.Config.RuntimeDir, i.Config.UID, i.Config.ManagementGID},
		{i.Config.StateDir, i.Config.UID, i.Config.GID},
	} {
		path := artifact.path
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to purge non-directory %s", path)
		}
		actualUID, actualGID, err := fileOwnership(info)
		if err != nil {
			return nil, err
		}
		if actualUID != artifact.uid || actualGID != artifact.gid {
			return nil, fmt.Errorf("refusing to purge unowned directory %s", path)
		}
		if err := os.RemoveAll(path); err != nil {
			return nil, err
		}
		removed = append(removed, path)
	}
	return removed, nil
}

func ensureDir(path string, mode fs.FileMode, uid, gid int, enforce bool) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, mode); err != nil {
			return false, err
		}
		if err := os.Chmod(path, mode); err != nil {
			return false, err
		}
		if err := os.Chown(path, uid, gid); err != nil {
			return false, err
		}
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%s is not a real directory", path)
	}
	if !enforce {
		if info.Mode().Perm()&0o022 != 0 {
			return false, fmt.Errorf("shared parent directory %s is group or world writable", path)
		}
		actualUID, _, err := fileOwnership(info)
		if err != nil {
			return false, err
		}
		if actualUID != uid {
			return false, fmt.Errorf("shared parent directory %s is owned by UID %d; want %d", path, actualUID, uid)
		}
		return false, nil
	}
	actualUID, actualGID, err := fileOwnership(info)
	if err != nil {
		return false, err
	}
	changed := info.Mode().Perm() != mode || actualUID != uid || actualGID != gid
	if err := os.Chmod(path, mode); err != nil {
		return false, err
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return false, err
	}
	return changed, nil
}

func writeOwnedFile(path string, data []byte, mode fs.FileMode, uid, gid int) (bool, error) {
	if current, err := os.ReadFile(path); err == nil {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return false, statErr
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("refusing to replace non-regular file %s", path)
		}
		actualUID, actualGID, ownerErr := fileOwnership(info)
		if ownerErr != nil {
			return false, ownerErr
		}
		if bytes.Equal(current, data) && info.Mode().Perm() == mode && actualUID == uid && actualGID == gid {
			if err := os.Chown(path, uid, gid); err != nil {
				return false, err
			}
			return false, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".portless-*")
	if err != nil {
		return false, err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return false, err
	}
	if err := temp.Chown(uid, gid); err != nil {
		temp.Close()
		return false, err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return false, err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return false, err
	}
	if err := temp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tempName, path); err != nil {
		return false, err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return false, err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return false, err
	}
	return true, nil
}

func inspectArtifact(path string) (ArtifactState, error) {
	state := ArtifactState{Path: path}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return state, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	digest := sha256.Sum256(data)
	uid, gid, err := fileOwnership(info)
	if err != nil {
		return state, err
	}
	state.Exists = true
	state.Mode = info.Mode().Perm()
	state.UID = uid
	state.GID = gid
	state.Size = info.Size()
	state.SHA256 = hex.EncodeToString(digest[:])
	return state, nil
}

func removeOwnedPath(path string, uid, gid int) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() && info.Mode()&os.ModeSocket == 0 {
		return false, fmt.Errorf("refusing to remove unexpected artifact %s", path)
	}
	actualUID, actualGID, err := fileOwnership(info)
	if err != nil {
		return false, err
	}
	if actualUID != uid || actualGID != gid {
		return false, fmt.Errorf("refusing to remove unowned artifact %s", path)
	}
	return true, os.Remove(path)
}
