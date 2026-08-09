package service

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var socketCreateMu sync.Mutex

// SocketConfig defines the daemon-owned management socket. UID is normally
// root and GID is the dedicated group allowed to perform routine operations.
type SocketConfig struct {
	Path string
	UID  int
	GID  int
}

// ListenManagement creates a real Unix socket with a non-searchable setup
// window, then exposes only group read/write access at 0660 in a 0750 directory.
func ListenManagement(config SocketConfig) (*net.UnixListener, error) {
	if !filepath.IsAbs(config.Path) || config.UID < 0 || config.GID < 0 {
		return nil, errors.New("invalid management socket configuration")
	}
	if runtime.GOOS == "darwin" && len(config.Path) > 103 {
		return nil, errors.New("management socket path exceeds the macOS 103-byte limit")
	}
	socketCreateMu.Lock()
	defer socketCreateMu.Unlock()

	dir := filepath.Dir(config.Path)
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is not a real directory", dir)
		}
		uid, gid, ownerErr := fileOwnership(info)
		if ownerErr != nil {
			return nil, ownerErr
		}
		if uid != config.UID || gid != config.GID {
			return nil, fmt.Errorf("refusing management directory owned by %d:%d", uid, gid)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chown(dir, config.UID, config.GID); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(config.Path); err == nil {
		uid, gid, ownerErr := fileOwnership(info)
		if ownerErr != nil {
			return nil, ownerErr
		}
		if info.Mode()&os.ModeSocket == 0 || uid != config.UID || gid != config.GID {
			return nil, fmt.Errorf("refusing to replace unowned non-socket %s", config.Path)
		}
		probe, probeErr := net.DialUnix("unix", nil, &net.UnixAddr{Name: config.Path, Net: "unix"})
		if probeErr == nil {
			probe.Close()
			if err := os.Chmod(dir, 0o750); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("management socket %s is already active", config.Path)
		}
		if err := os.Remove(config.Path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.Path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	cleanup := func(cause error) (*net.UnixListener, error) {
		listener.Close()
		os.Remove(config.Path)
		return nil, cause
	}
	if err := os.Chown(config.Path, config.UID, config.GID); err != nil {
		return cleanup(err)
	}
	if err := os.Chmod(config.Path, 0o660); err != nil {
		return cleanup(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return cleanup(err)
	}
	return listener, nil
}
