//go:build unix

package service

import (
	"errors"
	"io/fs"
	"syscall"
)

func fileOwnership(info fs.FileInfo) (int, int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("file ownership is unavailable")
	}
	return int(stat.Uid), int(stat.Gid), nil
}
