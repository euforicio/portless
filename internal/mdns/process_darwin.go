//go:build darwin

package mdns

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func inspectIdentity(pid int) (Identity, error) {
	process, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EIO) {
			return Identity{}, os.ErrProcessDone
		}
		return Identity{}, err
	}
	if process == nil || int(process.Proc.P_pid) != pid {
		return Identity{}, os.ErrProcessDone
	}
	start := process.Proc.P_starttime.Sec*1_000_000 + int64(process.Proc.P_starttime.Usec)
	if start <= 0 {
		return Identity{}, errors.New("dns-sd process has invalid start identity")
	}
	return Identity{PID: pid, Start: start}, nil
}
