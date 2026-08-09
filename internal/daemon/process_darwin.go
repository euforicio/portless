//go:build darwin

package daemon

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func inspectProcess(pid int) (uint32, int64, error) {
	if pid <= 0 {
		return 0, 0, fmt.Errorf("invalid process ID %d", pid)
	}
	process, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, 0, err
	}
	if process == nil || int(process.Proc.P_pid) != pid {
		return 0, 0, fmt.Errorf("process %d does not exist", pid)
	}
	start := process.Proc.P_starttime.Sec*1_000_000 + int64(process.Proc.P_starttime.Usec)
	if start <= 0 {
		return 0, 0, fmt.Errorf("process %d has invalid start identity", pid)
	}
	return process.Eproc.Ucred.Uid, start, nil
}
