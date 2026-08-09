//go:build darwin

package runner

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func processGroupAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

func inspectProcess(pid int) (uint32, Identity, int, error) {
	if pid <= 0 {
		return 0, Identity{}, 0, fmt.Errorf("invalid process ID %d", pid)
	}
	process, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		// SysctlKinfoProc reports EIO when kern.proc.pid returns a zero-sized
		// result, which is Darwin's normal missing-process result for this API.
		if errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EIO) {
			return 0, Identity{}, 0, ErrProcessGone
		}
		return 0, Identity{}, 0, err
	}
	if process == nil || int(process.Proc.P_pid) != pid {
		return 0, Identity{}, 0, ErrProcessGone
	}
	start := process.Proc.P_starttime.Sec*1_000_000 + int64(process.Proc.P_starttime.Usec)
	if start <= 0 {
		return 0, Identity{}, 0, fmt.Errorf("process %d has invalid start identity", pid)
	}
	return process.Eproc.Ucred.Uid, Identity{PID: pid, Start: start}, int(process.Eproc.Pgid), nil
}

func signalRecord(record Record, signal syscall.Signal) error {
	uid, identity, processGroup, err := inspectProcess(record.Identity.PID)
	if err != nil {
		if errors.Is(err, ErrProcessGone) {
			return os.ErrProcessDone
		}
		return err
	}
	if identity != record.Identity || uid != record.UID || processGroup != record.ProcessGroup || processGroup != record.Identity.PID {
		return ErrIdentityMismatch
	}
	if err := syscall.Kill(-processGroup, signal); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}

func probeRecord(record Record) (bool, error) {
	uid, identity, processGroup, err := inspectProcess(record.Identity.PID)
	if errors.Is(err, ErrProcessGone) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return identity == record.Identity && uid == record.UID && processGroup == record.ProcessGroup && processGroup == record.Identity.PID, nil
}

func supervisorAlive(record Record) (bool, error) {
	uid, identity, _, err := inspectProcess(record.Supervisor.PID)
	if errors.Is(err, ErrProcessGone) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return identity == record.Supervisor && uid == record.SupervisorUID, nil
}
