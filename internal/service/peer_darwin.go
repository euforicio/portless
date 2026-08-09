//go:build darwin

package service

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// PeerCredentials is the kernel-provided identity of a connected local client.
type PeerCredentials struct {
	UID    uint32
	Groups []uint32
}

// Credentials reads LOCAL_PEERCRED from a real accepted Unix connection.
func Credentials(connection *net.UnixConn) (PeerCredentials, error) {
	if connection == nil {
		return PeerCredentials{}, errors.New("nil Unix connection")
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return PeerCredentials{}, err
	}
	var credential *unix.Xucred
	var socketErr error
	err = raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if err != nil {
		return PeerCredentials{}, err
	}
	if socketErr != nil {
		return PeerCredentials{}, socketErr
	}
	if credential == nil || credential.Version != 0 || credential.Ngroups < 0 || int(credential.Ngroups) > len(credential.Groups) {
		return PeerCredentials{}, errors.New("invalid peer credentials")
	}
	groups := append([]uint32(nil), credential.Groups[:credential.Ngroups]...)
	return PeerCredentials{UID: credential.Uid, Groups: groups}, nil
}

// Allowed reports whether the peer is root, the designated owner, or a member
// of the narrowly selected management group.
func (p PeerCredentials) Allowed(ownerUID, managementGID uint32) bool {
	if p.UID == 0 || p.UID == ownerUID {
		return true
	}
	for _, group := range p.Groups {
		if group == managementGID {
			return true
		}
	}
	return false
}
