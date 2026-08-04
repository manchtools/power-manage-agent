//go:build linux

package deviceauth

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// peerUIDOf reads the connecting process's uid from the kernel via
// SO_PEERCRED. It works only for unix-domain connections; anything else
// fails closed.
func peerUIDOf(conn net.Conn) (int, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0, errors.New("connection does not expose a syscall.Conn")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var ucred *unix.Ucred
	var credErr error
	if ctrlErr := raw.Control(func(fd uintptr) {
		ucred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); ctrlErr != nil {
		return 0, ctrlErr
	}
	if credErr != nil {
		return 0, credErr
	}
	return int(ucred.Uid), nil
}
