//go:build linux

package luksd

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// peerUIDOf reads the connecting process's uid from the kernel via
// SO_PEERCRED. It works only for unix-domain connections; anything else fails
// closed.
func peerUIDOf(conn net.Conn) (int, error) {
	// SO_PEERCRED is only meaningful on AF_UNIX. On an AF_INET socket the
	// kernel answers with the LOCAL process's credentials instead of failing,
	// which would read as "the peer is us" — so the transport is checked first
	// rather than trusting the getsockopt to reject it.
	if addr := conn.LocalAddr(); addr == nil || addr.Network() != "unix" {
		return 0, errors.New("peer credentials are only available on a unix-domain connection")
	}
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
