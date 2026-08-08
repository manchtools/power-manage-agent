//go:build !linux

package luksd

import (
	"errors"
	"net"
)

// peerCredentialsOf has no portable implementation off Linux: SO_PEERCRED is
// Linux-specific and the agent ships only as a Linux systemd unit. Fail closed
// so a non-Linux build refuses every LUKS passphrase connection rather than
// admitting an unauthenticated caller to a root daemon.
func peerCredentialsOf(net.Conn) (peerCredentials, error) {
	return peerCredentials{}, errors.New("peer-credential authentication is unavailable on this platform")
}

func loginUIDOfPID(int) (int, error) {
	return -1, errors.New("login UID is unavailable on this platform")
}
