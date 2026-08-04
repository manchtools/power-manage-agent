//go:build !linux

package deviceauth

import (
	"errors"
	"net"
)

// peerUIDOf has no portable implementation off Linux: SO_PEERCRED is
// Linux-specific and the agent ships only as a Linux systemd unit. Fail
// closed so a non-Linux build refuses every enrollment connection rather than
// admitting an unauthenticated caller.
func peerUIDOf(net.Conn) (int, error) {
	return 0, errors.New("peer-credential authentication is unavailable on this platform")
}
