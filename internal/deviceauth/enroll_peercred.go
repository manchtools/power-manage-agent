package deviceauth

import (
	"log/slog"
	"net"
	"os"
)

// peerAuthorized reports whether a connection whose peer process runs as
// peerUID may use the local enrollment socket. Enrollment is a privileged
// local operation: only the agent's own uid (selfUID — root under the
// shipped unit) is accepted. Any other local uid, including an unprivileged
// caller, is refused.
func peerAuthorized(peerUID, selfUID int) bool {
	return peerUID == selfUID
}

// peerCredListener wraps a unix net.Listener and only yields connections
// whose peer process runs as the authorized uid (selfUID). Connections from
// any other uid — and any connection whose peer credentials cannot be read —
// are closed and skipped (fail closed). Skipping rather than returning an
// error keeps a hostile local caller from stalling the accept loop.
type peerCredListener struct {
	net.Listener
	selfUID int
	logger  *slog.Logger
}

// newPeerCredListener wraps l so that Accept only yields connections from the
// agent's own uid (os.Getuid()).
func newPeerCredListener(l net.Listener, logger *slog.Logger) *peerCredListener {
	if logger == nil {
		logger = slog.Default()
	}
	return &peerCredListener{Listener: l, selfUID: os.Getuid(), logger: logger}
}

// Accept returns the next connection from an authorized peer uid, closing and
// skipping every connection from another uid or whose credentials cannot be
// read. peerUIDOf is platform-specific; on platforms without peer-credential
// retrieval it fails closed, so this listener refuses every connection.
func (l *peerCredListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peerUID, err := peerUIDOf(conn)
		if err != nil {
			l.logger.Warn("enrollment: refusing connection; peer credentials unreadable", "error", err)
			conn.Close()
			continue
		}
		if !peerAuthorized(peerUID, l.selfUID) {
			l.logger.Warn("enrollment: refusing unprivileged local caller",
				"peer_uid", peerUID, "required_uid", l.selfUID)
			conn.Close()
			continue
		}
		return conn, nil
	}
}
