package luksd

import (
	"log/slog"
	"net"
	"os"
)

type peerCredentials struct {
	uid int
	pid int
}

// peerAuthorized reports whether a local peer running as peerUID may submit a
// LUKS passphrase request to the daemon running as selfUID.
//
// This socket is deliberately unlike enroll.sock, whose only legitimate client
// is the agent itself, so same-uid is its rule. Here the client is the endpoint
// user's UNPRIVILEGED CLI. Linux's audit login UID identifies the authenticated
// login session without guessing from numeric UID ranges, so low-UID and
// directory-backed users work while service processes with no login session do
// not.
//
// The agent's own uid remains allowed for local maintenance. Every other peer
// must run as the uid that authenticated the kernel audit session.
func peerAuthorized(peerUID, selfUID, loginUID int) bool {
	if peerUID < 0 {
		return false
	}
	if peerUID == selfUID {
		return true
	}
	return loginUID >= 0 && peerUID == loginUID
}

// peerCredListener wraps a unix net.Listener and only yields connections whose
// peer process passes peerAuthorized. Connections from any other uid — and any
// connection whose peer credentials cannot be read — are closed and skipped
// (fail closed). Skipping rather than returning an error keeps a hostile local
// caller from stalling the accept loop.
type peerCredListener struct {
	net.Listener
	selfUID int
	logger  *slog.Logger
}

// newPeerCredListener wraps l so that Accept only yields connections from a
// peer uid the daemon accepts, judged against the agent's own uid.
func newPeerCredListener(l net.Listener, logger *slog.Logger) *peerCredListener {
	if logger == nil {
		logger = slog.Default()
	}
	return &peerCredListener{Listener: l, selfUID: os.Getuid(), logger: logger}
}

// Accept returns the next connection from an authorized peer uid, closing and
// skipping every other one. peerCredentialsOf is platform-specific; on platforms
// without peer-credential retrieval it fails closed, so this listener refuses
// every connection there.
func (l *peerCredListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		credentials, err := peerCredentialsOf(conn)
		if err != nil {
			l.logger.Warn("luksd: refusing connection; peer credentials unreadable", "error", err)
			_ = conn.Close()
			continue
		}
		loginUID := -1
		if credentials.uid != l.selfUID {
			loginUID, err = loginUIDOfPID(credentials.pid)
			if err != nil {
				l.logger.Warn("luksd: refusing connection; login identity unreadable", "error", err)
				_ = conn.Close()
				continue
			}
		}
		if !peerAuthorized(credentials.uid, l.selfUID, loginUID) {
			// Attribution: a stolen token used from a service account leaves
			// the uid in the root-owned journal.
			l.logger.Warn("luksd: refusing LUKS passphrase request from a non-login uid",
				"peer_uid", credentials.uid, "login_uid", loginUID, "agent_uid", l.selfUID)
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}
