package luksd

import (
	"log/slog"
	"net"
	"os"
)

// firstRegularUID is the conventional floor for interactive login accounts on
// Linux (UID_MIN in /etc/login.defs). Below it sit root and the service
// accounts a remote compromise lands in.
const firstRegularUID = 1000

// nobodyUID is the unprivileged account kernel and userspace map anonymous or
// squashed identities onto. It is above firstRegularUID on most distributions
// but is never a person setting a disk passphrase, so it is excluded by name.
const nobodyUID = 65534

// peerAuthorized reports whether a local peer running as peerUID may submit a
// LUKS passphrase request to the daemon running as selfUID.
//
// This socket is deliberately unlike enroll.sock, whose only legitimate client
// is the agent itself, so same-uid is its rule. Here the client is the endpoint
// user's UNPRIVILEGED CLI and its uid is not knowable in advance — an AD/SSSD
// login gets an arbitrary one — so the rule is the strongest one that does not
// need to know the human:
//
//   - the agent's own uid (root under the shipped unit) is allowed, and
//   - any regular interactive login uid is allowed.
//
// That refuses the case that matters in practice: a service account
// (www-data, nobody, a compromised daemon) that scraped the one-time token out
// of somebody's /proc/<pid>/cmdline and connected as itself. It deliberately
// does NOT claim to tell one logged-in human from another — the token is a
// bearer credential and nothing the kernel reports about the peer can decide
// which human it was issued to. That residual is why the token no longer
// travels on argv at all (see cmd_luks.go and the control's CliCommand).
func peerAuthorized(peerUID, selfUID int) bool {
	if peerUID < 0 {
		return false
	}
	if peerUID == selfUID {
		return true
	}
	return peerUID >= firstRegularUID && peerUID != nobodyUID
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
// skipping every other one. peerUIDOf is platform-specific; on platforms
// without peer-credential retrieval it fails closed, so this listener refuses
// every connection there.
func (l *peerCredListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peerUID, err := peerUIDOf(conn)
		if err != nil {
			l.logger.Warn("luksd: refusing connection; peer credentials unreadable", "error", err)
			_ = conn.Close()
			continue
		}
		if !peerAuthorized(peerUID, l.selfUID) {
			// Attribution: a stolen token used from a service account leaves
			// the uid in the root-owned journal.
			l.logger.Warn("luksd: refusing LUKS passphrase request from a non-login uid",
				"peer_uid", peerUID, "agent_uid", l.selfUID)
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}
