// Package luksd implements the agent's LUKS user-passphrase daemon: a
// root, in-process Unix-socket service that lets an UNPRIVILEGED local
// user set a LUKS passphrase WITHOUT any sudoers rule.
//
// WS6 #1/#19 close a local privilege escalation. The previous design ran
// `power-manage-agent luks set-passphrase` under a NOPASSWD sudoers rule
// with an attacker-controllable `--data-dir`, so any local user could
// point root's cryptsetup helper at a forged credential store and a
// hostile gateway. This daemon removes BOTH: the sudoers rule is deleted,
// and the only thing crossing the socket is `{token, passphrase}` — no
// data dir, no store path. Authorization is the existing server-issued
// LUKS token (device-bound, single-use, short-TTL), validated by the
// daemon over the agent's OWN authenticated gateway connection — NEVER the
// socket peer's OS identity. So the socket can be world-connectable (0666,
// mirroring enroll.sock): the token is the authority, not the local user.
package luksd

// DefaultSocketPath is the unix socket the root agent listens on for
// LUKS passphrase requests. Mode 0666 (token is the authorization).
const DefaultSocketPath = "/run/pm-agent/luks.sock"

// userPassphraseSlot is the LUKS keyslot the user passphrase occupies.
// Slot 7 by convention across the agent (see executor/luks.go).
const userPassphraseSlot = 7

// minPassphraseLength is the floor the daemon enforces regardless of the
// server-supplied minimum, matching the agent's existing LUKS policy.
const minPassphraseLength = 16

// Request is the ONLY thing the unprivileged client sends. There is
// deliberately no data-dir / store-path field — the daemon uses its own
// fixed, root-owned data dir and the agent's own credentials. Unknown
// JSON fields (e.g. an injected "data_dir") are ignored by the decoder.
type Request struct {
	Token      string `json:"token"`
	Passphrase string `json:"passphrase"`
}

// Response is the daemon's reply. Code is a stable machine-readable
// reason; Error is a human-facing message.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Code  string `json:"code,omitempty"`
}

// Stable response codes.
const (
	CodeMissingToken     = "missing_token"
	CodeNotConnected     = "not_connected"
	CodeInvalidToken     = "invalid_token"
	CodePassphrasePolicy = "passphrase_policy"
	CodePassphraseReuse  = "passphrase_reuse"
	CodeKeyUnavailable   = "key_unavailable"
	CodeInternal         = "internal"
	CodeOK               = "ok"
)
