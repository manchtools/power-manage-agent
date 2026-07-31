package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysuser "github.com/manchtools/power-manage-sdk/sys/user"

	"github.com/manchtools/power-manage/agent/internal/store"
)

// LpsPasswordStore reports rotated local passwords to control over the agent's
// own mTLS stream.
//
// Spec 41 replaced two mechanisms at once. The passwords used to be sealed to a
// control public key and smuggled out inside the action result's
// `lps.rotations` metadata, because the agent had no authenticated channel of
// its own — a gateway relayed the result, and the seal existed so that relay
// could not read what it carried. The agent now holds a direct session with
// control, so the passwords travel on it as a first-class message and nothing
// in between ever sees them. Control encrypts them at rest on receipt.
type LpsPasswordStore interface {
	StorePasswords(ctx context.Context, actionID string, rotations []*pb.LpsPasswordRotation) error
}

// lpsRotationReason maps this package's internal reason strings to the wire
// enum. The string form used to survive to the server, which parsed it back;
// the enum is now set at the source and the server-side parser is gone.
func lpsRotationReason(reason string) pb.RotationReason {
	switch reason {
	case "initial", "user_created":
		return pb.RotationReason_ROTATION_REASON_INITIAL
	case "scheduled":
		return pb.RotationReason_ROTATION_REASON_SCHEDULED
	case "auth_grace":
		return pb.RotationReason_ROTATION_REASON_AUTH_GRACE
	default:
		return pb.RotationReason_ROTATION_REASON_UNSPECIFIED
	}
}

// executeLps manages local user password rotation (Local Password Solution).
func (e *Executor) executeLps(ctx context.Context, params *pb.LpsParams, state pb.DesiredState, actionID string) (*pb.CommandOutput, bool, map[string]string, error) {
	if params == nil {
		return nil, false, nil, fmt.Errorf("lps params required")
	}
	if actionID == "" {
		return nil, false, nil, fmt.Errorf("action ID required for LPS state tracking")
	}
	if len(params.Usernames) == 0 {
		return nil, false, nil, fmt.Errorf("at least one username is required")
	}
	for _, u := range params.Usernames {
		if !sysuser.IsValidName(u) {
			return nil, false, nil, fmt.Errorf("invalid username: %q", u)
		}
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		return e.removeLpsManagement(ctx, actionID)
	default:
		return e.setupLpsPasswords(ctx, params, actionID)
	}
}

// setupLpsPasswords checks if password rotation is needed for each user and rotates if so.
func (e *Executor) setupLpsPasswords(ctx context.Context, params *pb.LpsParams, actionID string) (*pb.CommandOutput, bool, map[string]string, error) {
	st := e.getStore()
	if st == nil {
		return nil, false, nil, fmt.Errorf("agent store not configured")
	}

	// Fail closed BEFORE touching any account: without a live session to
	// control we cannot report the rotated password, and rotating a credential
	// we cannot return to the operator would strand it. This is the same gate
	// the sealing key provided — a device that is not connected simply doesn't
	// rotate until it is.
	lpsStore := e.getLpsPasswordStore()
	if lpsStore == nil {
		return nil, false, nil, fmt.Errorf("LPS rotation requires a connection to the server (not connected)")
	}
	// Control attributes the password to this device; without our own ID the
	// rotation could not be recorded against the right record.
	if e.getDeviceID() == "" {
		return nil, false, nil, fmt.Errorf("LPS rotation requires the agent device ID (not configured)")
	}

	var output strings.Builder

	// Load state from SQLite
	userStates, err := st.GetLpsState(actionID)
	if err != nil {
		e.logger.Warn("failed to load LPS state, will treat as initial rotation", "action_id", actionID, "error", err)
		userStates = make(map[string]*store.LpsUserState)
	}

	// Map the complexity enum to the SDK's boolean flag. COMPLEX enables
	// special characters; ALPHANUMERIC uses letters and digits only.
	// UNSPECIFIED falls back to ALPHANUMERIC for compatibility with older
	// server versions that didn't set the field — logged so operators can
	// spot misconfigured policies.
	if params.Complexity == pb.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_UNSPECIFIED {
		e.logger.Warn("LPS policy has no complexity set, defaulting to alphanumeric",
			"action_id", actionID)
	}
	complexity := sysuser.ComplexityAlphanumeric
	if params.Complexity == pb.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_COMPLEX {
		complexity = sysuser.ComplexityComplex
	}

	// reported counts passwords control has accepted; it drives the
	// changed flag that used to be derived from the metadata batch.
	reported := 0
	var rotatedUsers []string
	var anyError error

	for _, username := range params.Usernames {
		// Verify user exists (fail closed on a check error — record it and move
		// on, matching this loop's other per-user error handling).
		uExists, err := userExists(ctx, username)
		if err != nil {
			anyError = fmt.Errorf("check user %s: %w", username, err)
			output.WriteString(fmt.Sprintf("LPS: %s — failed to verify user: %v\n", username, err))
			continue
		}
		if !uExists {
			output.WriteString(fmt.Sprintf("LPS: user %q does not exist, skipping\n", username))
			e.logger.Warn("LPS user does not exist, skipping", "username", username)
			continue
		}

		// Get per-user state
		storedState := userStates[username]

		// Determine if rotation is needed
		rotate, reason := shouldRotateLps(ctx, storedState, params, username, e.now().UTC())
		if !rotate {
			output.WriteString(fmt.Sprintf("LPS: %s — password up to date\n", username))
			continue
		}

		// Generate new password. Clamp the length to the SDK's accepted
		// range so out-of-bounds proto values don't fail the rotation.
		requested := int(params.PasswordLength)
		length := requested
		if length < sysuser.MinPasswordLength {
			length = sysuser.MinPasswordLength
		}
		if length > sysuser.MaxPasswordLength {
			length = sysuser.MaxPasswordLength
		}
		if length != requested {
			e.logger.Warn("LPS password length clamped to SDK bounds",
				"action_id", actionID, "username", username,
				"requested", requested, "effective", length,
				"min", sysuser.MinPasswordLength, "max", sysuser.MaxPasswordLength)
		}
		password, err := sysuser.GeneratePassword(length, complexity)
		if err != nil {
			anyError = fmt.Errorf("generate password for %s: %w", username, err)
			output.WriteString(fmt.Sprintf("LPS: %s — failed to generate password: %v\n", username, err))
			continue
		}

		// Report the new password to control BEFORE setting it locally.
		// password is an exec.Secret; Reveal() is the sanctioned plaintext
		// access. Reporting first means a failure here leaves the account's
		// password UNCHANGED — never rotate to a credential we cannot return
		// to the operator, which is the whole point of LPS. This is the
		// ordering the seal enforced; only the mechanism changed.
		plaintext := password.Reveal()
		rotatedAt := e.now().UTC()
		if err := lpsStore.StorePasswords(ctx, actionID, []*pb.LpsPasswordRotation{{
			Username:  username,
			Password:  plaintext,
			RotatedAt: rotatedAt.Format(time.RFC3339),
			Reason:    lpsRotationReason(reason),
		}}); err != nil {
			anyError = fmt.Errorf("report password for %s: %w", username, err)
			output.WriteString(fmt.Sprintf("LPS: %s — failed to report password to server, not rotating: %v\n", username, err))
			continue
		}

		// Set the password
		if err := userMgr.SetPassword(ctx, username, password); err != nil {
			anyError = fmt.Errorf("set password for %s: %w", username, err)
			output.WriteString(fmt.Sprintf("LPS: %s — failed to set password: %v\n", username, err))
			continue
		}

		rotatedUsers = append(rotatedUsers, username)

		now := rotatedAt
		output.WriteString(fmt.Sprintf("LPS: %s — rotated password (reason: %s)\n", username, reason))

		// Update per-user state in SQLite. The drift hash is over the local
		// plaintext (never leaves the device); the operator-facing record
		// carries only the sealed blob.
		hash := sha256.Sum256([]byte(plaintext))
		hashStr := hex.EncodeToString(hash[:])
		if err := st.SetLpsUserState(actionID, username, now, hashStr); err != nil {
			// The password WAS rotated (a durable side effect), but if the
			// rotation state fails to persist, last_rotated_at/password_hash stay
			// stale and the NEXT cycle re-rotates. Surface it as an action error
			// instead of reporting a clean success that hides the re-rotation.
			e.logger.Error("failed to persist LPS rotation state; next cycle will re-rotate",
				"action_id", actionID, "username", username, "error", err)
			anyError = fmt.Errorf("rotated password for %s but failed to persist rotation state (will re-rotate next cycle): %w", username, err)
		}

		reported++
	}

	// Notify affected users and terminate sessions after a grace period
	if len(rotatedUsers) > 0 {
		notifyUsers(ctx, rotatedUsers, "Session Termination",
			"Your password has been changed by Power Manage. All sessions will be terminated in 60 seconds. Please save your work.")
		output.WriteString(fmt.Sprintf("LPS: notified %d user(s), waiting 60 seconds before session termination\n", len(rotatedUsers)))

		select {
		case <-time.After(60 * time.Second):
		case <-ctx.Done():
			output.WriteString("LPS: grace period interrupted\n")
		}

		for _, username := range rotatedUsers {
			killUserSessions(ctx, username)
		}
		output.WriteString(fmt.Sprintf("LPS: terminated sessions for %d user(s)\n", len(rotatedUsers)))
	}

	// If no rotations occurred
	if reported == 0 {
		if anyError != nil {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stdout:   output.String(),
			}, false, nil, anyError
		}
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   output.String(),
		}, false, nil, nil
	}

	// No metadata: the passwords went to control on the stream, not through
	// the action result. Nothing parses `lps.rotations` any more — the gateway
	// that did is gone — so emitting it would only be a second copy of a
	// credential travelling a path with no reader.
	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, true, nil, anyError
}

// removeLpsManagement handles ABSENT state — stops managing, cleans up state.
func (e *Executor) removeLpsManagement(_ context.Context, actionID string) (*pb.CommandOutput, bool, map[string]string, error) {
	st := e.getStore()
	if st == nil {
		return nil, false, nil, fmt.Errorf("agent store not configured")
	}
	userStates, err := st.GetLpsState(actionID)
	if err != nil {
		// Sibling of the DeleteLpsState fail-closed below. Treating
		// a lookup failure as "no users to clean up" would let the
		// next branch return success even though the agent never
		// inspected its real local state.
		e.logger.Error("removeLpsManagement: failed to read local state",
			"action_id", actionID, "error", err)
		return nil, false, nil, fmt.Errorf("get lps state: %w", err)
	}

	if len(userStates) > 0 {
		if err := st.DeleteLpsState(actionID); err != nil {
			// Mirror the LUKS ABSENT-transition fix: returning
			// success here would tell the control plane the action
			// set is removed while leaving the local state row
			// intact, so the next reconcile re-rotates passwords
			// for users that should already be unmanaged.
			e.logger.Error("failed to delete LPS state", "action_id", actionID, "error", err)
			return nil, false, nil, fmt.Errorf("delete lps state: %w", err)
		}
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   "LPS: password management stopped, state removed\n",
		}, true, nil, nil
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   "LPS: password management not active, nothing to remove\n",
	}, false, nil, nil
}

// shouldRotateLps determines if a password rotation is needed for a user and returns the reason.
// now is the caller's clock reading (UTC); injecting it keeps rotation decisions
// deterministically testable with a fixed clock.
func shouldRotateLps(ctx context.Context, state *store.LpsUserState, params *pb.LpsParams, username string, now time.Time) (bool, string) {

	// No state = first run
	if state == nil {
		return true, "initial"
	}

	// Scheduled rotation: interval expired
	intervalDuration := time.Duration(params.RotationIntervalDays) * 24 * time.Hour
	if now.Sub(state.LastRotatedAt) >= intervalDuration {
		return true, "scheduled"
	}

	// Auth-based rotation: check if user authenticated since last rotation
	if params.GracePeriodHours > 0 {
		lastAuth, err := userMgr.LastLogin(ctx, username)
		if err == nil && !lastAuth.IsZero() && lastAuth.After(state.LastRotatedAt) {
			graceDuration := time.Duration(params.GracePeriodHours) * time.Hour
			if now.Sub(lastAuth) >= graceDuration {
				return true, "auth_grace"
			}
		}
	}

	return false, ""
}

// killUserSessions terminates all sessions and processes for a user.
// This ensures the old password cannot be used after rotation.
// Errors are logged at Warn but not returned — the user may have no
// active sessions (the most common case), in which case both
// loginctl and pkill exit non-zero. Operators triaging "the old
// password still works after rotation" need the underlying error in
// the journal to distinguish "no sessions present" from "loginctl /
// pkill failed", so the discarded errors get logged with stage tags
// instead of being silently swallowed.
func killUserSessions(ctx context.Context, username string) {
	// Delegate to the SDK user Manager, which terminates systemd-logind sessions
	// (loginctl terminate-user) and falls back to pkill -KILL -u, treating
	// "no sessions / no processes" as success — only a genuine failure returns
	// an error. Log it so operators can distinguish it from the benign case.
	if err := userMgr.KillSessions(ctx, username); err != nil {
		slog.Warn("killUserSessions: SDK KillSessions failed (may be benign — no active sessions/processes)",
			"username", username, "error", err)
	}
	// Brief wait for processes to fully exit
	time.Sleep(500 * time.Millisecond)
}

// reportUserCreatePassword sends a freshly created account's temporary password
// to control so an operator can retrieve it, using the same stream and the same
// message as an LPS rotation.
//
// Best-effort by design, and the one place in this file where that is the right
// call: the account already exists and already has the password by the time
// this runs, so refusing to report cannot un-create it. Every failure path
// writes a line into the action output, because the operator's only recovery is
// to notice and reset out of band.
func (e *Executor) reportUserCreatePassword(ctx context.Context, username, actionID, plaintext string, output *strings.Builder) {
	ps := e.getLpsPasswordStore()
	if ps == nil {
		e.logger.Warn("user create: no server connection; temp password not reported", "username", username)
		output.WriteString("warning: temporary password not reported (not connected; reset out of band)\n")
		return
	}
	if e.getDeviceID() == "" {
		e.logger.Warn("user create: no device ID; temp password not reported", "username", username)
		output.WriteString("warning: temporary password not reported (no device identity; reset out of band)\n")
		return
	}
	if err := ps.StorePasswords(ctx, actionID, []*pb.LpsPasswordRotation{{
		Username:  username,
		Password:  plaintext,
		RotatedAt: e.now().UTC().Format(time.RFC3339),
		Reason:    pb.RotationReason_ROTATION_REASON_INITIAL,
	}}); err != nil {
		e.logger.Warn("user create: failed to report temp password", "username", username, "error", err)
		output.WriteString("warning: temporary password not reported (server rejected it; reset out of band)\n")
	}
}
