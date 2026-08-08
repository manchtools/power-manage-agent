package executor

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	pb "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	sysenc "github.com/manchtools/power-manage-sdk/sys/encryption"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"

	"github.com/manchtools/power-manage/agent/internal/store"
)

// luksSecret wraps a key string the agent holds (a PSK or a key-store value) as
// an exec.Secret for the encryption Manager, which keeps it off argv (cryptsetup
// reads it via --key-file). NewMultilineSecret accepts arbitrary key material.
func luksSecret(s string) sysexec.Secret { return sysexec.NewMultilineSecret(s) }

func luksSecretBytes(b []byte) sysexec.Secret { return sysexec.NewMultilineSecret(string(b)) }

// LuksKeyStore is the executor's narrow in-process key boundary. The runtime
// adapter seals outbound passphrases and opens inbound passphrases immediately
// before this interface is crossed; protobuf never carries plaintext.
type LuksKeyStore interface {
	GetKey(ctx context.Context, actionID string) (string, error)
	StoreKey(ctx context.Context, actionID, devicePath, passphrase string, reason pb.RotationReason) error
}

// requireLuksStoreReady is the pre-mutation gate for the two store paths:
// without a usable route to control the new passphrase could never be stored,
// so bail BEFORE any LUKS slot is touched — a failed store after AddKey needs a
// rollback, and a rollback that itself fails orphans a slot.
func (e *Executor) requireLuksStoreReady() error {
	if e.getLuksKeyStore() == nil {
		return fmt.Errorf("no server connection; cannot store the new passphrase (fail closed, no cleartext-only rotation)")
	}
	if e.getDeviceID() == "" {
		return fmt.Errorf("device ID not available; cannot store the new passphrase")
	}
	return nil
}

// luksTimestampFailureThreshold is the consecutive-failure count after
// which the agent escalates SetLuksLastRotatedAt persistence failures
// from Warn to Error. Per #80 the operational risk is a silent
// rotation hot-loop (post-rotation timestamp never persists, so the
// next tick re-rotates) or rotation that never starts (initial
// timestamp never persists, so every tick re-enters the init branch);
// either case is easy to miss at Warn-level in journald and worth
// surfacing at Error so journald-priority filters page operators.
const luksTimestampFailureThreshold = 3

// recordLuksTimestampFailure logs a SetLuksLastRotatedAt failure and
// bumps the per-action consecutive-failure counter. The first
// (luksTimestampFailureThreshold-1) failures log at Warn; from the
// threshold-th failure onward the level escalates to Error so
// journald-priority filters surface what would otherwise be a buried
// hot-loop or stuck-rotation hazard (#80). The site label distinguishes
// the initial-timestamp branch from the post-rotation branch in logs.
func (e *Executor) recordLuksTimestampFailure(actionID, site string, err error) {
	e.luksTimestampFailMu.Lock()
	if e.luksTimestampFailCount == nil {
		e.luksTimestampFailCount = make(map[string]int)
	}
	e.luksTimestampFailCount[actionID]++
	n := e.luksTimestampFailCount[actionID]
	e.luksTimestampFailMu.Unlock()

	if n >= luksTimestampFailureThreshold {
		e.logger.Error("LUKS: SetLuksLastRotatedAt failing persistently — rotation may hot-loop or never start; investigate the agent store",
			"action_id", actionID,
			"site", site,
			"consecutive_failures", n,
			"error", err,
		)
		return
	}
	e.logger.Warn("LUKS: failed to persist rotation timestamp",
		"action_id", actionID,
		"site", site,
		"consecutive_failures", n,
		"error", err,
	)
}

// clearLuksTimestampFailures resets the per-action consecutive-failure
// counter on a successful SetLuksLastRotatedAt write. Companion to
// recordLuksTimestampFailure (#80).
func (e *Executor) clearLuksTimestampFailures(actionID string) {
	e.luksTimestampFailMu.Lock()
	if e.luksTimestampFailCount != nil {
		delete(e.luksTimestampFailCount, actionID)
	}
	e.luksTimestampFailMu.Unlock()
}

// executeLuks manages LUKS disk encryption.
//
// Audit F003: every read of e.luksKeyStore / e.store / e.actionStore in
// this file goes through the accessors (getLuksKeyStore / getStore /
// getActionStore). Snapshotted once per call so the rest of the
// function operates on a consistent view of the wired-in dependencies
// instead of racing SetLuksKeyStore() / SetStore() / SetActionStore()
// in runtime.go's reconnect loop.
func (e *Executor) executeLuks(ctx context.Context, params *pb.EncryptionParams, state pb.DesiredState, actionID string, openPresharedKey func() ([]byte, error)) (*pb.CommandOutput, bool, map[string]string, error) {
	if params == nil {
		return nil, false, nil, fmt.Errorf("luks params required")
	}
	if actionID == "" {
		return nil, false, nil, fmt.Errorf("action ID required for LUKS state tracking")
	}
	if e.getLuksKeyStore() == nil {
		return nil, false, nil, fmt.Errorf("LUKS key store not configured (no stream connection)")
	}
	if e.getStore() == nil {
		return nil, false, nil, fmt.Errorf("agent store not configured")
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		return e.removeLuksManagement(actionID)
	default:
		return e.setupLuks(ctx, params, actionID, openPresharedKey)
	}
}

// removeLuksManagement handles ABSENT state — removes local state only, LUKS keys stay on device.
func (e *Executor) removeLuksManagement(actionID string) (*pb.CommandOutput, bool, map[string]string, error) {
	st := e.getStore()
	if st == nil {
		return nil, false, nil, fmt.Errorf("agent store not configured")
	}
	localState, err := st.GetLuksState(actionID)
	if err != nil {
		// Sibling of the DeleteLuksState fail-closed below: a state
		// lookup error here would otherwise be swallowed and the
		// "no managed state" branch would report success, lying to
		// the control plane about an ABSENT transition that never
		// actually happened.
		e.logger.Error("removeLuksManagement: failed to read local state",
			"action_id", actionID, "error", err)
		return nil, false, nil, fmt.Errorf("get luks state: %w", err)
	}
	if localState != nil {
		if err := st.DeleteLuksState(actionID); err != nil {
			// Reporting success here would mask an incomplete
			// ABSENT transition: the action set claims the row is
			// gone but the agent still has the managed-state entry
			// and would re-rotate it on the next reconcile.
			e.logger.Error("removeLuksManagement: failed to delete local state",
				"action_id", actionID, "error", err)
			return nil, false, nil, fmt.Errorf("delete luks state: %w", err)
		}
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   "LUKS: management removed, keys remain on device\n",
		}, true, nil, nil
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   "LUKS: no managed state for this action, nothing to remove\n",
	}, false, nil, nil
}

// setupLuks handles PRESENT state — detect volume, check conflicts, take ownership, rotate, reconcile device key.
func (e *Executor) setupLuks(ctx context.Context, params *pb.EncryptionParams, actionID string, openPresharedKey func() ([]byte, error)) (*pb.CommandOutput, bool, map[string]string, error) {
	st := e.getStore()
	if st == nil {
		return nil, false, nil, fmt.Errorf("agent store not configured")
	}
	// Snapshot the action store accessor once per F003 — concurrent
	// SetActionStore must not change the value mid-execution.
	as := e.getActionStore()

	var output strings.Builder

	// Load local state. WS6 #13: a read failure here must fail closed,
	// not be mistaken for "first run". Swallowing the error (the previous
	// `localState, _ :=`) would drive the agent to re-detect the volume
	// and re-take ownership / re-add keys against a volume it may already
	// manage — the exact destructive path the state row exists to prevent.
	// Mirrors removeLuksManagement's fail-closed state read.
	localState, err := st.GetLuksState(actionID)
	if err != nil {
		return nil, false, nil, fmt.Errorf("get luks state: %w", err)
	}

	// Resolve policy conflicts before opening the PSK. A losing action never
	// reaches a LUKS operation and therefore has no reason to materialize its
	// credential.
	if as != nil {
		winnerID, err := resolveLuksConflict(as, actionID)
		if err != nil {
			return nil, false, nil, fmt.Errorf("conflict resolution failed: %w", err)
		}
		if winnerID != actionID {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("LUKS: skipped — another action %s takes precedence\n", winnerID),
			}, false, nil, nil
		}
	}

	// Determine device path
	var devicePath string
	var presharedKey []byte
	if localState != nil && localState.OwnershipTaken && localState.DevicePath != "" {
		// Subsequent run — use stored device path
		devicePath = localState.DevicePath
		isLuks, err := encMgr.IsEncrypted(ctx, devicePath)
		if err != nil {
			return nil, false, nil, fmt.Errorf("failed to check LUKS status: %w", err)
		}
		if !isLuks {
			return nil, false, nil, fmt.Errorf("previously managed device %s is no longer a LUKS volume", devicePath)
		}
		output.WriteString(fmt.Sprintf("LUKS: managing volume %s\n", devicePath))
	} else {
		if openPresharedKey == nil {
			return nil, false, nil, fmt.Errorf("encryption pre-shared key is not configured")
		}
		presharedKey, err = openPresharedKey()
		if err != nil {
			return nil, false, nil, err
		}
		defer clear(presharedKey)

		// First run — detect volume by PSK
		vol, err := encMgr.DetectVolumeByKey(ctx, luksSecretBytes(presharedKey))
		if err != nil {
			// Fall back to heuristic detection (PSK may have been removed by a partial prior run)
			vol, err = encMgr.DetectVolume(ctx)
			if err != nil {
				return nil, false, nil, fmt.Errorf("no LUKS-encrypted volumes detected on this device")
			}
			output.WriteString(fmt.Sprintf("LUKS: detected volume %s (fallback)\n", vol.DevicePath))
		} else {
			output.WriteString(fmt.Sprintf("LUKS: matched volume %s by pre-shared key\n", vol.DevicePath))
		}
		devicePath = vol.DevicePath
	}

	changed := false

	// Take ownership if not done yet
	if localState == nil || !localState.OwnershipTaken {
		if err := e.takeOwnership(ctx, params, actionID, devicePath, presharedKey); err != nil {
			return nil, false, nil, fmt.Errorf("failed to take ownership: %w", err)
		}
		output.WriteString("LUKS: ownership taken, managed passphrase set\n")
		changed = true
		// Reload state after ownership
		var reloadErr error
		localState, reloadErr = st.GetLuksState(actionID)
		if reloadErr != nil {
			e.logger.Warn("failed to reload LUKS state after ownership", "action_id", actionID, "error", reloadErr)
		}
	}

	// Check if rotation is due
	if localState != nil && localState.OwnershipTaken {
		rotated, err := e.checkAndRotate(ctx, params, localState, actionID, devicePath)
		if err != nil {
			e.logger.Warn("LUKS rotation failed", "action_id", actionID, "error", err)
			output.WriteString(fmt.Sprintf("LUKS: rotation check failed: %v\n", err))
		} else if rotated {
			output.WriteString("LUKS: managed passphrase rotated\n")
			changed = true
			// Rotation persisted store state (at minimum LastRotatedAt);
			// re-sync the in-memory snapshot so downstream consumers
			// (reconcileDeviceKey, metadata) never act on a stale view
			// (#174). Best-effort: the pre-rotation snapshot is still a
			// valid fallback.
			if reloaded, rerr := st.GetLuksState(actionID); rerr == nil && reloaded != nil {
				localState = reloaded
			} else if rerr != nil {
				e.logger.Warn("LUKS: state reload after rotation failed; continuing with pre-rotation snapshot",
					"action_id", actionID, "error", rerr)
			}
		}
	}

	// Reconcile device-bound key (slot 7)
	if localState != nil {
		keyChanged, err := e.reconcileDeviceKey(ctx, params, localState, actionID, devicePath)
		if err != nil {
			e.logger.Warn("LUKS device key reconciliation failed", "action_id", actionID, "error", err)
			output.WriteString(fmt.Sprintf("LUKS: device key reconciliation failed: %v\n", err))
		} else if keyChanged {
			output.WriteString("LUKS: device-bound key updated\n")
			changed = true
		}
	}

	// No result metadata. Control refuses any ActionResult with a non-empty
	// metadata map, and the outbox marks a frame synced as soon as the local
	// send returns — so a result that carried metadata was either dropped
	// outright or replayed on every reconnect. device_path reaches control
	// through StoreLuksKey, which is where it belongs.
	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, changed, nil, nil
}

// takeOwnership takes ownership of the LUKS volume by replacing the PSK with a managed passphrase.
// Server-confirmed: the old key is only removed after the server confirms receipt of the new key.
// If the server already has a working key (e.g. from a previous run with lost local state),
// ownership is recovered without re-using the PSK.
func (e *Executor) takeOwnership(ctx context.Context, params *pb.EncryptionParams, actionID, devicePath string, presharedKey []byte) error {
	ks := e.getLuksKeyStore()
	if ks == nil {
		return fmt.Errorf("LUKS key store not configured (no stream connection)")
	}
	st := e.getStore()
	if st == nil {
		return fmt.Errorf("agent store not configured")
	}

	// Recovery: check if server already has a key for this action (state loss recovery).
	existingKey, getKeyErr := ks.GetKey(ctx, actionID)
	if getKeyErr == nil && existingKey != "" {
		e.logger.Info("LUKS: server has stored key, testing against volume",
			"action_id", actionID, "key_len", len(existingKey))
		ok, testErr := encMgr.VerifyPassphrase(ctx, devicePath, luksSecret(existingKey))
		e.logger.Info("LUKS: test-passphrase result", "ok", ok, "error", testErr)
		if testErr == nil && ok {
			// No verifyKeyRoundTrip is needed here: the round-trip proves
			// the server durably stored a key the agent
			// just GENERATED; this key came FROM the server (GetKey) and
			// was verified against the volume above, so both ends are
			// already proven.
			e.logger.Info("LUKS: recovered ownership from server-stored key", "action_id", actionID)
			return st.SetLuksOwnershipTaken(actionID, devicePath)
		}
		e.logger.Warn("LUKS: server has key but it does not unlock the volume, proceeding with PSK",
			"action_id", actionID, "test_error", testErr)
	} else if getKeyErr != nil {
		// Server unreachable — cannot verify existing keys or store new ones.
		// Do NOT fall through to PSK because StoreKey will also fail,
		// and the PSK may have already been consumed by a prior run.
		return fmt.Errorf("server not reachable, cannot manage LUKS keys (retry when connected): %w", getKeyErr)
	}

	// Pre-mutation gate: without a route to control the store is doomed, so
	// refuse before any slot is touched.
	if err := e.requireLuksStoreReady(); err != nil {
		return fmt.Errorf("take ownership: %w", err)
	}

	minWords := int(params.MinWords)
	if minWords < 3 {
		minWords = 5
	}

	// Generate managed passphrase. The agent's key-store layer handles keys as
	// strings locally, so Reveal once here and re-wrap as a Secret at each
	// encryption-Manager boundary below.
	passSecret, err := sysenc.GeneratePassphrase(minWords)
	if err != nil {
		return fmt.Errorf("generate passphrase: %w", err)
	}
	passphrase := passSecret.Reveal()

	// Add managed passphrase using PSK (both keys now valid)
	e.logger.Info("LUKS: adding managed key using PSK",
		"psk_len", len(presharedKey),
		"new_key_len", len(passphrase))
	if err := encMgr.AddKey(ctx, devicePath, luksSecretBytes(presharedKey), luksSecret(passphrase), sysenc.AddKeyOptions{}); err != nil {
		return fmt.Errorf("add managed key: %w", err)
	}

	// Store on server — must succeed before removing the PSK.
	if err := ks.StoreKey(ctx, actionID, devicePath, passphrase, pb.RotationReason_ROTATION_REASON_INITIAL); err != nil {
		// Rollback: remove the managed key we just added
		if rmErr := encMgr.RemoveKey(ctx, devicePath, luksSecret(passphrase)); rmErr != nil {
			e.logger.Error("LUKS: rollback failed — managed key remains in slot",
				"action_id", actionID, "error", rmErr)
		}
		return fmt.Errorf("store key on server: %w", err)
	}

	// Round-trip verification: re-fetch the committed key from the server,
	// verify it matches exactly, and test it against the volume.
	if err := e.verifyKeyRoundTrip(ctx, actionID, devicePath, passphrase); err != nil {
		return fmt.Errorf("round-trip verification failed, keeping both keys: %w", err)
	}

	// Verified — now safe to remove PSK
	if err := encMgr.RemoveKey(ctx, devicePath, luksSecretBytes(presharedKey)); err != nil {
		e.logger.Warn("failed to remove PSK after ownership (both keys work)", "error", err)
	}

	// Update local state
	return st.SetLuksOwnershipTaken(actionID, devicePath)
}

// checkAndRotate checks if a rotation is due and rotates the managed passphrase if needed.
func (e *Executor) checkAndRotate(ctx context.Context, params *pb.EncryptionParams, localState *store.LuksState, actionID, devicePath string) (bool, error) {
	ks := e.getLuksKeyStore()
	if ks == nil {
		return false, fmt.Errorf("LUKS key store not configured (no stream connection)")
	}
	st := e.getStore()
	if st == nil {
		return false, fmt.Errorf("agent store not configured")
	}

	// Check if rotation interval has elapsed
	if params.RotationIntervalDays > 0 {
		// No previous rotation recorded — set the timestamp and skip.
		if localState.LastRotatedAt.IsZero() {
			if err := st.SetLuksLastRotatedAt(actionID, e.now().UTC()); err != nil {
				// First-rotation timestamp persistence failed. Subsequent
				// ticks re-enter this branch, so rotation would never
				// start. #80 escalated the buried Warn to Error after a
				// threshold; #173 goes further: fail the action LOUDLY so
				// the server sees a failing execution instead of a green
				// action whose rotation is silently parked forever. The
				// escalation counter stays for log-side telemetry.
				e.recordLuksTimestampFailure(actionID, "initial", err)
				return false, fmt.Errorf("persist initial LUKS rotation timestamp (rotation cannot start until this succeeds): %w", err)
			}
			e.clearLuksTimestampFailures(actionID)
			return false, nil
		}
		intervalDuration := time.Duration(params.RotationIntervalDays) * 24 * time.Hour
		if e.now().Sub(localState.LastRotatedAt) < intervalDuration {
			return false, nil
		}
	}

	// Pre-mutation gate: refuse a due rotation before touching any slot when
	// the store could never succeed.
	if err := e.requireLuksStoreReady(); err != nil {
		return false, fmt.Errorf("rotate: %w", err)
	}

	// Get current key from server
	currentKey, err := ks.GetKey(ctx, actionID)
	if err != nil {
		return false, fmt.Errorf("get current key: %w", err)
	}

	minWords := int(params.MinWords)
	if minWords < 3 {
		minWords = 5
	}

	// Generate new passphrase (Reveal once for the string-based local key
	// handling).
	newPassSecret, err := sysenc.GeneratePassphrase(minWords)
	if err != nil {
		return false, fmt.Errorf("generate passphrase: %w", err)
	}
	newPassphrase := newPassSecret.Reveal()

	// Add new key using old key (both valid)
	if err := encMgr.AddKey(ctx, devicePath, luksSecret(currentKey), luksSecret(newPassphrase), sysenc.AddKeyOptions{}); err != nil {
		return false, fmt.Errorf("add new key: %w", err)
	}

	// Store on server — must succeed before removing the old key.
	if err := ks.StoreKey(ctx, actionID, devicePath, newPassphrase, pb.RotationReason_ROTATION_REASON_SCHEDULED); err != nil {
		// Rollback: remove the new key we just added
		if rmErr := encMgr.RemoveKey(ctx, devicePath, luksSecret(newPassphrase)); rmErr != nil {
			e.logger.Error("LUKS: rotation rollback failed — new key remains in slot",
				"action_id", actionID, "error", rmErr)
		}
		return false, fmt.Errorf("store new key on server: %w", err)
	}

	// Round-trip verification: re-fetch the key from the server, verify it
	// matches exactly, and test it against the volume.
	if err := e.verifyKeyRoundTrip(ctx, actionID, devicePath, newPassphrase); err != nil {
		return false, fmt.Errorf("round-trip verification failed, keeping both keys: %w", err)
	}

	// Verified — now safe to remove old key
	if err := encMgr.RemoveKey(ctx, devicePath, luksSecret(currentKey)); err != nil {
		e.logger.Warn("failed to remove old key after rotation (both keys work)", "error", err)
	}

	// Record rotation time locally. If this fails persistently the
	// next tick believes nothing rotated and re-rotates — a hot loop
	// that churns LUKS slots. Track consecutive failures so the
	// buried-Warn case escalates to Error after the threshold (#80).
	if err := st.SetLuksLastRotatedAt(actionID, e.now().UTC()); err != nil {
		e.recordLuksTimestampFailure(actionID, "post_rotation", err)
	} else {
		e.clearLuksTimestampFailures(actionID)
	}

	return true, nil
}

// reconcileDeviceKey ensures LUKS slot 7 matches the desired device_bound_key_type.
func (e *Executor) reconcileDeviceKey(ctx context.Context, params *pb.EncryptionParams, localState *store.LuksState, actionID, devicePath string) (bool, error) {
	currentType := localState.DeviceKeyType
	desiredType := "none"
	switch params.DeviceBoundKeyType {
	case pb.EncryptionDeviceBoundKeyType_ENCRYPTION_DEVICE_BOUND_KEY_TYPE_TPM:
		desiredType = "tpm"
	case pb.EncryptionDeviceBoundKeyType_ENCRYPTION_DEVICE_BOUND_KEY_TYPE_USER_PASSPHRASE:
		desiredType = "user_passphrase"
	}

	if currentType == desiredType {
		return false, nil
	}

	// Revoke current key if occupied
	if currentType != "none" {
		if err := e.revokeDeviceKeyInternal(ctx, localState, actionID); err != nil {
			return false, fmt.Errorf("revoke current device key: %w", err)
		}
	}

	// Enroll new key
	switch desiredType {
	case "tpm":
		if err := e.enrollTpm(ctx, actionID, devicePath); err != nil {
			return false, fmt.Errorf("enroll TPM: %w", err)
		}
		// enrollTpm persists device_key_type="tpm" on success.
	case "user_passphrase":
		// No key is enrolled here — the user sets the actual passphrase
		// via the CLI token flow (cmd_luks.go records the hash). But the
		// MODE must still be persisted, or localState stays "none" and
		// every reconcile re-reports changed=true forever (never
		// converging). enrollTpm persists its mode; mirror that here.
		st := e.getStore()
		if st == nil {
			return false, fmt.Errorf("agent store not configured")
		}
		if err := st.SetLuksDeviceKeyType(actionID, "user_passphrase"); err != nil {
			return false, fmt.Errorf("persist user_passphrase device key type: %w", err)
		}
	}

	return true, nil
}

// enrollTpm enrolls a TPM2 key for the LUKS volume.
func (e *Executor) enrollTpm(ctx context.Context, actionID, devicePath string) error {
	ks := e.getLuksKeyStore()
	if ks == nil {
		return fmt.Errorf("LUKS key store not configured (no stream connection)")
	}
	st := e.getStore()
	if st == nil {
		return fmt.Errorf("agent store not configured")
	}

	tpm, ok := encMgr.TPM()
	if !ok {
		return fmt.Errorf("TPM2 not supported by the encryption backend")
	}
	hasTPM, err := tpm.Available(ctx)
	if err != nil {
		return fmt.Errorf("check TPM2: %w", err)
	}
	if !hasTPM {
		return fmt.Errorf("TPM2 device not found")
	}

	managedKey, err := ks.GetKey(ctx, actionID)
	if err != nil {
		return fmt.Errorf("get managed key: %w", err)
	}

	if err := tpm.Enroll(ctx, devicePath, luksSecret(managedKey)); err != nil {
		return err
	}

	return st.SetLuksDeviceKeyType(actionID, "tpm")
}

// revokeDeviceKeyInternal clears LUKS slot 7 (TPM or user passphrase).
func (e *Executor) revokeDeviceKeyInternal(ctx context.Context, localState *store.LuksState, actionID string) error {
	ks := e.getLuksKeyStore()
	if ks == nil {
		return fmt.Errorf("LUKS key store not configured (no stream connection)")
	}
	st := e.getStore()
	if st == nil {
		return fmt.Errorf("agent store not configured")
	}

	managedKey, err := ks.GetKey(ctx, actionID)
	if err != nil {
		return fmt.Errorf("get managed key: %w", err)
	}

	switch localState.DeviceKeyType {
	case "tpm":
		tpm, ok := encMgr.TPM()
		if !ok {
			return fmt.Errorf("TPM2 not supported by the encryption backend")
		}
		if err := tpm.Wipe(ctx, localState.DevicePath, luksSecret(managedKey)); err != nil {
			return err
		}
	case "user_passphrase":
		if err := encMgr.KillSlot(ctx, localState.DevicePath, 7, luksSecret(managedKey)); err != nil {
			return err
		}
	case "none":
		return nil
	}

	return st.SetLuksDeviceKeyType(actionID, "none")
}

// RevokeLuksDeviceKey handles the instant action to revoke the device-bound key.
// Called by the handler when a RevokeLuksDeviceKey stream message arrives.
func (e *Executor) RevokeLuksDeviceKey(ctx context.Context, actionID string) (bool, string) {
	st := e.getStore()
	ks := e.getLuksKeyStore()
	if st == nil {
		return false, "agent store not configured"
	}
	if ks == nil {
		return false, "LUKS key store not configured"
	}

	localState, err := st.GetLuksState(actionID)
	if err != nil {
		return false, fmt.Sprintf("failed to load LUKS state: %v", err)
	}
	if localState == nil {
		return true, "" // No state = nothing to revoke
	}
	if localState.DeviceKeyType == "none" {
		return true, "" // Already revoked
	}

	if err := e.revokeDeviceKeyInternal(ctx, localState, actionID); err != nil {
		return false, fmt.Sprintf("failed to revoke device key: %v", err)
	}
	return true, ""
}

// resolveLuksConflict determines which LUKS action should manage the volume.
// Returns the winning action ID. If this action is not the winner, it should fail.
func resolveLuksConflict(as ActionStore, actionID string) (string, error) {
	if as == nil {
		// No action store wired: assume this action wins.
		return actionID, nil
	}
	stored, err := as.GetStoredActions()
	if err != nil {
		return actionID, nil // Can't check, assume this action wins
	}

	type luksCandidate struct {
		id         string
		minWords   int32
		complexity int32
		assignedAt time.Time
	}

	var candidates []luksCandidate
	for _, sa := range stored {
		if sa.Action.Type != pb.ActionType_ACTION_TYPE_ENCRYPTION {
			continue
		}
		if sa.Action.DesiredState == pb.DesiredState_DESIRED_STATE_ABSENT {
			continue
		}
		params := sa.Action.GetEncryption()
		if params == nil {
			continue
		}
		candidates = append(candidates, luksCandidate{
			id:         sa.ID,
			minWords:   params.MinWords,
			complexity: int32(params.UserPassphraseComplexity),
			assignedAt: sa.AssignedAt,
		})
	}

	if len(candidates) <= 1 {
		return actionID, nil
	}

	// Pick winner: highest min_words → highest complexity → oldest.
	// slices.MaxFunc with an explicit comparator is easier to read
	// than the previous chained-if argmax, and adding a fourth
	// tie-breaker becomes a single line. Audit F043.
	winner := slices.MaxFunc(candidates, func(a, b luksCandidate) int {
		if a.minWords != b.minWords {
			return int(a.minWords - b.minWords)
		}
		if a.complexity != b.complexity {
			return int(a.complexity - b.complexity)
		}
		// Older assignment wins (smaller time = earlier). Return
		// negative when a is older so MaxFunc selects b for "later"
		// — invert because older should win.
		if a.assignedAt.Before(b.assignedAt) {
			return 1
		}
		if a.assignedAt.After(b.assignedAt) {
			return -1
		}
		return 0
	})

	return winner.id, nil
}

// verifyKeyRoundTrip re-fetches the committed key from the server, verifies it
// matches the expected passphrase exactly, then tests it against the LUKS
// volume. A successful StoreKey response is transactionally visible, so any
// mismatch is an error rather than eventual-consistency lag to retry.
func (e *Executor) verifyKeyRoundTrip(ctx context.Context, actionID, devicePath, expectedKey string) error {
	ks := e.getLuksKeyStore()
	if ks == nil {
		return fmt.Errorf("LUKS key store not configured (no stream connection)")
	}

	storedKey, err := ks.GetKey(ctx, actionID)
	if err != nil {
		return fmt.Errorf("re-fetch stored key: %w", err)
	}
	if storedKey != expectedKey {
		return fmt.Errorf("server returned a different key than the committed value")
	}

	// Defense-in-depth: verify the key actually unlocks the volume.
	ok, testErr := encMgr.VerifyPassphrase(ctx, devicePath, luksSecret(storedKey))
	if testErr != nil || !ok {
		return fmt.Errorf("server-stored key does not unlock volume (test_ok=%v, err=%v)", ok, testErr)
	}

	e.logger.Info("LUKS: round-trip verification passed", "action_id", actionID)
	return nil
}

// ActionStore is the interface for accessing stored actions (for conflict resolution).
type ActionStore interface {
	GetStoredActions() ([]*store.StoredAction, error)
}
