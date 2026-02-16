package executor

import (
	"context"
	"fmt"
	"strings"
	"time"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysluks "github.com/manchtools/power-manage/sdk/go/sys/luks"

	"github.com/manchtools/power-manage/agent/internal/store"
)

// LuksKeyStore is the interface for LUKS key operations via the agent stream.
type LuksKeyStore interface {
	GetKey(ctx context.Context, actionID string) (string, error)
	StoreKey(ctx context.Context, actionID, devicePath, passphrase, reason string) error
}

// executeLuks manages LUKS disk encryption.
func (e *Executor) executeLuks(ctx context.Context, params *pb.LuksParams, state pb.DesiredState, actionID string) (*pb.CommandOutput, bool, map[string]string, error) {
	if params == nil {
		return nil, false, nil, fmt.Errorf("luks params required")
	}
	if actionID == "" {
		return nil, false, nil, fmt.Errorf("action ID required for LUKS state tracking")
	}
	if e.luksKeyStore == nil {
		return nil, false, nil, fmt.Errorf("LUKS key store not configured (no stream connection)")
	}
	if e.store == nil {
		return nil, false, nil, fmt.Errorf("agent store not configured")
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		return e.removeLuksManagement(actionID)
	default:
		return e.setupLuks(ctx, params, actionID)
	}
}

// removeLuksManagement handles ABSENT state — removes local state only, LUKS keys stay on device.
func (e *Executor) removeLuksManagement(actionID string) (*pb.CommandOutput, bool, map[string]string, error) {
	localState, _ := e.store.GetLuksState(actionID)
	if localState != nil {
		e.store.DeleteLuksState(actionID)
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   "LUKS: management removed, keys remain on device\n",
		}, true, nil, nil
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   "LUKS: not managed, nothing to remove\n",
	}, false, nil, nil
}

// setupLuks handles PRESENT state — detect volume, check conflicts, take ownership, rotate, reconcile device key.
func (e *Executor) setupLuks(ctx context.Context, params *pb.LuksParams, actionID string) (*pb.CommandOutput, bool, map[string]string, error) {
	var output strings.Builder

	// Load local state
	localState, _ := e.store.GetLuksState(actionID)

	// Determine device path
	var devicePath string
	if localState != nil && localState.OwnershipTaken && localState.DevicePath != "" {
		// Subsequent run — use stored device path
		devicePath = localState.DevicePath
		isLuks, err := sysluks.IsLuks(ctx, devicePath)
		if err != nil {
			return nil, false, nil, fmt.Errorf("failed to check LUKS status: %w", err)
		}
		if !isLuks {
			return nil, false, nil, fmt.Errorf("previously managed device %s is no longer a LUKS volume", devicePath)
		}
		output.WriteString(fmt.Sprintf("LUKS: managing volume %s\n", devicePath))
	} else {
		// First run — detect volume by PSK
		vol, err := sysluks.DetectVolumeByKey(ctx, params.PresharedKey)
		if err != nil {
			// Fall back to heuristic detection (PSK may have been removed by a partial prior run)
			vol, err = sysluks.DetectVolume(ctx)
			if err != nil {
				return nil, false, nil, fmt.Errorf("no LUKS-encrypted volumes detected on this device")
			}
			output.WriteString(fmt.Sprintf("LUKS: detected volume %s (fallback)\n", vol.DevicePath))
		} else {
			output.WriteString(fmt.Sprintf("LUKS: matched volume %s by pre-shared key\n", vol.DevicePath))
		}
		devicePath = vol.DevicePath
	}

	// Conflict resolution — check if another LUKS action should win
	if e.actionStore != nil {
		winnerID, err := e.resolveLuksConflict(actionID)
		if err != nil {
			return nil, false, nil, fmt.Errorf("conflict resolution failed: %w", err)
		}
		if winnerID != actionID {
			output.WriteString(fmt.Sprintf("LUKS: skipped — another action %s takes precedence\n", winnerID))
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   output.String(),
			}, false, nil, nil
		}
	}

	changed := false

	// Take ownership if not done yet
	if localState == nil || !localState.OwnershipTaken {
		if err := e.takeOwnership(ctx, params, actionID, devicePath); err != nil {
			return nil, false, nil, fmt.Errorf("failed to take ownership: %w", err)
		}
		output.WriteString("LUKS: ownership taken, managed passphrase set\n")
		changed = true
		// Reload state after ownership
		localState, _ = e.store.GetLuksState(actionID)
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

	// Build metadata
	metadata := map[string]string{
		"luks.device_path": devicePath,
	}
	if localState != nil {
		metadata["luks.device_key_type"] = localState.DeviceKeyType
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, changed, metadata, nil
}

// takeOwnership takes ownership of the LUKS volume by replacing the PSK with a managed passphrase.
// Server-confirmed: the old key is only removed after the server confirms receipt of the new key.
func (e *Executor) takeOwnership(ctx context.Context, params *pb.LuksParams, actionID, devicePath string) error {
	minWords := int(params.MinWords)
	if minWords < 3 {
		minWords = 5
	}

	// Generate managed passphrase
	passphrase, err := sysluks.GeneratePassphrase(minWords)
	if err != nil {
		return fmt.Errorf("generate passphrase: %w", err)
	}

	// Add managed passphrase using PSK (both keys now valid)
	if err := sysluks.AddKey(ctx, devicePath, params.PresharedKey, passphrase); err != nil {
		return fmt.Errorf("add managed key: %w", err)
	}

	// Store on server — must succeed before removing PSK
	if err := e.luksKeyStore.StoreKey(ctx, actionID, devicePath, passphrase, "initial"); err != nil {
		// Rollback: remove the managed key we just added
		sysluks.RemoveKey(ctx, devicePath, passphrase)
		return fmt.Errorf("store key on server: %w", err)
	}

	// Server confirmed — now safe to remove PSK
	if err := sysluks.RemoveKey(ctx, devicePath, params.PresharedKey); err != nil {
		e.logger.Warn("failed to remove PSK after ownership (both keys work)", "error", err)
	}

	// Update local state
	return e.store.SetLuksOwnershipTaken(actionID, devicePath)
}

// checkAndRotate checks if a rotation is due and rotates the managed passphrase if needed.
func (e *Executor) checkAndRotate(ctx context.Context, params *pb.LuksParams, localState *store.LuksState, actionID, devicePath string) (bool, error) {
	// Check if rotation interval has elapsed
	if !localState.LastRotatedAt.IsZero() && params.RotationIntervalDays > 0 {
		intervalDuration := time.Duration(params.RotationIntervalDays) * 24 * time.Hour
		if time.Since(localState.LastRotatedAt) < intervalDuration {
			return false, nil
		}
	}

	// Get current key from server
	currentKey, err := e.luksKeyStore.GetKey(ctx, actionID)
	if err != nil {
		return false, fmt.Errorf("get current key: %w", err)
	}

	minWords := int(params.MinWords)
	if minWords < 3 {
		minWords = 5
	}

	// Generate new passphrase
	newPassphrase, err := sysluks.GeneratePassphrase(minWords)
	if err != nil {
		return false, fmt.Errorf("generate passphrase: %w", err)
	}

	// Add new key using old key (both valid)
	if err := sysluks.AddKey(ctx, devicePath, currentKey, newPassphrase); err != nil {
		return false, fmt.Errorf("add new key: %w", err)
	}

	// Store on server — must succeed before removing old key
	if err := e.luksKeyStore.StoreKey(ctx, actionID, devicePath, newPassphrase, "scheduled"); err != nil {
		// Rollback: remove the new key we just added
		sysluks.RemoveKey(ctx, devicePath, newPassphrase)
		return false, fmt.Errorf("store new key on server: %w", err)
	}

	// Server confirmed — now safe to remove old key
	if err := sysluks.RemoveKey(ctx, devicePath, currentKey); err != nil {
		e.logger.Warn("failed to remove old key after rotation (both keys work)", "error", err)
	}

	// Record rotation time locally
	if err := e.store.SetLuksLastRotatedAt(actionID, time.Now().UTC()); err != nil {
		e.logger.Warn("failed to record LUKS rotation time", "action_id", actionID, "error", err)
	}

	return true, nil
}

// reconcileDeviceKey ensures LUKS slot 7 matches the desired device_bound_key_type.
func (e *Executor) reconcileDeviceKey(ctx context.Context, params *pb.LuksParams, localState *store.LuksState, actionID, devicePath string) (bool, error) {
	currentType := localState.DeviceKeyType
	desiredType := "none"
	switch params.DeviceBoundKeyType {
	case pb.LuksDeviceBoundKeyType_LUKS_DEVICE_BOUND_KEY_TYPE_TPM:
		desiredType = "tpm"
	case pb.LuksDeviceBoundKeyType_LUKS_DEVICE_BOUND_KEY_TYPE_USER_PASSPHRASE:
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
	if desiredType == "tpm" {
		if err := e.enrollTpm(ctx, actionID, devicePath); err != nil {
			return false, fmt.Errorf("enroll TPM: %w", err)
		}
	}
	// USER_PASSPHRASE: no-op here — user sets it via CLI token flow

	return true, nil
}

// enrollTpm enrolls a TPM2 key for the LUKS volume.
func (e *Executor) enrollTpm(ctx context.Context, actionID, devicePath string) error {
	hasTPM, err := sysluks.HasTPM2(ctx)
	if err != nil {
		return fmt.Errorf("check TPM2: %w", err)
	}
	if !hasTPM {
		return fmt.Errorf("TPM2 device not found")
	}

	managedKey, err := e.luksKeyStore.GetKey(ctx, actionID)
	if err != nil {
		return fmt.Errorf("get managed key: %w", err)
	}

	if err := sysluks.EnrollTPM(ctx, devicePath, managedKey); err != nil {
		return err
	}

	return e.store.SetLuksDeviceKeyType(actionID, "tpm")
}

// revokeDeviceKeyInternal clears LUKS slot 7 (TPM or user passphrase).
func (e *Executor) revokeDeviceKeyInternal(ctx context.Context, localState *store.LuksState, actionID string) error {
	managedKey, err := e.luksKeyStore.GetKey(ctx, actionID)
	if err != nil {
		return fmt.Errorf("get managed key: %w", err)
	}

	switch localState.DeviceKeyType {
	case "tpm":
		if err := sysluks.WipeTPM(ctx, localState.DevicePath, managedKey); err != nil {
			return err
		}
	case "user_passphrase":
		if err := sysluks.KillSlot(ctx, localState.DevicePath, 7, managedKey); err != nil {
			return err
		}
	case "none":
		return nil
	}

	return e.store.SetLuksDeviceKeyType(actionID, "none")
}

// RevokeLuksDeviceKey handles the instant action to revoke the device-bound key.
// Called by the handler when a RevokeLuksDeviceKey stream message arrives.
func (e *Executor) RevokeLuksDeviceKey(ctx context.Context, actionID string) (bool, string) {
	if e.store == nil || e.luksKeyStore == nil {
		return false, "LUKS key store not configured"
	}

	localState, err := e.store.GetLuksState(actionID)
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
func (e *Executor) resolveLuksConflict(actionID string) (string, error) {
	stored, err := e.actionStore.GetStoredActions()
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
		if sa.Action.Type != pb.ActionType_ACTION_TYPE_LUKS {
			continue
		}
		if sa.Action.DesiredState == pb.DesiredState_DESIRED_STATE_ABSENT {
			continue
		}
		params := sa.Action.GetLuks()
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

	// Pick winner: highest min_words → highest complexity → oldest
	winner := candidates[0]
	for _, c := range candidates[1:] {
		if c.minWords > winner.minWords {
			winner = c
		} else if c.minWords == winner.minWords {
			if c.complexity > winner.complexity {
				winner = c
			} else if c.complexity == winner.complexity {
				if c.assignedAt.Before(winner.assignedAt) {
					winner = c
				}
			}
		}
	}

	return winner.id, nil
}

// ActionStore is the interface for accessing stored actions (for conflict resolution).
type ActionStore interface {
	GetStoredActions() ([]*store.StoredAction, error)
}
