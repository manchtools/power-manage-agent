package executor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysuser "github.com/manchtools/power-manage/sdk/go/sys/user"
)

const (
	lpsStateDir = "/var/lib/power-manage/lps"

	alphanumericChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	complexChars      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
)

// lpsUserState tracks local LPS rotation state for a single user.
type lpsUserState struct {
	LastRotatedAt time.Time `json:"last_rotated_at"`
	PasswordHash  string    `json:"password_hash"`
}

// lpsState tracks local LPS rotation state for all managed users in an action.
type lpsState struct {
	Users map[string]lpsUserState `json:"users"`
}

// lpsRotationEntry is the JSON structure reported in action result metadata.
type lpsRotationEntry struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	RotatedAt string `json:"rotated_at"`
	Reason    string `json:"reason"`
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
	var output strings.Builder

	// Load local state
	localState, err := loadLpsState(actionID)
	if err != nil {
		e.logger.Warn("failed to load LPS state, will treat as initial rotation", "action_id", actionID, "error", err)
		localState = nil
	}
	if localState == nil {
		localState = &lpsState{Users: make(map[string]lpsUserState)}
	}

	charset := alphanumericChars
	if params.Complexity == pb.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_COMPLEX {
		charset = complexChars
	}

	var rotations []lpsRotationEntry
	var anyError error

	for _, username := range params.Usernames {
		// Verify user exists
		if !userExists(username) {
			output.WriteString(fmt.Sprintf("LPS: user %q does not exist, skipping\n", username))
			e.logger.Warn("LPS user does not exist, skipping", "username", username)
			continue
		}

		// Get per-user state
		var userState *lpsUserState
		if us, ok := localState.Users[username]; ok {
			userState = &us
		}

		// Determine if rotation is needed
		rotate, reason := shouldRotateLps(userState, params, username)
		if !rotate {
			output.WriteString(fmt.Sprintf("LPS: %s — password up to date\n", username))
			continue
		}

		// Generate new password
		password, err := generatePassword(int(params.PasswordLength), charset)
		if err != nil {
			anyError = fmt.Errorf("generate password for %s: %w", username, err)
			output.WriteString(fmt.Sprintf("LPS: %s — failed to generate password: %v\n", username, err))
			continue
		}

		// Set the password
		if err := sysuser.SetPassword(ctx, username, password); err != nil {
			anyError = fmt.Errorf("set password for %s: %w", username, err)
			output.WriteString(fmt.Sprintf("LPS: %s — failed to set password: %v\n", username, err))
			continue
		}

		// Kill all user sessions after password rotation
		killUserSessions(ctx, username)

		now := time.Now().UTC()
		output.WriteString(fmt.Sprintf("LPS: %s — rotated password (reason: %s), sessions terminated\n", username, reason))

		// Update per-user state
		hash := sha256.Sum256([]byte(password))
		localState.Users[username] = lpsUserState{
			LastRotatedAt: now,
			PasswordHash:  hex.EncodeToString(hash[:]),
		}

		rotations = append(rotations, lpsRotationEntry{
			Username:  username,
			Password:  password,
			RotatedAt: now.Format(time.RFC3339),
			Reason:    reason,
		})
	}

	// Save updated state
	if err := saveLpsState(actionID, localState); err != nil {
		e.logger.Warn("failed to save LPS state", "action_id", actionID, "error", err)
	}

	// If no rotations occurred
	if len(rotations) == 0 {
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

	// Build metadata with JSON array of rotations
	rotationsJSON, _ := json.Marshal(rotations)
	metadata := map[string]string{
		"lps.rotations": string(rotationsJSON),
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, true, metadata, anyError
}

// removeLpsManagement handles ABSENT state — stops managing, cleans up local state.
func (e *Executor) removeLpsManagement(_ context.Context, actionID string) (*pb.CommandOutput, bool, map[string]string, error) {
	statePath := lpsStatePath(actionID)
	if _, err := os.Stat(statePath); err == nil {
		os.Remove(statePath)
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   "LPS: password management stopped, local state removed\n",
		}, true, nil, nil
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   "LPS: password management not active, nothing to remove\n",
	}, false, nil, nil
}

// shouldRotateLps determines if a password rotation is needed for a user and returns the reason.
func shouldRotateLps(state *lpsUserState, params *pb.LpsParams, username string) (bool, string) {
	now := time.Now().UTC()

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
		lastAuth, err := getLastAuthTime(username)
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
// Errors are logged but not returned — the user may not have active sessions.
func killUserSessions(ctx context.Context, username string) {
	// Graceful: terminate systemd-logind sessions
	runSudoCmd(ctx, "loginctl", "terminate-user", username)
	// Forceful: kill all remaining processes owned by the user
	runSudoCmd(ctx, "pkill", "-KILL", "-u", username)
	// Brief wait for processes to fully exit
	time.Sleep(500 * time.Millisecond)
}

// generatePassword creates a cryptographically random password from the given character set.
func generatePassword(length int, charset string) (string, error) {
	if length < 8 {
		length = 8
	}
	if length > 128 {
		length = 128
	}

	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := range result {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("crypto/rand: %w", err)
		}
		result[i] = charset[idx.Int64()]
	}

	return string(result), nil
}

// getLastAuthTime returns the most recent login time for a user by parsing `last -1 -F <username>`.
func getLastAuthTime(username string) (time.Time, error) {
	output, err := queryCmd("last", "-1", "-F", username)
	if err != nil {
		return time.Time{}, fmt.Errorf("last command: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		return time.Time{}, fmt.Errorf("no output from last command")
	}

	// Parse the first line of `last -1 -F` output
	// Format: "username pts/0    192.168.1.1  Mon Feb 10 14:30:00 2025   still logged in"
	// Or:     "username pts/0    192.168.1.1  Mon Feb 10 14:30:00 2025 - Mon Feb 10 15:00:00 2025  (00:30)"
	firstLine := lines[0]
	if strings.Contains(firstLine, "wtmp begins") || strings.Contains(firstLine, "btmp begins") || firstLine == "" {
		return time.Time{}, fmt.Errorf("no login records for user %s", username)
	}

	// The timestamp starts after the 3rd field (username, terminal, source)
	// Find the weekday name which starts the timestamp
	weekdays := []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
	for _, wd := range weekdays {
		idx := strings.Index(firstLine, wd+" ")
		if idx >= 0 {
			// Extract the date portion (e.g., "Mon Feb 10 14:30:00 2025")
			dateStr := firstLine[idx:]
			// Trim after the year (look for " - " or "   still" or "   gone")
			for _, sep := range []string{" - ", "   still", "   gone", "  ("} {
				if sepIdx := strings.Index(dateStr, sep); sepIdx > 0 {
					dateStr = dateStr[:sepIdx]
				}
			}
			dateStr = strings.TrimSpace(dateStr)

			// Parse with various formats
			formats := []string{
				"Mon Jan 2 15:04:05 2006",
				"Mon Jan  2 15:04:05 2006",
			}
			for _, fmt := range formats {
				if t, err := time.Parse(fmt, dateStr); err == nil {
					return t, nil
				}
			}
			return time.Time{}, fmt.Errorf("could not parse date: %q", dateStr)
		}
	}

	return time.Time{}, fmt.Errorf("could not find timestamp in last output: %q", firstLine)
}

// =============================================================================
// LPS state file management
// =============================================================================

func lpsStatePath(actionID string) string {
	return filepath.Join(lpsStateDir, fmt.Sprintf("lps-%s.json", strings.ToLower(actionID)))
}

func loadLpsState(actionID string) (*lpsState, error) {
	data, err := os.ReadFile(lpsStatePath(actionID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var state lpsState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if state.Users == nil {
		state.Users = make(map[string]lpsUserState)
	}
	return &state, nil
}

func saveLpsState(actionID string, state *lpsState) error {
	if err := os.MkdirAll(lpsStateDir, 0700); err != nil {
		return err
	}

	data, err := json.Marshal(state)
	if err != nil {
		return err
	}

	return os.WriteFile(lpsStatePath(actionID), data, 0600)
}
