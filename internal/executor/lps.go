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
)

const (
	lpsStateDir = "/var/lib/power-manage/lps"

	alphanumericChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	complexChars      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
)

// lpsState tracks local LPS rotation state per action.
type lpsState struct {
	LastRotatedAt time.Time `json:"last_rotated_at"`
	PasswordHash  string    `json:"password_hash"`
}

// executeLps manages local user password rotation (Linux Password Solution).
func (e *Executor) executeLps(ctx context.Context, params *pb.LpsParams, state pb.DesiredState, actionID string) (*pb.CommandOutput, bool, map[string]string, error) {
	if params == nil {
		return nil, false, nil, fmt.Errorf("lps params required")
	}
	if actionID == "" {
		return nil, false, nil, fmt.Errorf("action ID required for LPS state tracking")
	}
	if !isValidUsername(params.Username) {
		return nil, false, nil, fmt.Errorf("invalid username: %q", params.Username)
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		return e.removeLpsManagement(ctx, actionID)
	default:
		return e.setupLpsPassword(ctx, params, actionID)
	}
}

// setupLpsPassword checks if password rotation is needed and rotates if so.
func (e *Executor) setupLpsPassword(ctx context.Context, params *pb.LpsParams, actionID string) (*pb.CommandOutput, bool, map[string]string, error) {
	var output strings.Builder

	// Verify user exists
	if !userExists(params.Username) {
		return nil, false, nil, fmt.Errorf("user %q does not exist on this system", params.Username)
	}

	// Load local state
	localState, err := loadLpsState(actionID)
	if err != nil {
		e.logger.Warn("failed to load LPS state, will treat as initial rotation", "action_id", actionID, "error", err)
		localState = nil
	}

	// Determine if rotation is needed
	rotate, reason := shouldRotateLps(localState, params)
	if !rotate {
		output.WriteString("LPS: password is up to date, no rotation needed\n")
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   output.String(),
		}, false, nil, nil
	}

	// Generate new password
	charset := alphanumericChars
	if params.Complexity == pb.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_COMPLEX {
		charset = complexChars
	}
	password, err := generatePassword(int(params.PasswordLength), charset)
	if err != nil {
		return nil, false, nil, fmt.Errorf("generate password: %w", err)
	}

	// Set the password
	if err := setUserPassword(ctx, params.Username, password); err != nil {
		return nil, false, nil, fmt.Errorf("set password for user %s: %w", params.Username, err)
	}

	now := time.Now().UTC()
	output.WriteString(fmt.Sprintf("LPS: rotated password for user %s (reason: %s)\n", params.Username, reason))

	// Save local state
	hash := sha256.Sum256([]byte(password))
	newState := &lpsState{
		LastRotatedAt: now,
		PasswordHash:  hex.EncodeToString(hash[:]),
	}
	if err := saveLpsState(actionID, newState); err != nil {
		e.logger.Warn("failed to save LPS state", "action_id", actionID, "error", err)
	}

	// Build metadata for server-side password storage
	metadata := map[string]string{
		"lps.username":   params.Username,
		"lps.password":   password,
		"lps.rotated_at": now.Format(time.RFC3339),
		"lps.reason":     reason,
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, true, metadata, nil
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

// shouldRotateLps determines if a password rotation is needed and returns the reason.
func shouldRotateLps(state *lpsState, params *pb.LpsParams) (bool, string) {
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
		lastAuth, err := getLastAuthTime(params.Username)
		if err == nil && !lastAuth.IsZero() && lastAuth.After(state.LastRotatedAt) {
			graceDuration := time.Duration(params.GracePeriodHours) * time.Hour
			if now.Sub(lastAuth) >= graceDuration {
				return true, "auth_grace"
			}
		}
	}

	return false, ""
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
