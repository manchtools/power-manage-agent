package updater

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// State represents the current update phase persisted to disk.
type State struct {
	Phase   string `json:"phase"`
	Version string `json:"version"`
}

// Cooldown records a version that should be skipped until the cooldown expires.
type Cooldown struct {
	Version string    `json:"version"`
	Until   time.Time `json:"until"`
}

// updateDir returns the update directory path within dataDir.
func updateDir(dataDir string) string {
	return filepath.Join(dataDir, "update")
}

// statePath returns the path to state.json.
func statePath(dataDir string) string {
	return filepath.Join(updateDir(dataDir), "state.json")
}

// cooldownPath returns the path to cooldown.json.
func cooldownPath(dataDir string) string {
	return filepath.Join(updateDir(dataDir), "cooldown.json")
}

// ReadState reads the update state from disk. Returns nil if the file does
// not exist or cannot be parsed.
func ReadState(dataDir string) (*State, error) {
	data, err := os.ReadFile(statePath(dataDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}

	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}

	return &s, nil
}

// WriteState writes the update state to disk, creating the update directory
// if it does not exist.
func WriteState(dataDir string, state *State) error {
	dir := updateDir(dataDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create update dir: %w", err)
	}

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	if err := os.WriteFile(statePath(dataDir), data, 0644); err != nil {
		return fmt.Errorf("write state: %w", err)
	}

	return nil
}

// ClearState removes the state file from disk.
func ClearState(dataDir string) {
	os.Remove(statePath(dataDir))
}

// ReadCooldown reads the cooldown state from disk. Returns nil if the file
// does not exist or cannot be parsed.
func ReadCooldown(dataDir string) (*Cooldown, error) {
	data, err := os.ReadFile(cooldownPath(dataDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read cooldown: %w", err)
	}

	var c Cooldown
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse cooldown: %w", err)
	}

	return &c, nil
}

// WriteCooldown writes a cooldown entry for the given version with the
// specified duration from now.
func WriteCooldown(dataDir, version string, duration time.Duration) error {
	dir := updateDir(dataDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create update dir: %w", err)
	}

	c := Cooldown{
		Version: version,
		Until:   time.Now().Add(duration),
	}

	data, err := json.Marshal(&c)
	if err != nil {
		return fmt.Errorf("marshal cooldown: %w", err)
	}

	if err := os.WriteFile(cooldownPath(dataDir), data, 0644); err != nil {
		return fmt.Errorf("write cooldown: %w", err)
	}

	return nil
}

// IsCoolingDown returns true if the given version is currently in a cooldown
// period (i.e. a recent rollback occurred for this version).
func IsCoolingDown(dataDir, version string) bool {
	c, err := ReadCooldown(dataDir)
	if err != nil || c == nil {
		return false
	}

	if c.Version != version {
		return false
	}

	return time.Now().Before(c.Until)
}
