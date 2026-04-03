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

// WriteState writes the update state to disk atomically, creating the update
// directory if it does not exist.
func WriteState(dataDir string, state *State) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	return atomicWrite(statePath(dataDir), data)
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
// specified duration from now. The write is atomic (temp file + rename).
func WriteCooldown(dataDir, version string, duration time.Duration) error {
	c := Cooldown{
		Version: version,
		Until:   time.Now().Add(duration),
	}

	data, err := json.Marshal(&c)
	if err != nil {
		return fmt.Errorf("marshal cooldown: %w", err)
	}
	return atomicWrite(cooldownPath(dataDir), data)
}

// IsCoolingDown returns true if the given version is currently in a cooldown
// period (i.e. a recent rollback occurred for this version).
// Returns true on read errors to conservatively prevent retrying a bad version.
func IsCoolingDown(dataDir, version string) bool {
	c, err := ReadCooldown(dataDir)
	if err != nil {
		// Corrupted cooldown file — assume cooling down to be safe.
		return true
	}
	if c == nil {
		return false
	}

	if c.Version != version {
		return false
	}

	return time.Now().Before(c.Until)
}

// atomicWrite writes data to path via a temp file + rename to prevent
// torn writes on crash. Creates parent directories if needed.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename to final path: %w", err)
	}

	return nil
}
