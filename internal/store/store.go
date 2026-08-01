// Package store owns the agent's durable SQLite state.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/robfig/cron/v3"
	"google.golang.org/protobuf/proto"
	_ "modernc.org/sqlite"

	pb "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/agent/internal/store/migrations"
)

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

const (
	nilScheduleDrift  = 8 * time.Hour
	binaryProtoPrefix = byte(0x00)
)

// Store serializes access to the agent's local durable state.
type Store struct {
	db  *sql.DB
	mu  sync.RWMutex
	now func() time.Time
}

// StoredAction is the minimal view used to resolve overlapping LUKS policies.
type StoredAction struct {
	ID             string
	Action         *pb.Action
	AssignedAt     time.Time
	LastExecutedAt *time.Time
	NextExecuteAt  time.Time
}

func New(dataDir string) (*Store, error) { return open(dataDir, true) }

// OpenExisting opens a store initialized by the agent service without running
// migrations from a CLI helper process.
func OpenExisting(dataDir string) (*Store, error) {
	dbPath := filepath.Join(dataDir, "agent.db")
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("agent database %s does not exist — start the agent service first", dbPath)
		}
		return nil, fmt.Errorf("stat agent database: %w", err)
	}
	return open(dataDir, false)
}

func open(dataDir string, migrate bool) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	dbPath := filepath.Join(dataDir, "agent.db")
	if strings.ContainsAny(dbPath, "?#") {
		return nil, fmt.Errorf("store: data dir path %q contains '?' or '#', which would corrupt SQLite DSN pragmas", dbPath)
	}
	dsn := dbPath + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	closeOnError := func(err error) (*Store, error) {
		_ = db.Close()
		return nil, err
	}
	if migrate {
		goose.SetBaseFS(migrations.FS)
		if err := goose.SetDialect("sqlite3"); err != nil {
			return closeOnError(fmt.Errorf("set goose dialect: %w", err))
		}
		if err := goose.Up(db, "."); err != nil {
			return closeOnError(fmt.Errorf("run migrations: %w", err))
		}
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return closeOnError(fmt.Errorf("restrict data dir mode: %w", err))
	}
	if err := verifyRestrictiveDirMode(dataDir); err != nil {
		return closeOnError(err)
	}
	for _, path := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
			return closeOnError(fmt.Errorf("restrict %s mode: %w", filepath.Base(path), err))
		}
	}
	return &Store{db: db, now: time.Now}, nil
}

func verifyRestrictiveDirMode(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat data dir after chmod: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("data dir %s is %#o after tightening; refusing to store secrets there", dir, perm)
	}
	return nil
}

func (s *Store) SetClockForTest(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

func (s *Store) Close() error { return s.db.Close() }

func canonicalProtoBytes(message proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(message)
}

func marshalStoredProto(message proto.Message) ([]byte, error) {
	encoded, err := canonicalProtoBytes(message)
	if err != nil {
		return nil, err
	}
	return append([]byte{binaryProtoPrefix}, encoded...), nil
}

func unmarshalStoredProto(raw []byte, message proto.Message) error {
	if len(raw) == 0 || raw[0] != binaryProtoPrefix {
		return errors.New("stored blob is not binary protobuf")
	}
	return proto.Unmarshal(raw[1:], message)
}

func calculateNextExecuteFromSchedule(schedule *pb.ActionSchedule, lastExecuted *time.Time, runImmediately bool, now time.Time) time.Time {
	now = now.UTC()
	if runImmediately && lastExecuted == nil {
		return now
	}
	if schedule == nil {
		if lastExecuted == nil {
			return now
		}
		return clampInterval(lastExecuted.UTC().Add(nilScheduleDrift), now, nilScheduleDrift)
	}
	if schedule.GetRunOnAssign() && lastExecuted == nil {
		return now
	}
	if schedule.GetCron() != "" {
		scheduleParser, err := cronParser.Parse(schedule.GetCron())
		if err == nil {
			return scheduleParser.Next(now.Local()).UTC()
		}
		slog.Warn("invalid manifest cron expression; using interval fallback", "cron", schedule.GetCron(), "error", err)
	}
	intervalHours := schedule.GetIntervalHours()
	if intervalHours <= 0 {
		intervalHours = 8
	}
	if lastExecuted == nil {
		return now
	}
	interval := time.Duration(intervalHours) * time.Hour
	return clampInterval(lastExecuted.UTC().Add(interval), now, interval)
}

func clampInterval(computed, now time.Time, interval time.Duration) time.Time {
	ceiling := now.UTC().Add(interval)
	if computed.After(ceiling) {
		return ceiling
	}
	return computed
}

// LuksState is the device-local state that makes key rotation restart-safe.
type LuksState struct {
	ActionID       string
	DevicePath     string
	OwnershipTaken bool
	DeviceKeyType  string
	LastRotatedAt  time.Time
}

func (s *Store) GetLuksState(actionID string) (*LuksState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var state LuksState
	var lastRotated string
	err := s.db.QueryRow(
		"SELECT action_id, device_path, ownership_taken, device_key_type, last_rotated_at FROM luks_state WHERE action_id = ?",
		actionID,
	).Scan(&state.ActionID, &state.DevicePath, &state.OwnershipTaken, &state.DeviceKeyType, &lastRotated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if lastRotated != "" {
		state.LastRotatedAt, err = time.Parse(time.RFC3339, lastRotated)
		if err != nil {
			return nil, fmt.Errorf("parse LUKS last_rotated_at: %w", err)
		}
	}
	return &state, nil
}

func (s *Store) SetLuksOwnershipTaken(actionID, devicePath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO luks_state (action_id, device_path, ownership_taken, device_key_type, last_rotated_at)
		VALUES (?, ?, TRUE, 'none', ?)
		ON CONFLICT(action_id) DO UPDATE SET
			device_path = excluded.device_path,
			ownership_taken = TRUE,
			last_rotated_at = excluded.last_rotated_at
	`, actionID, devicePath, s.now().UTC().Format(time.RFC3339))
	return err
}

func (s *Store) SetLuksDeviceKeyType(actionID, keyType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE luks_state SET device_key_type = ? WHERE action_id = ?", keyType, actionID)
	return err
}

func (s *Store) SetLuksLastRotatedAt(actionID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE luks_state SET last_rotated_at = ? WHERE action_id = ?", at.UTC().Format(time.RFC3339), actionID)
	return err
}

func (s *Store) DeleteLuksState(actionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM luks_state WHERE action_id = ?", actionID)
	return err
}

func (s *Store) GetLuksPassphraseHashes(actionID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`
		SELECT passphrase_hash FROM luks_user_passphrase_history
		WHERE action_id = ? ORDER BY created_at DESC, id DESC LIMIT 3
	`, actionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	return hashes, rows.Err()
}

func (s *Store) AddLuksPassphraseHash(actionID, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		"INSERT INTO luks_user_passphrase_history (action_id, passphrase_hash) VALUES (?, ?)",
		actionID, hash,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(`
		DELETE FROM luks_user_passphrase_history
		WHERE action_id = ? AND id NOT IN (
			SELECT id FROM luks_user_passphrase_history
			WHERE action_id = ? ORDER BY created_at DESC, id DESC LIMIT 3
		)
	`, actionID, actionID); err != nil {
		return err
	}
	return tx.Commit()
}

// LpsUserState records password-rotation state without retaining plaintext.
type LpsUserState struct {
	ActionID      string
	Username      string
	LastRotatedAt time.Time
	PasswordHash  string
}

func (s *Store) GetLpsState(actionID string) (map[string]*LpsUserState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(
		"SELECT action_id, username, last_rotated_at, password_hash FROM lps_state WHERE action_id = ?",
		actionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make(map[string]*LpsUserState)
	for rows.Next() {
		var state LpsUserState
		var lastRotated string
		if err := rows.Scan(&state.ActionID, &state.Username, &lastRotated, &state.PasswordHash); err != nil {
			return nil, err
		}
		if lastRotated != "" {
			state.LastRotatedAt, err = time.Parse(time.RFC3339, lastRotated)
			if err != nil {
				return nil, fmt.Errorf("parse LPS last_rotated_at for %s: %w", state.Username, err)
			}
		}
		users[state.Username] = &state
	}
	return users, rows.Err()
}

func (s *Store) SetLpsUserState(actionID, username string, lastRotatedAt time.Time, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO lps_state (action_id, username, last_rotated_at, password_hash)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(action_id, username) DO UPDATE SET
			last_rotated_at = excluded.last_rotated_at,
			password_hash = excluded.password_hash
	`, actionID, username, lastRotatedAt.UTC().Format(time.RFC3339), passwordHash)
	return err
}

func (s *Store) DeleteLpsState(actionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM lps_state WHERE action_id = ?", actionID)
	return err
}

func (s *Store) GetSetting(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var value string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

func (s *Store) SetSetting(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, value)
	return err
}

func (s *Store) DeleteSetting(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM settings WHERE key = ?", key)
	return err
}
