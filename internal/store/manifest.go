package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
)

const (
	OccurrencePending       = "PENDING"
	OccurrenceStarted       = "STARTED"
	OccurrenceSuccess       = "SUCCESS"
	OccurrenceFailed        = "FAILED"
	OccurrenceIndeterminate = "INDETERMINATE"
)

type StoredManifestDelivery struct {
	Delivery      *pb.ManifestDelivery
	ReceivedAt    time.Time
	LastExecuted  *time.Time
	NextExecuteAt time.Time
	RunStartedAt  *time.Time
	RunInProgress bool
}

type ManifestOccurrenceState struct {
	State        string
	ResultStatus pb.ExecutionStatus
	ResultError  string
}

type PendingResult struct {
	ID             string
	ActionResult   *pb.ActionResult
	ManifestResult *pb.ManifestResult
}

// RecordManifestDelivery commits a delivery and every authored occurrence in
// one transaction. A replay with identical bytes is accepted without changing
// its schedule or execution state; the same delivery ID with different bytes
// is rejected.
func (s *Store) RecordManifestDelivery(ctx context.Context, delivery *pb.ManifestDelivery) (bool, error) {
	if delivery == nil || delivery.GetDeliveryId() == "" || delivery.GetManifest() == nil {
		return false, errors.New("record manifest delivery: missing delivery identity or manifest")
	}
	manifest := delivery.GetManifest()
	if len(manifest.GetOccurrences()) == 0 {
		return false, errors.New("record manifest delivery: manifest has no occurrences")
	}
	seen := make(map[string]struct{}, len(manifest.GetOccurrences()))
	for _, occurrence := range manifest.GetOccurrences() {
		if occurrence == nil || occurrence.GetOccurrenceId() == "" || occurrence.GetAction().GetId().GetValue() == "" {
			return false, errors.New("record manifest delivery: malformed occurrence")
		}
		if _, exists := seen[occurrence.GetOccurrenceId()]; exists {
			return false, fmt.Errorf("record manifest delivery: duplicate occurrence %s", occurrence.GetOccurrenceId())
		}
		seen[occurrence.GetOccurrenceId()] = struct{}{}
	}

	blob, err := marshalStoredProto(manifest)
	if err != nil {
		return false, fmt.Errorf("record manifest delivery: marshal manifest: %w", err)
	}
	now := s.now().UTC()
	next := calculateNextExecuteFromSchedule(manifest.GetSchedule(), nil, false, now)

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("record manifest delivery: begin: %w", err)
	}
	defer tx.Rollback()

	var existing []byte
	err = tx.QueryRow("SELECT manifest_blob FROM manifest_deliveries WHERE delivery_id = ?", delivery.GetDeliveryId()).Scan(&existing)
	if err == nil {
		if !bytes.Equal(existing, blob) {
			return false, errors.New("record manifest delivery: delivery ID replayed with different manifest")
		}
		return false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("record manifest delivery: lookup: %w", err)
	}

	if _, err := tx.Exec(`
		INSERT INTO manifest_deliveries
		    (delivery_id, manifest_blob, received_at, next_execute_at)
		VALUES (?, ?, ?, ?)
	`, delivery.GetDeliveryId(), blob, now, next); err != nil {
		return false, fmt.Errorf("record manifest delivery: insert: %w", err)
	}
	for position, occurrence := range manifest.GetOccurrences() {
		if _, err := tx.Exec(`
			INSERT INTO manifest_occurrences
			    (delivery_id, occurrence_id, position, action_id)
			VALUES (?, ?, ?, ?)
		`, delivery.GetDeliveryId(), occurrence.GetOccurrenceId(), position, occurrence.GetAction().GetId().GetValue()); err != nil {
			return false, fmt.Errorf("record manifest occurrence: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("record manifest delivery: commit: %w", err)
	}
	return true, nil
}

func (s *Store) GetDueManifestDeliveries(ctx context.Context) ([]StoredManifestDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.QueryContext(ctx, `
		SELECT delivery_id, manifest_blob, received_at, last_executed_at,
		       next_execute_at, run_started_at, run_in_progress
		FROM manifest_deliveries
		WHERE run_in_progress = TRUE OR next_execute_at <= ?
		ORDER BY run_in_progress DESC, next_execute_at, delivery_id
	`, s.now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deliveries []StoredManifestDelivery
	for rows.Next() {
		var deliveryID string
		var blob []byte
		var stored StoredManifestDelivery
		var last, runStarted sql.NullTime
		if err := rows.Scan(
			&deliveryID, &blob, &stored.ReceivedAt, &last,
			&stored.NextExecuteAt, &runStarted, &stored.RunInProgress,
		); err != nil {
			return nil, err
		}
		manifest := &pb.Manifest{}
		if err := unmarshalStoredProto(blob, manifest); err != nil {
			return nil, fmt.Errorf("decode manifest delivery %s: %w", deliveryID, err)
		}
		stored.Delivery = &pb.ManifestDelivery{DeliveryId: deliveryID, Manifest: manifest}
		if last.Valid {
			lastTime := last.Time
			stored.LastExecuted = &lastTime
		}
		if runStarted.Valid {
			runStartedTime := runStarted.Time
			stored.RunStartedAt = &runStartedTime
		}
		deliveries = append(deliveries, stored)
	}
	return deliveries, rows.Err()
}

func (s *Store) GetManifestActions() ([]*StoredAction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`
		SELECT delivery_id, manifest_blob, received_at, last_executed_at, next_execute_at
		FROM manifest_deliveries ORDER BY received_at, delivery_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var actions []*StoredAction
	for rows.Next() {
		var deliveryID string
		var blob []byte
		var received, next time.Time
		var last sql.NullTime
		if err := rows.Scan(&deliveryID, &blob, &received, &last, &next); err != nil {
			return nil, err
		}
		manifest := &pb.Manifest{}
		if err := unmarshalStoredProto(blob, manifest); err != nil {
			return nil, fmt.Errorf("decode manifest delivery %s: %w", deliveryID, err)
		}
		for _, occurrence := range manifest.GetOccurrences() {
			stored := &StoredAction{
				ID:            occurrence.GetAction().GetId().GetValue(),
				Action:        occurrence.GetAction(),
				AssignedAt:    received,
				NextExecuteAt: next,
			}
			if last.Valid {
				lastTime := last.Time
				stored.LastExecutedAt = &lastTime
			}
			actions = append(actions, stored)
		}
	}
	return actions, rows.Err()
}

// BeginManifestRun advances the manifest cursor before any side effect. An
// interrupted run stays active and resumes from its durable occurrence states.
func (s *Store) BeginManifestRun(delivery *pb.ManifestDelivery, startedAt time.Time) (time.Time, error) {
	if delivery == nil || delivery.GetManifest() == nil {
		return time.Time{}, errors.New("begin manifest run: missing delivery")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback()
	var inProgress bool
	var priorStarted sql.NullTime
	if err := tx.QueryRow(`
		SELECT run_in_progress, run_started_at
		FROM manifest_deliveries WHERE delivery_id = ?
	`, delivery.GetDeliveryId()).Scan(&inProgress, &priorStarted); err != nil {
		return time.Time{}, err
	}
	if inProgress {
		if !priorStarted.Valid {
			return time.Time{}, errors.New("begin manifest run: active run has no start time")
		}
		if err := tx.Commit(); err != nil {
			return time.Time{}, err
		}
		return priorStarted.Time.UTC(), nil
	}
	var started int
	if err := tx.QueryRow(`
		SELECT COUNT(*) FROM manifest_occurrences
		WHERE delivery_id = ? AND state = ?
	`, delivery.GetDeliveryId(), OccurrenceStarted).Scan(&started); err != nil {
		return time.Time{}, err
	}
	if started != 0 {
		return time.Time{}, fmt.Errorf("begin manifest run: delivery %s has interrupted occurrences", delivery.GetDeliveryId())
	}
	if _, err := tx.Exec(`
		UPDATE manifest_occurrences
		SET state = ?, started_at = NULL, completed_at = NULL,
		    result_status = NULL, result_error = ''
		WHERE delivery_id = ?
	`, OccurrencePending, delivery.GetDeliveryId()); err != nil {
		return time.Time{}, err
	}
	startedAt = startedAt.UTC()
	next := calculateNextExecuteFromSchedule(delivery.GetManifest().GetSchedule(), &startedAt, false, s.now())
	if _, err := tx.Exec(`
		UPDATE manifest_deliveries
		SET last_executed_at = ?, next_execute_at = ?,
		    run_started_at = ?, run_in_progress = TRUE
		WHERE delivery_id = ?
	`, startedAt, next, startedAt, delivery.GetDeliveryId()); err != nil {
		return time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, err
	}
	return startedAt, nil
}

func (s *Store) MarkOccurrenceStarted(deliveryID, occurrenceID string, startedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`
		UPDATE manifest_occurrences SET state = ?, started_at = ?, completed_at = NULL
		WHERE delivery_id = ? AND occurrence_id = ? AND state = ?
	`, OccurrenceStarted, startedAt.UTC(), deliveryID, occurrenceID, OccurrencePending)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return fmt.Errorf("mark occurrence started: invalid state for %s/%s", deliveryID, occurrenceID)
	}
	return nil
}

func (s *Store) MarkRebootStarted(deliveryID, occurrenceID, bootID string, startedAt time.Time) error {
	if bootID == "" {
		return errors.New("mark reboot started: boot ID is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	startedAt = startedAt.UTC()
	result, err := tx.Exec(`
		UPDATE manifest_occurrences SET state = ?, started_at = ?, completed_at = NULL
		WHERE delivery_id = ? AND occurrence_id = ? AND state = ?
	`, OccurrenceStarted, startedAt, deliveryID, occurrenceID, OccurrencePending)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return fmt.Errorf("mark reboot started: invalid state for %s/%s", deliveryID, occurrenceID)
	}
	if _, err := tx.Exec(`
		INSERT INTO reboot_markers (delivery_id, occurrence_id, boot_id, scheduled_at)
		VALUES (?, ?, ?, ?)
	`, deliveryID, occurrenceID, bootID, startedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetManifestOccurrenceStates(deliveryID string) (map[string]ManifestOccurrenceState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`
		SELECT occurrence_id, state, result_status, result_error
		FROM manifest_occurrences WHERE delivery_id = ? ORDER BY position
	`, deliveryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := make(map[string]ManifestOccurrenceState)
	for rows.Next() {
		var occurrenceID, state, resultError string
		var resultStatus sql.NullInt64
		if err := rows.Scan(&occurrenceID, &state, &resultStatus, &resultError); err != nil {
			return nil, err
		}
		item := ManifestOccurrenceState{State: state, ResultError: resultError}
		if resultStatus.Valid {
			item.ResultStatus = pb.ExecutionStatus(resultStatus.Int64)
		}
		states[occurrenceID] = item
	}
	return states, rows.Err()
}

func (s *Store) RecordOccurrenceResult(result *pb.ActionResult) (string, error) {
	if result == nil || result.GetDeliveryId() == "" || result.GetOccurrenceId() == "" {
		return "", errors.New("record occurrence result: missing delivery or occurrence identity")
	}
	state, err := occurrenceState(result.GetStatus())
	if err != nil {
		return "", err
	}
	return s.recordResult("ACTION", result, func(tx *sql.Tx, completedAt time.Time) error {
		updated, err := tx.Exec(`
			UPDATE manifest_occurrences
			SET state = ?, completed_at = ?, result_status = ?, result_error = ?
			WHERE delivery_id = ? AND occurrence_id = ? AND state = ?
		`, state, completedAt, result.GetStatus(), result.GetError(),
			result.GetDeliveryId(), result.GetOccurrenceId(), OccurrenceStarted)
		if err != nil {
			return err
		}
		rows, err := updated.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return errors.New("record occurrence result: occurrence was not STARTED")
		}
		if _, err := tx.Exec(`
			DELETE FROM reboot_markers WHERE delivery_id = ? AND occurrence_id = ?
		`, result.GetDeliveryId(), result.GetOccurrenceId()); err != nil {
			return err
		}
		return nil
	})
}

func (s *Store) RecordManifestResult(result *pb.ManifestResult) (string, error) {
	if result == nil || result.GetDeliveryId() == "" || result.GetManifestId() == "" {
		return "", errors.New("record manifest result: missing identity")
	}
	return s.recordResult("MANIFEST", result, func(tx *sql.Tx, _ time.Time) error {
		updated, err := tx.Exec(`
			UPDATE manifest_deliveries
			SET run_in_progress = FALSE, run_started_at = NULL
			WHERE delivery_id = ? AND run_in_progress = TRUE
		`, result.GetDeliveryId())
		if err != nil {
			return err
		}
		rows, err := updated.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return errors.New("record manifest result: manifest run is not active")
		}
		return nil
	})
}

func (s *Store) recordResult(kind string, message proto.Message, update func(*sql.Tx, time.Time) error) (string, error) {
	payload, err := marshalStoredProto(message)
	if err != nil {
		return "", fmt.Errorf("record result: marshal: %w", err)
	}
	now := s.now().UTC()
	id, err := randomResultID(kind, now)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if update != nil {
		if err := update(tx, now); err != nil {
			return "", err
		}
	}
	if _, err := tx.Exec(`
		INSERT INTO result_outbox (id, kind, payload, created_at)
		VALUES (?, ?, ?, ?)
	`, id, kind, payload, now); err != nil {
		return "", err
	}
	return id, tx.Commit()
}

func (s *Store) GetPendingResults() ([]PendingResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`
		SELECT id, kind, payload FROM result_outbox
		WHERE synced = FALSE ORDER BY sequence
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pending []PendingResult
	for rows.Next() {
		var item PendingResult
		var kind string
		var payload []byte
		if err := rows.Scan(&item.ID, &kind, &payload); err != nil {
			return nil, err
		}
		switch kind {
		case "ACTION":
			item.ActionResult = &pb.ActionResult{}
			if err := unmarshalStoredProto(payload, item.ActionResult); err != nil {
				return nil, fmt.Errorf("decode action result %s: %w", item.ID, err)
			}
		case "MANIFEST":
			item.ManifestResult = &pb.ManifestResult{}
			if err := unmarshalStoredProto(payload, item.ManifestResult); err != nil {
				return nil, fmt.Errorf("decode manifest result %s: %w", item.ID, err)
			}
		default:
			return nil, fmt.Errorf("unknown result outbox kind %q", kind)
		}
		pending = append(pending, item)
	}
	return pending, rows.Err()
}

func (s *Store) MarkPendingResultSynced(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE result_outbox SET synced = TRUE WHERE id = ?", id)
	return err
}

const rebootResolutionGrace = 15 * time.Minute

// RecoverInterruptedOccurrences resolves durable STARTED rows without ever
// repeating their side effects. A changed kernel boot ID proves a scheduled
// reboot completed; other interrupted work is INDETERMINATE. A reboot marker
// on the current boot is left pending briefly so an agent-service restart does
// not race the already scheduled operating-system reboot.
func (s *Store) RecoverInterruptedOccurrences(currentBootID string) ([]PendingResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`
		SELECT o.delivery_id, o.occurrence_id, o.action_id,
		       r.boot_id, r.scheduled_at
		FROM manifest_occurrences o
		LEFT JOIN reboot_markers r
		  ON r.delivery_id = o.delivery_id AND r.occurrence_id = o.occurrence_id
		WHERE o.state = ?
		ORDER BY o.delivery_id, o.position
	`, OccurrenceStarted)
	if err != nil {
		return nil, err
	}
	type interrupted struct {
		deliveryID, occurrenceID, actionID string
		bootID                             sql.NullString
		scheduledAt                        sql.NullTime
	}
	var interruptedRows []interrupted
	for rows.Next() {
		var item interrupted
		if err := rows.Scan(
			&item.deliveryID, &item.occurrenceID, &item.actionID,
			&item.bootID, &item.scheduledAt,
		); err != nil {
			rows.Close()
			return nil, err
		}
		interruptedRows = append(interruptedRows, item)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	var recovered []PendingResult
	for _, item := range interruptedRows {
		status := pb.ExecutionStatus_EXECUTION_STATUS_INDETERMINATE
		message := "agent restarted after STARTED; effect is unknown and was not repeated"
		var output *pb.CommandOutput
		if item.bootID.Valid {
			switch {
			case currentBootID != "" && currentBootID != item.bootID.String:
				status = pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS
				message = ""
				output = &pb.CommandOutput{Stdout: "Reboot completed\n"}
			case item.scheduledAt.Valid && now.Before(item.scheduledAt.Time.Add(rebootResolutionGrace)):
				continue
			default:
				message = "scheduled reboot did not produce a new boot ID; effect is indeterminate"
			}
		}
		result := &pb.ActionResult{
			ActionId:     &pb.ActionId{Value: item.actionID},
			DeliveryId:   item.deliveryID,
			OccurrenceId: item.occurrenceID,
			Status:       status,
			Error:        message,
			Output:       output,
			CompletedAt:  timestamppb.New(now),
		}
		payload, err := marshalStoredProto(result)
		if err != nil {
			return nil, err
		}
		id, err := randomResultID("ACTION", now)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`INSERT INTO result_outbox (id, kind, payload, created_at) VALUES (?, 'ACTION', ?, ?)`, id, payload, now); err != nil {
			return nil, err
		}
		state, err := occurrenceState(status)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`
			UPDATE manifest_occurrences
			SET state = ?, completed_at = ?, result_status = ?, result_error = ?
			WHERE delivery_id = ? AND occurrence_id = ? AND state = ?
		`, state, now, status, message, item.deliveryID, item.occurrenceID, OccurrenceStarted); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`
			DELETE FROM reboot_markers WHERE delivery_id = ? AND occurrence_id = ?
		`, item.deliveryID, item.occurrenceID); err != nil {
			return nil, err
		}
		recovered = append(recovered, PendingResult{ID: id, ActionResult: result})
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return recovered, nil
}

func occurrenceState(status pb.ExecutionStatus) (string, error) {
	switch status {
	case pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS:
		return OccurrenceSuccess, nil
	case pb.ExecutionStatus_EXECUTION_STATUS_INDETERMINATE:
		return OccurrenceIndeterminate, nil
	case pb.ExecutionStatus_EXECUTION_STATUS_FAILED,
		pb.ExecutionStatus_EXECUTION_STATUS_TIMEOUT,
		pb.ExecutionStatus_EXECUTION_STATUS_CANCELLED,
		pb.ExecutionStatus_EXECUTION_STATUS_SKIPPED,
		pb.ExecutionStatus_EXECUTION_STATUS_NOT_APPLICABLE:
		return OccurrenceFailed, nil
	default:
		return "", fmt.Errorf("record occurrence result: non-terminal status %s", status)
	}
}

func randomResultID(kind string, now time.Time) (string, error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generate result ID: %w", err)
	}
	return fmt.Sprintf("%s-%d-%s", kind, now.UnixNano(), hex.EncodeToString(suffix[:])), nil
}
