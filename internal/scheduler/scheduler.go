// Package scheduler executes durably received manifests on the agent.
package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/maintenance"
	"github.com/manchtools/power-manage/agent/internal/store"
)

const DefaultCheckInterval = time.Minute

const maintenanceWindowSettingKey = "maintenance_window"

type ActionExecutor interface {
	ExecuteAction(context.Context, *pb.Action) *pb.ActionResult
	ResetUpdateCycle()
}

type ExecutionResult struct {
	ResultID       string
	ActionResult   *pb.ActionResult
	ManifestResult *pb.ManifestResult
}

type Scheduler struct {
	store    *store.Store
	executor ActionExecutor
	logger   *slog.Logger
	now      func() time.Time
	wakeCh   chan struct{}
	results  chan *ExecutionResult

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	done    chan struct{}

	windowMu           sync.RWMutex
	window             *pb.MaintenanceWindow
	windowDecodeFailed bool
	syncTrigger        chan<- struct{}
}

func New(st *store.Store, executor ActionExecutor, logger *slog.Logger) *Scheduler {
	s := &Scheduler{
		store:    st,
		executor: executor,
		logger:   logger,
		now:      time.Now,
		wakeCh:   make(chan struct{}, 1),
		results:  make(chan *ExecutionResult, 100),
	}
	if window, err := loadMaintenanceWindow(st); err != nil {
		logger.Error("persisted maintenance window is unreadable; denying dispatch until sync", "error", err)
		s.windowDecodeFailed = true
	} else {
		s.window = window
	}
	return s
}

func (s *Scheduler) SetSyncTrigger(trigger chan<- struct{}) { s.syncTrigger = trigger }

func (s *Scheduler) Results() <-chan *ExecutionResult { return s.results }

func (s *Scheduler) RecordDelivery(ctx context.Context, delivery *pb.ManifestDelivery) (bool, error) {
	inserted, err := s.store.RecordManifestDelivery(ctx, delivery)
	if err == nil && inserted {
		s.Wake()
	}
	return inserted, err
}

func (s *Scheduler) GetPendingResults() ([]store.PendingResult, error) {
	return s.store.GetPendingResults()
}

func (s *Scheduler) MarkPendingResultSynced(id string) error {
	return s.store.MarkPendingResultSynced(id)
}

func (s *Scheduler) Wake() {
	select {
	case s.wakeCh <- struct{}{}:
	default:
	}
}

func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	if prior := s.done; prior != nil {
		s.mu.Unlock()
		<-prior
		s.mu.Lock()
		if s.running {
			s.mu.Unlock()
			return
		}
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.done = make(chan struct{})
	stopCh, done := s.stopCh, s.done
	s.mu.Unlock()
	defer close(done)

	if err := s.store.RecoverInterruptedOccurrences(); err != nil {
		s.logger.Error("failed to recover interrupted occurrences; refusing to schedule", "error", err)
		return
	}
	ticker := time.NewTicker(DefaultCheckInterval)
	defer ticker.Stop()
	s.runDue(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		case <-ticker.C:
			s.runDue(ctx)
		case <-s.wakeCh:
			s.runDue(ctx)
		}
	}
}

func (s *Scheduler) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	close(s.stopCh)
	s.running = false
	done := s.done
	s.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (s *Scheduler) runDue(ctx context.Context) {
	if !s.dispatchAllowed(s.now().Local()) {
		return
	}
	deliveries, err := s.store.GetDueManifestDeliveries(ctx)
	if err != nil {
		s.logger.Error("load due manifests", "error", err)
		return
	}
	for _, stored := range deliveries {
		if ctx.Err() != nil {
			return
		}
		s.executeManifest(ctx, stored.Delivery)
	}
}

func (s *Scheduler) executeManifest(ctx context.Context, delivery *pb.ManifestDelivery) {
	manifest := delivery.GetManifest()
	started := s.now().UTC()
	if err := s.store.BeginManifestRun(delivery, started); err != nil {
		s.logger.Error("begin manifest run", "delivery_id", delivery.GetDeliveryId(), "error", err)
		return
	}
	s.executor.ResetUpdateCycle()
	aggregate := pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS
	var aggregateError string
	stop := false
	for _, occurrence := range manifest.GetOccurrences() {
		if ctx.Err() != nil {
			return
		}
		action := occurrence.GetAction()
		if action == nil || action.GetId() == nil {
			aggregate = pb.ExecutionStatus_EXECUTION_STATUS_FAILED
			aggregateError = "manifest contains a malformed occurrence"
			break
		}
		if err := s.store.MarkOccurrenceStarted(delivery.GetDeliveryId(), occurrence.GetOccurrenceId(), s.now()); err != nil {
			s.logger.Error("mark occurrence started", "delivery_id", delivery.GetDeliveryId(), "occurrence_id", occurrence.GetOccurrenceId(), "error", err)
			aggregate = pb.ExecutionStatus_EXECUTION_STATUS_FAILED
			aggregateError = "failed to durably mark occurrence STARTED"
			break
		}

		var result *pb.ActionResult
		if stop {
			result = &pb.ActionResult{
				ActionId:    action.GetId(),
				Status:      pb.ExecutionStatus_EXECUTION_STATUS_SKIPPED,
				Error:       "skipped after an earlier occurrence failed with STOP policy",
				CompletedAt: timestamppb.New(s.now()),
			}
		} else if action.GetType() == pb.ActionType_ACTION_TYPE_SYNC {
			if s.syncTrigger != nil {
				select {
				case s.syncTrigger <- struct{}{}:
				default:
				}
			}
			result = &pb.ActionResult{
				ActionId:    action.GetId(),
				Status:      pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
				Output:      &pb.CommandOutput{Stdout: "Sync triggered"},
				CompletedAt: timestamppb.New(s.now()),
			}
		} else {
			result = s.executor.ExecuteAction(ctx, action)
		}
		if ctx.Err() != nil {
			// Leave STARTED durable. Startup recovery will report INDETERMINATE
			// and the next run cannot silently repeat the effect.
			return
		}
		result.DeliveryId = delivery.GetDeliveryId()
		result.OccurrenceId = occurrence.GetOccurrenceId()
		if result.CompletedAt == nil {
			result.CompletedAt = timestamppb.New(s.now())
		}
		resultID, err := s.store.RecordOccurrenceResult(result)
		if err != nil {
			s.logger.Error("record occurrence result", "delivery_id", delivery.GetDeliveryId(), "occurrence_id", occurrence.GetOccurrenceId(), "error", err)
			return
		}
		s.publish(&ExecutionResult{ResultID: resultID, ActionResult: result})
		if result.GetStatus() == pb.ExecutionStatus_EXECUTION_STATUS_INDETERMINATE {
			aggregate = pb.ExecutionStatus_EXECUTION_STATUS_INDETERMINATE
			aggregateError = result.GetError()
		} else if result.GetStatus() != pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS && result.GetStatus() != pb.ExecutionStatus_EXECUTION_STATUS_NOT_APPLICABLE && result.GetStatus() != pb.ExecutionStatus_EXECUTION_STATUS_SKIPPED {
			if aggregate != pb.ExecutionStatus_EXECUTION_STATUS_INDETERMINATE {
				aggregate = pb.ExecutionStatus_EXECUTION_STATUS_FAILED
				aggregateError = result.GetError()
			}
			stop = occurrence.GetOnFailure() == pb.OnFailure_ON_FAILURE_STOP
		}
	}

	finished := s.now().UTC()
	manifestResult := &pb.ManifestResult{
		DeliveryId:  delivery.GetDeliveryId(),
		ManifestId:  manifest.GetManifestId(),
		Status:      aggregate,
		CompletedAt: timestamppb.New(finished),
		DurationMs:  finished.Sub(started).Milliseconds(),
		Error:       aggregateError,
	}
	resultID, err := s.store.RecordManifestResult(manifestResult)
	if err != nil {
		s.logger.Error("record manifest result", "delivery_id", delivery.GetDeliveryId(), "error", err)
		return
	}
	s.publish(&ExecutionResult{ResultID: resultID, ManifestResult: manifestResult})
}

func (s *Scheduler) publish(result *ExecutionResult) {
	select {
	case s.results <- result:
	default:
		s.logger.Warn("result notification queue full; durable outbox will retry", "result_id", result.ResultID)
	}
}

// GetStoredActions supplies the LUKS conflict check from the manifest store.
func (s *Scheduler) GetStoredActions() ([]*store.StoredAction, error) {
	return s.store.GetManifestActions()
}

func (s *Scheduler) SetMaintenanceWindow(window *pb.MaintenanceWindow) {
	var normalized *pb.MaintenanceWindow
	if window != nil && len(window.GetSchedule()) != 0 {
		normalized = proto.Clone(window).(*pb.MaintenanceWindow)
	}
	s.windowMu.Lock()
	s.window = normalized
	s.windowDecodeFailed = false
	s.windowMu.Unlock()
	if err := storeMaintenanceWindow(s.store, normalized); err != nil {
		s.logger.Warn("persist maintenance window", "error", err)
	}
}

func (s *Scheduler) dispatchAllowed(at time.Time) bool {
	s.windowMu.RLock()
	defer s.windowMu.RUnlock()
	return !s.windowDecodeFailed && maintenance.IsAllowed(s.window, at)
}

func loadMaintenanceWindow(st *store.Store) (*pb.MaintenanceWindow, error) {
	raw, err := st.GetSetting(maintenanceWindowSettingKey)
	if err != nil || raw == "" {
		return nil, err
	}
	window := &pb.MaintenanceWindow{}
	if err := proto.Unmarshal([]byte(raw), window); err != nil {
		return nil, fmt.Errorf("decode maintenance window: %w", err)
	}
	if len(window.GetSchedule()) == 0 {
		return nil, nil
	}
	return window, nil
}

func storeMaintenanceWindow(st *store.Store, window *pb.MaintenanceWindow) error {
	if window == nil || len(window.GetSchedule()) == 0 {
		return st.DeleteSetting(maintenanceWindowSettingKey)
	}
	raw, err := proto.Marshal(window)
	if err != nil {
		return err
	}
	return st.SetSetting(maintenanceWindowSettingKey, string(raw))
}
