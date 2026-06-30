package executor

import (
	"context"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// All tests in this file use NewExecutor(nil, nil) — no real runner, no
// binary dependencies, no container needed. They test pure validation.

func TestExecuteService_RejectsNilParams(t *testing.T) {
	e := NewExecutor(nil, nil)
	_, changed, err := e.executeService(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil params, got nil")
	}
	if changed {
		t.Error("changed must be false when params are nil")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("error should mention 'required', got %q", err)
	}
}

func TestExecuteService_RejectsAgentOwnService(t *testing.T) {
	e := NewExecutor(nil, nil)
	name := "power-manage-agent.service"
	params := &pb.ServiceParams{UnitName: name}
	_, changed, err := e.executeService(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for agent's own service, got nil")
	}
	if changed {
		t.Error("changed must be false for protected service")
	}
	if !strings.Contains(err.Error(), "protected service") {
		t.Errorf("error should mention 'protected service', got %q", err)
	}

	// "power-manage-agent" without .service suffix is rejected at validation
	params = &pb.ServiceParams{UnitName: "power-manage-agent"}
	_, changed, err = e.executeService(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for agent's own service (no suffix), got nil")
	}
	if changed {
		t.Error("changed must be false for invalid unit name")
	}
	if !strings.Contains(err.Error(), "invalid systemd unit name") {
		t.Errorf("error should mention 'invalid systemd unit name', got %q", err)
	}
}

func TestExecuteService_RejectsInvalidUnitName(t *testing.T) {
	e := NewExecutor(nil, nil)
	invalidNames := []string{
		"",
		"../etc/systemd/system/evil.service",
		"a/b.service",
	}
	for _, name := range invalidNames {
		t.Run("rejects "+name, func(t *testing.T) {
			params := &pb.ServiceParams{UnitName: name}
			_, _, err := e.executeService(context.Background(), params)
			if err == nil {
				t.Fatalf("expected error for invalid unit name %q, got nil", name)
			}
		})
	}
}

func TestExecuteService_RejectsBeforeRemount(t *testing.T) {
	var remountCalled bool
	e := NewExecutor(nil, nil)
	e.repairFS = func(ctx context.Context) bool {
		remountCalled = true
		return true
	}
	params := &pb.ServiceParams{UnitName: "power-manage-agent.service"}
	_, _, err := e.executeService(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for agent's own service, got nil")
	}
	if remountCalled {
		t.Error("requireWritableFS must NOT be called for a rejected action")
	}
}

func TestExecuteService_IsUnitEnabled_ProbeErrorFailsSafe(t *testing.T) {
	e := NewExecutor(nil, nil)
	enabled := e.isUnitEnabled(context.Background(), "nonexistent.service")
	if enabled {
		t.Error("isUnitEnabled must return false (fail safe) when the probe fails")
	}
}

func TestExecuteService_IsUnitMasked_ProbeErrorFailsSafe(t *testing.T) {
	e := NewExecutor(nil, nil)
	masked := e.isUnitMasked(context.Background(), "nonexistent.service")
	if masked {
		t.Error("isUnitMasked must return false (fail safe) when the probe fails")
	}
}

func TestExecuteService_IsUnitActive_ProbeErrorFailsSafe(t *testing.T) {
	e := NewExecutor(nil, nil)
	active := e.isUnitActive(context.Background(), "nonexistent.service")
	if active {
		t.Error("isUnitActive must return false (fail safe) when the probe fails")
	}
}
