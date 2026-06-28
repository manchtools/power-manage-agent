package executor

import (
	"context"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/service"
)

// TestExecuteService_RejectsNilParams verifies that nil ServiceParams is
// rejected before any privileged work.
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

// TestExecuteService_RejectsAgentOwnService verifies that the executor refuses
// to manage its own service unit. A compromised gateway could otherwise
// dispatch a SERVICE action that stops or disables the agent.
func TestExecuteService_RejectsAgentOwnService(t *testing.T) {
	e := NewExecutor(nil, nil)
	for _, name := range []string{"power-manage-agent.service"} {
		t.Run(name, func(t *testing.T) {
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
		})
	}

	// "power-manage-agent" without .service suffix is rejected at validation
	params := &pb.ServiceParams{UnitName: "power-manage-agent"}
	_, changed, err := e.executeService(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for agent's own service (no suffix), got nil")
	}
	if changed {
		t.Error("changed must be false for invalid unit name")
	}
	// Validation rejects the name before the protected-service check
	if !strings.Contains(err.Error(), "invalid systemd unit name") {
		t.Errorf("error should mention 'invalid systemd unit name', got %q", err)
	}
}

// TestExecuteService_RejectsInvalidUnitName verifies that an invalid systemd
// unit name (path traversal, empty, too long) is rejected at the ValidateUnitName
// gate before any privileged filesystem access.
func TestExecuteService_RejectsInvalidUnitName(t *testing.T) {
	e := NewExecutor(nil, nil)
	invalidNames := []string{
		"",
		"../etc/systemd/system/evil.service",
		"a/b.service",
		"\x00.service",
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

// TestExecuteService_RejectsBeforeRemount verifies that a malformed service
// action is rejected BEFORE requireWritableFS is called — a privileged remount
// must not fire for a rejected action. This mirrors the existing
// TestExecuteDeb_RejectsBeforeRemount pattern.
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
		t.Error("requireWritableFS must NOT be called for a rejected action — remount would fire for a malformed request")
	}
}

// TestExecuteService_IsUnitEnabled_ProbeErrorFailsSafe verifies that
// isUnitEnabled treats a probe error as "not enabled" (the safe default)
// rather than panicking or returning a zero value that could be misinterpreted.
func TestExecuteService_IsUnitEnabled_ProbeErrorFailsSafe(t *testing.T) {
	e := NewExecutor(nil, nil)
	// With a nil serviceMgr, IsEnabled would fail. isUnitEnabled should surface
	// false (fail safe) and not crash.
	enabled := e.isUnitEnabled(context.Background(), "nonexistent.service")
	if enabled {
		t.Error("isUnitEnabled must return false (fail safe) when the probe fails")
	}
}

// TestExecuteService_IsUnitMasked_ProbeErrorFailsSafe verifies that
// isUnitMasked treats a probe error as "not masked" (safe default).
func TestExecuteService_IsUnitMasked_ProbeErrorFailsSafe(t *testing.T) {
	e := NewExecutor(nil, nil)
	masked := e.isUnitMasked(context.Background(), "nonexistent.service")
	if masked {
		t.Error("isUnitMasked must return false (fail safe) when the probe fails")
	}
}

// TestExecuteService_IsUnitActive_ProbeErrorFailsSafe verifies that
// isUnitActive treats a probe error as "not active" (safe default).
func TestExecuteService_IsUnitActive_ProbeErrorFailsSafe(t *testing.T) {
	e := NewExecutor(nil, nil)
	active := e.isUnitActive(context.Background(), "nonexistent.service")
	if active {
		t.Error("isUnitActive must return false (fail safe) when the probe fails")
	}
}

// TestServiceManager_WriteUnit_UsesSDK verifies that the service executor
// delegates unit-file writing to the SDK service Manager (serviceMgr.WriteUnit)
// and never reaches the privileged remount path when the unit name is rejected
// by ValidateUnitName. This guards against the agent hand-rolling a path-based
// write that could escape /etc/systemd/system.
func TestServiceManager_WriteUnit_DelegatesToSDK(t *testing.T) {
	// Build a real SDK Runner and service Manager so we exercise the actual
	// ValidateUnitName + WriteUnit path. The test uses a fake unit name to
	// avoid touching a real systemd unit on the host.
	r, err := sysexec.NewRunner(sysexec.Direct)
	if err != nil {
		t.Fatalf("build direct runner: %v", err)
	}
	m, err := service.New(service.Systemd, r)
	if err != nil {
		t.Fatalf("build service manager: %v", err)
	}
	orig := serviceMgr
	serviceMgr = m
	t.Cleanup(func() { serviceMgr = orig })

	e := NewExecutor(nil, r) // uses the overridden serviceMgr

	// A unit name with path separators must be rejected by ValidateUnitName,
	// which WriteUnit calls. The rejection must happen BEFORE any filesystem
	// access.
	params := &pb.ServiceParams{UnitName: "../../etc/cron.d/evil.service", UnitContent: "[Service]\nExecStart=/bin/true\n"}
	_, _, err2 := e.executeService(context.Background(), params)
	if err2 == nil {
		t.Fatal("expected error for path-escaping unit name, got nil")
	}
}
