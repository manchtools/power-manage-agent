package unit

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/service"
)

// fakeManager implements service.Manager hermetically: scripted version /
// read results, recorded writes and reloads. Only the methods the unit
// package touches carry behavior; the rest are wired to fail the test if
// ever called (the reconciler must never restart/enable/stop anything).
type fakeManager struct {
	t *testing.T

	version    int
	versionErr error

	readContent string
	readErr     error

	writeUnit    string
	writeContent string
	writeErr     error
	writeCalls   int

	reloads   int
	reloadErr error
}

func (f *fakeManager) Version(context.Context) (int, error) { return f.version, f.versionErr }
func (f *fakeManager) ReadUnit(_ context.Context, unit string) (string, error) {
	if f.readErr != nil {
		return "", f.readErr
	}
	return f.readContent, nil
}
func (f *fakeManager) WriteUnit(_ context.Context, unit, content string) error {
	f.writeCalls++
	f.writeUnit, f.writeContent = unit, content
	return f.writeErr
}
func (f *fakeManager) DaemonReload(context.Context) error {
	f.reloads++
	return f.reloadErr
}

func (f *fakeManager) fail(method string) {
	f.t.Helper()
	f.t.Fatalf("service.Manager.%s must never be called by the unit package", method)
}
func (f *fakeManager) Status(context.Context, string) (service.UnitStatus, error) {
	f.fail("Status")
	return service.UnitStatus{}, nil
}
func (f *fakeManager) IsEnabled(context.Context, string) (bool, error) {
	f.fail("IsEnabled")
	return false, nil
}
func (f *fakeManager) IsActive(context.Context, string) (bool, error) {
	f.fail("IsActive")
	return false, nil
}
func (f *fakeManager) IsMasked(context.Context, string) (bool, error) {
	f.fail("IsMasked")
	return false, nil
}
func (f *fakeManager) Enable(context.Context, string) error     { f.fail("Enable"); return nil }
func (f *fakeManager) Disable(context.Context, string) error    { f.fail("Disable"); return nil }
func (f *fakeManager) EnableNow(context.Context, string) error  { f.fail("EnableNow"); return nil }
func (f *fakeManager) DisableNow(context.Context, string) error { f.fail("DisableNow"); return nil }
func (f *fakeManager) Start(context.Context, string) error      { f.fail("Start"); return nil }
func (f *fakeManager) Stop(context.Context, string) error       { f.fail("Stop"); return nil }
func (f *fakeManager) Restart(context.Context, string) error    { f.fail("Restart"); return nil }
func (f *fakeManager) Reload(context.Context, string) error     { f.fail("Reload"); return nil }
func (f *fakeManager) Mask(context.Context, string) error       { f.fail("Mask"); return nil }
func (f *fakeManager) Unmask(context.Context, string) error     { f.fail("Unmask"); return nil }
func (f *fakeManager) RemoveUnit(context.Context, string) error { f.fail("RemoveUnit"); return nil }

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const testBin = "/usr/local/bin/power-manage-agent"
const testData = "/var/lib/power-manage"

// TestRender_RestrictRealtimeByVersion pins AC 2: ≥257 → true, <257 →
// false; the unparseable/unknown case is exercised on the sync paths
// below (Version error → false + WARN), because Render itself takes the
// already-decided boolean.
func TestRender_RestrictRealtimeByVersion(t *testing.T) {
	on, err := Render(Params{BinaryPath: testBin, DataDir: testData, RestrictRealtime: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(on, "RestrictRealtime=true") {
		t.Error("RestrictRealtime=true missing from rendered unit")
	}
	off, err := Render(Params{BinaryPath: testBin, DataDir: testData, RestrictRealtime: false})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(off, "RestrictRealtime=false") {
		t.Error("RestrictRealtime=false missing from rendered unit")
	}
}

// TestRender_CarriesInstallShape pins the load-bearing lines the
// install.sh heredoc used to carry — the capability set that #187
// showed must track the binary, the paths, and the restart policy the
// self-update respawn relies on.
func TestRender_CarriesInstallShape(t *testing.T) {
	out, err := Render(Params{BinaryPath: testBin, DataDir: testData, RestrictRealtime: false})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ExecStart=" + testBin + " -data-dir=" + testData + " -log-level=info",
		"Environment=\"POWER_MANAGE_DATA_DIR=" + testData + "\"",
		"CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_AUDIT_WRITE CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SYS_ADMIN CAP_KILL CAP_SETFCAP CAP_NET_RAW",
		"AmbientCapabilities=CAP_SETUID CAP_SETGID",
		"Restart=always",
		"RuntimeDirectory=pm-agent",
		"SyslogIdentifier=power-manage-agent",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered unit missing %q", want)
		}
	}
	if strings.Contains(out, "{{") {
		t.Error("rendered unit contains an unexpanded template action")
	}
}

// TestReconcile_DriftRewritesAndReloads is the core of AC 3.
func TestReconcile_DriftRewritesAndReloads(t *testing.T) {
	m := &fakeManager{t: t, version: 257, readContent: "stale unit\n"}
	drifted, err := Reconcile(context.Background(), m, testLogger(), Params{BinaryPath: testBin, DataDir: testData})
	if err != nil {
		t.Fatal(err)
	}
	if !drifted {
		t.Error("Reconcile must report drift")
	}
	if m.writeCalls != 1 || m.writeUnit != UnitName {
		t.Errorf("expected exactly one WriteUnit(%s), got %d (%s)", UnitName, m.writeCalls, m.writeUnit)
	}
	if !strings.Contains(m.writeContent, "RestrictRealtime=true") {
		t.Error("version 257 must render RestrictRealtime=true")
	}
	if m.reloads != 1 {
		t.Errorf("expected exactly one DaemonReload, got %d", m.reloads)
	}
}

// TestReconcile_IdenticalIsNoop pins AC 3's second half: identical
// bytes → no write, no reload. Identity is produced by rendering with
// the same inputs the fake will serve back.
func TestReconcile_IdenticalIsNoop(t *testing.T) {
	rendered, err := Render(Params{BinaryPath: testBin, DataDir: testData, RestrictRealtime: false})
	if err != nil {
		t.Fatal(err)
	}
	m := &fakeManager{t: t, version: 252, readContent: rendered}
	drifted, err := Reconcile(context.Background(), m, testLogger(), Params{BinaryPath: testBin, DataDir: testData})
	if err != nil {
		t.Fatal(err)
	}
	if drifted {
		t.Error("identical unit must not report drift")
	}
	if m.writeCalls != 0 || m.reloads != 0 {
		t.Errorf("identical unit must be a no-op, got %d writes / %d reloads", m.writeCalls, m.reloads)
	}
}

// TestReconcile_AbsentUnitSkips pins AC 7's unit-file guard: no unit on
// disk (container/dev run) → the startup reconcile does nothing.
func TestReconcile_AbsentUnitSkips(t *testing.T) {
	m := &fakeManager{t: t, version: 257, readErr: fs.ErrNotExist}
	drifted, err := Reconcile(context.Background(), m, testLogger(), Params{BinaryPath: testBin, DataDir: testData})
	if err != nil {
		t.Fatal(err)
	}
	if drifted || m.writeCalls != 0 || m.reloads != 0 {
		t.Error("absent unit must be a complete no-op for the startup reconcile")
	}
}

// TestReconcile_VersionProbeFailureFailsSafe: probe error → render with
// RestrictRealtime=false (the install.sh precaution, AC 2) rather than
// aborting the reconcile.
func TestReconcile_VersionProbeFailureFailsSafe(t *testing.T) {
	m := &fakeManager{t: t, versionErr: errors.New("no systemctl"), readContent: "stale\n"}
	drifted, err := Reconcile(context.Background(), m, testLogger(), Params{BinaryPath: testBin, DataDir: testData})
	if err != nil {
		t.Fatal(err)
	}
	if !drifted {
		t.Error("expected drift rewrite despite probe failure")
	}
	if !strings.Contains(m.writeContent, "RestrictRealtime=false") {
		t.Error("probe failure must fail safe to RestrictRealtime=false")
	}
}

// TestReconcile_WriteFailureSurfaces: the caller (daemon startup) is
// fail-open, so Reconcile must RETURN the error, not swallow it.
func TestReconcile_WriteFailureSurfaces(t *testing.T) {
	m := &fakeManager{t: t, version: 257, readContent: "stale\n", writeErr: errors.New("read-only /etc")}
	if _, err := Reconcile(context.Background(), m, testLogger(), Params{BinaryPath: testBin, DataDir: testData}); err == nil {
		t.Fatal("write failure must surface")
	}
}

// TestEnsureInstalled_WritesWhenAbsent covers the install-unit path
// (AC 1): absent unit → written + reloaded.
func TestEnsureInstalled_WritesWhenAbsent(t *testing.T) {
	m := &fakeManager{t: t, version: 257, readErr: fs.ErrNotExist}
	if err := EnsureInstalled(context.Background(), m, testLogger(), Params{BinaryPath: testBin, DataDir: testData}); err != nil {
		t.Fatal(err)
	}
	if m.writeCalls != 1 || m.reloads != 1 {
		t.Errorf("absent unit must be installed: %d writes / %d reloads", m.writeCalls, m.reloads)
	}
}

// TestEnsureInstalled_IdenticalIsNoop: re-running install-unit (e.g.
// updater hook after install.sh) must not churn the file or reload.
func TestEnsureInstalled_IdenticalIsNoop(t *testing.T) {
	rendered, err := Render(Params{BinaryPath: testBin, DataDir: testData, RestrictRealtime: true})
	if err != nil {
		t.Fatal(err)
	}
	m := &fakeManager{t: t, version: 257, readContent: rendered}
	if err := EnsureInstalled(context.Background(), m, testLogger(), Params{BinaryPath: testBin, DataDir: testData}); err != nil {
		t.Fatal(err)
	}
	if m.writeCalls != 0 || m.reloads != 0 {
		t.Errorf("identical unit must be a no-op: %d writes / %d reloads", m.writeCalls, m.reloads)
	}
}

// TestRenderedUnitPassesSDKContentGate: the agent's own template must
// pass the same content gate operator SERVICE units do — WriteUnit
// enforces it, so a template regression would brick the reconcile.
// Drives the REAL exported gate for both RestrictRealtime renders.
func TestRenderedUnitPassesSDKContentGate(t *testing.T) {
	for _, rr := range []bool{true, false} {
		out, err := Render(Params{BinaryPath: testBin, DataDir: testData, RestrictRealtime: rr})
		if err != nil {
			t.Fatal(err)
		}
		if err := service.ValidateUnitContent(out); err != nil {
			t.Errorf("rendered unit (RestrictRealtime=%v) rejected by the SDK content gate: %v", rr, err)
		}
	}
}
