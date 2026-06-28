package executor

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/pkg"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// TestExecutePackage_RejectsNilParams verifies that a nil PackageParams is
// rejected before any package-manager work runs. The executor rejects at the
// field level, not by crashing on a nil dereference deeper in the call chain.
func TestExecutePackage_RejectsNilParams(t *testing.T) {
	e := NewExecutor(nil, nil)
	_, changed, err := e.executePackage(context.Background(), nil, pb.DesiredState_DESIRED_STATE_PRESENT)
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

// TestExecutePackage_FailsWhenNoPackageManager verifies that the PACKAGE
// executor fails closed when no package manager was detected (pkgManager is
// nil). A nil manager must surface as an error, not a silent no-op.
func TestExecutePackage_FailsWhenNoPackageManager(t *testing.T) {
	e := NewExecutor(nil, nil) // runner=nil → pkgManager stays nil
	params := &pb.PackageParams{Name: "curl"}
	_, changed, err := e.executePackage(context.Background(), params, pb.DesiredState_DESIRED_STATE_PRESENT)
	if err == nil {
		t.Fatal("expected error when no package manager is available, got nil")
	}
	if changed {
		t.Error("changed must be false when no package manager exists")
	}
}

// TestExecutePackage_RejectsUnknownDesiredState verifies that an unknown (zero
// or out-of-range) desired state is rejected rather than silently falling
// through to a default branch.
func TestExecutePackage_RejectsUnknownDesiredState(t *testing.T) {
	// Wire a fake package manager so we get past the nil-mgr check.
	r, err := sysexec.NewRunner(sysexec.Direct)
	if err != nil {
		t.Fatalf("build direct runner: %v", err)
	}
	mgr, err := pkg.New(pkg.Apt, r)
	if err != nil {
		t.Fatalf("build apt manager: %v", err)
	}
	e := &Executor{pkgManager: mgr, pkgBackend: pkg.Apt}
	params := &pb.PackageParams{Name: "curl"}
	_, changed, err := e.executePackage(context.Background(), params, pb.DesiredState(999))
	if err == nil {
		t.Fatal("expected error for unknown desired state, got nil")
	}
	if changed {
		t.Error("changed must be false for unknown state")
	}
}

// TestExecutePackage_ContextCancelledBeforeDispatch verifies that a cancelled
// context is detected BEFORE any privileged package-manager call. The
// pkgManagerForCtx helper returns nil when ctx is already done, and
// executePackage surfaces that as an error.
func TestExecutePackage_ContextCancelledBeforeDispatch(t *testing.T) {
	r, err := sysexec.NewRunner(sysexec.Direct)
	if err != nil {
		t.Fatalf("build direct runner: %v", err)
	}
	mgr, err := pkg.New(pkg.Apt, r)
	if err != nil {
		t.Fatalf("build apt manager: %v", err)
	}
	e := &Executor{pkgManager: mgr, pkgBackend: pkg.Apt}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	params := &pb.PackageParams{Name: "curl"}
	_, changed, err := e.executePackage(ctx, params, pb.DesiredState_DESIRED_STATE_PRESENT)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
	if changed {
		t.Error("changed must be false when context is cancelled")
	}
}

// TestExecutePackage_GetPackageNameForManager_FallbackToName verifies that
// getPackageNameForManager falls back to the generic Name field when no
// backend-specific name is set. Without this fix, an AptName="curl" action
// would no-op on a dnf host even though Name="curl" is the right answer.
func TestGetPackageNameForManager_FallbackToName(t *testing.T) {
	tests := []struct {
		name     string
		backend  pkg.Backend
		params   *pb.PackageParams
		expected string
	}{
		{
			name:     "apt with apt-specific name",
			backend:  pkg.Apt,
			params:   &pb.PackageParams{Name: "curl", AptName: "libcurl4"},
			expected: "libcurl4",
		},
		{
			name:     "apt without apt-specific name falls back to Name",
			backend:  pkg.Apt,
			params:   &pb.PackageParams{Name: "curl", DnfName: "libcurl"},
			expected: "curl",
		},
		{
			name:     "dnf with dnf-specific name",
			backend:  pkg.Dnf,
			params:   &pb.PackageParams{Name: "curl", DnfName: "libcurl"},
			expected: "libcurl",
		},
		{
			name:     "dnf without dnf-specific falls back to Name",
			backend:  pkg.Dnf,
			params:   &pb.PackageParams{Name: "curl", AptName: "libcurl4"},
			expected: "curl",
		},
		{
			name:     "pacman falls back to Name when no pacman-specific",
			backend:  pkg.Pacman,
			params:   &pb.PackageParams{Name: "curl", AptName: "libcurl4"},
			expected: "curl",
		},
		{
			name:     "zypper falls back to Name when no zypper-specific",
			backend:  pkg.Zypper,
			params:   &pb.PackageParams{Name: "curl", AptName: "libcurl4"},
			expected: "curl",
		},
		{
			name:     "flatpak returns Name (no flatpak-specific override)",
			backend:  pkg.Flatpak,
			params:   &pb.PackageParams{Name: "org.gimp.GIMP"},
			expected: "org.gimp.GIMP",
		},
		{
			name:     "empty name returns empty (caller handles skip)",
			backend:  pkg.Apt,
			params:   &pb.PackageParams{Name: ""},
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Executor{pkgBackend: tt.backend}
			got := e.getPackageNameForManager(tt.params)
			if got != tt.expected {
				t.Errorf("getPackageNameForManager() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestIsPackagePinned_NilManagerFailsClosed verifies that isPackagePinned
// returns an error (not false, nil) when mgr is nil — a nil manager must never
// be treated as "not pinned", which would cause pinPackage to proceed into a
// nil dereference.
func TestIsPackagePinned_NilManagerFailsClosed(t *testing.T) {
	e := &Executor{}
	_, err := e.isPackagePinned(context.Background(), nil, "curl")
	if err == nil {
		t.Fatal("expected error for nil manager, got nil")
	}
}

// TestPinPackage_NilManagerFailsClosed verifies that pinPackage returns an
// error when mgr is nil.
func TestPinPackage_NilManagerFailsClosed(t *testing.T) {
	e := &Executor{}
	_, err := e.pinPackage(context.Background(), nil, "curl")
	if err == nil {
		t.Fatal("expected error for nil manager, got nil")
	}
}

// TestUnpinPackage_NilManagerFailsClosed verifies that unpinPackage returns an
// error when mgr is nil.
func TestUnpinPackage_NilManagerFailsClosed(t *testing.T) {
	e := &Executor{}
	_, err := e.unpinPackage(context.Background(), nil, "curl")
	if err == nil {
		t.Fatal("expected error for nil manager, got nil")
	}
}

// TestPackageResult_CommandNeverRan verifies that packageResult returns a
// visible failure when the runner error is non-nil AND Result.ExitCode is 0
// (meaning the command never ran — the runner itself failed). Without the
// exit-code synthesis the caller sees a clean exit and misreports success.
func TestPackageResult_CommandNeverRan(t *testing.T) {
	result := sysexec.Result{ExitCode: 0, Stdout: "", Stderr: ""}
	runnerErr := errors.New("exec: fork/exec: no such file or directory")
	out, changed, err := packageResult(result, runnerErr)
	if err == nil {
		t.Fatal("expected error from packageResult when runner fails, got nil")
	}
	if changed {
		t.Error("changed must be false when the command never ran")
	}
	if out.ExitCode != 1 {
		t.Errorf("exit code should be synthesised to 1 (runner failure), got %d", out.ExitCode)
	}
	if out.Stderr == "" {
		t.Error("stderr should carry the runner error message when the command never ran")
	}
}

// TestPackageResult_NonZeroExitIsError verifies that a non-zero exit code
// with nil runner error still propagates the error through the Mgr->agent
// error chain.
func TestPackageResult_NonZeroExitIsError(t *testing.T) {
	result := sysexec.Result{ExitCode: 100, Stdout: "stdout", Stderr: "command not found"}
	out, changed, err := packageResult(result, errors.New("command failed"))
	if err == nil {
		t.Fatal("expected error for non-zero exit, got nil")
	}
	if changed {
		t.Error("changed must be false when the command fails")
	}
	if out.ExitCode != 100 {
		t.Errorf("exit code must be the command's real exit code 100, got %d", out.ExitCode)
	}
}

// TestPackageResult_Success verifies the happy path.
func TestPackageResult_Success(t *testing.T) {
	result := sysexec.Result{ExitCode: 0, Stdout: "installed ok\n", Stderr: ""}
	out, changed, err := packageResult(result, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !changed {
		t.Error("changed must be true on success")
	}
	if out.ExitCode != 0 {
		t.Errorf("exit code must be 0, got %d", out.ExitCode)
	}
}
