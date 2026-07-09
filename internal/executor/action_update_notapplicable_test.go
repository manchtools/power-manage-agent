package executor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/pkg"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// upgradeFakeMgr embeds pkg.Manager (every un-overridden method nil-panics)
// and overrides exactly the calls executeUpdate makes: Repair, Update,
// HasUpdates and UpgradeAll. upgraded records whether UpgradeAll actually
// "performed" an upgrade so the fail-closed assertions are behavioral, not
// inferred from the error string.
type upgradeFakeMgr struct {
	pkg.Manager
	backend    pkg.Backend
	hasUpdates bool
	upgradeErr error
	upgraded   bool
}

func (f *upgradeFakeMgr) Backend() pkg.Backend { return f.backend }
func (f *upgradeFakeMgr) Repair(_ context.Context) (sysexec.Result, error) {
	return sysexec.Result{}, nil
}
func (f *upgradeFakeMgr) Update(_ context.Context) (sysexec.Result, error) {
	return sysexec.Result{Stdout: "index refreshed"}, nil
}
func (f *upgradeFakeMgr) HasUpdates(_ context.Context, _ bool) (bool, error) {
	return f.hasUpdates, nil
}
func (f *upgradeFakeMgr) UpgradeAll(_ context.Context, _ pkg.UpgradeOptions) (sysexec.Result, error) {
	if f.upgradeErr != nil {
		return sysexec.Result{}, f.upgradeErr
	}
	f.upgraded = true
	return sysexec.Result{Stdout: "upgraded"}, nil
}

// updateTestExecutor builds an Executor with the fake manager injected and
// every host side effect stubbed: repairFS short-circuits the filesystem
// repair, the empty PATH keeps pkg.Detect (flatpak repair) from finding real
// binaries, and the nil runner makes rebootRequired report false.
func updateTestExecutor(t *testing.T, fake *upgradeFakeMgr) *Executor {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	return &Executor{
		logger:     slog.Default(),
		now:        time.Now,
		pkgBackend: fake.backend,
		pkgManager: fake,
		repairFS:   func(context.Context) bool { return true },
	}
}

// TestExecuteUpdate_SecurityOnlyUnsupported_NotApplicable pins spec 23 AC 2
// for the pacman class: security_only on a backend with no security-patch
// scoping stays fail-closed (nothing upgraded) but classifies as
// NOT_APPLICABLE with the reason, not FAILED.
func TestExecuteUpdate_SecurityOnlyUnsupported_NotApplicable(t *testing.T) {
	fake := &upgradeFakeMgr{backend: pkg.Pacman, upgradeErr: pkg.ErrSecurityOnlyUnsupported}
	e := updateTestExecutor(t, fake)

	_, changed, err := e.executeUpdate(context.Background(), &pb.UpdateParams{SecurityOnly: true})

	if !errors.Is(err, errNotApplicable) {
		t.Fatalf("expected errNotApplicable, got: %v", err)
	}
	if !strings.Contains(err.Error(), "security-only") {
		t.Errorf("reason must name the security-only limitation, got: %v", err)
	}
	if changed {
		t.Error("expected changed=false for a not-applicable security-only update")
	}
	if fake.upgraded {
		t.Error("fail-closed violated: UpgradeAll performed an upgrade despite security-only being unsupported")
	}
}

// TestExecuteUpdate_SecurityOnlyToolingMissing_NotApplicable pins the apt
// class: the backend could scope to security updates but the tooling
// (unattended-upgrades) is absent — the SDK fails closed with
// ErrBackendUnavailable and the agent classifies NOT_APPLICABLE. hasUpdates
// is true so this also proves the NA path forces changed=false rather than
// inheriting updatesAvailable.
func TestExecuteUpdate_SecurityOnlyToolingMissing_NotApplicable(t *testing.T) {
	fake := &upgradeFakeMgr{
		backend:    pkg.Apt,
		hasUpdates: true,
		upgradeErr: fmt.Errorf("apt security upgrade: %w", sysexec.ErrBackendUnavailable),
	}
	e := updateTestExecutor(t, fake)

	_, changed, err := e.executeUpdate(context.Background(), &pb.UpdateParams{SecurityOnly: true})

	if !errors.Is(err, errNotApplicable) {
		t.Fatalf("expected errNotApplicable, got: %v", err)
	}
	if changed {
		t.Error("expected changed=false: nothing was upgraded even though updates were available")
	}
}

// TestExecuteUpdate_SecurityOnlyFalse_BackendErrorStaysFailed proves the NA
// mapping is scoped to security-only requests: the same ErrBackendUnavailable
// during a NORMAL update is a real failure, not inapplicability.
func TestExecuteUpdate_SecurityOnlyFalse_BackendErrorStaysFailed(t *testing.T) {
	fake := &upgradeFakeMgr{
		backend:    pkg.Apt,
		upgradeErr: fmt.Errorf("apt-get vanished mid-flight: %w", sysexec.ErrBackendUnavailable),
	}
	e := updateTestExecutor(t, fake)

	_, _, err := e.executeUpdate(context.Background(), &pb.UpdateParams{SecurityOnly: false})

	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, errNotApplicable) {
		t.Fatalf("a backend failure on a normal update must stay FAILED, got not-applicable: %v", err)
	}
}

// TestExecuteUpdate_SecurityOnlySupported_Proceeds is the complementary
// positive path (spec 23 AC 7): a capable backend performs the security-only
// upgrade and nothing classifies as not-applicable.
func TestExecuteUpdate_SecurityOnlySupported_Proceeds(t *testing.T) {
	fake := &upgradeFakeMgr{backend: pkg.Dnf, hasUpdates: true}
	e := updateTestExecutor(t, fake)

	_, changed, err := e.executeUpdate(context.Background(), &pb.UpdateParams{SecurityOnly: true})

	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if !fake.upgraded {
		t.Error("expected UpgradeAll to run on a capable backend")
	}
	if !changed {
		t.Error("expected changed=true when updates were applied")
	}
}

// TestExecuteEnvelope_SecurityOnly_NotApplicableStatus pins the central
// classification (spec 23 AC 2 end to end in the agent): the sentinel from
// the update path surfaces as EXECUTION_STATUS_NOT_APPLICABLE on the
// ActionResult — not FAILED — with the reason in the result error and
// Changed=false.
func TestExecuteEnvelope_SecurityOnly_NotApplicableStatus(t *testing.T) {
	fake := &upgradeFakeMgr{backend: pkg.Pacman, upgradeErr: pkg.ErrSecurityOnlyUnsupported}
	e := updateTestExecutor(t, fake)

	env := &pb.SignedActionEnvelope{
		ActionId:   &pb.ActionId{Value: "01JZTESTNOTAPPLICABLE0000A"},
		ActionType: pb.ActionType_ACTION_TYPE_UPDATE,
		Params:     &pb.SignedActionEnvelope_Update{Update: &pb.UpdateParams{SecurityOnly: true}},
	}
	result := e.ExecuteWithStreaming(context.Background(), env, nil)

	if result.Status != pb.ExecutionStatus_EXECUTION_STATUS_NOT_APPLICABLE {
		t.Fatalf("expected NOT_APPLICABLE, got %s (error: %s)", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "security-only") {
		t.Errorf("result error must carry the reason, got: %q", result.Error)
	}
	if result.Changed {
		t.Error("expected Changed=false on a not-applicable result")
	}
}
