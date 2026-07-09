package executor

import (
	"errors"
	"fmt"

	"github.com/manchtools/power-manage-sdk/pkg"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// errNotApplicable marks an action as structurally inapplicable to this
// device (spec 23): the device+action pair can never work as configured —
// a missing package-manager backend, a security-only upgrade on a manager
// with no security-patch scoping. ExecuteWithStreaming classifies it as
// EXECUTION_STATUS_NOT_APPLICABLE (terminal, non-error) with the wrapped
// reason as the result error. Transient conditions that re-run on the next
// reconciliation (e.g. no signed-in desktop users) are NOT this — they stay
// ordinary skip-successes.
var errNotApplicable = errors.New("not applicable to this device")

// notApplicable builds the errNotApplicable-wrapped reason an executor
// returns from a structural-inapplicability path.
func notApplicable(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errNotApplicable, fmt.Sprintf(format, args...))
}

// securityOnlyNotApplicable decides whether an update run's outcome is
// structural inapplicability (spec 23 AC 2): the request was security-only,
// the upgrade failed with one of the two capability sentinels
// (ErrSecurityOnlyUnsupported: pacman/flatpak can't scope;
// ErrBackendUnavailable: apt's unattended-upgrade tooling absent), and
// nothing ELSE went wrong afterwards — lastErr must still be exactly the
// upgrade error. A reboot-scheduling failure joined onto lastErr means the
// run had a real failure the operator asked to see, so it stays FAILED
// (CodeRabbit catch on the spec 23 change).
func securityOnlyNotApplicable(securityOnly bool, upgradeErr, lastErr error) bool {
	return securityOnly && upgradeErr != nil && lastErr == upgradeErr &&
		(errors.Is(upgradeErr, pkg.ErrSecurityOnlyUnsupported) ||
			errors.Is(upgradeErr, sysexec.ErrBackendUnavailable))
}
