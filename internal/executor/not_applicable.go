package executor

import (
	"errors"
	"fmt"
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
