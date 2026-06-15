package executor

import (
	"context"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// executeWifi splices the action ID into a filesystem path
// (network.CertBaseDir/<id> for EAP-TLS certificates) and into the
// pm-wifi-<id> NetworkManager connection name. Like the sudo/ssh/sshd
// executors it must run the action ID through validateActionIDForFilesystem
// BEFORE building any path, not merely reject the empty string.
//
// The "wrong" inputs are sourced from intent (path-meaningful characters and
// the 64-char ceiling), NOT from the validator's regex. Each must be refused
// before any NetworkManager call — the function returns at the validation
// check, before conName/certDir are computed, so no connection is created and
// no cert directory is written.
func TestExecuteWifi_RejectsUnsafeActionID(t *testing.T) {
	e := NewExecutor(nil)
	ctx := context.Background()
	// Non-nil params so the nil-params guard isn't what trips; the action-ID
	// gate must reject before params are ever read.
	params := &pb.WifiParams{Ssid: "corp-net"}

	unsafe := []struct {
		name string
		id   string
	}{
		{"parent traversal", "../../etc"},
		{"embedded slash", "a/b"},
		{"shell separator", "a;b"},
		{"over 64 chars", strings.Repeat("a", 65)},
		{"empty", ""},
	}
	for _, tc := range unsafe {
		t.Run(tc.name, func(t *testing.T) {
			out, changed, err := e.executeWifi(ctx, params, pb.DesiredState_DESIRED_STATE_PRESENT, tc.id)
			if err == nil {
				t.Fatalf("executeWifi(id=%q) = nil error, want rejection", tc.id)
			}
			if !strings.Contains(err.Error(), "action ID") {
				t.Errorf("error = %q, want a validateActionIDForFilesystem message naming the action ID", err)
			}
			if changed {
				t.Error("changed must be false on a rejected action ID")
			}
			if out != nil {
				t.Errorf("output must be nil on rejection, got %v", out)
			}
		})
	}

	// correct: a valid alphanumeric ULID passes the same gate executeWifi
	// consults, so legitimate WiFi actions are not broken by the new check.
	if err := validateActionIDForFilesystem("01ARZ3NDEKTSV4RRFFQ69G5FAV"); err != nil {
		t.Errorf("valid ULID action ID rejected by the gate: %v", err)
	}
}
