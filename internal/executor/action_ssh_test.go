package executor

import (
	"context"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// TestExecuteSsh_RejectsNilParams verifies nil SSH params are rejected.
func TestExecuteSsh_RejectsNilParams(t *testing.T) {
	e := NewExecutor(nil, nil)
	_, changed, err := e.executeSsh(context.Background(), nil, pb.DesiredState_DESIRED_STATE_PRESENT, "test1234")
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

// TestExecuteSsh_RejectsEmptyUsers verifies that an empty user list is rejected.
func TestExecuteSsh_RejectsEmptyUsers(t *testing.T) {
	e := NewExecutor(nil, nil)
	params := &pb.SshParams{}
	_, changed, err := e.executeSsh(context.Background(), params, pb.DesiredState_DESIRED_STATE_PRESENT, "test1234")
	if err == nil {
		t.Fatal("expected error for empty users, got nil")
	}
	if changed {
		t.Error("changed must be false when users are empty")
	}
}

// TestExecuteSsh_RejectsInvalidUsername verifies that non-alphanumeric or empty
// usernames are rejected by sysuser.IsValidName BEFORE any group creation.
func TestExecuteSsh_RejectsInvalidUsername(t *testing.T) {
	e := NewExecutor(nil, nil)
	invalidUsers := []string{
		"",
		"user name with spaces",
		"-startswithdash",
		"../../../etc/passwd",
	}
	for _, user := range invalidUsers {
		t.Run("rejects "+user, func(t *testing.T) {
			params := &pb.SshParams{Users: []string{user}}
			_, _, err := e.executeSsh(context.Background(), params, pb.DesiredState_DESIRED_STATE_PRESENT, "test1234")
			if err == nil {
				t.Fatalf("expected error for invalid username %q, got nil", user)
			}
		})
	}
}

// TestExecuteSsh_RejectsEmptyActionID verifies that an empty action ID is
// rejected by validateActionIDForFilesystem. The action ID is used to derive
// the group name and config path — an empty one would produce an empty group
// name, which is invalid.
func TestExecuteSsh_RejectsEmptyActionID(t *testing.T) {
	e := NewExecutor(nil, nil)
	params := &pb.SshParams{Users: []string{"alice"}}
	_, changed, err := e.executeSsh(context.Background(), params, pb.DesiredState_DESIRED_STATE_PRESENT, "")
	if err == nil {
		t.Fatal("expected error for empty action ID, got nil")
	}
	if changed {
		t.Error("changed must be false when action ID is empty")
	}
}

// TestExecuteSsh_RejectsTooLongActionID verifies that action IDs exceeding
// maxActionIDForFilesystem are rejected.
func TestExecuteSsh_RejectsTooLongActionID(t *testing.T) {
	e := NewExecutor(nil, nil)
	params := &pb.SshParams{Users: []string{"alice"}}
	longID := strings.Repeat("a", maxActionIDForFilesystem+1)
	_, changed, err := e.executeSsh(context.Background(), params, pb.DesiredState_DESIRED_STATE_PRESENT, longID)
	if err == nil {
		t.Fatal("expected error for too-long action ID, got nil")
	}
	if changed {
		t.Error("changed must be false when action ID is too long")
	}
}

// TestExecuteSsh_RejectsUnsafeCharsInActionID verifies that action IDs with
// non-alphanumeric characters are rejected — these could produce path-
// meaningful group names or config file names.
func TestExecuteSsh_RejectsUnsafeCharsInActionID(t *testing.T) {
	e := NewExecutor(nil, nil)
	params := &pb.SshParams{Users: []string{"alice"}}
	unsafeIDs := []string{
		"../../etc",
		"test/1234",
		"test 1234",
		"test\x00null",
	}
	for _, id := range unsafeIDs {
		t.Run("rejects "+id, func(t *testing.T) {
			_, _, err := e.executeSsh(context.Background(), params, pb.DesiredState_DESIRED_STATE_PRESENT, id)
			if err == nil {
				t.Fatalf("expected error for unsafe action ID %q, got nil", id)
			}
		})
	}
}

// TestShortGroupName_FitsIn32Chars verifies that shortGroupName produces names
// that fit within the Linux 32-character group-name limit. Names that don't
// fit are truncated with a hash suffix, never silently truncated in a
// collision-prone way.
func TestShortGroupName_FitsIn32Chars(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		actionID string
	}{
		{"short id fits", "pm-ssh-", "01J123456789"},
		{"exact fit", "pm-ssh-", strings.Repeat("a", 25)}, // 7+25=32
		{"overflow with hash", "pm-ssh-", strings.Repeat("a", 50)},
		{"long prefix with long id", "pm-sudo-verylongprefix-", "01J1234567890123456789"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shortGroupName(tt.prefix, tt.actionID)
			if len(got) > 32 {
				t.Errorf("shortGroupName(%q, ...) = %q (len=%d), must be ≤ 32 chars",
					tt.prefix, got, len(got))
			}
		})
	}
}

// TestShortGroupName_Deterministic verifies that the same actionID+prefix
// always produces the same group name (no random component).
func TestShortGroupName_Deterministic(t *testing.T) {
	prefix := "pm-ssh-"
	id := "01J1234567890123456789"
	first := shortGroupName(prefix, id)
	for i := 0; i < 100; i++ {
		if got := shortGroupName(prefix, id); got != first {
			t.Fatalf("shortGroupName is non-deterministic: first=%q, iteration %d=%q", first, i, got)
		}
	}
}

// TestShortGroupName_DifferentIDsProduceDifferentNames verifies that two
// distinct action IDs produce distinct group names (no collision).
func TestShortGroupName_DifferentIDsProduceDifferentNames(t *testing.T) {
	prefix := "pm-ssh-"
	// Two IDs sharing a long common prefix — truncation hazard.
	id1 := "01JARXABCDEFGHIJKLMNOP1234"
	id2 := "01JARXABCDEFGHIJKLMNOP5678"
	n1 := shortGroupName(prefix, id1)
	n2 := shortGroupName(prefix, id2)
	if n1 == n2 {
		t.Errorf("shortGroupName collision: %q and %q both map to %q", id1, id2, n1)
	}
}

// TestGenerateSshGroupConfig_ContainsMatchGroup verifies that the generated
// sshd_config content contains the expected Match Group directive.
func TestGenerateSshGroupConfig_ContainsMatchGroup(t *testing.T) {
	got := generateSshGroupConfig("pm-ssh-test1234", &pb.SshParams{
		AllowPubkey:   true,
		AllowPassword: false,
	})
	if !strings.Contains(got, "Match Group pm-ssh-test1234") {
		t.Errorf("generated config missing Match Group directive:\n%s", got)
	}
	if !strings.Contains(got, "PubkeyAuthentication yes") {
		t.Errorf("generated config missing PubkeyAuthentication yes:\n%s", got)
	}
	if !strings.Contains(got, "PasswordAuthentication no") {
		t.Errorf("generated config missing PasswordAuthentication no:\n%s", got)
	}
	if strings.Contains(got, "PasswordAuthentication yes") {
		t.Errorf("generated config should NOT contain PasswordAuthentication yes:\n%s", got)
	}
}

// TestGenerateSshGroupConfig_BothAllowed verifies that when both pubkey and
// password are allowed, both directives appear as "yes".
func TestGenerateSshGroupConfig_BothAllowed(t *testing.T) {
	got := generateSshGroupConfig("pm-ssh-test1234", &pb.SshParams{
		AllowPubkey:   true,
		AllowPassword: true,
	})
	if !strings.Contains(got, "PubkeyAuthentication yes") {
		t.Errorf("missing PubkeyAuthentication yes")
	}
	if !strings.Contains(got, "PasswordAuthentication yes") {
		t.Errorf("missing PasswordAuthentication yes")
	}
}

// TestValidateActionIDForFilesystem_RejectsEmpty verifies empty action ID
// rejection.
func TestValidateActionIDForFilesystem_RejectsEmpty(t *testing.T) {
	err := validateActionIDForFilesystem("")
	if err == nil {
		t.Fatal("expected error for empty action ID")
	}
}

// TestValidateActionIDForFilesystem_RejectsUnsafeChars verifies rejection
// of path-meaningful characters.
func TestValidateActionIDForFilesystem_RejectsUnsafeChars(t *testing.T) {
	unsafe := []string{
		"a/b",
		"a..b",
		"a b",
		"a\tb",
		"../../passwd",
	}
	for _, id := range unsafe {
		t.Run("rejects "+id, func(t *testing.T) {
			err := validateActionIDForFilesystem(id)
			if err == nil {
				t.Errorf("expected error for unsafe action ID %q", id)
			}
		})
	}
}
