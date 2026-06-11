package executor

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// An operator who can drive a USER action must not be able to set an
// account's login shell to an arbitrary binary: usermod -s does not
// enforce /etc/shells, so /tmp/evil would otherwise become a persistence
// primitive. executeUser must reject an explicit, non-allowlisted shell
// before it reaches useradd/usermod argv. The rejection runs ahead of any
// filesystem/exec side effect, so a minimal Executor exercises it.
func TestExecuteUser_RejectsArbitraryLoginShell(t *testing.T) {
	e := &Executor{logger: slog.Default()}
	params := &pb.UserParams{
		Username: "alice",
		Shell:    "/tmp/evil", // clean absolute path, but not a system shell
	}
	_, _, _, err := e.executeUser(context.Background(), params, pb.DesiredState_DESIRED_STATE_PRESENT)
	if err == nil {
		t.Fatal("executeUser accepted login shell /tmp/evil; want rejection")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "shell") {
		t.Errorf("error = %v, want it to name the login shell", err)
	}
}

// A flag-shaped shell must also be refused (defense against argv injection
// even though it would land as the operand of -s).
func TestExecuteUser_RejectsFlagShapedLoginShell(t *testing.T) {
	e := &Executor{logger: slog.Default()}
	params := &pb.UserParams{
		Username: "bob",
		Shell:    "--login",
	}
	if _, _, _, err := e.executeUser(context.Background(), params, pb.DesiredState_DESIRED_STATE_PRESENT); err == nil {
		t.Fatal("executeUser accepted flag-shaped shell --login; want rejection")
	}
}

// A GECOS/comment containing ':' or a newline would corrupt the
// /etc/passwd record (extra fields / forged record). executeUser must
// reject it with a comment-specific error BEFORE it reaches useradd/usermod
// -c. We assert the error names the comment so a generic useradd failure
// (e.g. "not root") can't make this pass for the wrong reason.
func TestExecuteUser_RejectsCommentInjection(t *testing.T) {
	e := &Executor{logger: slog.Default()}
	for _, bad := range []string{"root:x:0:0:", "name\nroot:x:0:0"} {
		params := &pb.UserParams{Username: "carol", Comment: bad}
		_, _, _, err := e.executeUser(context.Background(), params, pb.DesiredState_DESIRED_STATE_PRESENT)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "comment") {
			t.Errorf("executeUser(comment=%q) err = %v; want a comment-validation error", bad, err)
		}
	}
}

// A malformed PrimaryGroup (flag-shaped or otherwise invalid) must be
// rejected with a group-specific error before reaching `-g`, not silently
// appended after a logged GroupEnsureExists failure.
func TestExecuteUser_RejectsInvalidPrimaryGroup(t *testing.T) {
	e := &Executor{logger: slog.Default()}
	params := &pb.UserParams{Username: "dave", PrimaryGroup: "-G"}
	_, _, _, err := e.executeUser(context.Background(), params, pb.DesiredState_DESIRED_STATE_PRESENT)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "group") {
		t.Fatalf("executeUser(PrimaryGroup=-G) err = %v; want a primary-group-validation error", err)
	}
}
