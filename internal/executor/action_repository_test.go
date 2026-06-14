package executor

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// TestRpmImportGpgArgv_AfterEndOfOptions pins that a dnf/zypper GPG key
// import builds `rpm --import -- <ref>` so a flag-shaped ref can never be
// reparsed as an option to `rpm --import`.
func TestRpmImportGpgArgv_AfterEndOfOptions(t *testing.T) {
	if got, want := rpmImportArgs("https://m/key.asc"), []string{"--import", "--", "https://m/key.asc"}; !slices.Equal(got, want) {
		t.Errorf("rpmImportArgs = %v, want %v", got, want)
	}
	a := rpmImportArgs("--import=/etc/shadow")
	if n := len(a); n < 2 || a[n-1] != "--import=/etc/shadow" || a[n-2] != "--" {
		t.Errorf("flag-shaped ref must be the final operand preceded by --; args=%v", a)
	}
}

// TestExecuteRepository_RejectsBeforePrivilegedRemount pins finding 5:
// a malformed repository action (bad name, oversized name, non-https
// base URL) is rejected BEFORE any privileged filesystem
// remount/repair. The repairFS seam records zero invocations.
func TestExecuteRepository_RejectsBeforePrivilegedRemount(t *testing.T) {
	var remountCalls int
	e := &Executor{logger: slog.Default(), now: time.Now, repairFS: func(context.Context) bool {
		remountCalls++
		return true
	}}
	bad := []*pb.RepositoryParams{
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "http://evil", Gpgcheck: true}}, // non-https base URL
		{Name: "../etc"},                 // path-traversing name
		{Name: strings.Repeat("a", 200)}, // oversized name
	}
	for i, p := range bad {
		out, changed, err := e.executeRepository(context.Background(), p, pb.DesiredState_DESIRED_STATE_PRESENT)
		if err == nil {
			t.Errorf("case %d: malformed repo action accepted: out=%v changed=%v", i, out, changed)
		}
	}
	if remountCalls != 0 {
		t.Errorf("privileged remount ran %d times for rejected actions; want 0", remountCalls)
	}
}
