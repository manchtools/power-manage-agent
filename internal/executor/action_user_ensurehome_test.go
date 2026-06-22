package executor

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysfs "github.com/manchtools/power-manage-sdk/sys/fs"
	sysuser "github.com/manchtools/power-manage-sdk/sys/user"
)

// fakeExistsFS is a minimal fs.Manager that answers a single Exists probe with a
// fixed result and records the path it was asked about. Every other method
// panics on the nil embedded interface, keeping the fake honest about exactly
// what ensureHomeIfMissing touches.
type fakeExistsFS struct {
	sysfs.Manager
	ok          bool
	err         error
	calledPaths []string
}

func (f *fakeExistsFS) Exists(_ context.Context, path string) (bool, error) {
	f.calledPaths = append(f.calledPaths, path)
	return f.ok, f.err
}

// fakeEnsureHomeUser is a minimal user.Manager that records EnsureHome calls.
type fakeEnsureHomeUser struct {
	sysuser.Manager
	calls []ensureHomeCall
	err   error
}

type ensureHomeCall struct {
	name string
	opts sysuser.EnsureHomeOptions
}

func (u *fakeEnsureHomeUser) EnsureHome(_ context.Context, name string, opts sysuser.EnsureHomeOptions) error {
	u.calls = append(u.calls, ensureHomeCall{name: name, opts: opts})
	return u.err
}

func swapHomeMgrs(t *testing.T, fs *fakeExistsFS, usr *fakeEnsureHomeUser) {
	t.Helper()
	prevFS, prevUser := fsMgr, userMgr
	t.Cleanup(func() { fsMgr = prevFS; userMgr = prevUser })
	fsMgr = fs
	userMgr = usr
}

// TestEnsureHomeIfMissing_ProbeErrorFailsClosed is the core fail-closed
// assertion: when fsMgr.Exists cannot determine whether the home exists (an
// I/O / permission error, NOT a clean "no such file"), the state is
// indeterminate. ensureHomeIfMissing must surface a warning and skip
// EnsureHome — NOT treat the error as "missing" and create the home. Swallowing
// the probe error (the prior `ok, _ := fsMgr.Exists(...)` form) would invert an
// unknown into a confident "create it", running EnsureHome on every reconcile
// cycle and reporting changed=true forever.
func TestEnsureHomeIfMissing_ProbeErrorFailsClosed(t *testing.T) {
	fs := &fakeExistsFS{err: errors.New("permission denied")}
	usr := &fakeEnsureHomeUser{}
	swapHomeMgrs(t, fs, usr)

	var out strings.Builder
	e := &Executor{}
	changed := e.ensureHomeIfMissing(context.Background(),
		&pb.UserParams{Username: "alice", CreateHome: true}, "", &out)

	if changed {
		t.Error("changed=true on an indeterminate probe; must report no change")
	}
	if len(usr.calls) != 0 {
		t.Fatalf("EnsureHome called %d time(s) on a probe error; must fail closed and skip", len(usr.calls))
	}
	if !strings.Contains(out.String(), "could not check home directory") {
		t.Errorf("probe error not surfaced; output = %q", out.String())
	}
}

// TestEnsureHomeIfMissing_MissingCreatesWithOwnershipAndMode pins the repair
// path: a confirmed-absent home is created via the idempotent EnsureHome with
// the resolved group and a 0700 mode, and the call reports changed=true.
func TestEnsureHomeIfMissing_MissingCreatesWithOwnershipAndMode(t *testing.T) {
	fs := &fakeExistsFS{ok: false}
	usr := &fakeEnsureHomeUser{}
	swapHomeMgrs(t, fs, usr)

	var out strings.Builder
	e := &Executor{}
	changed := e.ensureHomeIfMissing(context.Background(),
		&pb.UserParams{Username: "alice", PrimaryGroup: "staff", CreateHome: true}, "", &out)

	if !changed {
		t.Error("changed=false though a missing home was created")
	}
	if len(usr.calls) != 1 {
		t.Fatalf("expected exactly 1 EnsureHome call, got %d", len(usr.calls))
	}
	c := usr.calls[0]
	if c.name != "alice" {
		t.Errorf("EnsureHome name = %q, want alice", c.name)
	}
	if c.opts.Group != "staff" {
		t.Errorf("EnsureHome group = %q, want staff (homeGroupFor)", c.opts.Group)
	}
	if c.opts.Mode != 0o700 {
		t.Errorf("EnsureHome mode = %o, want 0700", c.opts.Mode)
	}
	if !strings.Contains(out.String(), "created missing home directory") {
		t.Errorf("creation not surfaced; output = %q", out.String())
	}
}

// TestEnsureHomeIfMissing_PresentIsIdempotent: a home that already exists must
// not trigger EnsureHome and must report no change (re-applied action stays
// idempotent).
func TestEnsureHomeIfMissing_PresentIsIdempotent(t *testing.T) {
	fs := &fakeExistsFS{ok: true}
	usr := &fakeEnsureHomeUser{}
	swapHomeMgrs(t, fs, usr)

	var out strings.Builder
	e := &Executor{}
	changed := e.ensureHomeIfMissing(context.Background(),
		&pb.UserParams{Username: "alice", CreateHome: true}, "", &out)

	if changed {
		t.Error("changed=true though the home already existed")
	}
	if len(usr.calls) != 0 {
		t.Errorf("EnsureHome called %d time(s) on a present home", len(usr.calls))
	}
}

// TestEnsureHomeIfMissing_NoCreateHomeSkipsProbe: when create_home is false the
// agent honours the proto and does not even probe — no home management at all.
func TestEnsureHomeIfMissing_NoCreateHomeSkipsProbe(t *testing.T) {
	fs := &fakeExistsFS{ok: false}
	usr := &fakeEnsureHomeUser{}
	swapHomeMgrs(t, fs, usr)

	var out strings.Builder
	e := &Executor{}
	changed := e.ensureHomeIfMissing(context.Background(),
		&pb.UserParams{Username: "alice", CreateHome: false}, "", &out)

	if changed {
		t.Error("changed=true with create_home=false")
	}
	if len(fs.calledPaths) != 0 {
		t.Errorf("probed Exists %d time(s) with create_home=false; must skip entirely", len(fs.calledPaths))
	}
	if len(usr.calls) != 0 {
		t.Errorf("EnsureHome called with create_home=false")
	}
}

// TestEnsureHomeIfMissing_HomeDirResolution pins the home-path precedence:
// explicit params.HomeDir wins; else the passwd entry (currentHome); else the
// /home/<user> default.
func TestEnsureHomeIfMissing_HomeDirResolution(t *testing.T) {
	cases := []struct {
		name        string
		homeDir     string
		currentHome string
		want        string
	}{
		{"explicit", "/srv/alice", "/home/alice", "/srv/alice"},
		{"passwd-fallback", "", "/var/home/alice", "/var/home/alice"},
		{"default", "", "", "/home/alice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := &fakeExistsFS{ok: true} // present -> just exercise the path resolution + probe
			usr := &fakeEnsureHomeUser{}
			swapHomeMgrs(t, fs, usr)

			var out strings.Builder
			e := &Executor{}
			e.ensureHomeIfMissing(context.Background(),
				&pb.UserParams{Username: "alice", HomeDir: tc.homeDir, CreateHome: true}, tc.currentHome, &out)

			if len(fs.calledPaths) != 1 || fs.calledPaths[0] != tc.want {
				t.Errorf("probed %v, want exactly [%s]", fs.calledPaths, tc.want)
			}
		})
	}
}
