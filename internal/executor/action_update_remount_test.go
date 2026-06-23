package executor

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	sysfs "github.com/manchtools/power-manage-sdk/sys/fs"
)

// fakeRemountFS is a minimal fs.Manager that serves a fixed mount table and
// records RemountRW targets. It embeds the interface so any OTHER method (none
// are called by repairFilesystem) panics on the nil embedded value — keeping the
// fake honest about exactly what the code under test uses, and decoupling the
// test from the SDK's findmnt/mount argv.
type fakeRemountFS struct {
	sysfs.Manager
	mounts     []sysfs.MountInfo
	remounted  []string
	remountErr error
}

func (f *fakeRemountFS) ListMounts(ctx context.Context) ([]sysfs.MountInfo, error) {
	return f.mounts, nil
}

func (f *fakeRemountFS) RemountRW(ctx context.Context, target string) error {
	f.remounted = append(f.remounted, target)
	return f.remountErr
}

// TestRepairFilesystem_RemountsOnlyReadOnlyBlockDevices pins the agent's remount
// policy: a read-only REAL block-device mount (/dev/*) is remounted rw, while a
// read-only VIRTUAL mount (proc/sysfs/tmpfs) is left alone — those are
// legitimately ro and remounting them is wrong — and a writable block device is
// untouched.
func TestRepairFilesystem_RemountsOnlyReadOnlyBlockDevices(t *testing.T) {
	prev := fsMgr
	t.Cleanup(func() { fsMgr = prev })
	fake := &fakeRemountFS{mounts: []sysfs.MountInfo{
		{Source: "/dev/sda1", Target: "/", FSType: "ext4", ReadOnly: true},      // remount
		{Source: "/dev/sda2", Target: "/usr", FSType: "ext4", ReadOnly: true},   // remount
		{Source: "/dev/sda3", Target: "/home", FSType: "ext4", ReadOnly: false}, // writable -> skip
		{Source: "proc", Target: "/proc", FSType: "proc", ReadOnly: true},       // virtual ro -> skip
		{Source: "sysfs", Target: "/sys", FSType: "sysfs", ReadOnly: true},      // virtual ro -> skip
		{Source: "tmpfs", Target: "/run", FSType: "tmpfs", ReadOnly: true},      // virtual ro -> skip
	}}
	fsMgr = fake

	e := &Executor{logger: slog.Default()}
	if ok := e.repairFilesystem(context.Background()); !ok {
		t.Fatal("repairFilesystem reported failure though every remount succeeded")
	}

	want := []string{"/", "/usr"}
	if len(fake.remounted) != len(want) {
		t.Fatalf("remounted %v; want exactly %v (only read-only /dev mounts)", fake.remounted, want)
	}
	for i, w := range want {
		if fake.remounted[i] != w {
			t.Errorf("remounted[%d] = %q; want %q", i, fake.remounted[i], w)
		}
	}
}

// TestRepairFilesystem_RemountFailureReportsNotAllOk pins that a failed remount
// of a read-only block device makes repairFilesystem return false, so the action
// does not proceed as if the filesystem were writable.
func TestRepairFilesystem_RemountFailureReportsNotAllOk(t *testing.T) {
	prev := fsMgr
	t.Cleanup(func() { fsMgr = prev })
	fsMgr = &fakeRemountFS{
		mounts:     []sysfs.MountInfo{{Source: "/dev/sda1", Target: "/", ReadOnly: true}},
		remountErr: errors.New("remount: read-only file system"),
	}

	e := &Executor{logger: slog.Default()}
	if ok := e.repairFilesystem(context.Background()); ok {
		t.Error("a failed remount of a read-only block device must report not-all-ok (false)")
	}
}
