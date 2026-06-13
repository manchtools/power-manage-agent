package luksd

import (
	"context"

	sysenc "github.com/manchtools/power-manage/sdk/go/sys/encryption"
)

// sysencEnroller is the production Enroller: it runs the privileged
// cryptsetup slot operations via the SDK encryption helpers with the
// daemon's own (root) credentials. No sudo, no --data-dir.
type sysencEnroller struct{}

// NewSysencEnroller returns the production Enroller.
func NewSysencEnroller() Enroller { return sysencEnroller{} }

func (sysencEnroller) AddKeyToSlot(ctx context.Context, devicePath string, slot int, unlockKey, newKey string) error {
	return sysenc.AddKeyToSlot(ctx, devicePath, slot, unlockKey, newKey)
}

func (sysencEnroller) KillSlot(ctx context.Context, devicePath string, slot int, unlockKey string) error {
	return sysenc.KillSlot(ctx, devicePath, slot, unlockKey)
}

func (sysencEnroller) WipeTPM(ctx context.Context, devicePath, unlockKey string) error {
	return sysenc.WipeTPM(ctx, devicePath, unlockKey)
}
