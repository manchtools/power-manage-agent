package luksd

import (
	"context"
	"fmt"

	sysenc "github.com/manchtools/power-manage-sdk/sys/encryption"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// sysencEnroller is the production Enroller: it runs the privileged cryptsetup
// slot operations through the SDK encryption Manager with the daemon's own
// (root) credentials. The daemon already runs as root, so the Manager is built
// over a Direct runner — no sudo, no --data-dir. LUKS keys are written to a
// key-file sink (never argv), so they are wrapped as multiline secrets to pass
// through verbatim (a key may legitimately contain any byte).
type sysencEnroller struct {
	mgr sysenc.Manager
	err error // deferred construction error, surfaced fail-closed from each method
}

// NewSysencEnroller returns the production Enroller.
func NewSysencEnroller() Enroller {
	r, err := sysexec.NewRunner(sysexec.Direct)
	if err != nil {
		return sysencEnroller{err: fmt.Errorf("luksd: build direct runner: %w", err)}
	}
	m, err := sysenc.New(sysenc.LUKS, r)
	if err != nil {
		return sysencEnroller{err: fmt.Errorf("luksd: build encryption manager: %w", err)}
	}
	return sysencEnroller{mgr: m}
}

func (e sysencEnroller) AddKeyToSlot(ctx context.Context, devicePath string, slot int, unlockKey, newKey string) error {
	if e.err != nil {
		return e.err
	}
	return e.mgr.AddKey(ctx, devicePath,
		sysexec.NewMultilineSecret(unlockKey), sysexec.NewMultilineSecret(newKey),
		sysenc.AddKeyOptions{Slot: &slot})
}

func (e sysencEnroller) KillSlot(ctx context.Context, devicePath string, slot int, unlockKey string) error {
	if e.err != nil {
		return e.err
	}
	return e.mgr.KillSlot(ctx, devicePath, slot, sysexec.NewMultilineSecret(unlockKey))
}

func (e sysencEnroller) WipeTPM(ctx context.Context, devicePath, unlockKey string) error {
	if e.err != nil {
		return e.err
	}
	tpm, ok := e.mgr.TPM()
	if !ok {
		return fmt.Errorf("luksd: TPM enrollment not available for this backend")
	}
	return tpm.Wipe(ctx, devicePath, sysexec.NewMultilineSecret(unlockKey))
}
