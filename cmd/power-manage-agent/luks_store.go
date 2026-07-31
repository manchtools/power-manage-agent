// Package main is the entry point for the power-manage agent.
package main

import (
	"context"
	"fmt"

	sdk "github.com/manchtools/power-manage-sdk"
	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// clientLuksKeyStore adapts sdk.Client to the executor.LuksKeyStore interface.
type clientLuksKeyStore struct {
	client *sdk.Client
}

func (s *clientLuksKeyStore) GetKey(ctx context.Context, actionID string) (string, error) {
	if s.client == nil {
		return "", fmt.Errorf("luks key store: no SDK client wired (programmer error)")
	}
	return s.client.GetLuksKey(ctx, actionID)
}

func (s *clientLuksKeyStore) StoreKey(ctx context.Context, actionID, devicePath, passphrase string, reason pb.RotationReason) error {
	if s.client == nil {
		return fmt.Errorf("luks key store: no SDK client wired (programmer error)")
	}
	return s.client.StoreLuksKey(ctx, actionID, devicePath, passphrase, reason)
}

// clientLpsPasswordStore adapts sdk.Client to executor.LpsPasswordStore.
// Rotated local passwords used to leave the device inside the action result's
// metadata, sealed, because the gateway relayed that result. They now travel on
// the agent's own authenticated stream as StoreLpsPasswords.
type clientLpsPasswordStore struct {
	client *sdk.Client
}

func (s *clientLpsPasswordStore) StorePasswords(ctx context.Context, actionID string, rotations []*pb.LpsPasswordRotation) error {
	if s.client == nil {
		return fmt.Errorf("lps password store: no SDK client wired (programmer error)")
	}
	return s.client.StoreLpsPasswords(ctx, actionID, rotations)
}
