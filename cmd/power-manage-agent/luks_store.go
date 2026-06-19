// Package main is the entry point for the power-manage agent.
package main

import (
	"context"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sdk "github.com/manchtools/power-manage-sdk"
)

// clientLuksKeyStore adapts sdk.Client to the executor.LuksKeyStore interface.
type clientLuksKeyStore struct {
	client *sdk.Client
}

func (s *clientLuksKeyStore) GetKey(ctx context.Context, actionID string) (string, error) {
	return s.client.GetLuksKey(ctx, actionID)
}

func (s *clientLuksKeyStore) StoreKey(ctx context.Context, actionID, devicePath, passphrase string, reason pb.RotationReason) error {
	return s.client.StoreLuksKey(ctx, actionID, devicePath, passphrase, reason)
}
