// Package main is the entry point for the power-manage agent.
package main

import (
	"context"
	"fmt"

	sdk "github.com/manchtools/power-manage-sdk"
	pb "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/agent/internal/executor"
)

// clientLuksKeyStore adapts sdk.Client to the executor.LuksKeyStore interface.
type clientLuksKeyStore struct {
	client   *sdk.Client
	executor *executor.Executor
}

func (s *clientLuksKeyStore) GetKey(ctx context.Context, actionID string) (string, error) {
	if s.client == nil {
		return "", fmt.Errorf("luks key store: no SDK client wired (programmer error)")
	}
	sealed, err := s.client.GetLuksKey(ctx, actionID)
	if err != nil {
		return "", err
	}
	return s.executor.OpenLuksPassphrase(actionID, sealed)
}

func (s *clientLuksKeyStore) StoreKey(ctx context.Context, actionID, devicePath, passphrase string, reason pb.RotationReason) error {
	if s.client == nil {
		return fmt.Errorf("luks key store: no SDK client wired (programmer error)")
	}
	sealed, err := s.executor.SealLuksPassphrase(actionID, passphrase)
	if err != nil {
		return err
	}
	return s.client.StoreLuksKey(ctx, actionID, devicePath, sealed, reason)
}

func (s *clientLuksKeyStore) GetLuksKey(ctx context.Context, actionID string) (string, error) {
	return s.GetKey(ctx, actionID)
}

func (s *clientLuksKeyStore) ValidateLuksToken(ctx context.Context, token string) (*sdk.ValidateLuksTokenResult, error) {
	return s.client.ValidateLuksToken(ctx, token)
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
