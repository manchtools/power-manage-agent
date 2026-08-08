package executor

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"
	pb "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
)

const sealedFieldVersion = 1

func (e *Executor) ConfigureSealing(agentPrivate, controlPublic []byte) error {
	privateKey, err := ecdh.X25519().NewPrivateKey(agentPrivate)
	if err != nil {
		return fmt.Errorf("parse agent X25519 private key: %w", err)
	}
	publicKey, err := sdkcrypto.ParseX25519PublicKey(controlPublic)
	if err != nil {
		return fmt.Errorf("parse control X25519 public key: %w", err)
	}
	e.mu.Lock()
	e.sealingPrivate = privateKey
	e.controlSealingPublic = publicKey
	e.mu.Unlock()
	return nil
}

func (e *Executor) sealToControl(plaintext []byte, message, field string, bindings ...string) (*pb.SealedValue, error) {
	e.mu.RLock()
	recipient := e.controlSealingPublic
	e.mu.RUnlock()
	if recipient == nil {
		return nil, errors.New("control sealing public key is not configured")
	}
	aad, info, err := sdkcrypto.FieldSealContext(sdkcrypto.DirectionAgentToControl, message, field, bindings...)
	if err != nil {
		return nil, err
	}
	sealed, err := sdkcrypto.SealToPublicKey(recipient, plaintext, aad, info)
	if err != nil {
		return nil, err
	}
	return &pb.SealedValue{Version: sealedFieldVersion, Ciphertext: sealed}, nil
}

func (e *Executor) openFromControl(value *pb.SealedValue, message, field string, bindings ...string) ([]byte, error) {
	if value == nil || value.GetVersion() != sealedFieldVersion {
		return nil, errors.New("unsupported or missing sealed field")
	}
	e.mu.RLock()
	privateKey := e.sealingPrivate
	e.mu.RUnlock()
	if privateKey == nil {
		return nil, errors.New("agent sealing private key is not configured")
	}
	aad, info, err := sdkcrypto.FieldSealContext(sdkcrypto.DirectionControlToAgent, message, field, bindings...)
	if err != nil {
		return nil, err
	}
	plaintext, err := sdkcrypto.OpenWithPrivateKey(privateKey, value.GetCiphertext(), aad, info)
	if err != nil {
		return nil, fmt.Errorf("open sealed control field: %w", err)
	}
	if len(plaintext) == 0 {
		return nil, errors.New("opened secret is empty")
	}
	return plaintext, nil
}

func (e *Executor) SealLuksPassphrase(actionID, passphrase string) (*pb.SealedValue, error) {
	return e.sealToControl([]byte(passphrase),
		"powermanage.v1.StoreLuksKeyRequest", "passphrase",
		e.getDeviceID(), actionID)
}

func (e *Executor) OpenLuksPassphrase(actionID string, value *pb.SealedValue) (string, error) {
	plaintext, err := e.openFromControl(value,
		"powermanage.v1.GetLuksKeyResponse", "passphrase",
		e.getDeviceID(), actionID)
	if err != nil {
		return "", err
	}
	defer clear(plaintext)
	return string(plaintext), nil
}

func (e *Executor) executeSealedLuks(ctx context.Context, params *pb.EncryptionParams, state pb.DesiredState, actionID string) (*pb.CommandOutput, bool, map[string]string, error) {
	if state == pb.DesiredState_DESIRED_STATE_ABSENT {
		return e.executeLuks(ctx, params, state, actionID, nil)
	}
	openPresharedKey := func() ([]byte, error) {
		plaintext, err := e.openFromControl(params.GetPresharedKey(),
			"powermanage.v1.EncryptionParams", "preshared_key", e.getDeviceID(), actionID)
		if err != nil {
			return nil, fmt.Errorf("open encryption pre-shared key: %w", err)
		}
		return plaintext, nil
	}
	return e.executeLuks(ctx, params, state, actionID, openPresharedKey)
}

func (e *Executor) executeSealedWifi(ctx context.Context, params *pb.WifiParams, state pb.DesiredState, actionID string) (*pb.CommandOutput, bool, error) {
	if err := validateActionIDForFilesystem(actionID); err != nil {
		return nil, false, err
	}
	if state == pb.DesiredState_DESIRED_STATE_ABSENT {
		return e.executeWifi(ctx, params, state, actionID, "", "")
	}
	if params == nil {
		return nil, false, errors.New("wifi params required")
	}
	var psk, clientKey []byte
	var err error
	switch params.AuthType {
	case pb.WifiAuthType_WIFI_AUTH_TYPE_PSK:
		psk, err = e.openFromControl(params.GetPsk(), "powermanage.v1.WifiParams", "psk", e.getDeviceID(), actionID)
	case pb.WifiAuthType_WIFI_AUTH_TYPE_EAP_TLS:
		clientKey, err = e.openFromControl(params.GetClientKey(), "powermanage.v1.WifiParams", "client_key", e.getDeviceID(), actionID)
	default:
		err = errors.New("unsupported WiFi authentication type")
	}
	if err != nil {
		return nil, false, fmt.Errorf("open WiFi credential: %w", err)
	}
	defer clear(psk)
	defer clear(clientKey)
	return e.executeWifi(ctx, params, state, actionID, string(psk), string(clientKey))
}
