package executor

import (
	"context"
	"strings"
	"testing"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"
	pb "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
)

// executeWifi splices the action ID into a filesystem path
// (network.CertBaseDir/<id> for EAP-TLS certificates) and into the
// pm-wifi-<id> NetworkManager connection name. Like the sudo/ssh/sshd
// executors it must run the action ID through validateActionIDForFilesystem
// BEFORE building any path, not merely reject the empty string.
//
// The "wrong" inputs are sourced from intent (path-meaningful characters and
// the 64-char ceiling), NOT from the validator's regex. Each must be refused
// before any NetworkManager call — the function returns at the validation
// check, before conName/certDir are computed, so no connection is created and
// no cert directory is written.
func TestExecuteWifi_RejectsUnsafeActionID(t *testing.T) {
	e := NewExecutor(nil)
	ctx := context.Background()
	// Non-nil params so the nil-params guard isn't what trips; the action-ID
	// gate must reject before params are ever read.
	params := &pb.WifiParams{Ssid: "corp-net"}

	unsafe := []struct {
		name string
		id   string
	}{
		{"parent traversal", "../../etc"},
		{"embedded slash", "a/b"},
		{"shell separator", "a;b"},
		{"over 64 chars", strings.Repeat("a", 65)},
		{"empty", ""},
	}
	for _, tc := range unsafe {
		t.Run(tc.name, func(t *testing.T) {
			out, changed, err := e.executeWifi(ctx, params, pb.DesiredState_DESIRED_STATE_PRESENT, tc.id, "", "")
			if err == nil {
				t.Fatalf("executeWifi(id=%q) = nil error, want rejection", tc.id)
			}
			if !strings.Contains(err.Error(), "action ID") {
				t.Errorf("error = %q, want a validateActionIDForFilesystem message naming the action ID", err)
			}
			if changed {
				t.Error("changed must be false on a rejected action ID")
			}
			if out != nil {
				t.Errorf("output must be nil on rejection, got %v", out)
			}
		})
	}

	// correct: a valid alphanumeric ULID passes the same gate executeWifi
	// consults, so legitimate WiFi actions are not broken by the new check.
	if err := validateActionIDForFilesystem("01ARZ3NDEKTSV4RRFFQ69G5FAV"); err != nil {
		t.Errorf("valid ULID action ID rejected by the gate: %v", err)
	}
}

func TestExecuteSealedWifi_RejectsWrongFieldContext(t *testing.T) {
	agentKey, err := sdkcrypto.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	controlKey, err := sdkcrypto.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	e := NewExecutor(nil)
	const deviceID = "01HXDEVICE0000000000000000"
	const actionID = "01HXWIFISEAL00000000000000"
	e.SetDeviceID(deviceID)
	if err := e.ConfigureSealing(agentKey.Bytes(), controlKey.PublicKey().Bytes()); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		authType  pb.WifiAuthType
		sealField string
		params    func(*pb.SealedValue) *pb.WifiParams
	}{
		{
			name: "PSK", authType: pb.WifiAuthType_WIFI_AUTH_TYPE_PSK, sealField: "client_key",
			params: func(value *pb.SealedValue) *pb.WifiParams { return &pb.WifiParams{Psk: value} },
		},
		{
			name: "EAP-TLS", authType: pb.WifiAuthType_WIFI_AUTH_TYPE_EAP_TLS, sealField: "psk",
			params: func(value *pb.SealedValue) *pb.WifiParams { return &pb.WifiParams{ClientKey: value} },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			aad, info, err := sdkcrypto.FieldSealContext(sdkcrypto.DirectionControlToAgent,
				"powermanage.v1.WifiParams", tc.sealField, deviceID, actionID)
			if err != nil {
				t.Fatal(err)
			}
			ciphertext, err := sdkcrypto.SealToPublicKey(agentKey.PublicKey(), []byte("credential"), aad, info)
			if err != nil {
				t.Fatal(err)
			}
			params := tc.params(&pb.SealedValue{Version: 1, Ciphertext: ciphertext})
			params.AuthType = tc.authType
			_, _, err = e.executeSealedWifi(context.Background(), params,
				pb.DesiredState_DESIRED_STATE_PRESENT, actionID)
			if err == nil || !strings.Contains(err.Error(), "open WiFi credential") {
				t.Fatalf("executeSealedWifi() error = %v, want sealed-field rejection", err)
			}
		})
	}
}

func TestExecuteSealedWifi_RejectsUnsafeActionIDBeforeOpeningCredential(t *testing.T) {
	e := NewExecutor(nil)
	_, _, err := e.executeSealedWifi(context.Background(), &pb.WifiParams{
		AuthType: pb.WifiAuthType_WIFI_AUTH_TYPE_PSK,
	}, pb.DesiredState_DESIRED_STATE_PRESENT, "../../etc")
	if err == nil || !strings.Contains(err.Error(), "action ID") {
		t.Fatalf("executeSealedWifi() error = %v, want action-ID rejection before sealed-field access", err)
	}
}
