package executor

import (
	"context"
	"fmt"
	"path/filepath"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/sys/network"
)

// wifiConnectionName returns the managed connection name for an action.
// All Power Manage WiFi profiles are prefixed so they're distinguishable
// from user-managed NetworkManager connections.
func wifiConnectionName(actionID string) string {
	return "pm-wifi-" + actionID
}

// wifiCertPath returns the directory for EAP-TLS certificates for an action.
func wifiCertPath(actionID string) string {
	return filepath.Join(network.CertBaseDir, actionID)
}

// executeWifi manages WiFi connection profiles via NetworkManager.
// PRESENT: creates or updates the connection profile (delegated to the SDK).
// ABSENT: deletes the connection profile and any certificate files.
func (e *Executor) executeWifi(ctx context.Context, params *pb.WifiParams, state pb.DesiredState, actionID string) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("wifi params required")
	}
	if actionID == "" {
		return nil, false, fmt.Errorf("action ID required for wifi")
	}

	conName := wifiConnectionName(actionID)
	certDir := wifiCertPath(actionID)

	if state == pb.DesiredState_DESIRED_STATE_ABSENT {
		// Audit F055: previously always reported `changed=true`, even
		// when the connection did not exist before this call. That
		// surfaced spurious "wifi changed" events to the server on
		// every re-apply of an already-absent action. Probe with
		// ConnectionExists first so the result reflects reality.
		// Pattern matches the DNF/Zypper repository ABSENT branches
		// in action_repository.go which also short-circuit when the
		// resource is already gone.
		existed, existsErr := network.ConnectionExists(ctx, conName)
		if existsErr != nil {
			e.logger.Warn("wifi ABSENT: ConnectionExists failed; conservatively reporting changed=true",
				"connection", conName, "error", existsErr)
			existed = true
		}
		if err := network.Delete(ctx, conName, certDir); err != nil {
			return nil, false, fmt.Errorf("delete connection: %w", err)
		}
		stdout := fmt.Sprintf("connection %s already absent\n", conName)
		if existed {
			stdout = fmt.Sprintf("removed connection %s\n", conName)
		}
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   stdout,
		}, existed, nil
	}

	profile := network.WiFiProfile{
		Name:        conName,
		SSID:        params.Ssid,
		AuthType:    wifiAuthFromProto(params.AuthType),
		PSK:         params.Psk,
		CACert:      params.CaCert,
		ClientCert:  params.ClientCert,
		ClientKey:   params.ClientKey,
		Identity:    params.Identity,
		AutoConnect: params.AutoConnect,
		Hidden:      params.Hidden,
		Priority:    int(params.Priority),
		CertDir:     certDir,
	}

	changed, err := network.CreateOrUpdate(ctx, profile)
	if err != nil {
		return nil, false, err
	}

	stdout := fmt.Sprintf("connection %s already configured correctly\n", conName)
	if changed {
		stdout = fmt.Sprintf("configured connection %s for SSID %s\n", conName, params.Ssid)
	}
	return &pb.CommandOutput{ExitCode: 0, Stdout: stdout}, changed, nil
}

// wifiAuthFromProto maps the proto auth type enum to the SDK enum.
func wifiAuthFromProto(t pb.WifiAuthType) network.WiFiAuthType {
	switch t {
	case pb.WifiAuthType_WIFI_AUTH_TYPE_PSK:
		return network.WiFiAuthPSK
	case pb.WifiAuthType_WIFI_AUTH_TYPE_EAP_TLS:
		return network.WiFiAuthEAPTLS
	}
	return 0
}
