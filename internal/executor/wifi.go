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
		if err := network.Delete(ctx, conName, certDir); err != nil {
			return nil, false, fmt.Errorf("delete connection: %w", err)
		}
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("removed connection %s\n", conName),
		}, true, nil
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
