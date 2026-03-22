package executor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

const wifiCertDir = "/var/lib/power-manage/wifi"

// wifiConnectionName returns the managed connection name for an action.
func wifiConnectionName(actionID string) string {
	return "pm-wifi-" + actionID
}

// wifiCertPath returns the directory for EAP-TLS certificates.
func wifiCertPath(actionID string) string {
	return filepath.Join(wifiCertDir, actionID)
}

// executeWifi manages WiFi connection profiles via NetworkManager (nmcli).
// PRESENT: creates or updates the connection profile.
// ABSENT: deletes the connection profile and any certificate files.
func (e *Executor) executeWifi(ctx context.Context, params *pb.WifiParams, state pb.DesiredState, actionID string) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("wifi params required")
	}
	if actionID == "" {
		return nil, false, fmt.Errorf("action ID required for wifi")
	}

	conName := wifiConnectionName(actionID)

	if state == pb.DesiredState_DESIRED_STATE_ABSENT {
		return e.removeWifi(ctx, conName, actionID)
	}

	return e.ensureWifi(ctx, params, conName, actionID)
}

// removeWifi deletes a managed WiFi connection and its certificate files.
func (e *Executor) removeWifi(ctx context.Context, conName, actionID string) (*pb.CommandOutput, bool, error) {
	var output strings.Builder

	exists := wifiConnectionExists(conName)
	if !exists {
		output.WriteString(fmt.Sprintf("connection %s does not exist, nothing to remove\n", conName))
		// Also clean up cert dir if it exists
		certDir := wifiCertPath(actionID)
		os.RemoveAll(certDir)
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, false, nil
	}

	// Delete the connection
	out, err := runSudoCmd(ctx, "nmcli", "con", "delete", conName)
	if err != nil {
		return out, false, fmt.Errorf("failed to delete connection %s: %w", conName, err)
	}
	if out.ExitCode != 0 {
		return out, false, fmt.Errorf("nmcli con delete failed: %s", out.Stderr)
	}
	output.WriteString(fmt.Sprintf("deleted connection %s\n", conName))

	// Remove certificate directory
	certDir := wifiCertPath(actionID)
	if _, err := os.Stat(certDir); err == nil {
		os.RemoveAll(certDir)
		output.WriteString(fmt.Sprintf("removed certificate directory %s\n", certDir))
	}

	return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, true, nil
}

// ensureWifi creates or updates a WiFi connection profile.
func (e *Executor) ensureWifi(ctx context.Context, params *pb.WifiParams, conName, actionID string) (*pb.CommandOutput, bool, error) {
	var output strings.Builder

	// Write certificate files for EAP-TLS before configuring the connection
	if params.AuthType == pb.WifiAuthType_WIFI_AUTH_TYPE_EAP_TLS {
		if err := e.writeWifiCerts(actionID, params); err != nil {
			return nil, false, fmt.Errorf("failed to write certificates: %w", err)
		}
		output.WriteString("wrote EAP-TLS certificate files\n")
	}

	exists := wifiConnectionExists(conName)

	if exists {
		// Connection exists — check if modification is needed
		changed, err := e.modifyWifiIfNeeded(ctx, params, conName, actionID)
		if err != nil {
			return nil, false, err
		}
		if changed {
			output.WriteString(fmt.Sprintf("updated connection %s\n", conName))
		} else {
			output.WriteString(fmt.Sprintf("connection %s already configured correctly\n", conName))
		}
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, changed, nil
	}

	// Create new connection
	args := e.buildNmcliAddArgs(params, conName, actionID)
	out, err := runSudoCmd(ctx, "nmcli", args...)
	if err != nil {
		return out, false, fmt.Errorf("failed to create connection: %w", err)
	}
	if out.ExitCode != 0 {
		return out, false, fmt.Errorf("nmcli con add failed: %s", out.Stderr)
	}

	output.WriteString(fmt.Sprintf("created connection %s for SSID %s\n", conName, params.Ssid))
	return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, true, nil
}

// buildNmcliAddArgs builds the nmcli arguments for creating a WiFi connection.
func (e *Executor) buildNmcliAddArgs(params *pb.WifiParams, conName, actionID string) []string {
	args := []string{
		"con", "add",
		"con-name", conName,
		"type", "wifi",
		"ssid", params.Ssid,
	}

	switch params.AuthType {
	case pb.WifiAuthType_WIFI_AUTH_TYPE_PSK:
		args = append(args,
			"wifi-sec.key-mgmt", "wpa-psk",
			"wifi-sec.psk", params.Psk,
		)
	case pb.WifiAuthType_WIFI_AUTH_TYPE_EAP_TLS:
		certDir := wifiCertPath(actionID)
		args = append(args,
			"wifi-sec.key-mgmt", "wpa-eap",
			"802-1x.eap", "tls",
			"802-1x.identity", params.Identity,
			"802-1x.ca-cert", filepath.Join(certDir, "ca.pem"),
			"802-1x.client-cert", filepath.Join(certDir, "client.pem"),
			"802-1x.private-key", filepath.Join(certDir, "client-key.pem"),
		)
	}

	// Connection settings
	if params.AutoConnect {
		args = append(args, "connection.autoconnect", "yes")
	} else {
		args = append(args, "connection.autoconnect", "no")
	}

	if params.Priority != 0 {
		args = append(args, "connection.autoconnect-priority", fmt.Sprintf("%d", params.Priority))
	}

	if params.Hidden {
		args = append(args, "wifi.hidden", "yes")
	}

	return args
}

// modifyWifiIfNeeded checks current settings and modifies only if different.
func (e *Executor) modifyWifiIfNeeded(ctx context.Context, params *pb.WifiParams, conName, actionID string) (bool, error) {
	// Get current connection settings
	currentSettings, err := getConnectionSettings(ctx, conName)
	if err != nil {
		// Can't read settings — just modify to be safe
		return e.modifyWifi(ctx, params, conName, actionID)
	}

	// Build desired settings map
	desired := map[string]string{
		"wifi.ssid": params.Ssid,
	}

	switch params.AuthType {
	case pb.WifiAuthType_WIFI_AUTH_TYPE_PSK:
		desired["wifi-sec.key-mgmt"] = "wpa-psk"
		desired["wifi-sec.psk"] = params.Psk
	case pb.WifiAuthType_WIFI_AUTH_TYPE_EAP_TLS:
		desired["wifi-sec.key-mgmt"] = "wpa-eap"
		desired["802-1x.eap"] = "tls"
		desired["802-1x.identity"] = params.Identity
	}

	if params.AutoConnect {
		desired["connection.autoconnect"] = "yes"
	} else {
		desired["connection.autoconnect"] = "no"
	}
	desired["connection.autoconnect-priority"] = fmt.Sprintf("%d", params.Priority)
	if params.Hidden {
		desired["wifi.hidden"] = "yes"
	} else {
		desired["wifi.hidden"] = "no"
	}

	// Compare current vs desired
	needsUpdate := false
	for key, want := range desired {
		got := currentSettings[key]
		if got != want {
			needsUpdate = true
			break
		}
	}

	if !needsUpdate {
		return false, nil
	}

	return e.modifyWifi(ctx, params, conName, actionID)
}

// modifyWifi applies changes to an existing connection.
func (e *Executor) modifyWifi(ctx context.Context, params *pb.WifiParams, conName, actionID string) (bool, error) {
	args := []string{"con", "mod", conName, "wifi.ssid", params.Ssid}

	switch params.AuthType {
	case pb.WifiAuthType_WIFI_AUTH_TYPE_PSK:
		args = append(args,
			"wifi-sec.key-mgmt", "wpa-psk",
			"wifi-sec.psk", params.Psk,
		)
	case pb.WifiAuthType_WIFI_AUTH_TYPE_EAP_TLS:
		certDir := wifiCertPath(actionID)
		args = append(args,
			"wifi-sec.key-mgmt", "wpa-eap",
			"802-1x.eap", "tls",
			"802-1x.identity", params.Identity,
			"802-1x.ca-cert", filepath.Join(certDir, "ca.pem"),
			"802-1x.client-cert", filepath.Join(certDir, "client.pem"),
			"802-1x.private-key", filepath.Join(certDir, "client-key.pem"),
		)
	}

	if params.AutoConnect {
		args = append(args, "connection.autoconnect", "yes")
	} else {
		args = append(args, "connection.autoconnect", "no")
	}
	args = append(args, "connection.autoconnect-priority", fmt.Sprintf("%d", params.Priority))
	if params.Hidden {
		args = append(args, "wifi.hidden", "yes")
	} else {
		args = append(args, "wifi.hidden", "no")
	}

	out, err := runSudoCmd(ctx, "nmcli", args...)
	if err != nil {
		return false, fmt.Errorf("failed to modify connection: %w", err)
	}
	if out.ExitCode != 0 {
		return false, fmt.Errorf("nmcli con mod failed: %s", out.Stderr)
	}

	return true, nil
}

// writeWifiCerts writes EAP-TLS certificate files to disk.
func (e *Executor) writeWifiCerts(actionID string, params *pb.WifiParams) error {
	certDir := wifiCertPath(actionID)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
	}

	files := map[string]struct {
		content string
		mode    os.FileMode
	}{
		"ca.pem":         {content: params.CaCert, mode: 0644},
		"client.pem":     {content: params.ClientCert, mode: 0644},
		"client-key.pem": {content: params.ClientKey, mode: 0600},
	}

	for name, f := range files {
		if f.content == "" {
			continue
		}
		path := filepath.Join(certDir, name)
		if err := os.WriteFile(path, []byte(f.content), f.mode); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	return nil
}

// wifiConnectionExists checks if a named NetworkManager connection exists.
func wifiConnectionExists(conName string) bool {
	return checkCmdSuccess("nmcli", "-t", "-f", "NAME", "con", "show", conName)
}

// getConnectionSettings retrieves the current settings for a connection as a map.
func getConnectionSettings(ctx context.Context, conName string) (map[string]string, error) {
	out, err := runCmd(ctx, "nmcli", "-t", "-f", "all", "con", "show", conName)
	if err != nil {
		return nil, err
	}
	if out.ExitCode != 0 {
		return nil, fmt.Errorf("nmcli show failed: %s", out.Stderr)
	}

	settings := map[string]string{}
	for _, line := range strings.Split(out.Stdout, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			settings[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return settings, nil
}
