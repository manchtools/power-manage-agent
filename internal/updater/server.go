package updater

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"

	pmv1 "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
)

// CheckServer queries the control server for auto-update information via
// the InternalService/GetAutoUpdateInfo Connect-RPC endpoint.
//
// It uses the agent's mTLS credentials for authentication. Returns the new
// version, download URL, and SHA256 checksum if an update is available.
// Returns empty strings (and nil error) if no update is available.
func CheckServer(ctx context.Context, controlAddr, arch string, tlsConfig *tls.Config) (version, url, checksum string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
	}

	client := pmv1connect.NewInternalServiceClient(httpClient, controlAddr)

	resp, err := client.GetAutoUpdateInfo(ctx, connect.NewRequest(&pmv1.GetAutoUpdateInfoRequest{
		AgentArch: arch,
	}))
	if err != nil {
		return "", "", "", fmt.Errorf("GetAutoUpdateInfo: %w", err)
	}

	msg := resp.Msg
	if msg.UpdateUrl == "" {
		return "", "", "", nil
	}

	return msg.LatestAgentVersion, msg.UpdateUrl, msg.UpdateChecksum, nil
}
