package deviceauth

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"

	"github.com/manchtools/power-manage/agent/internal/credentials"
)

// TestEnroll_RejectsNonHTTPSServerURL pins the https-only gate (#2/#16):
// a cleartext/opaque/hostless server_url is refused BEFORE any network
// call. The error names the https requirement (distinct from a
// "registration failed" downstream error), and nothing is persisted — so
// even if the gate were removed, the test would not pass on a
// connection-refused error.
func TestEnroll_RejectsNonHTTPSServerURL(t *testing.T) {
	cases := []string{
		"http://control.example.com", // cleartext
		"HTTP://control.example.com", // case variant of cleartext
		"ftp://control.example.com",  // wrong scheme
		"control.example.com",        // scheme-less
		"https:foo",                  // opaque
		"https:",                     // no host
		"https://user:pass@host",     // embedded credentials
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			credStore := credentials.NewStore(t.TempDir())
			h := NewEnrollHandler("h", "dev", credStore, slog.Default(), nil)

			resp, err := h.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{
				ServerUrl: u,
				Token:     "some-token",
			}))
			require.NoError(t, err)
			assert.False(t, resp.Msg.Success)
			assert.Contains(t, resp.Msg.Error, "https")
			assert.False(t, credStore.Exists(), "no credentials must be saved on a rejected URL")
		})
	}
}

// TestEnroll_PerFieldRequired pins per-field required validation (#15):
// each of server_url / token absent is rejected before any network call.
func TestEnroll_PerFieldRequired(t *testing.T) {
	cases := []struct {
		name       string
		url, token string
	}{
		{"token absent", "https://control.example.com", ""},
		{"server_url absent", "", "tok"},
		{"both absent", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			credStore := credentials.NewStore(t.TempDir())
			h := NewEnrollHandler("h", "dev", credStore, slog.Default(), nil)

			resp, err := h.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{
				ServerUrl: tc.url,
				Token:     tc.token,
			}))
			require.NoError(t, err)
			assert.False(t, resp.Msg.Success)
			assert.Contains(t, resp.Msg.Error, "required")
			assert.False(t, credStore.Exists())
		})
	}
}
