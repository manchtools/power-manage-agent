package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// setupSSHKeys must refuse an authorized_keys entry that carries an embedded
// newline (or carriage return) BEFORE it writes anything to disk. Without the
// guard, a single signed action could smuggle extra authorized_keys lines —
// additional principals, a command="…" override, a restrict= bypass — by
// embedding "\nssh-rsa ATTACKER…" in one key value: the prefix check passes on
// the first line and the appended lines land in the file unfiltered.
//
// The malicious payload is sourced from intent (a forged second key line), not
// from the guard's own ContainsAny rule. The rejection happens in the
// key-building loop, before the .ssh mkdir / SafeReplaceFile, so no
// authorized_keys file is created — pointed at a temp HOME we assert exactly
// that.
func TestSetupSSHKeys_RejectsEmbeddedNewline(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{
			name: "embedded LF splices a second key",
			key:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5legit\nssh-rsa AAAAB3NzaC1ATTACKER command=\"/bin/sh\"",
		},
		{
			name: "embedded CR splices a second key",
			key:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5legit\rssh-rsa AAAAB3NzaC1ATTACKER",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewExecutor(nil, nil)
			home := t.TempDir()
			params := &pb.UserParams{
				Username:          "alice",
				HomeDir:           home,
				SshAuthorizedKeys: []string{tc.key},
			}

			var out strings.Builder
			changed, err := e.setupSSHKeys(context.Background(), params, &out)
			if err == nil {
				t.Fatal("expected setupSSHKeys to refuse the embedded-newline key")
			}
			if !strings.Contains(err.Error(), "embedded newline") && !strings.Contains(err.Error(), "refusing to splice") {
				t.Errorf("error = %q, want it to name the embedded newline / refusal to splice", err)
			}
			if changed {
				t.Error("changed must be false when the key is refused")
			}
			// The splice must not have reached the filesystem.
			authKeys := filepath.Join(home, ".ssh", "authorized_keys")
			if _, statErr := os.Stat(authKeys); !os.IsNotExist(statErr) {
				t.Errorf("authorized_keys must not be written on a refused key (stat err = %v)", statErr)
			}
		})
	}
}
