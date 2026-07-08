package executor

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// WS6 #16: sudoConfigForParams maps the access-level enum to a sudoers
// template. CUSTOM without content must be rejected (a blank custom
// fragment would silently grant nothing or, worse, an operator typo would
// pass); an unknown access level must be rejected (fail closed, never
// emit an empty/permissive file). The {group} placeholder must substitute.
func TestSudoConfigForParams_CustomRequiresConfig(t *testing.T) {
	const group = "pm-sudo-test"

	t.Run("CUSTOM without config is rejected", func(t *testing.T) {
		_, err := sudoConfigForParams(&pb.AdminPolicyParams{
			AccessLevel:  pb.AdminAccessLevel_ADMIN_ACCESS_LEVEL_CUSTOM,
			CustomConfig: "",
		}, group)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "custom_config is required")
	})

	t.Run("unset access level is rejected", func(t *testing.T) {
		_, err := sudoConfigForParams(&pb.AdminPolicyParams{
			AccessLevel: pb.AdminAccessLevel_ADMIN_ACCESS_LEVEL_UNSPECIFIED,
		}, group)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported access level")
	})

	t.Run("CUSTOM substitutes {group} and validates with visudo", func(t *testing.T) {
		content, err := sudoConfigForParams(&pb.AdminPolicyParams{
			AccessLevel:  pb.AdminAccessLevel_ADMIN_ACCESS_LEVEL_CUSTOM,
			CustomConfig: "%{group} ALL=(ALL) NOPASSWD: /usr/bin/id",
		}, group)
		require.NoError(t, err)
		assert.Contains(t, content, "%"+group+" ALL=(ALL) NOPASSWD: /usr/bin/id")
		assert.NotContains(t, content, "{group}", "the placeholder must be substituted")

		// If visudo is available, the generated fragment must parse.
		if path, lookErr := exec.LookPath("visudo"); lookErr == nil {
			f, err := os.CreateTemp(t.TempDir(), "sudoers-*")
			require.NoError(t, err)
			_, err = f.WriteString(content)
			require.NoError(t, err)
			require.NoError(t, f.Close())
			out, runErr := exec.CommandContext(visudoCtx(t), path, "-c", "-f", f.Name()).CombinedOutput()
			assert.NoErrorf(t, runErr, "visudo -c on generated CUSTOM fragment: %s", string(out))
		}
	})
}

// WS6 #17: setupSudoPolicy must reject an invalid username BEFORE creating
// any group or writing any sudoers file — an unvalidated name flows into
// group-membership and file content, so a name carrying shell/sudoers
// metacharacters is an injection vector. The invalid set is sourced from
// the POSIX user-name charset intent (start with a letter/underscore, then
// letters/digits/_/-), NOT from IsValidName's implementation.
func TestSetupSudoPolicy_RejectsInvalidUsernameBeforeWrite(t *testing.T) {
	e := &Executor{logger: slog.Default(), now: time.Now}

	invalid := []string{
		"root; rm -rf /", // command injection
		"../evil",        // path traversal
		"a b",            // space
		"bad!user",       // shell metacharacter
		"user\nroot",     // newline (sudoers line injection)
		"",               // empty
	}

	for _, name := range invalid {
		t.Run(name, func(t *testing.T) {
			groupName := "pm-sudo-rejecttest"
			// A writable temp path so that if validation were (wrongly)
			// moved after the write, the file would appear and fail the
			// assertion below — proving "rejected BEFORE write".
			sudoersPath := filepath.Join(t.TempDir(), "sudoers")
			_, changed, err := e.setupSudoPolicy(context.Background(),
				&pb.AdminPolicyParams{
					AccessLevel: pb.AdminAccessLevel_ADMIN_ACCESS_LEVEL_FULL,
					Users:       []string{name},
				}, groupName, sudoersPath)

			require.Error(t, err, "invalid username %q must be rejected", name)
			assert.Contains(t, err.Error(), "invalid username",
				"rejection must be the username validation (before any write), not a downstream fs error")
			assert.False(t, changed)
			// Validation runs before any filesystem mutation, so no
			// sudoers file is created.
			_, statErr := os.Stat(sudoersPath)
			assert.Truef(t, os.IsNotExist(statErr),
				"no sudoers file should be written for invalid username %q (stat err: %v)", name, statErr)
		})
	}
}
