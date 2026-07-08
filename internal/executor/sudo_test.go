package executor

// TerminalAdmin sudoers template coverage —
// manchtools/power-manage-server#70.
//
// This file covers ONLY the two new server-managed templates added
// alongside the new AdminAccessLevel enum values. The existing
// generateLimitedSudoConfig / generateFullSudoConfig / generateCustomSudoConfig
// generators are deliberately untouched by #70 and stay untested in
// this PR — that's separate test-coverage work.
//
// The two new templates exist because the operator-authored
// FULL/LIMITED templates assume a password-bearing account; pm-tty-*
// accounts (#327) are passwordless, so the server's TerminalAdmin
// reconciler points the two global AdminPolicy actions at these new
// templates instead. The ADR (server/docs/adr/0000-terminal-admin-
// threat-model.md) is the authoritative contract for what they must
// reject.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

const testTerminalAdminGroup = "pm-sudo-test"

// =============================================================================
// generateTerminalAdminLimitedSudoConfig — passwordless LIMITED.
// =============================================================================

func TestGenerateTerminalAdminLimitedSudoConfig_GroupInterpolation(t *testing.T) {
	out := generateTerminalAdminLimitedSudoConfig(testTerminalAdminGroup)
	assert.Contains(t, out, "%"+testTerminalAdminGroup+" ALL=",
		"the passed group name must appear in every rule")
}

// ADR T1: every command rule must carry NOPASSWD so the passwordless
// pm-tty-* account can use the allowlist at all. Without it the
// template is unusable — the operator has no password to type.
func TestGenerateTerminalAdminLimitedSudoConfig_NOPASSWD(t *testing.T) {
	out := generateTerminalAdminLimitedSudoConfig(testTerminalAdminGroup)
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Defaults lines and deny rules don't need NOPASSWD; only
		// affirmative command grants do.
		if !strings.HasPrefix(trimmed, "%"+testTerminalAdminGroup) {
			continue
		}
		// A grant line is of the form `%group ALL=(ALL) <stuff>`. If
		// the <stuff> starts with `!` it's a deny block and doesn't
		// need NOPASSWD. Otherwise NOPASSWD: must appear before the
		// command list.
		runspec := strings.SplitN(trimmed, "ALL=(ALL)", 2)
		if len(runspec) != 2 {
			t.Fatalf("unexpected rule shape: %q", line)
		}
		body := strings.TrimSpace(runspec[1])
		if strings.HasPrefix(body, "!") {
			continue // deny rule
		}
		assert.True(t, strings.HasPrefix(body, "NOPASSWD:"),
			"affirmative grant must start with NOPASSWD: — %q", line)
	}
}

// ADR T4: Defaults block must pin requiretty, env_reset, !lecture,
// and timestamp_timeout=0. The last forces sudoers re-evaluation on
// every sudo call so a fresh revocation lands immediately under
// NOPASSWD.
func TestGenerateTerminalAdminLimitedSudoConfig_DefaultsBlock(t *testing.T) {
	out := generateTerminalAdminLimitedSudoConfig(testTerminalAdminGroup)
	g := "%" + testTerminalAdminGroup
	for _, want := range []string{
		"Defaults:" + g + " requiretty",
		"Defaults:" + g + " env_reset",
		"Defaults:" + g + " !lecture",
		"Defaults:" + g + " timestamp_timeout=0",
	} {
		assert.Contains(t, out, want,
			"ADR T4: group-scoped Defaults block must include %q", want)
	}
}

// ADR T2: editor escapes (vim → :!bash etc.) MUST be denied — under
// NOPASSWD a missed editor in the allowlist is unprompted root.
func TestGenerateTerminalAdminLimitedSudoConfig_DeniesEditors(t *testing.T) {
	out := generateTerminalAdminLimitedSudoConfig(testTerminalAdminGroup)
	// Per ADR T2: vim, vi, vimdiff, view, nvim, emacs, emacsclient,
	// nano, less, more, most, ed, ex, mc, joe, jed.
	editors := []string{
		"/usr/bin/vim", "/usr/bin/vi", "/usr/bin/vimdiff", "/usr/bin/view", "/usr/bin/nvim",
		"/usr/bin/emacs", "/usr/bin/emacsclient",
		"/usr/bin/nano", "/bin/nano",
		"/usr/bin/less", "/usr/bin/more", "/usr/bin/most",
		"/usr/bin/ed", "/usr/bin/ex",
		"/usr/bin/mc", "/usr/bin/joe", "/usr/bin/jed",
	}
	for _, editor := range editors {
		assert.Contains(t, out, "!"+editor,
			"ADR T2: editor %s must appear in the deny block", editor)
	}
}

// ADR T3: shell spawns must be denied.
func TestGenerateTerminalAdminLimitedSudoConfig_DeniesShells(t *testing.T) {
	out := generateTerminalAdminLimitedSudoConfig(testTerminalAdminGroup)
	shells := []string{
		"/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh", "/bin/csh", "/bin/tcsh", "/bin/fish",
		"/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/zsh", "/usr/bin/ksh", "/usr/bin/csh", "/usr/bin/tcsh", "/usr/bin/fish",
		"/usr/bin/env",
	}
	for _, shell := range shells {
		assert.Contains(t, out, "!"+shell,
			"ADR T3: shell %s must appear in the deny block", shell)
	}
}

// ADR T5: persistence vectors (at, crontab, dpkg-divert,
// update-alternatives) must be denied.
func TestGenerateTerminalAdminLimitedSudoConfig_DeniesPersistenceVectors(t *testing.T) {
	out := generateTerminalAdminLimitedSudoConfig(testTerminalAdminGroup)
	vectors := []string{
		"/usr/bin/at", "/usr/bin/atq", "/usr/bin/atrm", "/usr/bin/batch",
		"/usr/bin/crontab",
		"/usr/sbin/dpkg-divert", "/usr/bin/dpkg-divert",
		"/usr/bin/update-alternatives", "/usr/sbin/update-alternatives",
	}
	for _, vector := range vectors {
		assert.Contains(t, out, "!"+vector,
			"ADR T5: persistence vector %s must appear in the deny block", vector)
	}
}

// ADR L1/L5 + "Deny modifications to power-manage-agent and sudoers":
// the agent-protection rules MUST actually deny. In sudoers(5) an EVEN
// number of '!' operators cancels out (resolving to an ALLOW); only an
// ODD number negates. So `!!/usr/bin/visudo` GRANTS visudo (sudoers
// edit → trivial root) and `!!systemctl * power-manage-agent*` GRANTS
// stopping/disabling the managed agent — the exact opposite of the
// rule's stated purpose. No reading of the ADR wants visudo granted to
// a LIMITED terminal admin, so a double-bang must never appear.
func TestGenerateTerminalAdminLimitedSudoConfig_AgentProtectionIsRealDeny(t *testing.T) {
	out := generateTerminalAdminLimitedSudoConfig(testTerminalAdminGroup)
	assert.NotContains(t, out, "!!",
		"double-bang in sudoers is an even negation = ALLOW; agent/visudo protection must use a single '!' deny")
	assert.Contains(t, out, "!/usr/bin/systemctl * power-manage-agent*",
		"LIMITED template must deny controlling the power-manage-agent unit")
	assert.Contains(t, out, "!/usr/bin/visudo",
		"LIMITED template must deny visudo (sudoers edit is root escalation)")
	assert.Contains(t, out, "!/usr/sbin/visudo",
		"LIMITED template must deny the /usr/sbin/visudo path too")
}

// The legacy password-bearing LIMITED template carries the identical
// double-bang bug; there `!!/usr/bin/visudo` actively ADDS visudo to
// the allowlist (no earlier grant cancels it), so a limited admin with
// their password can edit sudoers and become full root.
func TestGenerateLimitedSudoConfig_AgentProtectionIsRealDeny(t *testing.T) {
	out := generateLimitedSudoConfig(testTerminalAdminGroup)
	assert.NotContains(t, out, "!!",
		"double-bang grants the command it claims to deny — legacy LIMITED template must use a single '!'")
}

// ADR T4 pins the Defaults block to the TerminalAdmin group, not the
// whole host. A bare `Defaults requiretty` / `timestamp_timeout=0`
// line inside an /etc/sudoers.d drop-in applies host-globally to every
// sudo invocation (cron jobs, systemd units, ansible), so deploying one
// scoped policy would force requiretty on root's non-TTY sudo and strip
// credential caching for every other admin. The Defaults must be
// group-scoped: `Defaults:%<group> ...`.
func TestTerminalAdminDefaults_ScopedToGroup_NotHostGlobal(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
	}{
		{"limited", generateTerminalAdminLimitedSudoConfig(testTerminalAdminGroup)},
		{"full", generateTerminalAdminFullSudoConfig(testTerminalAdminGroup)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, setting := range []string{"requiretty", "env_reset", "!lecture", "timestamp_timeout=0"} {
				assert.NotContains(t, tc.out, "Defaults "+setting,
					"host-global Defaults leaks onto every sudo on the box; scope it to the group")
				assert.Contains(t, tc.out, "Defaults:%"+testTerminalAdminGroup+" "+setting,
					"Defaults must be scoped to the TerminalAdmin group")
			}
		})
	}
}

// =============================================================================
// generateTerminalAdminFullSudoConfig — passwordless FULL.
// =============================================================================

func TestGenerateTerminalAdminFullSudoConfig_GroupInterpolation(t *testing.T) {
	out := generateTerminalAdminFullSudoConfig(testTerminalAdminGroup)
	assert.Contains(t, out, "%"+testTerminalAdminGroup,
		"the passed group name must appear in the rule")
}

// ADR: Full template grants ALL=(ALL:ALL) NOPASSWD: ALL.
func TestGenerateTerminalAdminFullSudoConfig_NOPASSWD_ALL(t *testing.T) {
	out := generateTerminalAdminFullSudoConfig(testTerminalAdminGroup)
	assert.Contains(t, out, "%"+testTerminalAdminGroup+" ALL=(ALL:ALL) NOPASSWD: ALL",
		"FULL template must grant ALL=(ALL:ALL) NOPASSWD: ALL")
}

// The Defaults block applies to FULL too — audit and TTY constraints
// are the same regardless of access level.
func TestGenerateTerminalAdminFullSudoConfig_DefaultsBlock(t *testing.T) {
	out := generateTerminalAdminFullSudoConfig(testTerminalAdminGroup)
	g := "%" + testTerminalAdminGroup
	for _, want := range []string{
		"Defaults:" + g + " requiretty",
		"Defaults:" + g + " env_reset",
		"Defaults:" + g + " !lecture",
		"Defaults:" + g + " timestamp_timeout=0",
	} {
		assert.Contains(t, out, want,
			"ADR T4: group-scoped Defaults block must apply to FULL as well — missing %q", want)
	}
}

// =============================================================================
// Switch wiring: the two new enum values route to the new generators.
// =============================================================================

// TestSetupSudoPolicy_RoutesTerminalAdminLimitedEnumToNewGenerator pins
// the switch arm in setupSudoPolicy: the new enum value must select
// the new generator, NOT the existing LIMITED template (which requires
// a password and is unusable through pm-tty-* accounts).
func TestSetupSudoPolicy_RoutesTerminalAdminLimitedEnumToNewGenerator(t *testing.T) {
	out := contentForAccessLevel(t, pb.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED)
	want := generateTerminalAdminLimitedSudoConfig(testTerminalAdminGroup)
	assert.Equal(t, want, out,
		"AccessLevel=TERMINAL_ADMIN_LIMITED must select the new passwordless generator, not the existing LIMITED template")
}

func TestSetupSudoPolicy_RoutesTerminalAdminFullEnumToNewGenerator(t *testing.T) {
	out := contentForAccessLevel(t, pb.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_FULL)
	want := generateTerminalAdminFullSudoConfig(testTerminalAdminGroup)
	assert.Equal(t, want, out,
		"AccessLevel=TERMINAL_ADMIN_FULL must select the new passwordless generator, not the existing FULL template")
}

// contentForAccessLevel exercises sudoConfigForParams (the dispatch
// function the switch in setupSudoPolicy now uses) directly so the
// test isn't entangled with the filesystem / group-membership work
// the surrounding setupSudoPolicy does.
func contentForAccessLevel(t *testing.T, level pb.AdminAccessLevel) string {
	t.Helper()
	params := &pb.AdminPolicyParams{
		AccessLevel: level,
		Users:       []string{"pm-tty-alice"},
	}
	content, err := sudoConfigForParams(params, testTerminalAdminGroup)
	if err != nil {
		t.Fatalf("sudoConfigForParams: %v", err)
	}
	return content
}

// =============================================================================
// Integration: visudo -c -f accepts the generated content.
//
// Skipped when visudo isn't on PATH (CI containers may not install
// the sudo package). When present, this catches any syntax error the
// unit tests above wouldn't surface — a malformed Defaults line, an
// unterminated rule, etc.
// =============================================================================

func TestSudoConfig_PassesVisudoCheck_TerminalAdminLimited(t *testing.T) {
	requireVisudo(t)
	out := generateTerminalAdminLimitedSudoConfig(testTerminalAdminGroup)
	requireVisudoAccepts(t, out)
}

func TestSudoConfig_PassesVisudoCheck_TerminalAdminFull(t *testing.T) {
	requireVisudo(t)
	out := generateTerminalAdminFullSudoConfig(testTerminalAdminGroup)
	requireVisudoAccepts(t, out)
}

func requireVisudo(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("visudo"); err != nil {
		t.Skipf("visudo not on PATH; skipping syntax-check integration: %v", err)
	}
}

func requireVisudoAccepts(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sudoers.d.pm-test")
	if err := os.WriteFile(path, []byte(content), 0o440); err != nil {
		t.Fatalf("write tempfile: %v", err)
	}
	out, err := exec.CommandContext(visudoCtx(t), "visudo", "-c", "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("visudo -c -f rejected the generated content:\n%s\n---\n%s", err, out)
	}
}

// visudoCtx bounds a visudo invocation (#174): a hung visudo previously
// blocked the test binary forever (no deadline on either call site).
func visudoCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}
