// Package main is the entry point for the power-manage agent.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/manchtools/power-manage/agent/internal/credentials"
	"github.com/manchtools/power-manage/agent/internal/store"
)

// runTTY manages the device-local TTY enable/disable toggle.
// Usage:
//
//	power-manage-agent tty enable
//	power-manage-agent tty disable
//	power-manage-agent tty status
//
// The toggle is stored in the agent's SQLite database. `enable` and
// `disable` require ROOT (euid 0, e.g. via sudo) — the guard below is
// root-only; the retired sudoers-mode "power-manage user" identity has
// no special standing anymore (#173 doc/code mismatch). `status` only
// needs read access to the agent's database.
func runTTY(args []string) int {
	fs := flag.NewFlagSet("tty", flag.ExitOnError)
	dataDir := fs.String("data-dir", credentials.DefaultDataDir, "Agent data directory")

	if len(args) == 0 {
		printTTYUsage()
		return 1
	}

	sub := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}

	switch sub {
	case "-h", "--help", "help":
		printTTYUsage()
		return 0
	case "enable", "disable", "status":
		// handled below
	default:
		fmt.Fprintf(os.Stderr, "unknown tty subcommand: %s\n", sub)
		printTTYUsage()
		return 1
	}

	// Require root for mutating subcommands. The tty.enabled row in the
	// agent's SQLite DB is owned by the agent service user; another
	// unprivileged local user must not be able to flip the flag for a
	// user they aren't. Root-only enforces that — sudo or an equivalent
	// privilege backend is the only path to the mutator.
	//
	// An earlier revision also required the call to originate from an
	// interactive TTY so a server-dispatched `ACTION_TYPE_SHELL` couldn't
	// flip the flag remotely. That gate was dropped in this revision:
	// the `script(1)` utility routes around it in one line (pty
	// allocation makes the stdin check pass), so the gate only added
	// operational friction without providing real defence-in-depth. The
	// server-side answer to "who can grant terminal access on which
	// device" belongs in the permission model (RBAC + the fleet-wide
	// distribution of shell actions), not in a terminal-shape check on
	// the agent CLI.
	if sub == "enable" || sub == "disable" {
		if os.Geteuid() != 0 {
			fmt.Fprintf(os.Stderr, "Error: tty %s must be run as root (try: sudo power-manage-agent tty %s)\n", sub, sub)
			return 1
		}
	}

	// OpenExisting (not New): the agent service owns migrations, so a CLI toggle
	// must not run goose on an already-initialised database.
	st, err := store.OpenExisting(*dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: open agent store: %v\n", err)
		return 1
	}
	defer st.Close()

	switch sub {
	case "enable":
		if err := st.SetTTYEnabled(true); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		fmt.Println("TTY enabled.")
		return 0
	case "disable":
		if err := st.SetTTYEnabled(false); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		fmt.Println("TTY disabled.")
		return 0
	case "status":
		enabled, err := st.IsTTYEnabled()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		if enabled {
			fmt.Println("enabled")
			return 0
		}
		fmt.Println("disabled")
		return 1
	}
	return 1
}

func printTTYUsage() {
	fmt.Fprintln(os.Stderr, "usage: power-manage-agent tty {enable|disable|status} [--data-dir=PATH]")
}
