// Package main is the entry point for the power-manage agent.
package main

import (
	"flag"
	"fmt"
	"os"
)

// runSetup is a deprecation no-op subcommand. The agent now runs as
// root directly (systemd unit `User=root`), so the previous
// sudoers/doas drop-in install is unnecessary — every privileged
// operation that used to be sudo-escalated runs in-process. The
// subcommand is kept as a no-op so existing operator install scripts
// that call `power-manage-agent setup` keep working without erroring.
//
// Behaviour: prints a notice to stderr explaining the change, then
// exits 0. The legacy `--user`/`--backend` flags are accepted but
// ignored to preserve script compatibility.
func runSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	_ = fs.String("user", "power-manage", "(ignored) Service user — agent now runs as root")
	_ = fs.String("backend", "sudo", "(ignored) Privilege backend — agent now runs as root")
	fs.Parse(args)

	fmt.Fprintln(os.Stderr, "power-manage-agent now runs as root directly (systemd User=root).")
	fmt.Fprintln(os.Stderr, "The sudoers/doas drop-in install is no longer required and this subcommand is a no-op.")
	fmt.Fprintln(os.Stderr, "Remove any leftover /etc/sudoers.d/power-manage or /etc/doas.d/power-manage.conf left by previous installs.")
}
