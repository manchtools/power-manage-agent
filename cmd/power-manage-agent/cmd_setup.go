// Package main is the entry point for the power-manage agent.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/manchtools/power-manage/agent/internal/setup"
)

// runSetup installs the agent's privilege-escalation configuration.
// Usage: power-manage-agent setup [--user USER] [--backend sudo|doas]
//
// The backend defaults to POWER_MANAGE_PRIVILEGE_BACKEND if set,
// otherwise sudo. The --backend flag overrides both so an operator
// reinstalling a drop-in for a different backend than the running
// agent uses (e.g. prepping a dual-booted system) doesn't have to
// shuffle env vars.
func runSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	user := fs.String("user", "power-manage", "Service user name for the drop-in")
	defaultBackend := strings.ToLower(os.Getenv("POWER_MANAGE_PRIVILEGE_BACKEND"))
	if defaultBackend == "" {
		defaultBackend = "sudo"
	}
	backend := fs.String("backend", defaultBackend, "Privilege backend: sudo or doas")
	fs.Parse(args)

	switch strings.ToLower(*backend) {
	case "sudo":
		fmt.Printf("Installing sudoers drop-in for user: %s\n", *user)
		if err := setup.InstallSudoers(*user); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Sudoers installed successfully")
	case "doas":
		fmt.Printf("Installing doas drop-in for user: %s\n", *user)
		if err := setup.InstallDoas(*user); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("doas drop-in installed successfully")
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown backend %q (expected sudo or doas)\n", *backend)
		os.Exit(1)
	}
}
