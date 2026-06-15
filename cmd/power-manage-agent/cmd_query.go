// Package main is the entry point for the power-manage agent.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/sys/osquery"
)

// isNotInstalled reports whether err signals that osquery is not installed,
// matching the sentinel even when it is wrapped (WS16 #13).
func isNotInstalled(err error) bool {
	return errors.Is(err, osquery.ErrNotInstalled)
}

// runQuery executes a local osquery table query and prints results.
// Usage: power-manage-agent query <table> [--json]
func runQuery(args []string) {
	if len(args) == 0 {
		printQueryUsage()
		os.Exit(1)
	}

	tableName := args[0]
	jsonOutput := false

	// Check for --json flag
	for _, arg := range args[1:] {
		if arg == "--json" || arg == "-j" {
			jsonOutput = true
		}
	}

	// Special case: list tables
	if tableName == "tables" || tableName == "--list" || tableName == "-l" {
		printAvailableTables()
		return
	}

	// Create registry (requires osquery to be installed)
	registry, err := osquery.NewRegistry()
	if err != nil {
		if isNotInstalled(err) {
			fmt.Fprintln(os.Stderr, "Error: osquery is not installed on this system")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Install osquery to use this feature:")
			fmt.Fprintln(os.Stderr, "  Fedora/RHEL: sudo dnf install osquery")
			fmt.Fprintln(os.Stderr, "  Debian/Ubuntu: sudo apt install osquery")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "See: https://osquery.io/downloads/official")
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}

	result, err := registry.Query(&pm.OSQuery{
		QueryId: "cli-query",
		Table:   tableName,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !result.Success {
		fmt.Fprintf(os.Stderr, "Query failed: %s\n", result.Error)
		os.Exit(1)
	}

	if len(result.Rows) == 0 {
		fmt.Println("No results")
		return
	}

	if jsonOutput {
		printQueryResultsJSON(result.Rows)
	} else {
		printQueryResultsTable(result.Rows)
	}
}

func printQueryUsage() {
	fmt.Println("Usage: power-manage-agent query <table> [--json]")
	fmt.Println()
	fmt.Println("Query system information using the installed osquery binary.")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  query tables          List available tables")
	fmt.Println("  query <table>         Query a specific table")
	fmt.Println("  query <table> --json  Output results as JSON")
	fmt.Println()
	fmt.Println("Note: Requires osquery to be installed on the system.")
	fmt.Println("See: https://osquery.io/downloads/official")
}

func printAvailableTables() {
	// Check if osquery is installed
	if !osquery.IsInstalled() {
		fmt.Fprintln(os.Stderr, "Error: osquery is not installed on this system")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Install osquery to use this feature:")
		fmt.Fprintln(os.Stderr, "  Fedora/RHEL: sudo dnf install osquery")
		fmt.Fprintln(os.Stderr, "  Debian/Ubuntu: sudo apt install osquery")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "See: https://osquery.io/downloads/official")
		os.Exit(1)
	}

	registry, err := osquery.NewRegistry()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	tables, err := registry.ListTables()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing tables: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Available osquery tables:")
	for _, table := range tables {
		fmt.Printf("  %s\n", table)
	}
	fmt.Printf("\nTotal: %d tables\n", len(tables))
}

func printQueryResultsJSON(rows []*pm.OSQueryRow) {
	// Convert to slice of maps for JSON output
	data := make([]map[string]string, len(rows))
	for i, row := range rows {
		data[i] = row.Data
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}

func printQueryResultsTable(rows []*pm.OSQueryRow) {
	if len(rows) == 0 {
		return
	}

	// Collect all unique keys across all rows
	keySet := make(map[string]bool)
	for _, row := range rows {
		for k := range row.Data {
			keySet[k] = true
		}
	}

	// Sort keys for consistent output
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Use tabwriter for aligned output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Print header
	for i, k := range keys {
		if i > 0 {
			fmt.Fprint(w, "\t")
		}
		fmt.Fprint(w, strings.ToUpper(k))
	}
	fmt.Fprintln(w)

	// Print separator
	for i, k := range keys {
		if i > 0 {
			fmt.Fprint(w, "\t")
		}
		fmt.Fprint(w, strings.Repeat("-", len(k)))
	}
	fmt.Fprintln(w)

	// Print rows
	for _, row := range rows {
		for i, k := range keys {
			if i > 0 {
				fmt.Fprint(w, "\t")
			}
			fmt.Fprint(w, row.Data[k])
		}
		fmt.Fprintln(w)
	}

	w.Flush()
}
