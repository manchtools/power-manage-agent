// Package osquery provides integration with the osquery binary for system queries.
package osquery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

var (
	// ErrNotInstalled is returned when osquery is not installed on the system.
	ErrNotInstalled = errors.New("osquery is not installed")

	// ErrQueryFailed is returned when an osquery query fails.
	ErrQueryFailed = errors.New("osquery query failed")

	// Common osquery binary paths to check.
	osqueryPaths = []string{
		"/usr/bin/osqueryi",
		"/usr/local/bin/osqueryi",
		"/opt/osquery/bin/osqueryi",
	}

	// Default query timeout.
	defaultTimeout = 30 * time.Second
)

// Client wraps osquery binary execution.
type Client struct {
	binaryPath string
}

// NewClient creates a new osquery client.
// Returns ErrNotInstalled if osquery binary is not found.
func NewClient() (*Client, error) {
	path := findOsqueryBinary()
	if path == "" {
		return nil, ErrNotInstalled
	}
	return &Client{binaryPath: path}, nil
}

// IsInstalled checks if osquery is installed on the system.
func IsInstalled() bool {
	return findOsqueryBinary() != ""
}

// findOsqueryBinary searches for the osqueryi binary.
func findOsqueryBinary() string {
	for _, path := range osqueryPaths {
		if _, err := exec.LookPath(path); err == nil {
			return path
		}
	}
	// Also check PATH
	if path, err := exec.LookPath("osqueryi"); err == nil {
		return path
	}
	return ""
}

// ListTables returns a list of available osquery tables.
func (c *Client) ListTables(ctx context.Context) ([]string, error) {
	output, err := c.execQuery(ctx, ".tables")
	if err != nil {
		return nil, err
	}

	var tables []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// Skip empty lines and header lines
		if line == "" || strings.HasPrefix(line, "=>") || strings.HasPrefix(line, "+") {
			continue
		}
		// Remove leading "=>" if present
		line = strings.TrimPrefix(line, "=> ")
		if line != "" {
			tables = append(tables, line)
		}
	}
	return tables, nil
}

// tableSQL returns custom SQL for tables that need JOINs or special handling.
// Tables like authorized_keys scope to the current user by default and need
// a JOIN against the users table to return data for all users.
var tableSQL = map[string]string{
	"authorized_keys": "SELECT authorized_keys.* FROM users JOIN authorized_keys USING (uid)",
}

// Query executes an osquery SQL query and returns the results.
func (c *Client) Query(ctx context.Context, query *pb.OSQuery) (*pb.OSQueryResult, error) {
	// If raw SQL is provided, execute it directly
	var sql string
	if query.RawSql != "" {
		sql = query.RawSql
	} else if custom, ok := tableSQL[query.Table]; ok {
		sql = custom
	} else {
		sql = fmt.Sprintf("SELECT * FROM %s", query.Table)
	}

	rows, err := c.QuerySQL(ctx, sql)
	if err != nil {
		return &pb.OSQueryResult{
			QueryId: query.QueryId,
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.OSQueryResult{
		QueryId: query.QueryId,
		Success: true,
		Rows:    rows,
	}, nil
}

// QuerySQL executes a raw SQL query against osquery.
func (c *Client) QuerySQL(ctx context.Context, sql string) ([]*pb.OSQueryRow, error) {
	// Execute query with JSON output
	output, err := c.execQuery(ctx, sql)
	if err != nil {
		return nil, err
	}

	// Parse JSON output
	var results []map[string]string
	if err := json.Unmarshal([]byte(output), &results); err != nil {
		return nil, fmt.Errorf("failed to parse osquery output: %w", err)
	}

	// Convert to OSQueryRow
	rows := make([]*pb.OSQueryRow, 0, len(results))
	for _, result := range results {
		rows = append(rows, &pb.OSQueryRow{Data: result})
	}

	return rows, nil
}

// QueryTable queries a specific table by name.
func (c *Client) QueryTable(ctx context.Context, tableName string) ([]*pb.OSQueryRow, error) {
	sql, ok := tableSQL[tableName]
	if !ok {
		sql = fmt.Sprintf("SELECT * FROM %s", tableName)
	}
	return c.QuerySQL(ctx, sql)
}

// execQuery executes an osquery command via sudo and returns the output.
// Running with sudo allows osquery to access tables that require root
// privileges (e.g. authorized_keys, iptables).
func (c *Client) execQuery(ctx context.Context, query string) (string, error) {
	// Create context with timeout if none set
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	// Build command arguments
	// --json: output in JSON format (for SQL queries)
	// --line: for .tables command
	args := []string{}

	if strings.HasPrefix(query, ".") {
		// Meta command like .tables
		args = append(args, query)
	} else {
		// SQL query - use JSON output
		args = append(args, "--json", query)
	}

	result, err := sysexec.Sudo(ctx, c.binaryPath, args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = result.Stderr
		}
		if stderr != "" {
			return "", fmt.Errorf("%w: %s", ErrQueryFailed, stderr)
		}
		return "", fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	return strings.TrimSpace(result.Stdout), nil
}

// Registry provides backwards compatibility with the old interface.
// It wraps the Client and provides the same Query method signature.
type Registry struct {
	client *Client
}

// NewRegistry creates a new Registry.
// Returns an error if osquery is not installed.
func NewRegistry() (*Registry, error) {
	client, err := NewClient()
	if err != nil {
		return nil, err
	}
	return &Registry{client: client}, nil
}

// Query executes a query against an osquery table.
func (r *Registry) Query(query *pb.OSQuery) (*pb.OSQueryResult, error) {
	return r.client.Query(context.Background(), query)
}

// ListTables returns available osquery tables.
func (r *Registry) ListTables() ([]string, error) {
	return r.client.ListTables(context.Background())
}

// QueryTable queries a specific table by name.
func (r *Registry) QueryTable(tableName string) ([]*pb.OSQueryRow, error) {
	return r.client.QueryTable(context.Background(), tableName)
}
