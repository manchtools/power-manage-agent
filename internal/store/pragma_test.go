package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// foreign_keys is a per-CONNECTION pragma in SQLite. Setting it once via
// db.Exec only affects whichever pooled connection served that call, so
// concurrent readers that open additional connections get FK enforcement
// OFF — making ON DELETE CASCADE fire or not depending on which
// connection a statement lands on. It must be set on the DSN so every
// connection in the pool has it.
func TestStore_ForeignKeysOnEveryConnection(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	// Hold several connections open simultaneously to force the pool to
	// allocate distinct ones, then assert each enforces foreign keys.
	const n = 5
	conns := make([]*sql.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, err := st.db.Conn(context.Background())
		require.NoError(t, err)
		conns = append(conns, c)
	}
	for i, c := range conns {
		var fk int
		require.NoError(t, c.QueryRowContext(context.Background(), "PRAGMA foreign_keys").Scan(&fk))
		assert.Equal(t, 1, fk, "connection %d must have foreign_keys ON", i)
		require.NoError(t, c.Close())
	}
}

// busy_timeout and journal_mode=WAL are DSN pragmas (so they apply to every
// pooled connection). busy_timeout is what lets the CLI subcommands (tty/luks)
// wait for the daemon's writer instead of failing immediately with
// SQLITE_BUSY; WAL keeps readers and the writer from blocking each other. Pin
// both per-connection so dropping either from the DSN is caught.
func TestStore_BusyTimeoutAndWalOnEveryConnection(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	const n = 5
	conns := make([]*sql.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, err := st.db.Conn(context.Background())
		require.NoError(t, err)
		conns = append(conns, c)
	}
	for i, c := range conns {
		var busy int
		require.NoError(t, c.QueryRowContext(context.Background(), "PRAGMA busy_timeout").Scan(&busy))
		assert.Equal(t, 5000, busy, "connection %d must carry busy_timeout=5000", i)

		var journal string
		require.NoError(t, c.QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&journal))
		assert.Equal(t, "wal", strings.ToLower(journal), "connection %d must be in WAL journal mode", i)

		require.NoError(t, c.Close())
	}
}
