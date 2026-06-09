package store

import (
	"context"
	"database/sql"
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
