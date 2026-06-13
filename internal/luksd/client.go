package luksd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// PassphraseReader collects the user's chosen passphrase (e.g. an
// interactive terminal prompt with confirmation + retries). It returns an
// empty string with a nil error if the user failed to provide a matching
// passphrase, so the client refuses to send. Injectable for tests.
type PassphraseReader func() (string, error)

// Client is the UNPRIVILEGED side run by `power-manage-agent luks
// set-passphrase`. It collects the passphrase and sends EXACTLY
// {token, passphrase} to the root daemon socket — never credentials, a
// data dir, or a store path. All privileged work happens in the daemon.
type Client struct {
	socketPath string
	dialer     func() (net.Conn, error)
	now        func() time.Time // clock seam; defaults to time.Now
}

// NewClient returns a client for the given socket path.
func NewClient(socketPath string) *Client {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	c := &Client{socketPath: socketPath, now: time.Now}
	c.dialer = func() (net.Conn, error) {
		return net.DialTimeout("unix", c.socketPath, 5*time.Second)
	}
	return c
}

// SetPassphrase collects the passphrase via read and submits it with the
// token to the daemon. It returns nil on success and surfaces the
// daemon's error otherwise. An empty passphrase (read failed/aborted) is
// refused without contacting the daemon.
func (c *Client) SetPassphrase(token string, read PassphraseReader) error {
	if token == "" {
		return errors.New("token is required")
	}
	passphrase, err := read()
	if err != nil {
		return err
	}
	if passphrase == "" {
		return errors.New("no passphrase provided")
	}

	conn, err := c.dialer()
	if err != nil {
		return fmt.Errorf("connect to LUKS daemon at %s: %w (is the agent running?)", c.socketPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(c.now().Add(60 * time.Second))

	if err := json.NewEncoder(conn).Encode(Request{Token: token, Passphrase: passphrase}); err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if !resp.OK {
		if resp.Error != "" {
			return errors.New(resp.Error)
		}
		return fmt.Errorf("LUKS daemon rejected the request (%s)", resp.Code)
	}
	return nil
}
