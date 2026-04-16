package store

// TTYSettingKey is the settings row key storing the local TTY toggle state.
// Value is "1" when enabled, any other value (including absent) means disabled.
//
// The toggle is device-local — only the agent process (running as
// power-manage) can write it, so enable/disable is invoked via the
// power-manage-agent CLI which requires sudo or equivalent privilege
// escalation to the power-manage user. The server cannot flip this flag
// directly; it can only request the flip via a shell action, which still
// runs as the agent user on the device.
const TTYSettingKey = "tty.enabled"

// IsTTYEnabled returns true if remote terminal sessions are enabled on
// this device. Default (no row set) is false — terminals are off until
// a local admin explicitly enables them.
func (s *Store) IsTTYEnabled() (bool, error) {
	v, err := s.GetSetting(TTYSettingKey)
	if err != nil {
		return false, err
	}
	return v == "1", nil
}

// SetTTYEnabled toggles the TTY state. Passing true enables, false disables.
func (s *Store) SetTTYEnabled(enabled bool) error {
	v := "0"
	if enabled {
		v = "1"
	}
	return s.SetSetting(TTYSettingKey, v)
}
