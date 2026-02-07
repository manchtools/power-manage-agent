# Power Manage Agent

The Power Manage Agent runs on managed devices and executes actions dispatched from the Control Server. It supports autonomous operation, executing scheduled actions even when disconnected from the server.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Agent                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   Handler   │  │  Scheduler  │  │       Executor          │  │
│  │             │  │             │  │                         │  │
│  │ - Server    │  │ - Cron/     │  │ - Package management    │  │
│  │   commands  │  │   Interval  │  │ - Shell scripts         │  │
│  │ - Reports   │  │   execution │  │ - File management       │  │
│  │   results   │  │ - Offline   │  │ - Systemd units         │  │
│  └─────────────┘  │   capable   │  │ - App installations     │  │
│         │         └──────┬──────┘  │ - System updates        │  │
│         │                │         └───────────┬─────────────┘  │
│         └────────────────┴─────────────────────┘                │
│                          │                                      │
│                    ┌─────▼─────┐                                │
│                    │  Results  │                                │
│                    │   Store   │                                │
│                    └───────────┘                                │
└───────────┬─────────────────────────────────┬───────────────────┘
            │ (1) Register                    │ (2) Stream
            ▼                                 ▼
┌───────────────────────────┐   ┌─────────────────────────────────┐
│  Control Server (RPC)     │   │   Gateway Server (mTLS gRPC)    │
│  - Token validation       │   │   - Bidirectional streaming     │
│  - Certificate signing    │   │   - Action dispatch             │
│  - Returns gateway URL    │   │   - Heartbeats & results        │
└───────────────────────────┘   └─────────────────────────────────┘
```

### Registration Flow

1. The agent calls the **Control Server** `Register` RPC with a registration token and CSR
2. The Control Server validates the token, signs the certificate, and returns:
   - Device ID
   - Signed mTLS certificate
   - CA certificate
   - Gateway URL
3. The agent stores the credentials and connects to the **Gateway** using mTLS for streaming communication

## Installation

### Using the Install Script

```bash
# Download and run the install script
curl -fsSL https://your-server/install.sh | sudo bash -s -- \
  --server control.example.com:8081 \
  --token YOUR_REGISTRATION_TOKEN
```

### Manual Installation

```bash
# Build the agent
go build -o power-manage-agent ./agent/cmd/agent

# Run with registration
./power-manage-agent -server=https://control.example.com:8081 -token=YOUR_TOKEN
```

### Using URI Scheme

The agent supports a URI scheme for easy registration:

```bash
power-manage-agent 'power-manage://control.example.com:8081?token=abc123'
```

URI Parameters:
- `server:port` - Control server address (required)
- `token` - Registration token (required for first run)
- `skip-verify=true` - Skip TLS verification (development only)
- `tls=false` - Use HTTP instead of HTTPS

## Configuration

### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | (required) | Control server URL (used for registration) |
| `-token` | (optional) | Registration token (first run only) |
| `-data-dir` | `/var/lib/power-manage` | Data directory for state |
| `-skip-verify` | `false` | Skip TLS certificate verification |
| `-log-level` | `info` | Log level (debug, info, warn, error) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `PM_SERVER` | Control server URL (used for registration) |
| `PM_TOKEN` | Registration token |
| `PM_DATA_DIR` | Data directory |
| `PM_SKIP_VERIFY` | Skip TLS verification |
| `PM_LOG_LEVEL` | Log level |

## Action Types

The agent supports various action types for managing the system:

### Package Management (`PACKAGE`)

Install, update, or remove system packages using the detected package manager (apt, dnf, or pacman).

| Field | Description |
|-------|-------------|
| `name` | Package name |
| `version` | Optional version constraint |
| `allow_downgrade` | Allow downgrading to specified version |

**Desired State:**
- `PRESENT`: Install or update the package, optionally pin to version
- `ABSENT`: Unpin and remove the package

### System Update (`UPDATE`)

Perform system-wide package updates.

| Field | Description |
|-------|-------------|
| `security_only` | Only install security updates |
| `autoremove` | Remove unused dependencies after update |
| `reboot_if_required` | Automatically reboot if required |

**Desired State:** Not applicable - updates always run forward.

### Shell Script (`SHELL`)

Execute arbitrary shell scripts on the device.

| Field | Description |
|-------|-------------|
| `script` | The script content to execute |
| `interpreter` | Interpreter path (default: `/bin/bash`) |
| `run_as_root` | Execute with root privileges |

**Desired State:** Not applicable - scripts execute the same regardless of state. Implement conditional logic within the script if needed.

### Systemd Unit (`SYSTEMD`)

Manage systemd service units.

| Field | Description |
|-------|-------------|
| `unit_name` | Name of the systemd unit (e.g., `nginx.service`) |
| `desired_state` | Unit state: `RUNNING`, `STOPPED`, or `RESTARTED` |
| `enable` | Enable unit to start on boot |

**Desired State:** Not applicable - uses separate `SystemdUnitState` enum for unit-specific states.

### File Management (`FILE`)

Create, modify, or remove files on the system.

| Field | Description |
|-------|-------------|
| `path` | Absolute path to the file |
| `content` | File contents (for PRESENT state) |
| `owner` | File owner (username) |
| `group` | File group |
| `mode` | File permissions (e.g., `0644`) |

**Desired State:**
- `PRESENT`: Create or update the file with specified content and permissions
- `ABSENT`: Remove the file

### App Image (`APP_IMAGE`)

Download and install standalone application binaries.

| Field | Description |
|-------|-------------|
| `url` | Download URL |
| `checksum_sha256` | Optional SHA256 checksum for verification |
| `install_path` | Installation path |

**Desired State:**
- `PRESENT`: Download and install the application
- `ABSENT`: Remove the installed file

### DEB Package (`DEB`)

Install or remove Debian packages directly from URLs.

| Field | Description |
|-------|-------------|
| `url` | Download URL for the .deb file |

**Desired State:**
- `PRESENT`: Download and install with `dpkg`
- `ABSENT`: Remove the package

### RPM Package (`RPM`)

Install or remove RPM packages directly from URLs.

| Field | Description |
|-------|-------------|
| `url` | Download URL for the .rpm file |

**Desired State:**
- `PRESENT`: Download and install with `rpm`
- `ABSENT`: Remove the package

## Desired State Summary

| Action Type | Supports Desired State | PRESENT | ABSENT |
|-------------|------------------------|---------|--------|
| `PACKAGE` | Yes | Install/pin package | Unpin and remove |
| `APP_IMAGE` | Yes | Download and install | Remove file |
| `DEB` | Yes | Install package | Remove package |
| `RPM` | Yes | Install package | Remove package |
| `FILE` | Yes | Create/update file | Remove file |
| `SHELL` | No | Execute script | Execute script (same) |
| `UPDATE` | No | Run update | Run update (same) |
| `SYSTEMD` | No | Uses `SystemdUnitState` | Uses `SystemdUnitState` |

## Scheduling

Actions can be configured with schedules for autonomous execution on the agent. The scheduler operates independently and continues running actions even when disconnected from the server. Results are stored locally and synced when connection is restored.

### Schedule Fields

| Field | Description |
|-------|-------------|
| `cron` | Cron expression (e.g., `0 2 * * *` for 2 AM daily) |
| `interval_hours` | Run every N hours (alternative to cron, default: 8 hours) |
| `run_on_assign` | Execute immediately when first assigned, then follow the schedule |
| `skip_if_unchanged` | Skip scheduled execution if system state already matches desired state |

### Run on Assign

When enabled, the action executes immediately when it is first assigned to a device, rather than waiting for the first scheduled interval. After the initial execution, the action follows its normal schedule.

**Use case**: You want a package installed right away when assigning the action to new devices, but also want periodic checks to ensure it stays installed.

### Skip if Unchanged

When enabled, the scheduler checks if the system state already matches the desired state before executing. If nothing needs to change, the execution is skipped.

**Examples**:
- Package action with `PRESENT` state: Skip if the package is already installed
- File action with `PRESENT` state: Skip if the file already exists with correct content
- Systemd action with `RUNNING` state: Skip if the service is already running

**Use case**: Reduce unnecessary operations for idempotent actions that run frequently. Instead of reinstalling a package every 4 hours, only act when the package is missing or changed.

## Package Manager Detection

The agent automatically detects the system's package manager:

| Distribution | Package Manager |
|--------------|-----------------|
| Debian, Ubuntu | apt |
| Fedora, RHEL, CentOS | dnf |
| Arch Linux | pacman |

## Security

- **Registration**: Agent registers with the Control Server over HTTPS, authenticating with a registration token
- **mTLS**: After registration, the agent connects to the Gateway using mutual TLS with certificates signed by the Control Server CA
- **Certificate Storage**: Certificates stored in `$DATA_DIR/certs/`
- **Privileged Operations**: Some actions require root privileges (systemd, package management)

## Logging

Logs are written to stdout/stderr and can be collected by systemd journal:

```bash
# View agent logs
journalctl -u power-manage-agent -f
```

## Data Directory Structure

```
/var/lib/power-manage/
├── certs/
│   ├── device.crt      # Device certificate
│   └── device.key      # Device private key
├── state.json          # Agent state
└── results/            # Pending execution results
```

## Systemd Service

The install script creates a systemd service:

```ini
[Unit]
Description=Power Manage Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/power-manage-agent
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Manage with:

```bash
sudo systemctl start power-manage-agent
sudo systemctl stop power-manage-agent
sudo systemctl status power-manage-agent
sudo systemctl enable power-manage-agent
```
