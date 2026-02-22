# Power Manage Agent

The Power Manage Agent runs on managed devices and executes actions dispatched from the Control Server. It supports autonomous operation, executing scheduled actions even when disconnected from the server.

## Architecture

The executor delegates low-level system operations to the SDK's `sys/` packages (`sys/exec`, `sys/fs`, `sys/user`, `sys/systemd`), keeping the agent focused on action dispatch, idempotency checks, and result reporting.

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
│  └─────────────┘  │   capable   │  │ - User/group management │  │
│         │         └──────┬──────┘  │ - SSH/sudo policies     │  │
│         │                │         └───────────┬─────────────┘  │
│         └────────────────┴─────────────────────┘                │
│                          │              │                       │
│                    ┌─────▼─────┐  ┌─────▼──────────────┐       │
│                    │  Results  │  │  SDK sys/ packages  │       │
│                    │   Store   │  │  (exec, fs, user,   │       │
│                    └───────────┘  │   systemd)          │       │
│                                   └────────────────────┘       │
└───────────┬─────────────────────────────────────┬───────────────┘
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

The agent supports 16 action types for managing the system:

### Package Management (`PACKAGE`)

Install, update, or remove system packages using the detected package manager (apt, dnf, pacman, or zypper).

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
| `timeout_seconds` | Maximum execution time (default: 300s) |

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

### Directory Management (`DIRECTORY`)

Create or remove directories on the system.

| Field | Description |
|-------|-------------|
| `path` | Absolute path to the directory |
| `owner` | Directory owner (username) |
| `group` | Directory group |
| `mode` | Directory permissions (e.g., `0755`) |

**Desired State:**
- `PRESENT`: Create or update the directory with specified ownership and permissions
- `ABSENT`: Remove the directory

### User Management (`USER`)

Create, modify, or remove system users.

| Field | Description |
|-------|-------------|
| `username` | Login name |
| `comment` | Full name / GECOS field |
| `shell` | Login shell (e.g., `/bin/bash`) |
| `groups` | Supplementary groups |

On creation, a temporary password is generated and returned in the `lps.rotations` metadata field. The `power-manage` system user is protected from deletion.

**Desired State:**
- `PRESENT`: Create the user or update attributes (shell, groups, comment)
- `ABSENT`: Delete the user and remove their home directory

### Group Management (`GROUP`)

Create, modify, or remove system groups.

| Field | Description |
|-------|-------------|
| `name` | Group name |
| `members` | List of usernames to add as group members |

The `power-manage` system group is protected from deletion.

**Desired State:**
- `PRESENT`: Create the group or update membership
- `ABSENT`: Delete the group

### Sudo Policy (`SUDO`)

Manage per-action sudoers policies in `/etc/sudoers.d/`.

| Field | Description |
|-------|-------------|
| `access_level` | `FULL` (unrestricted) or `LIMITED` (specific commands only) |
| `users` | Users to grant sudo access |
| `commands` | Allowed commands (for LIMITED access) |

Each policy is installed as a separate file, validated with `visudo -c` before activation. A dedicated group is created for each policy and users are added to it.

**Desired State:**
- `PRESENT`: Install or update the sudoers policy
- `ABSENT`: Remove the sudoers file and associated group

### SSH Access (`SSH`)

Manage per-action SSH access policies in `/etc/ssh/sshd_config.d/`.

| Field | Description |
|-------|-------------|
| `users` | Users to grant SSH access |
| `allow_pubkey` | Allow public key authentication |
| `allow_password` | Allow password authentication |

Creates a dedicated group per policy and adds an `sshd_config.d` snippet restricting access. The SSHD config is validated with `sshd -t` before applying.

**Desired State:**
- `PRESENT`: Install or update the SSH access policy
- `ABSENT`: Remove the SSH config snippet and associated group

### SSHD Configuration (`SSHD`)

Manage global SSHD configuration directives in `/etc/ssh/sshd_config.d/`.

| Field | Description |
|-------|-------------|
| `priority` | Config file priority (0-9999, lower = applied first) |
| `directives` | Map of SSHD directive key-value pairs |

Configuration is validated with `sshd -t` before applying and the service is reloaded.

**Desired State:**
- `PRESENT`: Install or update the SSHD configuration
- `ABSENT`: Remove the configuration snippet

### Local Password Store (`LPS`)

Automated password rotation with encrypted state tracking.

| Field | Description |
|-------|-------------|
| `usernames` | Users whose passwords to manage |
| `password_length` | Generated password length |
| `complexity` | `ALPHANUMERIC` or `COMPLEX` |
| `rotation_interval_days` | Days between rotations |

Rotated passwords are returned in the `lps.rotations` metadata field and stored encrypted on the server. The LPS state is tracked per-action in `/var/lib/power-manage/lps/`.

**Desired State:**
- `PRESENT`: Rotate passwords if the rotation interval has elapsed
- `ABSENT`: Remove LPS state tracking (does not change existing passwords)

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

### LUKS Disk Encryption (`LUKS`)

Manage LUKS disk encryption on the device. The agent auto-detects the primary LUKS-encrypted volume, generates a managed passphrase stored on the server, and rotates it on schedule. Optionally, a device-bound key (TPM or user passphrase) can be enrolled in LUKS slot 7.

| Field | Description |
|-------|-------------|
| `preshared_key` | Pre-shared key for initial ownership (agent uses this to authenticate against the volume on first run) |
| `rotation_interval_days` | Days between scheduled passphrase rotations (1–365) |
| `min_words` | Minimum words in generated managed passphrase (default 5, range 3–10) |
| `device_bound_key_type` | What goes in LUKS slot 7: `NONE`, `TPM` (auto-unlock at boot), or `USER_PASSPHRASE` (user-defined via CLI) |
| `user_passphrase_min_length` | Minimum length for user-defined passphrases (16–128, only for `USER_PASSPHRASE` type) |
| `user_passphrase_complexity` | Complexity requirement for user-defined passphrases (`ALPHANUMERIC` or `COMPLEX`) |

The agent communicates with the server via bidirectional stream messages (`GetLuksKey`, `StoreLuksKey`) to retrieve and store managed passphrases. Key rotation only proceeds after the server confirms receipt of the new passphrase, preventing key loss.

**Desired State:**
- `PRESENT`: Take ownership of the LUKS volume, rotate the managed passphrase if the interval has elapsed
- `ABSENT`: Remove LUKS state tracking (does not modify the LUKS volume itself)

### Repository (`REPOSITORY`)

Manage package manager repositories.

| Field | Description |
|-------|-------------|
| `name` | Repository identifier |
| `apt` | APT repository config (url, distribution, components, gpg_key, trusted) |
| `dnf` | DNF repository config (baseurl, gpgkey, gpgcheck) |
| `pacman` | Pacman repository config (server, sig_level) |
| `zypper` | Zypper repository config (baseurl, gpgkey, gpgcheck) |

Only one repository type should be set per action. The matching type is determined by the detected package manager.

**Desired State:**
- `PRESENT`: Add or update the repository configuration
- `ABSENT`: Remove the repository configuration and GPG keys

## Desired State Summary

| Action Type | Supports Desired State | PRESENT | ABSENT |
|-------------|------------------------|---------|--------|
| `PACKAGE` | Yes | Install/pin package | Unpin and remove |
| `APP_IMAGE` | Yes | Download and install | Remove file |
| `DEB` | Yes | Install package | Remove package |
| `RPM` | Yes | Install package | Remove package |
| `FILE` | Yes | Create/update file | Remove file |
| `DIRECTORY` | Yes | Create/update directory | Remove directory |
| `USER` | Yes | Create/update user | Delete user |
| `GROUP` | Yes | Create/update group | Delete group |
| `SUDO` | Yes | Install sudoers policy | Remove policy |
| `SSH` | Yes | Install SSH access policy | Remove policy |
| `SSHD` | Yes | Install SSHD config | Remove config |
| `LPS` | Yes | Rotate passwords | Remove state tracking |
| `LUKS` | Yes | Take ownership, rotate passphrase | Remove state tracking |
| `REPOSITORY` | Yes | Add/update repository | Remove repository |
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
| openSUSE | zypper |

## Security

### Dedicated Service User

The agent runs as a dedicated `power-manage` system user with restricted sudo access. The install script (`power-manage-agent setup`) creates:

- A `power-manage` system user with `/usr/sbin/nologin` shell
- A sudoers policy at `/etc/sudoers.d/power-manage` granting access only to specific commands

The sudoers template (`internal/setup/sudoers.tmpl`) restricts access to:
- Package managers (apt, dnf, pacman, zypper, flatpak)
- Systemd service management (start, stop, restart, reload, enable, disable, status, daemon-reload)
- File operations (tee, chown, chmod, mkdir, rm, cp, mv, cat)
- System information (ss, lsof)
- Process management (pkill, loginctl)
- User/group management (useradd, usermod, userdel, groupadd, groupdel, gpasswd, chpasswd, chage, getent)
- Sudoers/SSHD validation (visudo, sshd)
- Shell execution for `run_as_root` scripts (bash, sh)
- Filesystem repair (mount -o remount,rw /)
- System power management (shutdown)
- LUKS disk encryption management (cryptsetup)

All privileged commands are executed via `sudo -n` with absolute paths for sudoers matching. The agent itself never runs as root.

### Self-Protection

The agent prevents actions from modifying its own infrastructure:
- The `power-manage` user and group cannot be deleted via USER/GROUP actions
- This prevents accidental self-destruction through misconfigured actions

### Network Security

- **Registration**: Agent registers with the Control Server over HTTPS, authenticating with a registration token
- **mTLS**: After registration, the agent connects to the Gateway using mutual TLS with certificates signed by the Control Server CA
- **Certificate Storage**: Certificates stored in `$DATA_DIR/certs/`

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
├── lps/                 # LPS password rotation state (per-action JSON files)
├── luks/                # LUKS encryption state (per-action SQLite databases)
├── state.json           # Agent state
└── results/             # Pending execution results
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
User=power-manage
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

## Development

### Building

```bash
# Build for current platform
make build

# Cross-compile for ARM64
make build GOARCH=arm64
```

### Deploying to a Test Server

```bash
# Build + deploy + restart on remote machine
make deploy SSH=user@testserver

# Full install (including setup)
make install SSH=user@testserver
```

### Running Integration Tests

The agent includes a comprehensive integration test suite that runs inside Docker/Podman containers. Tests execute as the `power-manage` user with the production sudoers template, ensuring the test environment matches production exactly.

```bash
# Run tests on a single distro
make test-integration-debian
make test-integration-fedora
make test-integration-opensuse
make test-integration-archlinux

# Run all 4 distros in parallel
make test-integration-all

# Run privileged edge case tests (requires --privileged container)
make test-integration-edgecase
```

### CI/CD

Integration tests run automatically on push to `main` and on pull requests via GitHub Actions (`.github/workflows/integration-test.yml`). The workflow is triggered only on actual code changes (Go files, go.mod/sum, Makefile, cmd/**, test/**, internal/**).

The release workflow (`.github/workflows/release.yml`) gates binary builds on passing integration tests, ensuring no release is published without all tests passing across all 4 distros.

## Integration Test Suite

The test suite (`internal/executor/integration_test.go`, ~3,500 lines) exercises the executor against real system state inside containerized environments. Each test container mimics the production setup: a `power-manage` system user with the real sudoers template from `internal/setup/sudoers.tmpl`, so any missing sudo permission causes an immediate test failure.

### Test Containers

Each distro has its own Dockerfile in `test/`:

| Container | Dockerfile | Base Image | Package Manager |
|-----------|------------|------------|-----------------|
| Debian | `Dockerfile.integration` | `golang:1.25-bookworm` | apt |
| Fedora | `Dockerfile.integration.fedora` | `fedora:latest` | dnf |
| openSUSE | `Dockerfile.integration.opensuse` | `opensuse/tumbleweed` | zypper |
| Arch Linux | `Dockerfile.integration.archlinux` | `archlinux:base` | pacman |

Container setup:
1. Install Go toolchain and test dependencies
2. Create `power-manage` system user (matching production)
3. Install the real sudoers template rendered with `sed 's/{{.User}}/power-manage/g'`
4. Install test-only sudoers for mount/umount/chattr (edge case tests only)
5. Create LPS state directory owned by `power-manage`
6. Set up SSHD host keys and config directory for validation tests
7. Pre-download Go module dependencies

Tests run via `runuser -u power-manage -- go test ...`, so every privileged operation must go through sudo, exactly as in production.

### Core Action Tests

These tests verify the full lifecycle (create, idempotent re-run, update, remove) for each action type:

| Test | Action Type | What It Verifies |
|------|-------------|------------------|
| `TestIntegration_Package` | PACKAGE | Install, idempotent re-install, remove via apt |
| `TestIntegration_Package_Dnf` | PACKAGE | Install, idempotent re-install, remove via dnf |
| `TestIntegration_Package_Pacman` | PACKAGE | Install, idempotent re-install, remove via pacman |
| `TestIntegration_Package_Zypper` | PACKAGE | Install, idempotent re-install, remove via zypper |
| `TestIntegration_Package_GracefulSkip` | PACKAGE | Graceful handling when package is not in any repo (apt) |
| `TestIntegration_Package_GracefulSkip_Dnf` | PACKAGE | Graceful handling when package is not in any repo (dnf) |
| `TestIntegration_Package_GracefulSkip_Pacman` | PACKAGE | Graceful handling when package is not in any repo (pacman) |
| `TestIntegration_Package_GracefulSkip_Zypper` | PACKAGE | Graceful handling when package is not in any repo (zypper) |
| `TestIntegration_Update` | UPDATE | System update via apt |
| `TestIntegration_Update_Dnf` | UPDATE | System update via dnf |
| `TestIntegration_Update_Pacman` | UPDATE | System update via pacman |
| `TestIntegration_Update_Zypper` | UPDATE | System update via zypper |
| `TestIntegration_Shell` | SHELL | Basic execution, exit code handling, stderr capture, timeout, `run_as_root`, working directory, environment variables, multi-line scripts |
| `TestIntegration_File` | FILE | Create with content/owner/group/mode, idempotent re-create, update content, remove, binary content |
| `TestIntegration_Directory` | DIRECTORY | Create with owner/group/mode, idempotent re-create, update permissions, nested directories, remove, remove non-existent |
| `TestIntegration_User` | USER | Create, idempotent re-create, update shell, remove, remove non-existent, protect `power-manage` |
| `TestIntegration_Group` | GROUP | Create, idempotent re-create, add members, remove, protect `power-manage` |
| `TestIntegration_Sudo` | SUDO | Full-access policy setup, idempotent re-setup, remove (sudoers file + group) |
| `TestIntegration_SSH` | SSH | Access policy setup (group + sshd_config.d snippet), idempotent re-setup, remove |
| `TestIntegration_SSHD` | SSHD | Config directives setup, idempotent re-setup, `sshd -t` validation, remove |
| `TestIntegration_LPS` | LPS | Initial password rotation, idempotent skip (interval not elapsed), remove state |
| `TestIntegration_Deb` | DEB | Build test .deb, serve via HTTP, install via dpkg, remove |
| `TestIntegration_Rpm` | RPM | Build test .rpm via rpmbuild, serve via HTTP, install, remove |
| `TestIntegration_AppImage` | APP_IMAGE | Download with checksum verification, install to custom path, idempotent, remove |
| `TestIntegration_Repository` | REPOSITORY | Add/remove apt sources.list.d entry |
| `TestIntegration_Repository_Dnf` | REPOSITORY | Add/remove dnf .repo file |
| `TestIntegration_Repository_Pacman` | REPOSITORY | Add/remove pacman.conf server entry |
| `TestIntegration_Repository_Zypper` | REPOSITORY | Add/remove zypper repository |
| `TestIntegration_Systemd` | SYSTEMD | Unit file creation, daemon-reload, start, status check, stop, remove, invalid unit handling |

### Edge Case Tests

These tests verify resilience against real-world failure conditions. Some require `--privileged` containers:

**Package manager lock recovery:**
| Test | Description |
|------|-------------|
| `EdgeCase_AptLock` | Stale `/var/lib/dpkg/lock*` files are cleaned up before install |
| `EdgeCase_PacmanLock` | Stale `/var/lib/pacman/db.lck` is removed before install |
| `EdgeCase_ZypperLock` | Stale `/var/run/zypp.pid` is removed before install |
| `EdgeCase_DnfStaleHistory` | DNF repair path (`history redo`, `remove --duplicates`, `rpm --verifydb`) runs cleanly |
| `EdgeCase_InterruptedDpkg` | `dpkg --configure -a` repairs interrupted dpkg state |
| `EdgeCase_InterruptedDpkgConfigure` | Partial dpkg configure is repaired before package install |
| `EdgeCase_PackagePinConflict` | Package version pinning conflict is handled gracefully |

**LPS state corruption:**
| Test | Description |
|------|-------------|
| `EdgeCase_LpsInvalidJson` | Corrupted JSON state file is treated as initial rotation |
| `EdgeCase_LpsMissingDirectory` | Missing `/var/lib/power-manage/lps/` directory is re-created |

**Missing system directories:**
| Test | Description |
|------|-------------|
| `EdgeCase_MissingSudoersDir` | Missing `/etc/sudoers.d/` is re-created before policy install |
| `EdgeCase_MissingSshdConfigDir` | Missing `/etc/ssh/sshd_config.d/` is re-created before config install |

**Download failures:**
| Test | Description |
|------|-------------|
| `EdgeCase_DownloadHttp500` | HTTP 500 from download server returns FAILED status |
| `EdgeCase_DownloadHttp404` | HTTP 404 returns FAILED status |
| `EdgeCase_DownloadChecksumMismatch` | SHA256 checksum mismatch is detected and reported |
| `EdgeCase_DownloadTimeout` | Slow/hanging server is handled with timeout |
| `EdgeCase_DNSResolutionFailure` | Unresolvable hostname returns FAILED status |
| `EdgeCase_HTTPSCertError` | Invalid TLS certificate returns FAILED status |

**Invalid input:**
| Test | Description |
|------|-------------|
| `EdgeCase_NilParams` | Nil action params for all types return FAILED status |
| `EdgeCase_InvalidUsername` | Usernames with special characters (`../`, `;`, etc.) are rejected |
| `EdgeCase_InvalidPaths` | Path traversal (`../../etc/passwd`), relative paths, and empty paths are rejected |
| `EdgeCase_SystemdInvalidUnit` | Invalid systemd unit names are rejected |

**Filesystem edge cases (require `--privileged`):**
| Test | Description |
|------|-------------|
| `EdgeCase_DiskFull` | File write to a full tmpfs reports clear error |
| `EdgeCase_ReadOnlyMount` | File write to read-only filesystem reports clear error |
| `EdgeCase_ImmutableFile` | Overwriting a `chattr +i` immutable file reports clear error |
| `EdgeCase_SymlinkCircular` | Circular symlink at target path is detected |
| `EdgeCase_VeryLongFilePath` | Paths exceeding filesystem limits are handled |

**User/group edge cases:**
| Test | Description |
|------|-------------|
| `EdgeCase_UserExistsDifferentShell` | Updating a user's shell correctly reports `changed=true` |
| `EdgeCase_UserDeleteWhileLoggedIn` | Deleting a user with active sessions terminates sessions first |
| `EdgeCase_GroupIsPrimaryGroup` | Deleting a user's primary group returns clear error |

**File content edge cases:**
| Test | Description |
|------|-------------|
| `EdgeCase_FileExistsDifferentPerms` | Updating permissions on existing file reports `changed=true` |
| `EdgeCase_FileExistsAsDirectory` | Writing file to path that is a directory returns FAILED |
| `EdgeCase_EmptyFileContent` | Empty content creates a zero-byte file |
| `EdgeCase_BinaryFileContent` | Binary content with null bytes is written correctly |
| `EdgeCase_ConcurrentFileWrites` | Parallel file writes to different paths all succeed (atomic write safety) |

**SSH/sudo edge cases:**
| Test | Description |
|------|-------------|
| `EdgeCase_BrokenSudoersFile` | Pre-existing broken sudoers file is replaced with valid policy |
| `EdgeCase_SSHDirWrongPermissions` | `~/.ssh` directory with wrong permissions is corrected |

**Other edge cases:**
| Test | Description |
|------|-------------|
| `EdgeCase_ShellTimeout` | Shell script exceeding timeout is killed |
| `EdgeCase_LargeShellOutput` | Large stdout/stderr output is captured without truncation or hang |
| `EdgeCase_PartialAppImage` | Incomplete download leaves no partial file on disk |
| `EdgeCase_RepositoryExpiredGPGKey` | Expired GPG key is handled gracefully |
