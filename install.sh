#!/bin/bash
#
# Power Manage Agent Installation Script
#
# Downloads the agent binary, installs it as a systemd service, and optionally
# registers with a control server — all in one step.
#
# One-liner install (stable):
#   curl -fsSL https://github.com/MANCHTOOLS/power-manage-agent/releases/latest/download/install.sh | sudo bash -s -- -s https://your-server.example.com -t YOUR_TOKEN
#
# One-liner install (prerelease):
#   curl -fsSL https://github.com/MANCHTOOLS/power-manage-agent/releases/latest/download/install.sh | sudo bash -s -- --pre -s https://your-server.example.com -t YOUR_TOKEN
#
# Usage:
#   sudo ./install.sh [OPTIONS]
#
# Options:
#   -t, --token TOKEN       Registration token for initial setup
#   -s, --server URL        Control server URL (e.g., https://control.example.com:8081)
#   -v, --version VERSION   Version to install (default: latest)
#   --pre                   Install the latest prerelease (release candidate) version
#   -d, --data-dir DIR      Data directory (default: /var/lib/power-manage)
#   -b, --binary PATH       Path to the agent binary (default: /usr/local/bin/power-manage-agent)
#   --skip-download         Skip downloading the binary (use existing binary at --binary path)
#   --uninstall             Remove the agent and all configuration
#   -h, --help              Show this help message
#

set -e

GITHUB_REPO="MANCHTOOLS/power-manage-agent"

# Default values
DATA_DIR="/var/lib/power-manage"
BINARY_PATH="/usr/local/bin/power-manage-agent"
SERVICE_NAME="power-manage-agent"
REGISTRATION_TOKEN=""
SERVER_URL=""
SKIP_DOWNLOAD=""
PRE_RELEASE=""
VERSION="latest"
# WS7 #4: the power-manage:// desktop URI handler is OPT-IN and OFF by
# default — an unconditional handler exposes the root-capable binary to
# drive-by browser links. Enable with --enable-uri-handler or
# POWER_MANAGE_ENABLE_URI_HANDLER=true.
ENABLE_URI_HANDLER="${POWER_MANAGE_ENABLE_URI_HANDLER:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

show_help() {
    cat << EOF
Power Manage Agent Installation Script

Usage:
  sudo ./install.sh [OPTIONS]

  One-liner:
  curl -fsSL https://github.com/${GITHUB_REPO}/releases/latest/download/install.sh | sudo bash -s -- -s URL -t TOKEN

Options:
  -t, --token TOKEN       Registration token for initial setup
  -s, --server URL        Control server URL (e.g., https://control.example.com:8081)
  -v, --version VERSION   Version to install (e.g., v2026.2.0; default: latest)
  --pre                   Install the latest prerelease (release candidate) version
  -d, --data-dir DIR      Data directory (default: /var/lib/power-manage)
  -b, --binary PATH       Path to the agent binary (default: /usr/local/bin/power-manage-agent)
  --skip-download         Skip downloading the binary (use existing binary at --binary path)
  --uninstall             Remove the agent and all configuration
  -h, --help              Show this help message

Examples:
  # Download, install and register (one-liner)
  curl -fsSL https://github.com/${GITHUB_REPO}/releases/latest/download/install.sh | sudo bash -s -- -s https://power-manage.example.com -t abc123

  # Install the latest prerelease version
  sudo ./install.sh --pre -s https://power-manage.example.com -t abc123

  # Install a specific version
  sudo ./install.sh -v v2026.2.0 -s https://power-manage.example.com -t abc123

  # Install with existing binary (skip download)
  sudo ./install.sh --skip-download -s https://power-manage.example.com -t abc123

  # Uninstall completely
  sudo ./install.sh --uninstall
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--token)
                REGISTRATION_TOKEN="$2"
                shift 2
                ;;
            -s|--server)
                SERVER_URL="$2"
                shift 2
                ;;
            -d|--data-dir)
                DATA_DIR="$2"
                shift 2
                ;;
            -b|--binary)
                BINARY_PATH="$2"
                shift 2
                ;;
            -v|--version)
                VERSION="$2"
                shift 2
                ;;
            --pre)
                PRE_RELEASE="true"
                shift
                ;;
            --skip-download)
                SKIP_DOWNLOAD="true"
                shift
                ;;
            --enable-uri-handler)
                ENABLE_URI_HANDLER="true"
                shift
                ;;
            --uninstall)
                uninstall
                exit 0
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_arch() {
    local machine
    machine=$(uname -m)
    case "$machine" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *)
            log_error "Unsupported architecture: $machine"
            exit 1
            ;;
    esac
}

resolve_latest_prerelease() {
    local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases"
    log_info "Querying GitHub API for latest prerelease..."

    local response
    if command -v curl &>/dev/null; then
        response=$(curl -gfsSL "$api_url")
    elif command -v wget &>/dev/null; then
        response=$(wget -qO- "$api_url")
    else
        log_error "Neither curl nor wget found. Please install one and try again."
        exit 1
    fi

    # Extract tag_name from the first release where prerelease is true
    local tag
    tag=$(echo "$response" | awk '/"tag_name"/{tag=$2} /"prerelease": true/{print tag; exit}' | tr -dc 'a-zA-Z0-9._-')

    if [[ -z "$tag" ]]; then
        log_error "No prerelease found on GitHub"
        exit 1
    fi

    echo "$tag"
}

download_binary() {
    if [[ -n "$SKIP_DOWNLOAD" ]]; then
        if [[ ! -f "$BINARY_PATH" ]]; then
            log_error "Agent binary not found at $BINARY_PATH (--skip-download was set)"
            exit 1
        fi
        log_info "Using existing binary at $BINARY_PATH"
        chmod +x "$BINARY_PATH"
        return
    fi

    # Resolve version for --pre flag
    if [[ -n "$PRE_RELEASE" ]] && [[ "$VERSION" == "latest" ]]; then
        VERSION=$(resolve_latest_prerelease)
        log_info "Latest prerelease: ${VERSION}"
    fi

    local arch
    arch=$(detect_arch)
    local binary_name="power-manage-agent-linux-${arch}"
    local download_url sums_url release_base

    if [[ "$VERSION" == "latest" ]]; then
        release_base="https://github.com/${GITHUB_REPO}/releases/latest/download"
    else
        release_base="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}"
    fi
    download_url="${release_base}/${binary_name}"
    sums_url="${release_base}/SHA256SUMS"

    log_info "Detected architecture: ${arch}"
    log_info "Downloading agent from ${download_url}..."

    # Download to a sibling tmp file inside the destination directory
    # so the final `mv` is an atomic rename inside the same filesystem.
    # Clobbering BINARY_PATH directly with a partial download — the
    # previous behaviour — could leave the host with a truncated or
    # malicious binary if the transfer was interrupted or the release
    # endpoint was compromised.
    local dest_dir
    dest_dir=$(dirname "$BINARY_PATH")
    mkdir -p "$dest_dir"
    local tmp_binary tmp_sums
    tmp_binary=$(mktemp "${dest_dir}/.power-manage-agent.XXXXXX")
    tmp_sums=$(mktemp "${dest_dir}/.SHA256SUMS.XXXXXX")
    # Trap via a named function so the tmp paths are expanded
    # inside the function body (where normal "$var" quoting
    # handles spaces / quotes cleanly) rather than spliced into
    # the trap command string at registration time. An earlier
    # shape used `trap "rm -f '${tmp_binary}' '${tmp_sums}'"`,
    # which would break if BINARY_PATH's directory ever contained
    # a single quote — unlikely on a typical deploy host, but a
    # gratuitous shell-quoting fragility we can just drop.
    cleanup_download_tmp() {
        rm -f "$tmp_binary" "$tmp_sums"
    }
    trap cleanup_download_tmp EXIT INT TERM

    if command -v curl &>/dev/null; then
        if ! curl -gfSL --progress-bar -o "$tmp_binary" "$download_url"; then
            log_error "Download failed. Check the version and that the release exists."
            exit 1
        fi
        if ! curl -gfSL -o "$tmp_sums" "$sums_url"; then
            log_error "SHA256SUMS download failed. Refusing to install unverified binary."
            exit 1
        fi
    elif command -v wget &>/dev/null; then
        if ! wget -q --show-progress -O "$tmp_binary" "$download_url"; then
            log_error "Download failed. Check the version and that the release exists."
            exit 1
        fi
        if ! wget -q -O "$tmp_sums" "$sums_url"; then
            log_error "SHA256SUMS download failed. Refusing to install unverified binary."
            exit 1
        fi
    else
        log_error "Neither curl nor wget found. Please install one and try again."
        exit 1
    fi

    # Verify the downloaded binary against the publisher's SHA256SUMS.
    # Fail closed: a missing / mismatched / tampered checksum ends the
    # install before we touch BINARY_PATH. The SHA256SUMS file is served
    # by the same GitHub release as the binary, so this does not protect
    # against a release-channel compromise on its own — the release
    # workflow should additionally sign the file (cosign / minisign) and
    # this script should verify that signature once CI publishes it.
    # Until then, SHA256SUMS still catches the "half-downloaded binary
    # was silently installed as root" class of failures.
    local expected_sha actual_sha
    expected_sha=$(awk -v f="$binary_name" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp_sums")
    if [[ -z "$expected_sha" ]]; then
        log_error "SHA256SUMS has no entry for ${binary_name}. Refusing to install."
        exit 1
    fi
    if ! command -v sha256sum &>/dev/null; then
        log_error "sha256sum not found. Cannot verify binary integrity; refusing to install."
        exit 1
    fi
    actual_sha=$(sha256sum "$tmp_binary" | awk '{print $1}')
    if [[ "$expected_sha" != "$actual_sha" ]]; then
        log_error "SHA256 mismatch for ${binary_name}."
        log_error "  expected: ${expected_sha}"
        log_error "  actual:   ${actual_sha}"
        log_error "Refusing to install tampered or corrupt binary."
        exit 1
    fi
    log_info "SHA256 verified."

    chmod 0755 "$tmp_binary"
    # mv across the same filesystem is atomic, so a crash here never
    # leaves BINARY_PATH in a partially-written state. The trap above
    # handles the case where the mv itself fails.
    if ! mv -f "$tmp_binary" "$BINARY_PATH"; then
        log_error "Failed to install binary to ${BINARY_PATH}."
        exit 1
    fi
    rm -f "$tmp_sums"
    trap - EXIT INT TERM

    log_info "Binary installed to $BINARY_PATH"
}

create_directories() {
    log_info "Creating data directory: $DATA_DIR"
    mkdir -p "$DATA_DIR"
    chown root:root "$DATA_DIR"
    chmod 700 "$DATA_DIR"
}

install_systemd_service() {
    local service_file="/etc/systemd/system/${SERVICE_NAME}.service"

    log_info "Installing systemd service..."

    # Detect systemd version to conditionally enable RestrictRealtime.
    # systemd <257 (Debian Bookworm 252) implements RestrictRealtime via a
    # seccomp filter that sets no_new_privs, preventing the agent from using
    # sudo. systemd 257+ (Trixie) does not have this issue.
    local restrict_realtime="false"
    local systemd_ver
    systemd_ver=$(systemctl --version 2>/dev/null | head -1 | awk '{for(i=1;i<=NF;i++) if($i+0==$i){print $i; exit}}')
    if [[ -z "$systemd_ver" ]]; then
        log_warn "Could not detect systemd version, disabling RestrictRealtime as a precaution"
    elif ! [[ "$systemd_ver" =~ ^[0-9]+$ ]]; then
        log_warn "Unexpected systemd version format '$systemd_ver', disabling RestrictRealtime as a precaution"
    elif [[ "$systemd_ver" -ge 257 ]]; then
        restrict_realtime="true"
    fi

    cat > "$service_file" << EOF
[Unit]
Description=Power Manage Agent
Documentation=https://github.com/manchtools/power-manage
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
# Agent runs as root. The previous power-manage + sudoers escalation
# model was retired (see agent/README.md "Runs as root"); every
# privileged operation now runs in-process without a sudo round-trip.
User=root
Group=root

# Environment
Environment="POWER_MANAGE_DATA_DIR=$DATA_DIR"

# Main process
ExecStart=$BINARY_PATH -data-dir=$DATA_DIR -log-level=info

# Restart configuration
Restart=always
RestartSec=10

# Runtime directory (/run/pm-agent) for enrollment socket
RuntimeDirectory=pm-agent
RuntimeDirectoryMode=0755

# Security hardening — most ProtectXxx knobs are intentionally
# disabled: the agent's job is to mutate system state (install
# packages, write unit files, reload systemd, set LUKS keys, …) and
# the protection knobs would block exactly those operations.
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
PrivateTmp=false
ProtectKernelTunables=false
ProtectKernelModules=false
ProtectControlGroups=true
RestrictRealtime=$restrict_realtime
RestrictSUIDSGID=false

# Capabilities.
#
# Running as root means the agent process inherits the full default
# capability set, but we pin both the ambient set and the bounding
# set so:
#
#   - Children launched from shell actions (which may shed caps via
#     execve onto a binary without file caps) keep the caps the
#     action needs. The bounding set is the hard ceiling that the
#     execve cap-stripping rules reduce against, so any cap NOT
#     listed below is unavailable to children regardless of how
#     they're launched.
#
#   - Remote terminal sessions spawn /bin/bash under per-user
#     pm-tty-* accounts via setresuid/setresgid. CAP_SETUID and
#     CAP_SETGID are already in root's effective set, but listing
#     them as ambient caps makes the privilege transition explicit
#     and survives any future drop-priv refactor that runs the
#     agent as a non-root user with the relevant caps file-set on
#     the binary.
#
#   - CAP_AUDIT_WRITE in the bounding set keeps the kernel-audit
#     channel open for any setuid-root child (sudo invocations
#     from run_as_root shell actions still happen on hosts where
#     the operator policy uses them). Without it, audit messages
#     fail with "audit message cannot be sent: operation not
#     permitted" — silent compliance gap on SOC2/PCI/CIS hosts.
#
# Bounding set caps and what they're for:
#   CAP_SETUID / CAP_SETGID — drop priv to per-user pm-tty-* shells.
#   CAP_AUDIT_WRITE — kernel audit log writes from setuid children.
#   CAP_CHOWN / CAP_DAC_OVERRIDE / CAP_FOWNER — file ownership +
#     permission overrides during package hooks and config writes.
#   CAP_NET_BIND_SERVICE — daemons restarted by shell actions that
#     bind privileged ports without setuid.
#   CAP_NET_ADMIN — firewall control via ufw / firewall-cmd / nft.
#   CAP_SYS_ADMIN — mount / umount during LUKS operations.
#   CAP_KILL — signal other-uid (pm-tty-*) process groups when tearing
#     down terminal sessions; without it the in-process root model's
#     kill(-pgid, …) / pkill -u returns EPERM and the sweeper degrades
#     to relying on pty-close SIGHUP, leaking detached/ignoring procs.
#   CAP_SETFCAP — let dpkg/rpm set file capabilities during package
#     installs (e.g. iputils, anything shipping +ep file caps).
#   CAP_NET_RAW — file-cap binaries like ping (and raw-socket children)
#     exec-fail with EPERM under a bounding set that excludes it.
#
# Since the agent runs as root (User=root), the in-process daemon's own
# syscalls are also subject to this bounding set — not just its
# children — so the three caps above are required for the in-process
# model, not optional. The agent's only listener is the UNIX socket at
# /run/pm-agent/enroll.sock — it never binds a TCP port itself.
AmbientCapabilities=CAP_SETUID CAP_SETGID
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_AUDIT_WRITE CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SYS_ADMIN CAP_KILL CAP_SETFCAP CAP_NET_RAW

# Allow network access
PrivateNetwork=false

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$service_file"

    log_info "Reloading systemd daemon..."
    systemctl daemon-reload
}

enroll_agent() {
    if [[ -z "$REGISTRATION_TOKEN" ]] || [[ -z "$SERVER_URL" ]]; then
        log_warn "No registration token or server URL provided, skipping enrollment"
        log_info "You can enroll later by running (no sudo required):"
        log_info "  $BINARY_PATH enroll -server=<URL> -token-file=<PATH>"
        return
    fi

    log_info "Enrolling agent with server via socket..."

    # Deliver the token via a 0600 file, NOT on argv: process arguments
    # are world-readable via /proc/<pid>/cmdline, so `-token=…` would leak
    # the registration token to any local user for the life of the call.
    local token_file
    token_file="$(mktemp)"
    chmod 600 "$token_file"
    # Remove the token file on any return path (success, failure, signal).
    trap 'rm -f "$token_file"' RETURN
    printf '%s' "$REGISTRATION_TOKEN" > "$token_file"

    # Build the enrollment command as an array so arguments are passed
    # one-per-element and bash does not word-split, glob, or re-tokenise
    # user-supplied values such as SERVER_URL.
    local -a enroll_cmd=(
        "$BINARY_PATH"
        "enroll"
        "-server=$SERVER_URL"
        "-token-file=$token_file"
    )

    # Wait for the enrollment socket to become available (agent needs to start first)
    local max_wait=10
    local waited=0
    while [[ ! -S "/run/pm-agent/enroll.sock" ]] && [[ $waited -lt $max_wait ]]; do
        sleep 1
        waited=$((waited + 1))
    done

    if [[ ! -S "/run/pm-agent/enroll.sock" ]]; then
        log_warn "Enrollment socket not available after ${max_wait}s, agent may already be enrolled"
        return
    fi

    # Enroll via socket — no sudo needed, any user can connect
    if "${enroll_cmd[@]}"; then
        log_info "Agent enrolled successfully"
    else
        log_error "Agent enrollment failed"
        log_info "You can try again later by running:"
        log_info "  $BINARY_PATH enroll -server=$SERVER_URL -token-file=<PATH>"
        return 1
    fi
}

enable_and_start_service() {
    log_info "Enabling and starting service..."

    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    log_info "Service started"

    # If not yet enrolled, the agent will listen on the enrollment socket
    # and wait for enrollment via: power-manage-agent enroll -server=URL -token=TOKEN
}

uninstall() {
    log_info "Uninstalling Power Manage Agent..."

    # Stop and disable service
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_info "Stopping service..."
        systemctl stop "$SERVICE_NAME"
    fi

    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_info "Disabling service..."
        systemctl disable "$SERVICE_NAME"
    fi

    # Remove service file
    if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
        log_info "Removing service file..."
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload
    fi

    if [[ -f "/etc/sudoers.d/power-manage-luks" ]]; then
        log_info "Removing LUKS sudoers configuration..."
        rm -f "/etc/sudoers.d/power-manage-luks"
    fi

    # Remove desktop handler
    if [[ -f "/usr/share/applications/power-manage-agent.desktop" ]]; then
        log_info "Removing desktop handler..."
        rm -f "/usr/share/applications/power-manage-agent.desktop"
    fi

    # Ask about data directory
    if [[ -d "$DATA_DIR" ]]; then
        read -p "Remove data directory $DATA_DIR? This will delete agent credentials! [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Removing data directory..."
            rm -rf "$DATA_DIR"
        else
            log_info "Data directory preserved"
        fi
    fi

    log_info "Uninstall complete"
}

# install_desktop_handler registers the power-manage:// URI scheme so a
# browser link can launch `power-manage-agent luks set-passphrase`. It is
# OPT-IN (--enable-uri-handler / POWER_MANAGE_ENABLE_URI_HANDLER=true) and
# OFF by default: an unconditional handler exposes the root-capable binary
# to drive-by links (WS7 #4). The entry sets Terminal=false so a malicious
# link cannot silently auto-spawn a terminal; operators who enable the
# handler get a non-auto-launching entry.
install_desktop_handler() {
    local desktop_file="/usr/share/applications/power-manage-agent.desktop"

    log_info "Installing desktop URI handler (opt-in)..."

    cat > "$desktop_file" << EOF
[Desktop Entry]
Name=Power Manage Agent
Comment=Power Manage device agent
Exec=$BINARY_PATH %u
Terminal=false
Type=Application
MimeType=x-scheme-handler/power-manage;
NoDisplay=true
EOF

    chmod 644 "$desktop_file"

    # Register the URI scheme handler
    if command -v xdg-mime &>/dev/null; then
        xdg-mime default power-manage-agent.desktop x-scheme-handler/power-manage 2>/dev/null || true
    fi

    log_info "Desktop URI handler installed"
}

# NOTE: the LUKS set-passphrase flow no longer uses a sudoers rule (WS6
# #1/#19). The agent runs as root and exposes an in-process daemon socket
# at /run/pm-agent/luks.sock (created at runtime under the unit's
# RuntimeDirectory=pm-agent). The unprivileged `power-manage-agent luks
# set-passphrase` client sends only {token, passphrase} to that socket;
# the root agent performs the cryptsetup work with its own credentials,
# authorized by the server-issued device-bound, single-use token. The old
# `ALL ALL=(root) NOPASSWD: <binary> luks set-passphrase *` rule (with an
# attacker-controllable --data-dir) is removed entirely. The uninstall
# path still deletes /etc/sudoers.d/power-manage-luks to clean it up on
# upgrade from a pre-WS6 install.

show_status() {
    echo ""
    echo "=========================================="
    echo "  Power Manage Agent Installation Complete"
    echo "=========================================="
    echo ""
    echo "Runs As:       root"
    echo "Data Directory: $DATA_DIR"
    echo "Binary Path:   $BINARY_PATH"
    echo "Service Name:  $SERVICE_NAME"
    echo ""
    echo "Useful commands:"
    echo "  Check status:    sudo systemctl status $SERVICE_NAME"
    echo "  View logs:       sudo journalctl -u $SERVICE_NAME -f"
    echo "  Start service:   sudo systemctl start $SERVICE_NAME"
    echo "  Stop service:    sudo systemctl stop $SERVICE_NAME"
    echo "  Restart service: sudo systemctl restart $SERVICE_NAME"
    echo ""

    if [[ -f "$DATA_DIR/credentials.enc" ]]; then
        echo "Agent is enrolled and ready."
    else
        echo "Agent is NOT enrolled yet."
        echo "To enroll (no sudo required), run:"
        echo "  $BINARY_PATH enroll -server=<URL> -token=<TOKEN>"
    fi
    echo ""
}

stop_service_if_running() {
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_info "Stopping running agent service for update..."
        systemctl stop "$SERVICE_NAME"
    fi
}

main() {
    parse_args "$@"
    check_root

    # Download (and atomically stage) the new binary BEFORE stopping the
    # running agent. download_binary fetches to a temp file in the
    # destination dir and renames it into place, so replacing the file
    # does not disturb the still-running process (it holds the old
    # inode). If the download fails under `set -e`, the script aborts
    # while the existing agent is still running, instead of leaving the
    # device offline with a healthy agent stopped and no new binary.
    download_binary

    # Now stop the old instance so enable_and_start_service below brings
    # up the freshly-installed binary.
    stop_service_if_running

    log_info "Starting Power Manage Agent installation..."

    create_directories
    install_systemd_service
    # WS7 #4: opt-in only — the URI handler exposes the root-capable binary
    # to drive-by power-manage:// links, so it is not installed by default.
    if [[ "$ENABLE_URI_HANDLER" == "true" ]]; then
        install_desktop_handler
    else
        log_info "Skipping power-manage:// URI handler (enable with --enable-uri-handler)"
    fi

    enable_and_start_service

    if [[ -n "$REGISTRATION_TOKEN" ]] && [[ -n "$SERVER_URL" ]]; then
        enroll_agent
    fi

    show_status
}

main "$@"
