#!/bin/bash
#
# Power Manage Agent Installation Script
#
# Downloads the agent binary, installs it as a systemd service, and optionally
# registers with a control server — all in one step.
#
# One-liner install:
#   curl -fsSL https://github.com/MANCHTOOLS/power-manage-agent/releases/latest/download/install.sh | sudo bash -s -- -s https://your-server.example.com -t YOUR_TOKEN
#
# Usage:
#   sudo ./install.sh [OPTIONS]
#
# Options:
#   -t, --token TOKEN       Registration token for initial setup
#   -s, --server URL        Control server URL (e.g., https://control.example.com:8081)
#   -v, --version VERSION   Version to install (default: latest)
#   -d, --data-dir DIR      Data directory (default: /var/lib/power-manage)
#   -b, --binary PATH       Path to the agent binary (default: /usr/local/bin/power-manage-agent)
#   -u, --user USER         Service user name (default: power-manage)
#   --skip-verify           Skip TLS certificate verification (development only)
#   --skip-download         Skip downloading the binary (use existing binary at --binary path)
#   --uninstall             Remove the agent and all configuration
#   -h, --help              Show this help message
#

set -e

GITHUB_REPO="MANCHTOOLS/power-manage-agent"

# Default values
DATA_DIR="/var/lib/power-manage"
BINARY_PATH="/usr/local/bin/power-manage-agent"
SERVICE_USER="power-manage"
SERVICE_NAME="power-manage-agent"
REGISTRATION_TOKEN=""
SERVER_URL=""
SKIP_VERIFY=""
SKIP_DOWNLOAD=""
VERSION="latest"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
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
  -d, --data-dir DIR      Data directory (default: /var/lib/power-manage)
  -b, --binary PATH       Path to the agent binary (default: /usr/local/bin/power-manage-agent)
  -u, --user USER         Service user name (default: power-manage)
  --skip-verify           Skip TLS certificate verification (development only)
  --skip-download         Skip downloading the binary (use existing binary at --binary path)
  --uninstall             Remove the agent and all configuration
  -h, --help              Show this help message

Examples:
  # Download, install and register (one-liner)
  curl -fsSL https://github.com/${GITHUB_REPO}/releases/latest/download/install.sh | sudo bash -s -- -s https://power-manage.example.com -t abc123

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
            -u|--user)
                SERVICE_USER="$2"
                shift 2
                ;;
            -v|--version)
                VERSION="$2"
                shift 2
                ;;
            --skip-verify)
                SKIP_VERIFY="true"
                shift
                ;;
            --skip-download)
                SKIP_DOWNLOAD="true"
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

    local arch
    arch=$(detect_arch)
    local binary_name="power-manage-agent-linux-${arch}"
    local download_url

    if [[ "$VERSION" == "latest" ]]; then
        download_url="https://github.com/${GITHUB_REPO}/releases/latest/download/${binary_name}"
    else
        download_url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${binary_name}"
    fi

    log_info "Detected architecture: ${arch}"
    log_info "Downloading agent from ${download_url}..."

    if command -v curl &>/dev/null; then
        if ! curl -fSL --progress-bar -o "$BINARY_PATH" "$download_url"; then
            log_error "Download failed. Check the version and that the release exists."
            exit 1
        fi
    elif command -v wget &>/dev/null; then
        if ! wget -q --show-progress -O "$BINARY_PATH" "$download_url"; then
            log_error "Download failed. Check the version and that the release exists."
            exit 1
        fi
    else
        log_error "Neither curl nor wget found. Please install one and try again."
        exit 1
    fi

    chmod +x "$BINARY_PATH"
    log_info "Binary installed to $BINARY_PATH"
}

create_user() {
    if id "$SERVICE_USER" &>/dev/null; then
        log_info "User $SERVICE_USER already exists"
    else
        log_info "Creating service user: $SERVICE_USER"
        useradd \
            --system \
            --no-create-home \
            --shell /usr/sbin/nologin \
            --comment "Power Manage Agent Service" \
            "$SERVICE_USER"
    fi
}

setup_sudo() {
    log_info "Configuring sudo access for $SERVICE_USER..."

    # Use the agent binary's embedded sudoers template for a single source of truth.
    # This ensures the sudoers rules always match the agent version.
    if "$BINARY_PATH" setup --user "$SERVICE_USER"; then
        log_info "Sudoers configuration installed successfully"
    else
        log_error "Failed to install sudoers configuration"
        exit 1
    fi
}

create_directories() {
    log_info "Creating data directory: $DATA_DIR"
    mkdir -p "$DATA_DIR"
    chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
    chmod 700 "$DATA_DIR"
}

install_systemd_service() {
    local service_file="/etc/systemd/system/${SERVICE_NAME}.service"

    log_info "Installing systemd service..."

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
User=$SERVICE_USER
Group=$SERVICE_USER

# Environment
Environment="POWER_MANAGE_DATA_DIR=$DATA_DIR"

# Main process
ExecStart=$BINARY_PATH -data-dir=$DATA_DIR -log-level=info

# Restart configuration
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=read-only
PrivateTmp=false
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=false

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

register_agent() {
    if [[ -z "$REGISTRATION_TOKEN" ]] || [[ -z "$SERVER_URL" ]]; then
        log_warn "No registration token or server URL provided, skipping registration"
        log_info "You can register later by running:"
        log_info "  sudo -u $SERVICE_USER $BINARY_PATH -server=<URL> -token=<TOKEN> -data-dir=$DATA_DIR"
        return
    fi

    log_info "Registering agent with server..."

    local register_cmd="$BINARY_PATH -server=$SERVER_URL -token=$REGISTRATION_TOKEN -data-dir=$DATA_DIR"

    if [[ -n "$SKIP_VERIFY" ]]; then
        register_cmd="$register_cmd -skip-verify"
    fi

    # Run registration as the service user
    if sudo -u "$SERVICE_USER" $register_cmd; then
        log_info "Agent registered successfully"
    else
        log_error "Agent registration failed"
        log_info "You can try again later by running:"
        log_info "  sudo -u $SERVICE_USER $register_cmd"
        return 1
    fi
}

enable_and_start_service() {
    log_info "Enabling and starting service..."

    systemctl enable "$SERVICE_NAME"

    # Only start if credentials exist (agent is registered)
    if [[ -f "$DATA_DIR/credentials.enc" ]]; then
        systemctl start "$SERVICE_NAME"
        log_info "Service started"
    else
        log_warn "Agent not registered yet - service will not start until registered"
        log_info "After registration, start the service with: sudo systemctl start $SERVICE_NAME"
    fi
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

    # Remove sudoers file
    if [[ -f "/etc/sudoers.d/$SERVICE_USER" ]]; then
        log_info "Removing sudoers configuration..."
        rm -f "/etc/sudoers.d/$SERVICE_USER"
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

    # Ask about user
    if id "$SERVICE_USER" &>/dev/null; then
        read -p "Remove service user $SERVICE_USER? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Removing service user..."
            userdel "$SERVICE_USER"
        else
            log_info "Service user preserved"
        fi
    fi

    log_info "Uninstall complete"
}

show_status() {
    echo ""
    echo "=========================================="
    echo "  Power Manage Agent Installation Complete"
    echo "=========================================="
    echo ""
    echo "Service User:  $SERVICE_USER"
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
        echo "Agent is registered and ready."
    else
        echo "Agent is NOT registered yet."
        echo "To register, run:"
        echo "  sudo -u $SERVICE_USER $BINARY_PATH -server=<URL> -token=<TOKEN> -data-dir=$DATA_DIR"
        echo ""
        echo "Then start the service:"
        echo "  sudo systemctl start $SERVICE_NAME"
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

    # Stop the service before updating the binary to avoid in-place update issues
    stop_service_if_running

    download_binary

    log_info "Starting Power Manage Agent installation..."

    create_user
    setup_sudo
    create_directories
    install_systemd_service

    if [[ -n "$REGISTRATION_TOKEN" ]] && [[ -n "$SERVER_URL" ]]; then
        register_agent
    fi

    enable_and_start_service
    show_status
}

main "$@"
