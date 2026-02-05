# Build stage
FROM docker.io/library/golang:1.25-bookworm AS builder

WORKDIR /build

# Copy SDK first (needed for replace directive)
COPY sdk/ ./sdk/

# Copy agent module
COPY agent/go.mod agent/go.sum ./agent/
WORKDIR /build/agent
RUN go mod download

# Copy agent source
COPY agent/ ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /power-manage-agent ./cmd/power-manage-agent

# Runtime stage - Debian for apt testing
FROM docker.io/library/debian:bookworm-slim

# Install common packages for testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    systemd \
    && rm -rf /var/lib/apt/lists/*

# Create data directory for agent credentials
RUN mkdir -p /var/lib/power-manage

COPY --from=builder /power-manage-agent /usr/local/bin/power-manage-agent

# Create entrypoint script that keeps the container running
RUN cat > /entrypoint.sh <<'EOF'
#!/bin/bash
set -e

# If no token and no stored credentials, wait for token to be provided
DATA_DIR="${POWER_MANAGE_DATA_DIR:-/var/lib/power-manage}"

if [ -z "$POWER_MANAGE_TOKEN" ] && [ ! -f "$DATA_DIR/credentials.enc" ]; then
    echo "No registration token provided and no stored credentials found."
    echo "Set POWER_MANAGE_TOKEN environment variable to register."
    echo "Container will stay running - use 'podman exec' to register manually."
    echo ""
    echo "Example:"
    echo "  podman exec -e POWER_MANAGE_TOKEN=<token> pm-test-agent power-manage-agent"
    echo ""
    # Keep container alive
    exec sleep infinity
fi

# Run the agent - it will reconnect on errors automatically
exec /usr/local/bin/power-manage-agent "$@"
EOF
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
