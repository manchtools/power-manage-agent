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

# Create data directory for agent credentials. chmod 700 to match
# install.sh (WS7 #10): the dir holds action secrets and the agent store,
# so it must not be group/world-readable.
RUN mkdir -p /var/lib/power-manage && chmod 700 /var/lib/power-manage

COPY --from=builder /power-manage-agent /usr/local/bin/power-manage-agent

# An unenrolled agent remains running on its local enrollment socket. Enrollment
# is performed explicitly with a registration token and the control CA pin.
ENTRYPOINT ["/usr/local/bin/power-manage-agent"]
