# Power Manage Agent — dev deploy Makefile
#
# Usage:
#   make deploy SSH=user@testserver                    # build + deploy + restart
#   make deploy SSH=user@testserver KEY=~/.ssh/id_ed25519  # with specific key
#   make build                                         # just cross-compile
#   make logs  SSH=user@testserver                     # tail remote journal
#   make status SSH=user@testserver                    # check service status

# ── Configuration ──────────────────────────────────────────────
SSH         ?= user@testserver
KEY         ?=
GOARCH      ?= amd64
BINARY      := power-manage-agent
REMOTE_BIN  := /usr/local/bin/$(BINARY)
SERVICE     := power-manage-agent
BUILD_DIR   := dist

VERSION     := dev-$(shell date +%Y%m%d-%H%M%S)
LDFLAGS     := -s -w -X main.version=$(VERSION)

KEY_OPTS    := $(if $(KEY),-i $(KEY),)
SSH_OPTS    := -t $(KEY_OPTS)
SCP_OPTS    := $(KEY_OPTS)

# ── Targets ────────────────────────────────────────────────────
.PHONY: build deploy install logs status restart stop \
    test-integration test-integration-debian test-integration-fedora \
    test-integration-opensuse test-integration-archlinux test-integration-all \
    test-integration-edgecase

build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build \
		-ldflags="$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY)-linux-$(GOARCH) \
		./cmd/power-manage-agent
	@echo "Built $(BUILD_DIR)/$(BINARY)-linux-$(GOARCH)  ($(VERSION))"

deploy: build
	ssh $(SSH_OPTS) $(SSH) 'sudo rm -f /tmp/$(BINARY) /tmp/install.sh'
	scp $(SCP_OPTS) $(BUILD_DIR)/$(BINARY)-linux-$(GOARCH) $(SSH):/tmp/$(BINARY)
	ssh $(SSH_OPTS) $(SSH) 'sudo systemctl stop $(SERVICE) 2>/dev/null; \
		sudo mv /tmp/$(BINARY) $(REMOTE_BIN) && \
		sudo chmod +x $(REMOTE_BIN) && \
		sudo $(REMOTE_BIN) setup --user power-manage && \
		sudo systemctl start $(SERVICE)'
	@echo "Deployed $(VERSION) to $(SSH)"

install: build
	ssh $(SSH_OPTS) $(SSH) 'sudo rm -f /tmp/$(BINARY) /tmp/install.sh'
	scp $(SCP_OPTS) $(BUILD_DIR)/$(BINARY)-linux-$(GOARCH) $(SSH):/tmp/$(BINARY)
	scp $(SCP_OPTS) install.sh $(SSH):/tmp/install.sh
	ssh $(SSH_OPTS) $(SSH) 'sudo mv /tmp/$(BINARY) $(REMOTE_BIN) && sudo chmod +x $(REMOTE_BIN) && sudo bash /tmp/install.sh --skip-download'
	@echo "Full install on $(SSH) complete"

logs:
	ssh $(SSH_OPTS) $(SSH) 'sudo journalctl -u $(SERVICE) -f'

status:
	ssh $(SSH_OPTS) $(SSH) 'sudo systemctl status $(SERVICE); echo "---"; $(REMOTE_BIN) -version 2>/dev/null || true'

restart:
	ssh $(SSH_OPTS) $(SSH) 'sudo systemctl restart $(SERVICE)'

stop:
	ssh $(SSH_OPTS) $(SSH) 'sudo systemctl stop $(SERVICE)'

CONTAINER_CMD := $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
TEST_CMD := runuser -u power-manage -- /usr/local/go/bin/go test -v -tags=integration -count=1 -timeout=10m ./agent/internal/executor/ -run Integration

test-integration-debian:
	$(CONTAINER_CMD) build -f test/Dockerfile.integration -t pm-agent-test-debian ../
	$(CONTAINER_CMD) run --rm pm-agent-test-debian $(TEST_CMD)

test-integration-fedora:
	$(CONTAINER_CMD) build -f test/Dockerfile.integration.fedora -t pm-agent-test-fedora ../
	$(CONTAINER_CMD) run --rm pm-agent-test-fedora $(TEST_CMD)

test-integration-opensuse:
	$(CONTAINER_CMD) build -f test/Dockerfile.integration.opensuse -t pm-agent-test-opensuse ../
	$(CONTAINER_CMD) run --rm pm-agent-test-opensuse $(TEST_CMD)

test-integration-archlinux:
	$(CONTAINER_CMD) build -f test/Dockerfile.integration.archlinux -t pm-agent-test-archlinux ../
	$(CONTAINER_CMD) run --rm pm-agent-test-archlinux $(TEST_CMD)

# Backward-compatible alias (Debian only)
test-integration: test-integration-debian

# Run all 4 distros in parallel
test-integration-all:
	$(MAKE) -j4 test-integration-debian test-integration-fedora test-integration-opensuse test-integration-archlinux

# Edge case tests in privileged Debian container (disk-full, read-only FS, etc.)
test-integration-edgecase:
	$(CONTAINER_CMD) build -f test/Dockerfile.integration -t pm-agent-test-debian ../
	$(CONTAINER_CMD) run --rm --privileged pm-agent-test-debian $(TEST_CMD) -run EdgeCase
