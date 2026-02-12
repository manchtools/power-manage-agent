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

SSH_OPTS    := $(if $(KEY),-i $(KEY),)

# ── Targets ────────────────────────────────────────────────────
.PHONY: build deploy install logs status restart stop

build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build \
		-ldflags="$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY)-linux-$(GOARCH) \
		./cmd/power-manage-agent
	@echo "Built $(BUILD_DIR)/$(BINARY)-linux-$(GOARCH)  ($(VERSION))"

deploy: build
	scp $(SSH_OPTS) $(BUILD_DIR)/$(BINARY)-linux-$(GOARCH) $(SSH):/tmp/$(BINARY)
	ssh $(SSH_OPTS) $(SSH) 'sudo systemctl stop $(SERVICE) 2>/dev/null; \
		sudo mv /tmp/$(BINARY) $(REMOTE_BIN) && \
		sudo chmod +x $(REMOTE_BIN) && \
		sudo $(REMOTE_BIN) setup --user power-manage && \
		sudo systemctl start $(SERVICE)'
	@echo "Deployed $(VERSION) to $(SSH)"

install: build
	scp $(SSH_OPTS) $(BUILD_DIR)/$(BINARY)-linux-$(GOARCH) $(SSH):/tmp/$(BINARY)
	scp $(SSH_OPTS) install.sh $(SSH):/tmp/install.sh
	ssh $(SSH_OPTS) $(SSH) 'sudo bash /tmp/install.sh --skip-download -b /tmp/$(BINARY)'
	@echo "Full install on $(SSH) complete"

logs:
	ssh $(SSH_OPTS) $(SSH) 'sudo journalctl -u $(SERVICE) -f'

status:
	ssh $(SSH_OPTS) $(SSH) 'sudo systemctl status $(SERVICE); echo "---"; $(REMOTE_BIN) -version 2>/dev/null || true'

restart:
	ssh $(SSH_OPTS) $(SSH) 'sudo systemctl restart $(SERVICE)'

stop:
	ssh $(SSH_OPTS) $(SSH) 'sudo systemctl stop $(SERVICE)'
