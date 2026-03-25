.PHONY: build package dist clean example-run test-package test-grpc test-grpc-no-server

# SDK-specific paths (define BEFORE including common.mk)
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SDK_ROOT     := $(MAKEFILE_DIR)

# Include common SDK build configuration
include $(SDK_ROOT)/../common.mk

# ---------------------------------------------------------------------------
# Build targets
# ---------------------------------------------------------------------------

build: ## Build the Rust SDK package
	@cd $(SDK_ROOT) && cargo build --release

# ---------------------------------------------------------------------------
# Package / Distribution
# ---------------------------------------------------------------------------

package: ## Package the Rust SDK (preparation for publishing)
	@cd $(SDK_ROOT) && cargo package --allow-dirty

dist: package ## Build distribution package (alias for package)

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------

test-package: build-ffi-lib ## Build FFI → Run Rust smoke test
	@echo "Running Rust smoke test..."
	@cd $(REPO_ROOT) && cargo test -p hyperswitch-smoke-test --release-fast 2>&1 | tail -20

# test-grpc
# Builds the grpc-server binary, starts it as a background process, runs
# the gRPC smoke test against it, then shuts it down.
#
# Usage:
#   make test-grpc
#   make test-grpc GRPC_CONNECTOR=adyen
#   make test-grpc GRPC_PROFILE=release
# ---------------------------------------------------------------------------
GRPC_CONNECTOR  ?= stripe
GRPC_AUTH_TYPE  ?= header-key
GRPC_API_KEY    ?=
GRPC_ENDPOINT   ?= http://localhost:8000
GRPC_PROFILE    ?= release-fast
GRPC_SERVER_BIN := $(REPO_ROOT)/target/$(GRPC_PROFILE)/grpc-server

# Run test assuming server is already running (used by top-level test-grpc)
test-grpc-no-server: ## Run gRPC smoke test only (assumes server is already running)
	@echo "Running gRPC smoke test (connector: $(GRPC_CONNECTOR))…"
	@if [ -f $(REPO_ROOT)/creds.json ]; then \
		CREDS_ARGS="--creds-file $(REPO_ROOT)/creds.json --connector $(GRPC_CONNECTOR) --endpoint $(GRPC_ENDPOINT) --auth-type $(GRPC_AUTH_TYPE)"; \
	elif [ -n "$(GRPC_API_KEY)" ]; then \
		CREDS_ARGS="--endpoint $(GRPC_ENDPOINT) --connector $(GRPC_CONNECTOR) --auth-type $(GRPC_AUTH_TYPE) --api-key $(GRPC_API_KEY)"; \
	else \
		echo "  Note: no creds.json found and no GRPC_API_KEY set."; \
		echo "  Add credentials to creds.json at the repo root."; \
		exit 1; \
	fi; \
	cd $(SDK_ROOT)/smoke-test && CONNECTORS=$(GRPC_CONNECTOR) cargo run --profile $(GRPC_PROFILE) --bin grpc-smoke-test -- $$CREDS_ARGS

test-grpc: ## Build grpc-server → start in background → run gRPC smoke test → stop
	@echo "Building grpc-server ($(GRPC_PROFILE))…"
	@cd $(REPO_ROOT) && cargo build -p grpc-server --profile $(GRPC_PROFILE) 2>&1
	@echo "Starting gRPC server…"
	@pkill -KILL -f grpc-server 2>/dev/null || true
	@sleep 1
	@cd $(REPO_ROOT) && $(GRPC_SERVER_BIN) > /tmp/grpc-server.log 2>&1 &
	@$(MAKE) test-grpc-no-server; \
	EXIT=$$?; \
	pkill -f grpc-server 2>/dev/null || true; \
	exit $$EXIT

# Run the example
example-run:
	@cd $(SDK_ROOT) && STRIPE_API_KEY=$(STRIPE_API_KEY) cargo run --example basic --release

clean:
	@echo "Cleaning Rust SDK artifacts..."
	@cd $(SDK_ROOT) && cargo clean
	@rm -rf $(PACKAGE_DIR)
	@echo "Clean complete."
