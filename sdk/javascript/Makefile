.PHONY: install-deps install-codegen-deps generate-bindings generate-proto generate-grpc-bindings \
        generate-all build-ts pack-archive install test-package test-composite test-grpc test-grpc-no-server dist clean

# SDK-specific paths (define BEFORE including common.mk)
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SDK_ROOT     := $(MAKEFILE_DIR)

# Connectors to test (comma-separated, default: stripe)
CONNECTORS ?= stripe

# Include common SDK build configuration
include $(SDK_ROOT)/../common.mk

# SDK-specific paths continued
GENERATED_OUT    := $(SDK_ROOT)/src/payments/generated
PACKAGE_DIR      := $(ARTIFACTS_DIR)/sdk-javascript
JS_TARBALL       := $(PACKAGE_DIR)/hs-playlib-0.3.0.tgz

# ---------------------------------------------------------------------------
# install-deps
# Checks for required build tools. In Nix environments tools are provided by
# the shell so this is effectively a no-op. Outside Nix it exits with a helpful
# message for any missing tool rather than failing silently mid-build.
# ---------------------------------------------------------------------------
install-deps:
	@command -v node >/dev/null 2>&1 || \
		(echo "Error: node not found. Install via nix or a Node version manager." && exit 1)
	@command -v npm >/dev/null 2>&1 || \
		(echo "Error: npm not found. Install Node.js which includes npm." && exit 1)
	@command -v cargo >/dev/null 2>&1 || \
		(echo "Error: cargo not found. Install Rust via rustup." && exit 1)
	@command -v protoc >/dev/null 2>&1 || \
		(echo "Error: protoc not found. Install via nix or 'apt install protobuf-compiler'." && exit 1)
	@echo "All required tools present."

# ---------------------------------------------------------------------------
# install-codegen-deps
# Ensures jinja2 etc. are installed before generate-flows (used by CI and local).
# Delegates to sdk/Makefile install-deps (idempotent, skips if present).
# ---------------------------------------------------------------------------
install-codegen-deps:
	@$(MAKE) -C $(REPO_ROOT)/sdk install-deps

# ---------------------------------------------------------------------------
# generate-descriptor
# Generates the proto descriptor file used by all SDK codegen scripts.
# ---------------------------------------------------------------------------
generate-descriptor:
	@echo "Generating proto descriptor..."
	@mkdir -p $(REPO_ROOT)/scripts/generators/code
	@protoc \
		--proto_path=$(REPO_ROOT)/crates/types-traits/grpc-api-types/proto \
		--descriptor_set_out=$(REPO_ROOT)/scripts/generators/code/services.desc \
		--include_source_info \
		$(REPO_ROOT)/crates/types-traits/grpc-api-types/proto/services.proto \
		$(REPO_ROOT)/crates/types-traits/grpc-api-types/proto/payment.proto \
		$(REPO_ROOT)/crates/types-traits/grpc-api-types/proto/payouts.proto \
		$(REPO_ROOT)/crates/types-traits/grpc-api-types/proto/payment_methods.proto \
		$(REPO_ROOT)/crates/types-traits/grpc-api-types/proto/sdk_config.proto
	@echo "Descriptor written to scripts/generators/code/services.desc"

# ---------------------------------------------------------------------------
# build-ts
# Compiles TypeScript sources to dist/ and copies the generated proto stubs
# and native FFI library into dist/src/payments/generated/ so that npm pack
# includes them. Must run after generate-all (requires generated/ to be populated).
# ---------------------------------------------------------------------------
build-ts: install-deps
	@echo "Compiling TypeScript..."
	@npm run build
	@echo "TypeScript compilation complete."

# ---------------------------------------------------------------------------
# pack-archive
# Packages the SDK into a tarball for distribution.
# ---------------------------------------------------------------------------
pack-archive: build-ts
	@echo "Packing npm archive..."
	@mkdir -p $(PACKAGE_DIR)
	@npm pack --pack-destination $(PACKAGE_DIR)
	@echo "Tarball created: $(JS_TARBALL)"

# ---------------------------------------------------------------------------
# install
# Local install: builds TypeScript and links for development.
# ---------------------------------------------------------------------------
install: install-deps generate-all build-ts
	@npm install

# ---------------------------------------------------------------------------
# test-package
# End-to-end test: build FFI → pack → install in temp dir → run smoke test.
# ---------------------------------------------------------------------------
test-package: build-ffi-lib generate-all build-ts pack-archive
	@echo "Testing in isolation..."
	@rm -rf /tmp/test-hyperswitch-js
	@mkdir -p /tmp/test-hyperswitch-js
	@test -f $(JS_TARBALL) || (echo "Error: Tarball not found: $(JS_TARBALL)" && exit 1)
	@cd /tmp/test-hyperswitch-js && npm init -y --silent && \
		npm install $(JS_TARBALL) typescript @types/node --silent
	@cp $(SDK_ROOT)/smoke-test/test_smoke.ts /tmp/test-hyperswitch-js/
	@cp $(SDK_ROOT)/smoke-test/tsconfig.json      /tmp/test-hyperswitch-js/
	@if [ -f $(REPO_ROOT)/creds.json ]; then \
		cp $(REPO_ROOT)/creds.json /tmp/test-hyperswitch-js/; \
	fi
	@cd /tmp/test-hyperswitch-js && npx tsc && \
		NODE_PATH=/tmp/test-hyperswitch-js/node_modules node test_smoke.js \
		--connectors $(CONNECTORS) --examples-dir $(REPO_ROOT)/examples
	@rm -rf /tmp/test-hyperswitch-js

# ---------------------------------------------------------------------------
# test-composite
# End-to-end composite flow test: build FFI → pack → install → run composite test.
# ---------------------------------------------------------------------------
test-composite: build-ffi-lib generate-all build-ts pack-archive
	@echo "Testing composite flows in isolation..."
	@rm -rf /tmp/test-hyperswitch-js-composite
	@mkdir -p /tmp/test-hyperswitch-js-composite
	@test -f $(JS_TARBALL) || (echo "Error: Tarball not found: $(JS_TARBALL)" && exit 1)
	@cd /tmp/test-hyperswitch-js-composite && npm init -y --silent && \
		npm install $(JS_TARBALL) typescript @types/node --silent
	@cp $(SDK_ROOT)/smoke-test/test_composite.ts /tmp/test-hyperswitch-js-composite/
	@cp $(SDK_ROOT)/smoke-test/tsconfig.json      /tmp/test-hyperswitch-js-composite/
	@if [ -f $(REPO_ROOT)/creds.json ]; then \
		cp $(REPO_ROOT)/creds.json /tmp/test-hyperswitch-js-composite/; \
	fi
	@cd /tmp/test-hyperswitch-js-composite && npx tsc && \
		NODE_PATH=/tmp/test-hyperswitch-js-composite/node_modules node test_composite.js \
		--connectors $(CONNECTORS) --examples-dir $(REPO_ROOT)/examples
	@rm -rf /tmp/test-hyperswitch-js-composite

# ---------------------------------------------------------------------------
# test-grpc
# End-to-end gRPC smoke test: builds both FFI libraries, packs the tarball,
# installs it in an isolated temp project, then runs test_smoke_grpc.ts.
# ---------------------------------------------------------------------------
GRPC_PROFILE    ?= release-fast
GRPC_SERVER_BIN := $(REPO_ROOT)/target/$(GRPC_PROFILE)/grpc-server

# Run gRPC test assuming server is already running (used by top-level test-grpc)
test-grpc-no-server: build-ffi-lib build-grpc-ffi-lib generate-all generate-grpc-bindings build-ts pack-archive
	@echo "Testing gRPC flows in isolation..."
	@rm -rf /tmp/test-hyperswitch-js-grpc
	@mkdir -p /tmp/test-hyperswitch-js-grpc
	@test -f $(JS_TARBALL) || (echo "Error: Tarball not found: $(JS_TARBALL)" && exit 1)
	@cd /tmp/test-hyperswitch-js-grpc && npm init -y --silent && \
		npm install $(JS_TARBALL) typescript @types/node --silent
	@cp $(SDK_ROOT)/smoke-test/test_smoke_grpc.ts /tmp/test-hyperswitch-js-grpc/
	@cp $(SDK_ROOT)/smoke-test/tsconfig.json      /tmp/test-hyperswitch-js-grpc/
	@if [ -f $(REPO_ROOT)/creds.json ]; then \
		cp $(REPO_ROOT)/creds.json /tmp/test-hyperswitch-js-grpc/; \
	else \
		echo "  Note: no creds.json found, test will use placeholder credentials"; \
	fi
	@cd /tmp/test-hyperswitch-js-grpc && npx tsc && \
		NODE_PATH=/tmp/test-hyperswitch-js-grpc/node_modules FORCE_COLOR=1 node test_smoke_grpc.js \
		--connectors $(CONNECTORS) --examples-dir $(REPO_ROOT)/examples
	@rm -rf /tmp/test-hyperswitch-js-grpc

test-grpc: build-ffi-lib build-grpc-ffi-lib generate-all generate-grpc-bindings build-ts pack-archive
	@echo "Building grpc-server ($(GRPC_PROFILE))..."
	@cd $(REPO_ROOT) && cargo build -p grpc-server --profile $(GRPC_PROFILE) 2>&1
	@echo "Starting gRPC server..."
	@pkill -KILL -f grpc-server 2>/dev/null || true
	@sleep 1
	@cd $(REPO_ROOT) && $(GRPC_SERVER_BIN) > /tmp/grpc-server-js.log 2>&1 &
	@echo "Testing gRPC flows in isolation..."
	@rm -rf /tmp/test-hyperswitch-js-grpc
	@mkdir -p /tmp/test-hyperswitch-js-grpc
	@test -f $(JS_TARBALL) || (echo "Error: Tarball not found: $(JS_TARBALL)" && exit 1)
	@cd /tmp/test-hyperswitch-js-grpc && npm init -y --silent && \
		npm install $(JS_TARBALL) typescript @types/node --silent
	@cp $(SDK_ROOT)/smoke-test/test_smoke_grpc.ts /tmp/test-hyperswitch-js-grpc/
	@cp $(SDK_ROOT)/smoke-test/tsconfig.json      /tmp/test-hyperswitch-js-grpc/
	@if [ -f $(REPO_ROOT)/creds.json ]; then \
		cp $(REPO_ROOT)/creds.json /tmp/test-hyperswitch-js-grpc/; \
	else \
		echo "  Note: no creds.json found, test will use placeholder credentials"; \
	fi
	@cd /tmp/test-hyperswitch-js-grpc && npx tsc && \
		NODE_PATH=/tmp/test-hyperswitch-js-grpc/node_modules FORCE_COLOR=1 node test_smoke_grpc.js \
		--connectors $(CONNECTORS) --examples-dir $(REPO_ROOT)/examples; \
		EXIT=$$?; \
		pkill -f grpc-server 2>/dev/null || true; \
		rm -rf /tmp/test-hyperswitch-js-grpc; \
		exit $$EXIT

clean:
	@rm -rf $(GENERATED_OUT) node_modules
	@rm -f $(SDK_ROOT)src/payments/_generated_flows.js \
	        $(SDK_ROOT)src/payments/_generated_connector_client_flows.ts \
	        $(SDK_ROOT)src/payments/_generated_uniffi_client_flows.ts
