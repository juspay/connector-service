.PHONY: install-deps generate-bindings generate-proto generate-all \
        generate-flows pack-archive install test-package dist clean

# SDK-specific paths (define BEFORE including common.mk)
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SDK_ROOT     := $(MAKEFILE_DIR)

# Connectors to test (comma-separated, default: stripe)
CONNECTORS ?= stripe

# Include common SDK build configuration
include $(SDK_ROOT)/../common.mk

# SDK-specific paths continued
GENERATED_OUT := $(SDK_ROOT)/lib/payments/generated
PACKAGE_DIR   := $(ARTIFACTS_DIR)/sdk-ruby

# ---------------------------------------------------------------------------
# install-deps
# Installs Ruby build-time dependencies required for protobuf code generation.
# Checks for tool existence before installing. In Nix environments tools are
# provided by the shell so installation is skipped.
# ---------------------------------------------------------------------------
install-deps:
	@command -v ruby >/dev/null 2>&1 || \
		(echo "Error: ruby not found. Install via nix or https://www.ruby-lang.org" && exit 1)
	@command -v gem >/dev/null 2>&1 || \
		(echo "Error: gem not found. Install via nix or https://www.ruby-lang.org" && exit 1)
	@cd $(SDK_ROOT) && bundle install
	@echo "All required tools present."

# ---------------------------------------------------------------------------
# generate-bindings
# Copies the pre-built FFI native library into the generated output directory
# so it is bundled with the gem package. The Ruby SDK drives the native
# library directly via Ruby FFI; no UniFFI code generation is required.
# Requires: build-ffi-lib to have been run first (or library downloaded in CI).
# ---------------------------------------------------------------------------
generate-bindings:
	@[ -f "$(LIBRARY)" ] || \
		(echo "Error: FFI library not found at $(LIBRARY). Run 'make build-ffi-lib' first." && exit 1)
	@echo "Copying FFI library to $(GENERATED_OUT)/..."
	@mkdir -p $(GENERATED_OUT)
	@cp -f $(LIBRARY) $(GENERATED_OUT)/
	@echo "Library copied to $(GENERATED_OUT)/"

# ---------------------------------------------------------------------------
# generate-proto
# Generates Ruby protobuf stubs from .proto files into the generated output
# directory, alongside the native FFI library.
# ---------------------------------------------------------------------------
generate-proto: install-deps
	@echo "Generating Ruby protobuf stubs..."
	@mkdir -p $(GENERATED_OUT)
	@protoc \
		-I $(PROTO_DIR) \
		--ruby_out=$(GENERATED_OUT) \
		$(PROTO_DIR)/payment.proto $(PROTO_DIR)/payment_methods.proto $(PROTO_DIR)/sdk_config.proto
	@echo "Proto stubs generated in $(GENERATED_OUT)/"

# ---------------------------------------------------------------------------
# generate-all
# Runs all code-generation steps: copies the native library and generates the
# protobuf Ruby stubs.
# ---------------------------------------------------------------------------
generate-all: generate-proto generate-bindings generate-flows

# ---------------------------------------------------------------------------
# generate-flows
# Generates flow methods (authorize, capture, etc.) by running the SDK
# codegen script. Assumes descriptor is already generated.
# ---------------------------------------------------------------------------
generate-flows:
	@echo "Generating Ruby flow methods..."
	@cd $(REPO_ROOT)/sdk/codegen && python3 generate.py --lang ruby
	@echo "Ruby flow methods generated."

# ---------------------------------------------------------------------------
# pack-archive
# Builds the SDK gem (.gem) using gem build.
# Assumes lib/payments/generated/ has been populated by generate-all.
# ---------------------------------------------------------------------------
pack-archive:
	@mkdir -p $(PACKAGE_DIR)
	@cd $(SDK_ROOT) && gem build hyperswitch-payments.gemspec -o $(PACKAGE_DIR)/hyperswitch-payments-0.1.0.gem
	@echo "Gem built in $(PACKAGE_DIR)/"

# ---------------------------------------------------------------------------
# install
# Builds the SDK gem. Exists for interface parity with the other SDK Makefiles.
# ---------------------------------------------------------------------------
install: pack-archive

# ---------------------------------------------------------------------------
# test-package
# Full end-to-end local test: builds the FFI library, generates all code
# artifacts, packs the gem, then installs it into an isolated temporary
# directory and runs the smoke test to verify the package works correctly.
# The temp directory is cleaned up after the test.
# ---------------------------------------------------------------------------
test-package: build-ffi-lib generate-all pack-archive
	@echo "Testing packed gem in isolation..."
	@rm -rf /tmp/test-hyperswitch-rb
	@mkdir -p /tmp/test-hyperswitch-rb
	@test -f $(PACKAGE_DIR)/hyperswitch-payments-0.1.0.gem || (echo "Error: Gem not found" && exit 1)
	@cd /tmp/test-hyperswitch-rb && gem install --local $(PACKAGE_DIR)/hyperswitch-payments-0.1.0.gem --no-document
	@cp $(SDK_ROOT)/smoke-test/test_smoke.rb /tmp/test-hyperswitch-rb/
	@# Copy credentials file if it exists
	@if [ -f $(REPO_ROOT)/creds.json ]; then \
		cp $(REPO_ROOT)/creds.json /tmp/test-hyperswitch-rb/; \
	else \
		echo "  Note: creds.json not found, test will use placeholder credentials"; \
	fi
	@cd /tmp/test-hyperswitch-rb && ruby test_smoke.rb --connectors $(CONNECTORS)
	@echo "Running composite flow test..."
	@cp $(SDK_ROOT)/smoke-test/test_smoke_composite.rb /tmp/test-hyperswitch-rb/
	@cd /tmp/test-hyperswitch-rb && ruby test_smoke_composite.rb
	@rm -rf /tmp/test-hyperswitch-rb
	@echo "Package test passed."

# ---------------------------------------------------------------------------
# dist
# Builds the distribution gem for all supported platforms.
# Copies pre-built native binaries for each target platform into the generated
# output directory, generates proto stubs, then packs the gem.
# ---------------------------------------------------------------------------
dist:
	@echo "Building Ruby SDK distribution gem..."
	@mkdir -p $(GENERATED_OUT)
	@cp -fL $(REPO_ROOT)/target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: Linux x86_64 binary not found (skipping)"
	@cp -fL $(REPO_ROOT)/target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: macOS aarch64 binary not found (skipping)"
	@$(MAKE) -C $(SDK_ROOT) pack-archive
	@echo "Distribution gem created in $(PACKAGE_DIR)/"

clean:
	@rm -rf $(GENERATED_OUT)
	@rm -f $(SDK_ROOT)/lib/payments/_generated_flows.rb \
	        $(SDK_ROOT)/lib/payments/_generated_service_clients.rb
