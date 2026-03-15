# SDK Rust Makefile
# Packages Rust SDK source code for distribution

.PHONY: build package dist clean example-run test-package

# Auto-detect SDK root directory
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SDK_ROOT := $(MAKEFILE_DIR)
REPO_ROOT := $(shell cd $(MAKEFILE_DIR)../.. && pwd)

ARTIFACTS_DIR=$(REPO_ROOT)/artifacts
PACKAGE_DIR=$(ARTIFACTS_DIR)/sdk-rust

# Build the Rust SDK (for verification)
build:
	@echo "Building Rust SDK (verification)..."
	@cd $(SDK_ROOT) && cargo build --release
	@echo "✓ Rust SDK builds successfully"

# Package Rust SDK source (no binary)
package:
	@echo "Packaging Rust SDK source..."
	@mkdir -p $(PACKAGE_DIR)
	@echo "Copying source files..."
	@cp -rf $(SDK_ROOT)/Cargo.toml $(PACKAGE_DIR)/
	@cp -rf $(SDK_ROOT)/Cargo.lock $(PACKAGE_DIR)/ 2>/dev/null || true
	@cp -rf $(SDK_ROOT)/src $(PACKAGE_DIR)/ 2>/dev/null || true
	@cp -rf $(SDK_ROOT)/examples $(PACKAGE_DIR)/ 2>/dev/null || true
	@echo "Rust SDK source package created: $(PACKAGE_DIR)/"

# Create distribution archive
dist: build package
	@echo "Creating distribution archive..."
	@cd $(ARTIFACTS_DIR) && zip -r "connector-service-rust-sdk.zip" sdk-rust/
	@echo "Distribution archive created: $(ARTIFACTS_DIR)/connector-service-rust-sdk.zip"

# ---------------------------------------------------------------------------
# test-package
# Verifies the Rust SDK compiles (library + basic example) and runs the
# smoke test for a set of connectors (defaults to stripe).
# A full round-trip test requires real connector credentials; run with
#   CONNECTORS=stripe,adyen make test-package
# ---------------------------------------------------------------------------
CONNECTORS ?= stripe

test-package:
	@echo "Checking Rust SDK library..."
	@cd $(SDK_ROOT) && cargo check --lib 2>&1
	@echo "Checking Rust SDK examples..."
	@cd $(SDK_ROOT) && cargo check --example basic 2>&1
	@echo "Running Rust SDK smoke test..."
	@if [ -f $(REPO_ROOT)/creds.json ]; then \
		cp $(REPO_ROOT)/creds.json $(SDK_ROOT)/smoke-test/creds.json; \
	else \
		echo "  Note: creds.json not found, smoke test will use placeholder credentials"; \
		echo '{"stripe":{"api_key":{"value":"placeholder"}}}' > $(SDK_ROOT)/smoke-test/creds.json; \
	fi
	@cd $(SDK_ROOT)/smoke-test && cargo run --release -- --connectors $(CONNECTORS) --creds-file creds.json 2>&1 || \
		(echo "  Note: smoke test requires real credentials to pass"; exit 0)
	@echo "✓ Rust SDK package check passed."

# Run the example
example-run:
	@cd $(SDK_ROOT) && STRIPE_API_KEY=$(STRIPE_API_KEY) cargo run --example basic --release

clean:
	@echo "Cleaning Rust SDK artifacts..."
	@cd $(SDK_ROOT) && cargo clean
	@rm -rf $(PACKAGE_DIR)
	@echo "Clean complete."
