# SDK Rust Makefile
# Packages Rust SDK source code for distribution

.PHONY: build package dist clean example-run

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

# Run the example
example-run:
	@cd $(SDK_ROOT) && STRIPE_API_KEY=$(STRIPE_API_KEY) cargo run --example basic --release

clean:
	@echo "Cleaning Rust SDK artifacts..."
	@cd $(SDK_ROOT) && cargo clean
	@rm -rf $(PACKAGE_DIR)
	@echo "Clean complete."
