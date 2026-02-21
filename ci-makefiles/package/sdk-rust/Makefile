# SDK Rust Packaging Makefile
# Packages Rust SDK source code for distribution

.PHONY: help build package clean

# Default target
.DEFAULT_GOAL := help

# Configuration
SDK_DIR := sdk/rust
ARTIFACTS_DIR := artifacts
PACKAGE_DIR := $(ARTIFACTS_DIR)/sdk-rust
PACKAGE_NAME := hyperswitch-payments-client

help: ## Show this help message
	@echo "SDK Rust Packaging Makefile - Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}'

build: ## Build Rust SDK to verify it compiles
	@echo "Building Rust SDK (verification)..."
	@cd $(SDK_DIR) && cargo build --release
	@echo "✓ Rust SDK builds successfully"

package: ## Package Rust SDK source (no binary)
	@echo "Packaging Rust SDK source..."
	@mkdir -p $(PACKAGE_DIR)
	@echo "Copying source files..."
	@cp -rf $(SDK_DIR)/Cargo.toml $(PACKAGE_DIR)/
	@cp -rf $(SDK_DIR)/Cargo.lock $(PACKAGE_DIR)/ 2>/dev/null || true
	@cp -rf $(SDK_DIR)/src $(PACKAGE_DIR)/ 2>/dev/null || true
	@echo "Rust SDK source package created: $(PACKAGE_DIR)/"

# Create distribution archive
dist: build package ## Create distribution archive (builds for verification only)
	@echo "Creating distribution archive..."
	@cd $(ARTIFACTS_DIR) && zip -r "connector-service-rust-sdk.zip" sdk-rust/
	@echo "Distribution archive created: $(ARTIFACTS_DIR)/connector-service-rust-sdk.zip"

clean: ## Clean package artifacts
	@echo "Cleaning Rust SDK package artifacts..."
	@rm -rf $(PACKAGE_DIR)
	@echo "Clean complete."
