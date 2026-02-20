# SDK Rust Packaging Makefile
# Packages Rust SDK (hyperswitch-payments-client) for distribution

.PHONY: help package clean check-cargo

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

check-cargo: ## Verify cargo is installed
	@which cargo > /dev/null 2>&1 || (echo "Error: cargo is not installed" && exit 1)

package: check-cargo ## Package Rust SDK
	@echo "Packaging Rust SDK..."
	@mkdir -p $(PACKAGE_DIR)
	@echo "Building Rust SDK in release mode..."
	@cd $(SDK_DIR) && cargo build --release
	@echo "Copying build artifacts..."
	@cp -rf $(SDK_DIR)/Cargo.toml $(PACKAGE_DIR)/
	@cp -rf $(SDK_DIR)/src $(PACKAGE_DIR)/ 2>/dev/null || true
	@cp -rf $(SDK_DIR)/target/release $(PACKAGE_DIR)/target/ 2>/dev/null || true
	@echo "Rust SDK package created: $(PACKAGE_DIR)/"

# Create distribution archive
dist: package ## Create distribution archive
	@echo "Creating distribution archive..."
	@cd $(ARTIFACTS_DIR) && zip -r "connector-service-rust-sdk.zip" sdk-rust/
	@echo "Distribution archive created: $(ARTIFACTS_DIR)/connector-service-rust-sdk.zip"

clean: ## Clean package artifacts
	@echo "Cleaning Rust SDK package artifacts..."
	@rm -rf $(PACKAGE_DIR)
	@echo "Clean complete."
