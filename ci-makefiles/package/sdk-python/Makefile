# SDK Python Packaging Makefile
# Packages Python SDK with UniFFI bindings and native libraries

.PHONY: help package package-macos package-linux package-all clean

# Default target
.DEFAULT_GOAL := help

# Configuration
SDK_DIR := sdk/python
FFI_CRATE := backend/ffi
ARTIFACTS_DIR := artifacts
PACKAGE_DIR := $(ARTIFACTS_DIR)/sdk-python
GENERATED_DIR := $(SDK_DIR)/generated

# Python package metadata (will be updated during release)
PACKAGE_NAME := connector-service
PACKAGE_VERSION ?= 0.1.0

help: ## Show this help message
	@echo "SDK Python Packaging Makefile - Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}'

# Generate bindings if needed
generate-bindings: ## Generate UniFFI Python bindings
	@echo "Generating UniFFI Python bindings..."
	@$(MAKE) -C $(SDK_DIR) generate-bindings

# Package for specific platforms
package-macos-x86_64: ## Package Python SDK for macOS Intel
	@echo "Packaging Python SDK for macOS Intel..."
	@mkdir -p $(PACKAGE_DIR)/macos-x86_64
	@cp -f target/x86_64-apple-darwin/release/libconnector_service_ffi.dylib $(PACKAGE_DIR)/macos-x86_64/ 2>/dev/null || \
		(echo "Warning: macOS x86_64 binary not found. Build it first with: make -f ci-makefiles/compile/Makefile build-macos-x86_64" && exit 1)
	@cp -rf $(GENERATED_DIR)/*.py $(PACKAGE_DIR)/macos-x86_64/ 2>/dev/null || true
	@cp -f $(SDK_DIR)/main.py $(PACKAGE_DIR)/macos-x86_64/example.py 2>/dev/null || true
	@echo "macOS Intel package created: $(PACKAGE_DIR)/macos-x86_64/"

package-macos-aarch64: ## Package Python SDK for macOS Apple Silicon
	@echo "Packaging Python SDK for macOS Apple Silicon..."
	@mkdir -p $(PACKAGE_DIR)/macos-aarch64
	@cp -f target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || \
		(echo "Warning: macOS aarch64 binary not found. Build it first with: make -f ci-makefiles/compile/Makefile build-macos-aarch64" && exit 1)
	@cp -rf $(GENERATED_DIR)/*.py $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@cp -f $(SDK_DIR)/main.py $(PACKAGE_DIR)/macos-aarch64/example.py 2>/dev/null || true
	@echo "macOS ARM package created: $(PACKAGE_DIR)/macos-aarch64/"

package-linux-x86_64: ## Package Python SDK for Linux x86_64
	@echo "Packaging Python SDK for Linux x86_64..."
	@mkdir -p $(PACKAGE_DIR)/linux-x86_64
	@cp -f target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || \
		(echo "Warning: Linux x86_64 binary not found. Build it first with: make -f ci-makefiles/compile/Makefile build-linux-x86_64" && exit 1)
	@cp -rf $(GENERATED_DIR)/*.py $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@cp -f $(SDK_DIR)/main.py $(PACKAGE_DIR)/linux-x86_64/example.py 2>/dev/null || true
	@echo "Linux x86_64 package created: $(PACKAGE_DIR)/linux-x86_64/"

package-linux-aarch64: ## Package Python SDK for Linux aarch64
	@echo "Packaging Python SDK for Linux aarch64..."
	@mkdir -p $(PACKAGE_DIR)/linux-aarch64
	@cp -f target/aarch64-unknown-linux-gnu/release/libconnector_service_ffi.so $(PACKAGE_DIR)/linux-aarch64/ 2>/dev/null || \
		(echo "Warning: Linux aarch64 binary not found. Build it first with: make -f ci-makefiles/compile/Makefile build-linux-aarch64" && exit 1)
	@cp -rf $(GENERATED_DIR)/*.py $(PACKAGE_DIR)/linux-aarch64/ 2>/dev/null || true
	@cp -f $(SDK_DIR)/main.py $(PACKAGE_DIR)/linux-aarch64/example.py 2>/dev/null || true
	@echo "Linux aarch64 package created: $(PACKAGE_DIR)/linux-aarch64/"

# Native platforms only (active builds)
package-native: package-macos-aarch64 package-linux-x86_64 ## Package Python SDK for native platforms only
	@echo "Native Python SDK packages created in $(PACKAGE_DIR)/"

# All platforms (includes cross-compile - temporarily limited)
package-macos: package-macos-aarch64 ## Package Python SDK for macOS (aarch64 only)

package-linux: package-linux-x86_64 ## Package Python SDK for Linux (x86_64 only)

package-all: package-native ## Package Python SDK for all platforms (native only)
	@echo "All Python SDK packages created in $(PACKAGE_DIR)/"

# Create distribution archive
dist: package-native ## Create distribution archives for native platforms
	@echo "Creating distribution archives..."
	@cd $(PACKAGE_DIR) && for dir in */; do \
		if [ -d "$$dir" ]; then \
			zip -r "connector-service-python-sdk-$${dir%/}.zip" "$$dir"; \
		fi; \
	done
	@echo "Distribution archives created in $(PACKAGE_DIR)/"
	@ls -la $(PACKAGE_DIR)/*.zip 2>/dev/null || echo "No archives created"

clean: ## Clean package artifacts
	@echo "Cleaning Python SDK package artifacts..."
	@rm -rf $(PACKAGE_DIR)
	@echo "Clean complete."
