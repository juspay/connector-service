# SDK JavaScript Packaging Makefile
# Packages JavaScript SDK with native libraries and protobuf stubs

.PHONY: help package package-macos package-linux package-all clean

# Default target
.DEFAULT_GOAL := help

# Configuration
SDK_DIR := sdk/javascript
FFI_CRATE := backend/ffi
ARTIFACTS_DIR := artifacts
PACKAGE_DIR := $(ARTIFACTS_DIR)/sdk-javascript
GENERATED_DIR := $(SDK_DIR)/generated

# Package metadata
PACKAGE_NAME := connector-service-js
PACKAGE_VERSION ?= 0.1.0

help: ## Show this help message
	@echo "SDK JavaScript Packaging Makefile - Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}'

# Generate bindings if needed
generate-bindings: ## Generate JavaScript protobuf stubs
	@echo "Generating JavaScript protobuf stubs..."
	@$(MAKE) -C $(SDK_DIR) generate-proto

# Package for specific platforms
package-macos-x86: ## Package JavaScript SDK for macOS Intel
	@echo "Packaging JavaScript SDK for macOS Intel..."
	@mkdir -p $(PACKAGE_DIR)/macos-x86_64
	@cp -f target/x86_64-apple-darwin/release/libconnector_service_ffi.dylib $(PACKAGE_DIR)/macos-x86_64/ 2>/dev/null || \
		(echo "Warning: macOS x86_64 binary not found. Build it first with: make -f makefiles/build/makefile build-macos-x86" && exit 1)
	@cp -rf $(GENERATED_DIR)/*.js $(PACKAGE_DIR)/macos-x86_64/ 2>/dev/null || true
	@cp -rf $(GENERATED_DIR)/*.d.ts $(PACKAGE_DIR)/macos-x86_64/ 2>/dev/null || true
	@cp -f $(SDK_DIR)/main.js $(PACKAGE_DIR)/macos-x86_64/example.js 2>/dev/null || true
	@cp -f $(SDK_DIR)/package.json $(PACKAGE_DIR)/macos-x86_64/ 2>/dev/null || true
	@echo "macOS Intel package created: $(PACKAGE_DIR)/macos-x86_64/"

package-macos-arm: ## Package JavaScript SDK for macOS Apple Silicon
	@echo "Packaging JavaScript SDK for macOS Apple Silicon..."
	@mkdir -p $(PACKAGE_DIR)/macos-aarch64
	@cp -f target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || \
		(echo "Warning: macOS aarch64 binary not found. Build it first with: make -f makefiles/build/makefile build-macos-arm" && exit 1)
	@cp -rf $(GENERATED_DIR)/*.js $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@cp -rf $(GENERATED_DIR)/*.d.ts $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@cp -f $(SDK_DIR)/main.js $(PACKAGE_DIR)/macos-aarch64/example.js 2>/dev/null || true
	@cp -f $(SDK_DIR)/package.json $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@echo "macOS ARM package created: $(PACKAGE_DIR)/macos-aarch64/"

package-linux-x86: ## Package JavaScript SDK for Linux x86_64
	@echo "Packaging JavaScript SDK for Linux x86_64..."
	@mkdir -p $(PACKAGE_DIR)/linux-x86_64
	@cp -f target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || \
		(echo "Warning: Linux x86_64 binary not found. Build it first with: make -f makefiles/build/makefile build-linux-x86" && exit 1)
	@cp -rf $(GENERATED_DIR)/*.js $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@cp -rf $(GENERATED_DIR)/*.d.ts $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@cp -f $(SDK_DIR)/main.js $(PACKAGE_DIR)/linux-x86_64/example.js 2>/dev/null || true
	@cp -f $(SDK_DIR)/package.json $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@echo "Linux x86_64 package created: $(PACKAGE_DIR)/linux-x86_64/"

package-linux-arm: ## Package JavaScript SDK for Linux aarch64
	@echo "Packaging JavaScript SDK for Linux aarch64..."
	@mkdir -p $(PACKAGE_DIR)/linux-aarch64
	@cp -f target/aarch64-unknown-linux-gnu/release/libconnector_service_ffi.so $(PACKAGE_DIR)/linux-aarch64/ 2>/dev/null || \
		(echo "Warning: Linux aarch64 binary not found. Build it first with: make -f makefiles/build/makefile build-linux-arm" && exit 1)
	@cp -rf $(GENERATED_DIR)/*.js $(PACKAGE_DIR)/linux-aarch64/ 2>/dev/null || true
	@cp -rf $(GENERATED_DIR)/*.d.ts $(PACKAGE_DIR)/linux-aarch64/ 2>/dev/null || true
	@cp -f $(SDK_DIR)/main.js $(PACKAGE_DIR)/linux-aarch64/example.js 2>/dev/null || true
	@cp -f $(SDK_DIR)/package.json $(PACKAGE_DIR)/linux-aarch64/ 2>/dev/null || true
	@echo "Linux aarch64 package created: $(PACKAGE_DIR)/linux-aarch64/"

package-macos: package-macos-x86 package-macos-arm ## Package JavaScript SDK for all macOS platforms

package-linux: package-linux-x86 package-linux-arm ## Package JavaScript SDK for all Linux platforms

package-all: package-macos package-linux ## Package JavaScript SDK for all platforms
	@echo "All JavaScript SDK packages created in $(PACKAGE_DIR)/"

# Create distribution archive
dist: package-all ## Create distribution archives for all platforms
	@echo "Creating distribution archives..."
	@cd $(PACKAGE_DIR) && for dir in */; do \
		if [ -d "$$dir" ]; then \
			zip -r "connector-service-javascript-sdk-$${dir%/}.zip" "$$dir"; \
		fi; \
	done
	@echo "Distribution archives created in $(PACKAGE_DIR)/"
	@ls -la $(PACKAGE_DIR)/*.zip 2>/dev/null || echo "No archives created"

clean: ## Clean package artifacts
	@echo "Cleaning JavaScript SDK package artifacts..."
	@rm -rf $(PACKAGE_DIR)
	@echo "Clean complete."
