# SDK Java Packaging Makefile
# Packages Java SDK with UniFFI bindings and native libraries

.PHONY: help package package-macos package-linux package-all clean check-gradle

# Default target
.DEFAULT_GOAL := help

# Configuration
SDK_DIR := sdk/java
FFI_CRATE := backend/ffi
ARTIFACTS_DIR := artifacts
PACKAGE_DIR := $(ARTIFACTS_DIR)/sdk-java
GENERATED_DIR := $(SDK_DIR)/generated

# Detect OS
UNAME := $(shell uname)

help: ## Show this help message
	@echo "SDK Java Packaging Makefile - Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}'

check-gradle: ## Verify gradle is available
	@cd $(SDK_DIR) && ./gradlew --version > /dev/null 2>&1 || (echo "Error: Gradle wrapper not found in $(SDK_DIR)" && exit 1)

# Generate bindings if needed
generate-bindings: ## Generate UniFFI Kotlin bindings
	@echo "Generating UniFFI Kotlin bindings..."
	@$(MAKE) -C $(SDK_DIR) generate-bindings

# Package for specific platforms
package-macos-x86: ## Package Java SDK for macOS Intel
	@echo "Packaging Java SDK for macOS Intel..."
	@mkdir -p $(PACKAGE_DIR)/macos-x86_64/native
	@cp -f target/x86_64-apple-darwin/release/libconnector_service_ffi.dylib $(PACKAGE_DIR)/macos-x86_64/native/ 2>/dev/null || \
		(echo "Warning: macOS x86_64 binary not found. Build it first with: make -f makefiles/build/makefile build-macos-x86" && exit 1)
	@cp -rf $(GENERATED_DIR)/*.kt $(PACKAGE_DIR)/macos-x86_64/ 2>/dev/null || true
	@echo "macOS Intel package created: $(PACKAGE_DIR)/macos-x86_64/"

package-macos-arm: ## Package Java SDK for macOS Apple Silicon
	@echo "Packaging Java SDK for macOS Apple Silicon..."
	@mkdir -p $(PACKAGE_DIR)/macos-aarch64/native
	@cp -f target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib $(PACKAGE_DIR)/macos-aarch64/native/ 2>/dev/null || \
		(echo "Warning: macOS aarch64 binary not found. Build it first with: make -f makefiles/build/makefile build-macos-arm" && exit 1)
	@cp -rf $(GENERATED_DIR)/*.kt $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@echo "macOS ARM package created: $(PACKAGE_DIR)/macos-aarch64/"

package-macos-universal: ## Package Java SDK with universal macOS binary
	@echo "Packaging Java SDK for macOS Universal..."
	@mkdir -p $(PACKAGE_DIR)/macos-universal/native
	@cp -f target/universal/release/libconnector_service_ffi.dylib $(PACKAGE_DIR)/macos-universal/native/ 2>/dev/null || \
		(echo "Warning: Universal macOS binary not found. Build it first with: make -f makefiles/build/makefile build-macos-universal" && exit 1)
	@cp -rf $(GENERATED_DIR)/*.kt $(PACKAGE_DIR)/macos-universal/ 2>/dev/null || true
	@echo "macOS Universal package created: $(PACKAGE_DIR)/macos-universal/"

package-linux-x86: ## Package Java SDK for Linux x86_64
	@echo "Packaging Java SDK for Linux x86_64..."
	@mkdir -p $(PACKAGE_DIR)/linux-x86_64/native
	@cp -f target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so $(PACKAGE_DIR)/linux-x86_64/native/ 2>/dev/null || \
		(echo "Warning: Linux x86_64 binary not found. Build it first with: make -f makefiles/build/makefile build-linux-x86" && exit 1)
	@cp -rf $(GENERATED_DIR)/*.kt $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@echo "Linux x86_64 package created: $(PACKAGE_DIR)/linux-x86_64/"

package-linux-arm: ## Package Java SDK for Linux aarch64
	@echo "Packaging Java SDK for Linux aarch64..."
	@mkdir -p $(PACKAGE_DIR)/linux-aarch64/native
	@cp -f target/aarch64-unknown-linux-gnu/release/libconnector_service_ffi.so $(PACKAGE_DIR)/linux-aarch64/native/ 2>/dev/null || \
		(echo "Warning: Linux aarch64 binary not found. Build it first with: make -f makefiles/build/makefile build-linux-arm" && exit 1)
	@cp -rf $(GENERATED_DIR)/*.kt $(PACKAGE_DIR)/linux-aarch64/ 2>/dev/null || true
	@echo "Linux aarch64 package created: $(PACKAGE_DIR)/linux-aarch64/"

package-macos: package-macos-x86 package-macos-arm package-macos-universal ## Package Java SDK for all macOS platforms

package-linux: package-linux-x86 package-linux-arm ## Package Java SDK for all Linux platforms

package-all: package-macos package-linux ## Package Java SDK for all platforms
	@echo "All Java SDK packages created in $(PACKAGE_DIR)/"

# Create distribution archive
dist: package-all ## Create distribution archives for all platforms
	@echo "Creating distribution archives..."
	@cd $(PACKAGE_DIR) && for dir in */; do \
		if [ -d "$$dir" ]; then \
			zip -r "connector-service-java-sdk-$${dir%/}.zip" "$$dir"; \
		fi; \
	done
	@echo "Distribution archives created in $(PACKAGE_DIR)/"
	@ls -la $(PACKAGE_DIR)/*.zip 2>/dev/null || echo "No archives created"

clean: ## Clean package artifacts
	@echo "Cleaning Java SDK package artifacts..."
	@rm -rf $(PACKAGE_DIR)
	@echo "Clean complete."
