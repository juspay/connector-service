# SDK Build Makefile
# Builds FFI binaries for all SDK platforms
# This Makefile should be run from the repository root

.PHONY: help build build-all build-macos build-linux clean check-cargo

# Default target
.DEFAULT_GOAL := help

# Auto-detect repo root (works when run from sdk/ via -C or from repo root via -f)
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(shell cd $(MAKEFILE_DIR).. && pwd)

# Configuration
FFI_CRATE := $(REPO_ROOT)/backend/ffi
RELEASE_DIR := $(REPO_ROOT)/target/release
CROSS_RELEASE_DIR := $(REPO_ROOT)/target/cross

# Target platforms
TARGET_MACOS_x86_64 := x86_64-apple-darwin
TARGET_MACOS_AARCH64 := aarch64-apple-darwin
TARGET_LINUX_x86_64 := x86_64-unknown-linux-gnu
TARGET_LINUX_AARCH64 := aarch64-unknown-linux-gnu

# Detect current platform
UNAME := $(shell uname -s)
ARCH := $(shell uname -m)

help: ## Show this help message
	@echo "SDK Build Makefile - Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Current platform: $(UNAME) $(ARCH)"

check-cargo: ## Verify cargo is installed
	@which cargo > /dev/null 2>&1 || (echo "Error: cargo is not installed" && exit 1)

build: check-cargo ## Build UniFFI library for current platform
	@echo "Building UniFFI library for current platform..."
	@cd $(FFI_CRATE) && cargo build --no-default-features --features uniffi --release
	@echo "Build complete: $(REPO_ROOT)/target/release/libconnector_service_ffi.$(LIB_EXT)"

# macOS builds
build-macos-x86_64: check-cargo ## Build for macOS Intel (x86_64)
	@echo "Building for macOS Intel (x86_64)..."
	@cd $(FFI_CRATE) && cargo build --no-default-features --features uniffi --release --target $(TARGET_MACOS_x86_64)
	@echo "Build complete: target/$(TARGET_MACOS_x86_64)/release/libconnector_service_ffi.dylib"

build-macos-aarch64: check-cargo ## Build for macOS Apple Silicon (aarch64)
	@echo "Building for macOS Apple Silicon (aarch64)..."
	@cd $(FFI_CRATE) && cargo build --no-default-features --features uniffi --release --target $(TARGET_MACOS_AARCH64)
	@echo "Build complete: target/$(TARGET_MACOS_AARCH64)/release/libconnector_service_ffi.dylib"

build-macos-universal: build-macos-x86_64 build-macos-aarch64 ## Build universal binary for macOS
	@echo "Creating universal binary for macOS..."
	@mkdir -p $(REPO_ROOT)/target/universal/release
	@lipo -create \
		$(REPO_ROOT)/target/$(TARGET_MACOS_x86_64)/release/libconnector_service_ffi.dylib \
		$(REPO_ROOT)/target/$(TARGET_MACOS_AARCH64)/release/libconnector_service_ffi.dylib \
		-output $(REPO_ROOT)/target/universal/release/libconnector_service_ffi.dylib
	@echo "Universal binary created: $(REPO_ROOT)/target/universal/release/libconnector_service_ffi.dylib"

build-macos: ## Build for all macOS platforms
	$(if $(filter Darwin,$(UNAME)),,$(error "macOS builds can only be done on macOS"))
	@$(MAKE) build-macos-x86_64 build-macos-aarch64 build-macos-universal

# Linux builds (native - no zig/cross needed for native platforms)
build-linux-x86_64: check-cargo ## Build for Linux x86_64
	@echo "Building for Linux x86_64..."
	@cd $(FFI_CRATE) && cargo build --no-default-features --features uniffi --release --target $(TARGET_LINUX_x86_64)
	@echo "Build complete: target/$(TARGET_LINUX_x86_64)/release/libconnector_service_ffi.so"

build-linux-aarch64: check-cargo ## Build for Linux aarch64
	@echo "Building for Linux aarch64..."
	@cd $(FFI_CRATE) && cargo zigbuild --no-default-features --features uniffi --release --target $(TARGET_LINUX_AARCH64)
	@echo "Build complete: target/$(TARGET_LINUX_AARCH64)/release/libconnector_service_ffi.so"

build-linux: build-linux-x86_64 build-linux-aarch64 ## Build for all Linux platforms

# All platforms
build-all: ## Build for all supported platforms
	@echo "Building for all platforms..."
	$(if $(filter Darwin,$(UNAME)),\
		$(MAKE) build-macos-x86_64 build-macos-aarch64 build-macos-universal build-linux-x86_64 build-linux-aarch64\
	)
	@echo "All builds complete!"

clean: ## Clean all build artifacts
	@echo "Cleaning build artifacts..."
	@cd $(FFI_CRATE) && cargo clean
	@echo "Clean complete."
