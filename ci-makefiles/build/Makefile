# Build Makefile
# Handles cross-platform Rust builds for UniFFI binaries
# Supports macOS (x86_64, aarch64) and Linux (x86_64, aarch64)

.PHONY: help build build-all build-macos build-linux clean check-cargo

# Default target
.DEFAULT_GOAL := help

# Configuration
FFI_CRATE := backend/ffi
RELEASE_DIR := target/release
CROSS_RELEASE_DIR := target/cross

# Target platforms
TARGET_MACOS_X86 := x86_64-apple-darwin
TARGET_MACOS_AARCH64 := aarch64-apple-darwin
TARGET_LINUX_X86 := x86_64-unknown-linux-gnu
TARGET_LINUX_AARCH64 := aarch64-unknown-linux-gnu

# Detect current platform
UNAME := $(shell uname -s)
ARCH := $(shell uname -m)

help: ## Show this help message
	@echo "Build Makefile - Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Current platform: $(UNAME) $(ARCH)"

check-cargo: ## Verify cargo is installed
	@which cargo > /dev/null 2>&1 || (echo "Error: cargo is not installed" && exit 1)

install-cross: check-cargo ## Install cross compilation tool (cargo-zigbuild)
	@echo "Installing cross-compilation tools..."
	@cargo install cargo-zigbuild 2>/dev/null || echo "cargo-zigbuild already installed or alternative in use"

add-targets: check-cargo ## Add required Rust targets for cross-compilation
	@echo "Adding Rust targets..."
	rustup target add $(TARGET_LINUX_X86) 2>/dev/null || true
	rustup target add $(TARGET_LINUX_AARCH64) 2>/dev/null || true
	@echo "Targets configured."

build: check-cargo ## Build UniFFI library for current platform
	@echo "Building UniFFI library for current platform..."
	@cd $(FFI_CRATE) && cargo build --no-default-features --features uniffi --release
	@echo "Build complete: target/release/libconnector_service_ffi.$(LIB_EXT)"

build-native: check-cargo ## Build native library with all optimizations
	@echo "Building native optimized library..."
	@cd $(FFI_CRATE) && RUSTFLAGS="-C target-cpu=native" cargo build --no-default-features --features uniffi --release
	@echo "Native build complete."

# macOS builds
build-macos-x86: check-cargo ## Build for macOS Intel (x86_64)
	@echo "Building for macOS Intel (x86_64)..."
	@cd $(FFI_CRATE) && cargo build --no-default-features --features uniffi --release --target $(TARGET_MACOS_X86)
	@echo "Build complete: target/$(TARGET_MACOS_X86)/release/libconnector_service_ffi.dylib"

build-macos-aarch64: check-cargo ## Build for macOS Apple Silicon (aarch64)
	@echo "Building for macOS Apple Silicon (aarch64)..."
	@cd $(FFI_CRATE) && cargo build --no-default-features --features uniffi --release --target $(TARGET_MACOS_AARCH64)
	@echo "Build complete: target/$(TARGET_MACOS_AARCH64)/release/libconnector_service_ffi.dylib"

build-macos-universal: build-macos-x86 build-macos-aarch64 ## Build universal binary for macOS
	@echo "Creating universal binary for macOS..."
	@mkdir -p target/universal/release
	@lipo -create \
		target/$(TARGET_MACOS_X86)/release/libconnector_service_ffi.dylib \
		target/$(TARGET_MACOS_AARCH64)/release/libconnector_service_ffi.dylib \
		-output target/universal/release/libconnector_service_ffi.dylib
	@echo "Universal binary created: target/universal/release/libconnector_service_ffi.dylib"

build-macos: ## Build for all macOS platforms
	$(if $(filter Darwin,$(UNAME)),,$(error "macOS builds can only be done on macOS"))
	@$(MAKE) build-macos-x86 build-macos-aarch64 build-macos-universal

# Linux builds (using cross or zigbuild)
build-linux-x86: check-cargo ## Build for Linux x86_64
	@echo "Building for Linux x86_64..."
	@cd $(FFI_CRATE) && cargo zigbuild --no-default-features --features uniffi --release --target $(TARGET_LINUX_X86)
	@echo "Build complete: target/$(TARGET_LINUX_X86)/release/libconnector_service_ffi.so"

build-linux-aarch64: check-cargo ## Build for Linux aarch64
	@echo "Building for Linux aarch64..."
	@cd $(FFI_CRATE) && cargo zigbuild --no-default-features --features uniffi --release --target $(TARGET_LINUX_AARCH64)
	@echo "Build complete: target/$(TARGET_LINUX_AARCH64)/release/libconnector_service_ffi.so"

build-linux: build-linux-x86 build-linux-aarch64 ## Build for all Linux platforms

# All platforms
build-all: ## Build for all supported platforms
	@echo "Building for all platforms..."
	$(if $(filter Darwin,$(UNAME)),\
		$(MAKE) build-macos-x86 build-macos-aarch64 build-macos-universal build-linux-x86 build-linux-arm,\
		$(MAKE) build-linux-x86 build-linux-aarch64)
	@echo "All builds complete!"

collect-binaries: ## Collect all built binaries into a single directory
	@echo "Collecting binaries..."
	@mkdir -p artifacts/binaries
	@cp -f target/release/libconnector_service_ffi.* artifacts/binaries/ 2>/dev/null || true
	@cp -f target/$(TARGET_MACOS_X86)/release/libconnector_service_ffi.dylib artifacts/binaries/libconnector_service_ffi-x86_64-apple-darwin.dylib 2>/dev/null || true
	@cp -f target/$(TARGET_MACOS_AARCH64)/release/libconnector_service_ffi.dylib artifacts/binaries/libconnector_service_ffi-aarch64-apple-darwin.dylib 2>/dev/null || true
	@cp -f target/universal/release/libconnector_service_ffi.dylib artifacts/binaries/libconnector_service_ffi-universal-apple-darwin.dylib 2>/dev/null || true
	@cp -f target/$(TARGET_LINUX_X86)/release/libconnector_service_ffi.so artifacts/binaries/libconnector_service_ffi-x86_64-unknown-linux-gnu.so 2>/dev/null || true
	@cp -f target/$(TARGET_LINUX_AARCH64)/release/libconnector_service_ffi.so artifacts/binaries/libconnector_service_ffi-aarch64-unknown-linux-gnu.so 2>/dev/null || true
	@echo "Binaries collected in artifacts/binaries/"
	@ls -la artifacts/binaries/

clean: ## Clean all build artifacts
	@echo "Cleaning build artifacts..."
	@cd $(FFI_CRATE) && cargo clean
	@rm -rf artifacts/binaries
	@echo "Clean complete."

print-targets: ## Print all supported build targets
	@echo "Supported build targets:"
	@echo "  - $(TARGET_MACOS_X86)     (macOS Intel)"
	@echo "  - $(TARGET_MACOS_AARCH64)     (macOS Apple Silicon)"
	@echo "  - $(TARGET_LINUX_X86)     (Linux x86_64)"
	@echo "  - $(TARGET_LINUX_AARCH64)     (Linux aarch64)"
