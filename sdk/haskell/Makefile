.PHONY: install-deps generate-bindings generate-proto generate-all \
        generate-flows build-hs pack-archive install test-package dist clean

# SDK-specific paths (define BEFORE including common.mk)
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SDK_ROOT     := $(MAKEFILE_DIR)

# Connectors to test (comma-separated, default: stripe)
CONNECTORS ?= stripe

# Include common SDK build configuration
include $(SDK_ROOT)/../common.mk

# SDK-specific paths continued
GENERATED_OUT := $(SDK_ROOT)/src/Payments/Generated
PACKAGE_DIR   := $(ARTIFACTS_DIR)/sdk-haskell

# ---------------------------------------------------------------------------
# install-deps
# Checks for GHC and cabal, which are provided by the Nix shell.
# ---------------------------------------------------------------------------
install-deps:
	@command -v ghc >/dev/null 2>&1 || \
		(echo "Error: ghc not found. Install via nix or ghcup." && exit 1)
	@command -v cabal >/dev/null 2>&1 || \
		(echo "Error: cabal not found. Install via nix or ghcup." && exit 1)
	@command -v protoc >/dev/null 2>&1 || \
		(echo "Error: protoc not found. Install via nix or your system package manager." && exit 1)
	@echo "All required tools present."

# ---------------------------------------------------------------------------
# generate-bindings
# Copies the pre-built FFI native library into the generated output directory
# so it is bundled with the Haskell package. The Haskell SDK drives the native
# library directly via Haskell FFI (dlopen/dlsym); no UniFFI code generation
# is required.
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
# Generates Haskell protobuf modules from .proto files using proto-lens-protoc.
# Output is placed in the Generated directory.
# ---------------------------------------------------------------------------
generate-proto: install-deps
	@echo "Generating Haskell protobuf modules..."
	@mkdir -p $(GENERATED_OUT)
	@command -v proto-lens-protoc >/dev/null 2>&1 && { \
		protoc \
			--plugin=protoc-gen-haskell=$$(which proto-lens-protoc) \
			--haskell_out=$(GENERATED_OUT) \
			-I $(PROTO_DIR) \
			$(PROTO_DIR)/payment.proto \
			$(PROTO_DIR)/payment_methods.proto \
			$(PROTO_DIR)/sdk_config.proto; \
		echo "Proto Haskell modules generated in $(GENERATED_OUT)/"; \
	} || { \
		echo "  Note: proto-lens-protoc not found, skipping proto generation."; \
		echo "  Types will need to be generated separately or obtained from proto-lens."; \
	}

# ---------------------------------------------------------------------------
# generate-flows
# Generates flow methods (authorize, capture, etc.) by running the SDK
# codegen script.
# ---------------------------------------------------------------------------
generate-flows:
	@echo "Generating Haskell flow methods..."
	@cd $(REPO_ROOT)/sdk/codegen && python3 generate.py --lang haskell
	@echo "Haskell flow methods generated."

# ---------------------------------------------------------------------------
# generate-all
# Runs all code-generation steps.
# ---------------------------------------------------------------------------
generate-all: generate-proto generate-bindings generate-flows

# ---------------------------------------------------------------------------
# build-hs
# Builds the Haskell SDK using cabal.
# ---------------------------------------------------------------------------
build-hs: install-deps
	@echo "Building Haskell SDK..."
	@cd $(SDK_ROOT) && cabal build all
	@echo "Haskell SDK built."

# ---------------------------------------------------------------------------
# pack-archive
# Creates a source distribution tarball using cabal sdist.
# ---------------------------------------------------------------------------
pack-archive:
	@mkdir -p $(PACKAGE_DIR)
	@cd $(SDK_ROOT) && cabal sdist -o $(PACKAGE_DIR)/
	@echo "Source tarball built in $(PACKAGE_DIR)/"

# ---------------------------------------------------------------------------
# install
# Installs the SDK locally via cabal install.
# ---------------------------------------------------------------------------
install: pack-archive

# ---------------------------------------------------------------------------
# test-package
# Full end-to-end test: builds the FFI library, generates all code artifacts,
# builds the Haskell SDK, and runs the smoke test.
# ---------------------------------------------------------------------------
test-package: build-ffi-lib generate-all build-hs
	@echo "Running Haskell SDK smoke test..."
	@if [ -f $(REPO_ROOT)/creds.json ]; then \
		cd $(SDK_ROOT) && cabal run smoke-test -- --connectors $(CONNECTORS); \
	else \
		echo "  Note: creds.json not found, running in dry-run mode"; \
		cd $(SDK_ROOT) && cabal run smoke-test -- --connectors $(CONNECTORS) --dry-run; \
	fi
	@echo "Haskell SDK test passed."

# ---------------------------------------------------------------------------
# dist
# Builds the distribution tarball for all supported platforms.
# ---------------------------------------------------------------------------
dist:
	@echo "Building Haskell SDK distribution tarball..."
	@mkdir -p $(GENERATED_OUT)
	@cp -fL $(REPO_ROOT)/target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: Linux x86_64 binary not found (skipping)"
	@cp -fL $(REPO_ROOT)/target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: macOS aarch64 binary not found (skipping)"
	@$(MAKE) -C $(SDK_ROOT) pack-archive
	@echo "Distribution tarball created in $(PACKAGE_DIR)/"

clean:
	@rm -rf $(GENERATED_OUT)/*.so $(GENERATED_OUT)/*.dylib
	@rm -f $(SDK_ROOT)/src/Payments/Generated/Flows.hs
	@cd $(SDK_ROOT) && cabal clean 2>/dev/null || true
