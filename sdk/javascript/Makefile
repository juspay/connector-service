.PHONY: install-deps build-ffi-lib generate-bindings generate-proto generate-all \
        pack-archive install test-package dist clean

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SDK_ROOT     := $(MAKEFILE_DIR)
REPO_ROOT    := $(shell cd $(MAKEFILE_DIR)../.. && pwd)

FFI_CRATE     := $(REPO_ROOT)/backend/ffi
PROTO_DIR     := $(REPO_ROOT)/backend/grpc-api-types/proto
GENERATED_OUT := $(SDK_ROOT)/src/payments/generated
ARTIFACTS_DIR := $(REPO_ROOT)/artifacts
PACKAGE_DIR   := $(ARTIFACTS_DIR)/sdk-javascript

# ---------------------------------------------------------------------------
# Platform detection
# Always building with --target <PLATFORM> keeps the artifact layout identical
# on CI runners and developer machines (target/<PLATFORM>/release/).
# ---------------------------------------------------------------------------
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S), Darwin)
  ifeq ($(UNAME_M), arm64)
    PLATFORM := aarch64-apple-darwin
  else
    PLATFORM := x86_64-apple-darwin
  endif
  LIB_EXT := dylib
else
  ifeq ($(UNAME_M), aarch64)
    PLATFORM := aarch64-unknown-linux-gnu
  else
    PLATFORM := x86_64-unknown-linux-gnu
  endif
  LIB_EXT := so
endif

# Pre-built FFI library for the current platform (output of build-ffi-lib).
LIBRARY := $(REPO_ROOT)/target/$(PLATFORM)/release/libconnector_service_ffi.$(LIB_EXT)

# ---------------------------------------------------------------------------
# install-deps
# Installs Node.js build dependencies required for protobuf code generation.
# Checks for tool existence before installing. In Nix environments, node and
# npm are provided by the shell. Outside Nix, runs npm install only when
# node_modules or the required pbjs/pbts binaries are absent.
# ---------------------------------------------------------------------------
install-deps:
	@command -v node >/dev/null 2>&1 || \
		(echo "Error: node not found. Install via nix or https://nodejs.org" && exit 1)
	@command -v npm >/dev/null 2>&1 || \
		(echo "Error: npm not found. Install via nix or https://nodejs.org" && exit 1)
	@cd $(SDK_ROOT) && \
		(test -d node_modules && test -f node_modules/.bin/pbjs && test -f node_modules/.bin/pbts) || \
		(echo "  → Installing npm dependencies..." && npm install)
	@echo "All required tools present."

# ---------------------------------------------------------------------------
# build-ffi-lib
# Builds the Rust FFI shared library for the auto-detected platform.
# Output: target/<PLATFORM>/release/libconnector_service_ffi.<ext>
# Using --target consistently means local builds and CI builds share the same
# directory layout — no special-case LIBRARY= or TARGET_TRIPLE= variables needed.
# ---------------------------------------------------------------------------
build-ffi-lib:
	@echo "Building FFI shared library for $(PLATFORM)..."
	@cd $(FFI_CRATE) && cargo build --no-default-features --features uniffi \
		--release --target $(PLATFORM)
	@echo "Build complete: $(LIBRARY)"

# ---------------------------------------------------------------------------
# generate-bindings
# Copies the pre-built FFI native library into the generated output directory
# so it is bundled with the npm package. The JavaScript SDK drives the native
# library directly via Node.js FFI; no UniFFI code generation is required.
# Requires: build-ffi-lib to have been run first (or library downloaded in CI).
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
# Generates a static protobuf JavaScript module and its TypeScript declaration
# from the .proto files using protobufjs (pbjs/pbts). Output is placed in the
# generated output directory alongside the native FFI library.
# ---------------------------------------------------------------------------
generate-proto: install-deps
	@echo "Generating static protobuf JS module..."
	@mkdir -p $(GENERATED_OUT)
	@cd $(SDK_ROOT) && ./node_modules/.bin/pbjs \
		-t static-module -w commonjs --no-delimited --no-convert --alt-comment \
		-p $(PROTO_DIR) \
		$(PROTO_DIR)/payment.proto $(PROTO_DIR)/payment_methods.proto \
		$(PROTO_DIR)/sdk_options.proto \
		-o $(GENERATED_OUT)/proto.js
	@echo "Proto JS generated: $(GENERATED_OUT)/proto.js"
	@cd $(SDK_ROOT) && ./node_modules/.bin/pbts \
		-o $(GENERATED_OUT)/proto.d.ts $(GENERATED_OUT)/proto.js
	@echo "Proto TS generated: $(GENERATED_OUT)/proto.d.ts"

# ---------------------------------------------------------------------------
# generate-all
# Runs all code-generation steps: copies the native library and generates the
# protobuf JS/TS module. Proto depends on install-deps; both can run in any
# order relative to each other.
# ---------------------------------------------------------------------------
generate-all: generate-proto generate-bindings

# ---------------------------------------------------------------------------
# pack-archive
# Builds the SDK npm tarball (.tgz) using npm pack.
# Assumes generated/ already contains the native FFI library and proto stubs.
# Copies any symlinks as real files first since npm does not follow symlinks.
# ---------------------------------------------------------------------------
pack-archive:
	@mkdir -p $(PACKAGE_DIR)
	@if [ -L $(GENERATED_OUT)/libconnector_service_ffi.$(LIB_EXT) ]; then \
		cp -fL $(GENERATED_OUT)/libconnector_service_ffi.$(LIB_EXT) \
		        $(GENERATED_OUT)/libconnector_service_ffi.$(LIB_EXT).tmp && \
		mv -f   $(GENERATED_OUT)/libconnector_service_ffi.$(LIB_EXT).tmp \
		        $(GENERATED_OUT)/libconnector_service_ffi.$(LIB_EXT); \
	fi
	@cd $(SDK_ROOT) && npm pack --pack-destination $(PACKAGE_DIR)/
	@echo "Tarball built in $(PACKAGE_DIR)/"

# ---------------------------------------------------------------------------
# install
# Builds the SDK tarball. npm tarballs do not require a system-level install
# step — users install directly with 'npm install file:...tgz'. This target
# is a no-op beyond pack-archive and exists for interface parity with the
# other SDK Makefiles.
# ---------------------------------------------------------------------------
install: pack-archive

# ---------------------------------------------------------------------------
# test-package
# Full end-to-end local test: builds the FFI library, generates all code
# artifacts, packs the tarball, then installs it into an isolated temporary
# npm project and runs the smoke test to verify the package works correctly.
# The temp directory is cleaned up after the test.
# ---------------------------------------------------------------------------
test-package: build-ffi-lib generate-all pack-archive
	@echo "Testing packed tarball in isolation..."
	@rm -rf /tmp/test-hyperswitch-js
	@mkdir -p /tmp/test-hyperswitch-js
	@cd /tmp/test-hyperswitch-js && npm init -y --silent && \
		npm install $(PACKAGE_DIR)/hyperswitch-payments-0.1.0.tgz --silent
	@cp $(SDK_ROOT)/test_smoke.js /tmp/test-hyperswitch-js/test_smoke.js
	@cd /tmp/test-hyperswitch-js && node test_smoke.js
	@rm -rf /tmp/test-hyperswitch-js
	@echo "Package test passed."

# ---------------------------------------------------------------------------
# dist
# Builds the distribution tarball for all supported platforms.
# Copies pre-built native binaries for each target platform into the generated
# output directory as real files (not symlinks — npm does not follow symlinks),
# generates the proto JS/TS module, then packs the tarball. The single-platform
# library from generate-bindings is overwritten by the multi-platform copies.
# ---------------------------------------------------------------------------
dist:
	@echo "Building JavaScript SDK distribution tarball..."
	@mkdir -p $(GENERATED_OUT)
	@cp -fL $(REPO_ROOT)/target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: Linux x86_64 binary not found (skipping)"
	@cp -fL $(REPO_ROOT)/target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: macOS aarch64 binary not found (skipping)"
	@$(MAKE) -C $(SDK_ROOT) pack-archive
	@echo "Distribution tarball created in $(PACKAGE_DIR)/"

clean:
	@rm -rf $(GENERATED_OUT) node_modules
