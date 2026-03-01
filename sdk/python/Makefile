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
PACKAGE_DIR   := $(ARTIFACTS_DIR)/sdk-python

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

# uniffi-bindgen is compiled into an ISOLATED target directory so that cargo
# never overwrites the pre-built library as a side-effect of feature-set changes
# (uniffi-cli vs uniffi). Using a separate --target-dir guarantees LIBRARY
# always points to the original artifact produced by build-ffi-lib.
UNIFFI_CLI_DIR := $(REPO_ROOT)/target-uniffi-cli
BINDGEN        := $(UNIFFI_CLI_DIR)/$(PLATFORM)/release/uniffi-bindgen

# ---------------------------------------------------------------------------
# install-deps
# Installs Python build-time dependencies required for code generation.
# Checks for tool existence before installing. In Nix environments tools are
# provided by the shell so installation is skipped (IN_NIX_SHELL is set).
# Outside Nix, installs grpcio-tools for protoc Python plugin if absent.
# ---------------------------------------------------------------------------
install-deps:
	@command -v python3 >/dev/null 2>&1 || \
		(echo "Error: python3 not found. Install via nix or your system package manager." && exit 1)
	@command -v cargo >/dev/null 2>&1 || \
		(echo "Error: cargo not found. Install Rust via rustup." && exit 1)
	@if [ -z "$${IN_NIX_SHELL:-}" ]; then \
		python3 -c "import grpc_tools" 2>/dev/null || \
			(echo "  → Installing grpcio-tools..." && \
			 pip3 install grpcio-tools --quiet 2>/dev/null || \
			 pip3 install grpcio-tools --user --quiet); \
	fi
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
# Builds the uniffi-bindgen binary (into $(UNIFFI_CLI_DIR)) then rebuilds the
# FFI library with --features uniffi to guarantee scaffolding symbols are
# present before running uniffi-bindgen generate. Building uniffi-bindgen uses
# --features uniffi-cli which can overwrite the cdylib in target/ despite
# --target-dir; the trailing build-ffi-lib call corrects that.
# ---------------------------------------------------------------------------
generate-bindings:
	@echo "Building uniffi-bindgen (isolated dir: $(UNIFFI_CLI_DIR))..."
	@cd $(FFI_CRATE) && cargo build --no-default-features --features uniffi-cli \
		--release --target $(PLATFORM) --bin uniffi-bindgen \
		--target-dir $(UNIFFI_CLI_DIR)
	@# The uniffi-cli build can overwrite the library in target/ (Cargo builds all declared
	@# crate-types: cdylib, rlib, staticlib). Rebuild with --features uniffi to ensure the
	@# scaffolding symbols are present before uniffi-bindgen generate reads the library.
	@$(MAKE) build-ffi-lib
	@echo "Generating UniFFI Python bindings from $(LIBRARY)..."
	@mkdir -p $(GENERATED_OUT)
	@cp -f $(LIBRARY) $(GENERATED_OUT)/
	@$(BINDGEN) generate \
		--library $(LIBRARY) \
		--language python \
		--out-dir $(GENERATED_OUT)
	@ls $(GENERATED_OUT)/connector_service_ffi.py > /dev/null 2>&1 || \
		(echo "ERROR: uniffi-bindgen generated no Python files." \
		 "Check that $(LIBRARY) was built with --features uniffi (uniffi::setup_scaffolding)." && exit 1)
	@echo "Python bindings generated in $(GENERATED_OUT)/"

# ---------------------------------------------------------------------------
# generate-proto
# Generates Python protobuf stubs from .proto files into the generated output
# directory, alongside the UniFFI Python bindings.
# Rewrites bare imports to relative package imports so the stubs work correctly
# under the payments package layout.
# ---------------------------------------------------------------------------
generate-proto: install-deps
	@echo "Generating Python protobuf stubs..."
	@mkdir -p $(GENERATED_OUT)
	@python3 -m grpc_tools.protoc \
		-I $(PROTO_DIR) \
		--python_out=$(GENERATED_OUT) \
		$(PROTO_DIR)/payment.proto $(PROTO_DIR)/payment_methods.proto $(PROTO_DIR)/sdk_options.proto
	@# TODO: protoc --python_out generates bare imports (e.g. "import payment_methods_pb2")
	@# which break under a package layout. Rewrite to relative imports until protoc
	@# adds a --python_relative_imports flag or we switch to a package-aware plugin.
	@cd $(GENERATED_OUT) && for f in *_pb2.py; do \
		sed -i.bak 's/^import \(.*_pb2\) as/from . import \1 as/' "$$f" && rm -f "$$f.bak"; \
	done
	@touch $(GENERATED_OUT)/__init__.py
	@echo "Proto stubs generated in $(GENERATED_OUT)/"

# ---------------------------------------------------------------------------
# generate-all
# Runs all code-generation steps: UniFFI Python bindings and Python protobuf
# stubs. Proto is generated first to ensure the __init__.py marker exists
# before the UniFFI wrapper references the package.
# ---------------------------------------------------------------------------
generate-all: generate-proto generate-bindings

# ---------------------------------------------------------------------------
# pack-archive
# Builds the SDK distribution wheel (.whl) using pip.
# Assumes generated/ already contains the UniFFI Python bindings, proto stubs,
# and the native FFI library. Does not rebuild any sources.
# ---------------------------------------------------------------------------
pack-archive:
	@mkdir -p $(PACKAGE_DIR)
	@cd $(SDK_ROOT) && python3 -m pip wheel . --no-deps --wheel-dir $(PACKAGE_DIR)/
	@echo "Wheel built in $(PACKAGE_DIR)/"

# ---------------------------------------------------------------------------
# install
# Builds the SDK wheel. Python wheels do not require a system-level install
# step analogous to Maven local — users install directly from the .whl file.
# This target is a no-op beyond pack-archive and exists for interface parity
# with the other SDK Makefiles.
# ---------------------------------------------------------------------------
install: pack-archive

# ---------------------------------------------------------------------------
# test-package
# Full end-to-end local test: builds the FFI library, generates all code
# artifacts, packs the wheel, then installs it into an isolated temp directory
# and runs the smoke test to verify the package works correctly.
# The temp directory is cleaned up after the test.
# ---------------------------------------------------------------------------
test-package: generate-all pack-archive
	@echo "Testing packed wheel in isolation..."
	@rm -rf /tmp/test-hyperswitch-py
	@mkdir -p /tmp/test-hyperswitch-py
	@cp $(SDK_ROOT)/test_smoke.py /tmp/test-hyperswitch-py/
	@python3 -m pip install \
		--target /tmp/test-hyperswitch-py \
		$(PACKAGE_DIR)/hyperswitch_payments-0.1.0-py3-none-any.whl \
		--no-deps --force-reinstall
	@cd /tmp/test-hyperswitch-py && python3 test_smoke.py
	@rm -rf /tmp/test-hyperswitch-py
	@echo "Package test passed."

# ---------------------------------------------------------------------------
# dist
# Builds the distribution wheel for all supported platforms.
# Copies pre-built native binaries for each target platform into the generated
# output directory, generates proto stubs, then packs the wheel. UniFFI Python
# bindings are expected to be already present (generated by a prior
# generate-bindings step or downloaded from a CI artifact).
# ---------------------------------------------------------------------------
dist:
	@echo "Building Python SDK distribution wheel..."
	@mkdir -p $(GENERATED_OUT)
	@cp -f $(REPO_ROOT)/target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: Linux x86_64 binary not found (skipping)"
	@cp -f $(REPO_ROOT)/target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: macOS aarch64 binary not found (skipping)"
	@$(MAKE) -C $(SDK_ROOT) pack-archive
	@echo "Distribution wheel created in $(PACKAGE_DIR)/"

clean:
	@rm -rf $(GENERATED_OUT)
	@rm -rf $(SDK_ROOT)/build $(SDK_ROOT)/*.egg-info $(SDK_ROOT)/src/*.egg-info
