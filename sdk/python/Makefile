.PHONY: build-lib generate-bindings generate-proto install-deps setup clean pack pack-archive test-pack dist

# Auto-detect SDK root directory (works when run from sdk/python/ or repo root)
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SDK_ROOT := $(MAKEFILE_DIR)
REPO_ROOT := $(shell cd $(MAKEFILE_DIR)../.. && pwd)

# Paths relative to SDK root
FFI_CRATE=$(REPO_ROOT)/backend/ffi
PROTO_DIR=$(REPO_ROOT)/backend/grpc-api-types/proto
GENERATED_OUT=$(SDK_ROOT)/src/payments/generated
ARTIFACTS_DIR=$(REPO_ROOT)/artifacts
PACKAGE_DIR=$(ARTIFACTS_DIR)/sdk-python

# Detect OS for library extension
UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
  LIB_EXT = dylib
else
  LIB_EXT = so
endif

# Build the Rust shared library with uniffi feature
build-lib:
	@echo "Building UniFFI shared library..."
	@cd $(FFI_CRATE) && cargo build --no-default-features --features uniffi --release
	@echo "Build complete."

# Generate UniFFI Python bindings and symlink the shared library
generate-bindings: build-lib
	@echo "Generating UniFFI Python bindings..."
	@mkdir -p $(GENERATED_OUT)
	$(eval TARGET_DIR := $(shell cd $(FFI_CRATE) && cargo metadata --format-version 1 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['target_directory'])"))
	@cd $(FFI_CRATE) && cargo run --no-default-features --features uniffi-cli \
		--bin uniffi-bindgen -- \
		generate \
		--library $(TARGET_DIR)/release/libconnector_service_ffi.$(LIB_EXT) \
		--language python \
		--out-dir $(GENERATED_OUT)
	@ln -sf $(TARGET_DIR)/release/libconnector_service_ffi.$(LIB_EXT) $(GENERATED_OUT)/
	@echo "UniFFI bindings generated in $(GENERATED_OUT)/"

# Install Python dependencies
install-deps:
	@if [ -z "$${IN_NIX_SHELL:-}" ] && [ -f $(SDK_ROOT)/requirements.txt ]; then \
		echo "Installing Python dependencies (non-nix environment)..."; \
		pip3 install -r $(SDK_ROOT)/requirements.txt --quiet 2>/dev/null || pip3 install -r $(SDK_ROOT)/requirements.txt --user --quiet; \
	fi

# Generate Python protobuf stubs
generate-proto:
	@echo "Generating Python protobuf stubs..."
	@mkdir -p $(GENERATED_OUT)
	@python3 -m grpc_tools.protoc \
		-I $(PROTO_DIR) \
		--python_out=$(GENERATED_OUT) \
		$(PROTO_DIR)/payment.proto $(PROTO_DIR)/payment_methods.proto
	@# TODO: protoc --python_out generates bare imports (e.g. "import payment_methods_pb2")
	@# which break under a package layout. This sed rewrites them to relative imports.
	@# Remove this workaround if protoc adds a --python_relative_imports flag or if we
	@# switch to a protoc plugin that generates package-aware imports.
	@cd $(GENERATED_OUT) && for f in *_pb2.py; do \
		sed -i.bak 's/^import \(.*_pb2\) as/from . import \1 as/' "$$f" && rm -f "$$f.bak"; \
	done
	@touch $(GENERATED_OUT)/__init__.py
	@echo "Proto stubs generated."

# Full setup: build lib, generate both bindings and proto stubs
setup: install-deps generate-proto generate-bindings
	@echo "Setup complete. Run 'make test-pack' to package it and test the package."

# Archive step only — assumes generated/ already has binaries and proto stubs
pack-archive:
	@mkdir -p $(PACKAGE_DIR)
	@cd $(SDK_ROOT) && python3 -m pip wheel . --no-deps --wheel-dir $(PACKAGE_DIR)/
	@echo "Wheel built in $(PACKAGE_DIR)/"

# Local dev: build everything from scratch, then archive
pack: setup pack-archive

# Test the packed wheel in isolation
test-pack: pack
	@echo "Testing packed wheel..."
	@rm -rf /tmp/test-hyperswitch-py
	@mkdir -p /tmp/test-hyperswitch-py
	@cp $(SDK_ROOT)/test_smoke.py /tmp/test-hyperswitch-py/
	@python3 -m pip install --target /tmp/test-hyperswitch-py $(PACKAGE_DIR)/hyperswitch_payments-0.1.0-py3-none-any.whl --no-deps --force-reinstall
	@cd /tmp/test-hyperswitch-py && python3 test_smoke.py
	@rm -rf /tmp/test-hyperswitch-py
	@echo "Pack test passed."

# CI / cross-platform dist: copy all available binaries, then archive once
dist: generate-proto
	@echo "Building Python SDK distribution archive..."
	@cp -f $(REPO_ROOT)/target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: Linux x86_64 binary not found (skipping)"
	@cp -f $(REPO_ROOT)/target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: macOS aarch64 binary not found (skipping)"
	@$(MAKE) -C $(SDK_ROOT) pack-archive
	@echo "Distribution archive created in $(PACKAGE_DIR)/"

clean:
	@rm -rf $(GENERATED_OUT)
	@rm -rf $(SDK_ROOT)/build $(SDK_ROOT)/*.egg-info $(SDK_ROOT)/src/*.egg-info
