.PHONY: build-lib generate-bindings generate-proto install-deps setup example-run clean pack test-pack package package-native dist

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
	@echo "Setup complete. Run 'make example-run' to execute."

# Run the example
example-run: setup
	@cd $(SDK_ROOT) && python3 examples/example.py

# Build distributable wheel
pack: setup
	@cd $(SDK_ROOT) && python3 -m pip wheel . --no-deps --wheel-dir dist
	@echo "Package built. Artifacts in $(SDK_ROOT)/dist/"

# Test the packed wheel in isolation
test-pack: pack
	@echo "Testing packed wheel..."
	@rm -rf /tmp/test-hyperswitch-py
	@python3 -m pip install --target /tmp/test-hyperswitch-py $(SDK_ROOT)/dist/hyperswitch_payments-0.1.0-py3-none-any.whl --no-deps --force-reinstall
	@cd $(SDK_ROOT) && python3 examples/test_pack.py /tmp/test-hyperswitch-py
	@rm -rf /tmp/test-hyperswitch-py
	@echo "Pack test passed."

clean:
	@rm -rf $(GENERATED_OUT)
	@rm -rf $(SDK_ROOT)/dist $(SDK_ROOT)/build $(SDK_ROOT)/*.egg-info $(SDK_ROOT)/src/*.egg-info

# Packaging targets for release workflow - PLATFORM SPECIFIC
package-linux-x86_64: generate-proto
	@echo "Packaging Python SDK for Linux x86_64..."
	@mkdir -p $(PACKAGE_DIR)/linux-x86_64/examples
	@cp -f $(REPO_ROOT)/target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || \
		(echo "Warning: Linux x86_64 binary not found. Build it first with: make -C $(REPO_ROOT)/sdk build-linux-x86_64" && exit 1)
	@cp -rf $(GENERATED_OUT)/*.py $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@cp $(SDK_ROOT)/src/payments/connector_client.py $(PACKAGE_DIR)/linux-x86_64/
	@cp $(SDK_ROOT)/examples/example.py $(PACKAGE_DIR)/linux-x86_64/examples/ 2>/dev/null || true
	@echo "Linux x86_64 package created: $(PACKAGE_DIR)/linux-x86_64/"

package-macos-aarch64: generate-proto
	@echo "Packaging Python SDK for macOS aarch64..."
	@mkdir -p $(PACKAGE_DIR)/macos-aarch64/examples
	@cp -f $(REPO_ROOT)/target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || \
		(echo "Warning: macOS aarch64 binary not found. Build it first with: make -C $(REPO_ROOT)/sdk build-macos-aarch64" && exit 1)
	@cp -rf $(GENERATED_OUT)/*.py $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@cp $(SDK_ROOT)/src/payments/connector_client.py $(PACKAGE_DIR)/macos-aarch64/
	@cp $(SDK_ROOT)/examples/example.py $(PACKAGE_DIR)/macos-aarch64/examples/ 2>/dev/null || true
	@echo "macOS aarch64 package created: $(PACKAGE_DIR)/macos-aarch64/"

package-native: package-linux-x86_64 package-macos-aarch64

# Create distribution archives for all platforms
dist: package-native
	@echo "Creating Python SDK distribution archives..."
	@cd $(PACKAGE_DIR) && for dir in */; do \
		if [ -d "$$dir" ]; then \
			zip -r "connector-service-python-sdk-$${dir%/}.zip" "$$dir"; \
		fi; \
	done
	@echo "Distribution archives created in $(PACKAGE_DIR)/"
