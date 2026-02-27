.PHONY: build-lib generate-bindings generate-proto install-deps setup clean pack pack-archive test-pack dist

# Auto-detect SDK root directory (works when run from sdk/javascript/ or repo root)
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SDK_ROOT := $(MAKEFILE_DIR)
REPO_ROOT := $(shell cd $(MAKEFILE_DIR)../.. && pwd)

# Paths relative to SDK root
FFI_CRATE=$(REPO_ROOT)/backend/ffi
PROTO_DIR=$(REPO_ROOT)/backend/grpc-api-types/proto
GENERATED_OUT=$(SDK_ROOT)/src/payments/generated
ARTIFACTS_DIR=$(REPO_ROOT)/artifacts
PACKAGE_DIR=$(ARTIFACTS_DIR)/sdk-javascript

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

# Symlink the shared library into generated/
generate-bindings: build-lib
	@echo "Symlinking UniFFI shared library..."
	@mkdir -p $(GENERATED_OUT)
	$(eval TARGET_DIR := $(shell cd $(FFI_CRATE) && cargo metadata --format-version 1 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['target_directory'])"))
	@ln -sf $(TARGET_DIR)/release/libconnector_service_ffi.$(LIB_EXT) $(GENERATED_OUT)/
	@echo "Library linked in $(GENERATED_OUT)/"

# Generate static JS protobuf module from .proto files
generate-proto: install-deps
	@echo "Generating static protobuf JS module..."
	@mkdir -p $(GENERATED_OUT)
	@cd $(SDK_ROOT) && ./node_modules/.bin/pbjs -t static-module -w commonjs --no-delimited --no-convert --alt-comment \
		-p $(PROTO_DIR) \
		$(PROTO_DIR)/payment.proto $(PROTO_DIR)/payment_methods.proto \
		-o $(GENERATED_OUT)/proto.js
	@echo "Proto JS generated in $(GENERATED_OUT)/proto.js"
	@cd $(SDK_ROOT) && ./node_modules/.bin/pbts -o $(GENERATED_OUT)/proto.d.ts $(GENERATED_OUT)/proto.js
	@echo "Proto TS generated in $(GENERATED_OUT)/proto.d.ts"

# Install Node.js dependencies
install-deps:
	@echo "Checking Node.js dependencies..."
	@cd $(SDK_ROOT) && (test -d node_modules || (echo "  → Installing npm dependencies..." && npm install))
	@cd $(SDK_ROOT) && (test -f node_modules/.bin/pbjs || (echo "  → Installing protobufjs..." && npm install protobufjs))
	@echo "Done."

# Full setup
setup: install-deps generate-bindings generate-proto
	@echo "Setup complete. Run 'make test-pack' to package it and test the package."

# Archive step only — assumes generated/ already has binaries and proto stubs
# Resolves any symlink before packing (npm does not follow symlinks)
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

# Local dev: build everything from scratch, then archive
pack: setup pack-archive

# Test the packed tarball in isolation
test-pack: pack
	@echo "Testing packed tarball..."
	@rm -rf /tmp/test-hyperswitch-js
	@mkdir -p /tmp/test-hyperswitch-js && cd /tmp/test-hyperswitch-js && npm init -y --silent && npm install $(PACKAGE_DIR)/hyperswitch-payments-0.1.0.tgz --silent
	@cp $(SDK_ROOT)/test_smoke.js /tmp/test-hyperswitch-js/test_smoke.js
	@cd /tmp/test-hyperswitch-js && node test_smoke.js
	@rm -rf /tmp/test-hyperswitch-js
	@echo "Pack test passed."

# CI / cross-platform dist: copy all available binaries (real files, not symlinks), then archive once
dist: generate-proto install-deps
	@echo "Building JavaScript SDK distribution archive..."
	@cp -fL $(REPO_ROOT)/target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: Linux x86_64 binary not found (skipping)"
	@cp -fL $(REPO_ROOT)/target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: macOS aarch64 binary not found (skipping)"
	@$(MAKE) -C $(SDK_ROOT) pack-archive
	@echo "Distribution archive created in $(PACKAGE_DIR)/"

clean:
	@rm -rf $(GENERATED_OUT) node_modules
