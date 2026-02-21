.PHONY: build-lib generate-bindings generate-proto install-deps setup run clean package package-native dist

# Auto-detect SDK root directory (works when run from sdk/javascript/ or repo root)
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SDK_ROOT := $(MAKEFILE_DIR)
REPO_ROOT := $(MAKEFILE_DIR)../..

# Paths relative to SDK root
FFI_CRATE=$(REPO_ROOT)/backend/ffi
PROTO_DIR=$(REPO_ROOT)/backend/grpc-api-types/proto
GENERATED_OUT=$(SDK_ROOT)/generated
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
	@./node_modules/.bin/pbjs -t static-module -w commonjs --no-delimited --no-convert --alt-comment \
		-p $(PROTO_DIR) \
		$(PROTO_DIR)/payment.proto $(PROTO_DIR)/payment_methods.proto \
		-o $(GENERATED_OUT)/proto.js
	@echo "Proto JS generated in $(GENERATED_OUT)/proto.js"
	@./node_modules/.bin/pbts -o $(GENERATED_OUT)/proto.d.ts $(GENERATED_OUT)/proto.js
	@echo "Proto TS generated in $(GENERATED_OUT)/proto.d.ts"

# Install Node.js dependencies
install-deps:
	@echo "Checking Node.js dependencies..."
	@test -d node_modules || (echo "  → Installing npm dependencies..." && npm install)
	@test -f node_modules/.bin/pbjs || (echo "  → Installing protobufjs..." && npm install protobufjs)
	@echo "Done."

# Full setup
setup: install-deps generate-bindings generate-proto
	@echo "Setup complete. Run 'make run' to execute."

# Run the example
run:
	@node main.js

clean:
	@rm -rf $(GENERATED_OUT) node_modules

# Packaging targets for release workflow - PLATFORM SPECIFIC
package-linux-x86_64: generate-proto
	@echo "Packaging JavaScript SDK for Linux x86_64..."
	@mkdir -p $(PACKAGE_DIR)/linux-x86_64
	@cp -f ../../target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || \
		(echo "Warning: Linux x86_64 binary not found. Build it first with: make -C ../.. build-linux-x86_64" && exit 1)
	@cp -rf $(GENERATED_OUT)/*.js $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@cp -rf $(GENERATED_OUT)/*.d.ts $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@cp main.js $(PACKAGE_DIR)/linux-x86_64/example.js 2>/dev/null || true
	@echo "Linux x86_64 package created: $(PACKAGE_DIR)/linux-x86_64/"

package-macos-aarch64: generate-proto
	@echo "Packaging JavaScript SDK for macOS aarch64..."
	@mkdir -p $(PACKAGE_DIR)/macos-aarch64
	@cp -f ../../target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || \
		(echo "Warning: macOS aarch64 binary not found. Build it first with: make -C ../.. build-macos-aarch64" && exit 1)
	@cp -rf $(GENERATED_OUT)/*.js $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@cp -rf $(GENERATED_OUT)/*.d.ts $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@cp main.js $(PACKAGE_DIR)/macos-aarch64/example.js 2>/dev/null || true
	@echo "macOS aarch64 package created: $(PACKAGE_DIR)/macos-aarch64/"

package-native: package-linux-x86_64 package-macos-aarch64

# Create distribution archives for all platforms
dist: package-native
	@echo "Creating JavaScript SDK distribution archives..."
	@cd $(PACKAGE_DIR) && for dir in */; do \
		if [ -d "$$dir" ]; then \
			zip -r "connector-service-javascript-sdk-$${dir%/}.zip" "$$dir"; \
		fi; \
	done
	@echo "Distribution archives created in $(PACKAGE_DIR)/"
