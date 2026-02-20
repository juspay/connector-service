.PHONY: build-lib generate-bindings generate-proto install-deps setup run clean

# Path to the ffi crate
FFI_CRATE=../../backend/ffi
PROTO_DIR=../../backend/grpc-api-types/proto
GENERATED_OUT=./generated

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
	@./node_modules/.bin/pbjs -t static-module -w commonjs --no-delimited --no-convert \
		-p $(PROTO_DIR) \
		$(PROTO_DIR)/payment.proto $(PROTO_DIR)/payment_methods.proto \
		-o $(GENERATED_OUT)/proto.js
	@echo "Proto JS generated in $(GENERATED_OUT)/proto.js"
	@./node_modules/.bin/pbts -o $(GENERATED_OUT)/proto.d.ts $(GENERATED_OUT)/proto.js
	@echo "Proto TS generated in $(GENERATED_OUT)/proto.d.ts"

# Check if Node.js dependencies are available
CHECK_NODE_MODULES := $(shell test -d node_modules && echo "yes" || echo "no")
CHECK_PBJS := $(shell test -f node_modules/.bin/pbjs && echo "yes" || echo "no")

# Install Node.js dependencies (only if not already available)
install-deps:
	@echo "Checking Node.js dependencies..."
ifeq ($(CHECK_NODE_MODULES),yes)
	@echo "  ✓ node_modules already exists"
else
	@echo "  → Installing npm dependencies..."
	@npm install
endif
ifeq ($(CHECK_PBJS),yes)
	@echo "  ✓ protobufjs tools already available"
else
	@echo "  → Installing protobufjs..."
	@npm install protobufjs
endif
	@echo "Done."

# Full setup
setup: install-deps generate-bindings generate-proto
	@echo "Setup complete. Run 'make run' to execute."

# Run the example
run:
	@node main.js

clean:
	@rm -rf $(GENERATED_OUT) node_modules

# Packaging targets for release workflow
package: ## Package SDK for distribution
	@echo "Packaging JavaScript SDK..."
	@mkdir -p artifacts/javascript
	@cp -rf $(GENERATED_OUT) artifacts/javascript/
	@cp main.js artifacts/javascript/example.js 2>/dev/null || true
	@cp package*.json artifacts/javascript/ 2>/dev/null || true
	@echo "Package created in artifacts/javascript/"

dist: ## Create distribution archive
	@$(MAKE) package
	@cd artifacts && zip -r connector-service-javascript-sdk.zip javascript/
	@echo "Distribution archive: artifacts/connector-service-javascript-sdk.zip"
