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

# Install Node.js dependencies
install-deps:
	@echo "Installing Node.js dependencies..."
	@npm install
	@echo "Done."

# Full setup
setup: install-deps generate-bindings generate-proto
	@echo "Setup complete. Run 'make run' or 'node main.js'."

# Run the example
run:
	@node main.js

clean:
	@rm -rf $(GENERATED_OUT) node_modules
