.PHONY: build-lib generate-bindings generate-proto install-deps setup run clean

# Path to the ffi crate
FFI_CRATE=../../backend/ffi
# Proto files
PROTO_DIR=../../backend/grpc-api-types/proto
PYTHON_OUT=./generated

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
	@mkdir -p $(PYTHON_OUT)
	$(eval TARGET_DIR := $(shell cd $(FFI_CRATE) && cargo metadata --format-version 1 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['target_directory'])"))
	@cd $(FFI_CRATE) && cargo run --no-default-features --features uniffi-cli \
		--bin uniffi-bindgen -- \
		generate \
		--library $(TARGET_DIR)/release/libconnector_service_ffi.$(LIB_EXT) \
		--language python \
		--out-dir $(CURDIR)/$(PYTHON_OUT)
	@ln -sf $(TARGET_DIR)/release/libconnector_service_ffi.$(LIB_EXT) $(PYTHON_OUT)/
	@echo "UniFFI bindings generated in $(PYTHON_OUT)/"

# Generate Python protobuf stubs (same as example-py)
generate-proto:
	@echo "Generating Python protobuf stubs..."
	@mkdir -p $(PYTHON_OUT)
	@python3 -m grpc_tools.protoc \
		-I $(PROTO_DIR) \
		--python_out=$(PYTHON_OUT) \
		--mypy_out=$(PYTHON_OUT) \
		$(PROTO_DIR)/payment.proto $(PROTO_DIR)/payment_methods.proto
	@touch $(PYTHON_OUT)/__init__.py
	@echo "Proto stubs generated."

# Check if Python dependencies are available
CHECK_GRPCIO := $(shell python3 -c "import grpc" 2>/dev/null && echo "yes" || echo "no")
CHECK_PROTOC := $(shell python3 -m grpc_tools.protoc --version 2>/dev/null && echo "yes" || echo "no")

# Install Python dependencies (only if not already available, e.g., via nix)
install-deps:
	@echo "Checking Python dependencies..."
ifeq ($(CHECK_GRPCIO),yes)
	@echo "  ✓ grpcio already available"
else
	@echo "  → Installing grpcio..."
	@pip install grpcio
endif
ifeq ($(CHECK_PROTOC),yes)
	@echo "  ✓ grpcio-tools already available"
else
	@echo "  → Installing grpcio-tools..."
	@pip install grpcio-tools
endif
	@echo "Done."

# Full setup: build lib, generate both bindings and proto stubs
setup: install-deps generate-proto generate-bindings
	@echo "Setup complete. Run 'make run' to execute."

# Run the example
run:
	@python3 main.py

clean:
	@rm -rf $(PYTHON_OUT)

# Packaging targets for release workflow
package: ## Package SDK for distribution
	@echo "Packaging Python SDK..."
	@mkdir -p artifacts/python
	@cp -rf $(PYTHON_OUT) artifacts/python/
	@cp main.py artifacts/python/example.py 2>/dev/null || true
	@cp requirements*.txt artifacts/python/ 2>/dev/null || true
	@echo "Package created in artifacts/python/"

dist: ## Create distribution archive
	@$(MAKE) package
	@cd artifacts && zip -r connector-service-python-sdk.zip python/
	@echo "Distribution archive: artifacts/connector-service-python-sdk.zip"
