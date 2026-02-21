.PHONY: build-lib generate-bindings generate-proto install-deps setup run clean package package-native dist

# Path to the ffi crate
FFI_CRATE=../../backend/ffi
# Proto files
PROTO_DIR=../../backend/grpc-api-types/proto
PYTHON_OUT=./generated
ARTIFACTS_DIR=../../artifacts
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

# Generate Python protobuf stubs
generate-proto:
	@echo "Generating Python protobuf stubs..."
	@mkdir -p $(PYTHON_OUT)
	@python3 -m grpc_tools.protoc \
		-I $(PROTO_DIR) \
		--python_out=$(PYTHON_OUT) \
		$(PROTO_DIR)/payment.proto $(PROTO_DIR)/payment_methods.proto
	@touch $(PYTHON_OUT)/__init__.py
	@echo "Proto stubs generated."

# Full setup: build lib, generate both bindings and proto stubs
setup: generate-proto generate-bindings
	@echo "Setup complete. Run 'make run' to execute."

# Run the example
run:
	@python3 main.py

clean:
	@rm -rf $(PYTHON_OUT)

# Packaging targets for release workflow - PLATFORM SPECIFIC
package-linux-x86_64: generate-proto
	@echo "Packaging Python SDK for Linux x86_64..."
	@mkdir -p $(PACKAGE_DIR)/linux-x86_64
	@cp -f ../../target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || \
		(echo "Warning: Linux x86_64 binary not found. Build it first with: make -C ../.. build-linux-x86_64" && exit 1)
	@cp -rf $(PYTHON_OUT)/*.py $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@cp main.py $(PACKAGE_DIR)/linux-x86_64/example.py 2>/dev/null || true
	@echo "Linux x86_64 package created: $(PACKAGE_DIR)/linux-x86_64/"

package-macos-aarch64: generate-proto
	@echo "Packaging Python SDK for macOS aarch64..."
	@mkdir -p $(PACKAGE_DIR)/macos-aarch64
	@cp -f ../../target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || \
		(echo "Warning: macOS aarch64 binary not found. Build it first with: make -C ../.. build-macos-aarch64" && exit 1)
	@cp -rf $(PYTHON_OUT)/*.py $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@cp main.py $(PACKAGE_DIR)/macos-aarch64/example.py 2>/dev/null || true
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
