.PHONY: build-lib generate-bindings generate-proto setup run clean

# Path to the ffi crate
FFI_CRATE=../../backend/ffi
# Proto files
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

# Generate UniFFI Kotlin bindings and symlink the shared library
generate-bindings: build-lib
	@echo "Generating UniFFI Kotlin bindings..."
	@mkdir -p $(GENERATED_OUT)
	$(eval TARGET_DIR := $(shell cd $(FFI_CRATE) && cargo metadata --format-version 1 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['target_directory'])"))
	@cd $(FFI_CRATE) && cargo run --no-default-features --features uniffi-cli \
		--bin uniffi-bindgen -- \
		generate \
		--library $(TARGET_DIR)/release/libconnector_service_ffi.$(LIB_EXT) \
		--language kotlin \
		--out-dir $(CURDIR)/$(GENERATED_OUT)
	@ln -sf $(TARGET_DIR)/release/libconnector_service_ffi.$(LIB_EXT) $(GENERATED_OUT)/
	@echo "UniFFI Kotlin bindings generated in $(GENERATED_OUT)/"

# Generate Java protobuf stubs (usable from Kotlin)
generate-proto:
	@echo "Generating Java protobuf stubs..."
	@mkdir -p $(GENERATED_OUT)
	@protoc \
		-I $(PROTO_DIR) \
		--java_out=$(GENERATED_OUT) \
		$(PROTO_DIR)/payment.proto $(PROTO_DIR)/payment_methods.proto
	@echo "Proto stubs generated."

# Full setup: build lib, generate both bindings and proto stubs
setup: generate-proto generate-bindings
	@echo "Setup complete. Run './gradlew run' to execute."

# Run the example via Gradle
run:
	@./gradlew run --quiet

clean:
	@rm -rf $(GENERATED_OUT)
	@./gradlew clean 2>/dev/null || true
