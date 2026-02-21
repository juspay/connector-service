.PHONY: build-lib generate-bindings generate-proto setup example-run clean package package-native dist

# Auto-detect SDK root directory (works when run from sdk/java/ or repo root)
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SDK_ROOT := $(MAKEFILE_DIR)
# REPO_ROOT is either parent of SDK_ROOT or current dir if running from repo root
REPO_ROOT := $(shell cd $(MAKEFILE_DIR)../.. && pwd)

# Paths relative to SDK root
FFI_CRATE=$(REPO_ROOT)/backend/ffi
PROTO_DIR=$(REPO_ROOT)/backend/grpc-api-types/proto
GENERATED_OUT=$(SDK_ROOT)/generated
ARTIFACTS_DIR=$(REPO_ROOT)/artifacts
PACKAGE_DIR=$(ARTIFACTS_DIR)/sdk-java

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
		--out-dir $(GENERATED_OUT)
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
	@echo "Setup complete. Run 'make example-run' to execute."

# Run the example via Gradle
example-run: setup
	@./gradlew run --quiet

clean:
	@rm -rf $(GENERATED_OUT)
	@./gradlew clean 2>/dev/null || true

# Packaging targets for release workflow - PLATFORM SPECIFIC
package-linux-x86_64: generate-proto
	@echo "Packaging Java SDK for Linux x86_64..."
	@mkdir -p $(PACKAGE_DIR)/linux-x86_64/native
	@cp -f $(REPO_ROOT)/target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so $(PACKAGE_DIR)/linux-x86_64/native/ 2>/dev/null || \
		(echo "Warning: Linux x86_64 binary not found. Build it first with: make -C $(REPO_ROOT)/sdk build-linux-x86_64" && exit 1)
	@cp -rf $(GENERATED_OUT)/*.java $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@cp -rf $(GENERATED_OUT)/*.kt $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@cp -rf $(SDK_ROOT)/src $(PACKAGE_DIR)/linux-x86_64/
	@cp $(SDK_ROOT)/build.gradle* $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@cp $(SDK_ROOT)/settings.gradle* $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@cp $(SDK_ROOT)/gradlew* $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@cp -rf $(SDK_ROOT)/gradle $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@echo "Linux x86_64 package created: $(PACKAGE_DIR)/linux-x86_64/"

package-macos-aarch64: generate-proto
	@echo "Packaging Java SDK for macOS aarch64..."
	@mkdir -p $(PACKAGE_DIR)/macos-aarch64/native
	@cp -f $(REPO_ROOT)/target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib $(PACKAGE_DIR)/macos-aarch64/native/ 2>/dev/null || \
		(echo "Warning: macOS aarch64 binary not found. Build it first with: make -C $(REPO_ROOT)/sdk build-macos-aarch64" && exit 1)
	@cp -rf $(GENERATED_OUT)/*.java $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@cp -rf $(GENERATED_OUT)/*.kt $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@cp -rf $(SDK_ROOT)/src $(PACKAGE_DIR)/macos-aarch64/
	@cp $(SDK_ROOT)/build.gradle* $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@cp $(SDK_ROOT)/settings.gradle* $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@cp $(SDK_ROOT)/gradlew* $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@cp -rf $(SDK_ROOT)/gradle $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@echo "macOS aarch64 package created: $(PACKAGE_DIR)/macos-aarch64/"

package-native: package-linux-x86_64 package-macos-aarch64

# Create distribution archives for all platforms
dist: package-native
	@echo "Creating Java SDK distribution archives..."
	@cd $(PACKAGE_DIR) && for dir in */; do \
		if [ -d "$$dir" ]; then \
			zip -r "connector-service-java-sdk-$${dir%/}.zip" "$$dir"; \
		fi; \
	done
	@echo "Distribution archives created in $(PACKAGE_DIR)/"
