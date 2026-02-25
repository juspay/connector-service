.PHONY: build-lib generate-bindings generate-proto setup example-run clean pack test-pack package package-native dist

# Auto-detect SDK root directory (works when run from sdk/java/ or repo root)
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SDK_ROOT := $(MAKEFILE_DIR)
# REPO_ROOT is either parent of SDK_ROOT or current dir if running from repo root
REPO_ROOT := $(shell cd $(MAKEFILE_DIR)../.. && pwd)

# Paths relative to SDK root
FFI_CRATE=$(REPO_ROOT)/backend/ffi
PROTO_DIR=$(REPO_ROOT)/backend/grpc-api-types/proto
GENERATED_KOTLIN=$(SDK_ROOT)/src/main/kotlin/generated
GENERATED_JAVA=$(SDK_ROOT)/src/main/java/generated
NATIVE_DIR=$(SDK_ROOT)/src/main/resources/native
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
	@mkdir -p $(GENERATED_KOTLIN) $(NATIVE_DIR)
	$(eval TARGET_DIR := $(shell cd $(FFI_CRATE) && cargo metadata --format-version 1 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['target_directory'])"))
	@cd $(FFI_CRATE) && cargo run --no-default-features --features uniffi-cli \
		--bin uniffi-bindgen -- \
		generate \
		--library $(TARGET_DIR)/release/libconnector_service_ffi.$(LIB_EXT) \
		--language kotlin \
		--out-dir $(GENERATED_KOTLIN)
	@ln -sf $(TARGET_DIR)/release/libconnector_service_ffi.$(LIB_EXT) $(NATIVE_DIR)/
	@# TODO: UniFFI codegen (v0.28) generates IntegrationException with a constructor
	@# parameter `val message: String` that conflicts with Exception.message. The sed
	@# below adds `override` and removes the redundant getter. Remove this workaround
	@# when upgrading to a UniFFI version that fixes this Kotlin codegen issue.
	@# See: https://github.com/mozilla/uniffi-rs/issues/2182
	@find $(GENERATED_KOTLIN) -name '*.kt' -exec sed -i.bak 's/^        val `message`: kotlin\.String/        override val `message`: kotlin.String/' {} +
	@find $(GENERATED_KOTLIN) -name '*.kt' -exec sed -i.bak '/class IntegrationException/,/^    }/{/^        override val message/d;/^            get() = "message=/d;}' {} +
	@find $(GENERATED_KOTLIN) -name '*.kt.bak' -delete
	@echo "UniFFI Kotlin bindings generated in $(GENERATED_KOTLIN)/"

# Generate Java protobuf stubs (usable from Kotlin)
generate-proto:
	@echo "Generating Java protobuf stubs..."
	@mkdir -p $(GENERATED_JAVA)
	@protoc \
		-I $(PROTO_DIR) \
		--java_out=$(GENERATED_JAVA) \
		$(PROTO_DIR)/payment.proto $(PROTO_DIR)/payment_methods.proto
	@echo "Proto stubs generated."

# Full setup: build lib, generate both bindings and proto stubs
setup: generate-proto generate-bindings
	@echo "Setup complete. Run 'make example-run' to execute."

# Run the example via Gradle (from separate examples/ project)
example-run: pack
	@cd $(SDK_ROOT)/examples && $(SDK_ROOT)/gradlew run --quiet

# Publish to local Maven repository
pack: setup
	@./gradlew publishToMavenLocal
	@echo "Published to Maven Local (~/.m2/repository/com/hyperswitch/payments-client/0.1.0/)"

# Test the packed JAR — verify it contains the expected classes and native lib
test-pack: pack
	@echo "Testing packed JAR..."
	@JAR=$$HOME/.m2/repository/com/hyperswitch/payments-client/0.1.0/payments-client-0.1.0.jar && \
	echo "  JAR: $$JAR" && \
	jar tf "$$JAR" | grep -q 'ConnectorClient.class' && echo "  ConnectorClient.class: found" && \
	jar tf "$$JAR" | grep -q 'native/libconnector_service_ffi' && echo "  native lib: found" && \
	jar tf "$$JAR" | grep -q 'uniffi/connector_service_ffi' && echo "  UniFFI bindings: found" && \
	jar tf "$$JAR" | grep -q 'ucs/v2/Payment' && echo "  Protobuf stubs: found"
	@echo "  Running example from separate project..."
	@cd $(SDK_ROOT)/examples && $(SDK_ROOT)/gradlew run --quiet
	@echo "Pack test passed."

clean:
	@rm -rf $(GENERATED_KOTLIN) $(GENERATED_JAVA) $(NATIVE_DIR)
	@./gradlew clean 2>/dev/null || true

# Packaging targets for release workflow - PLATFORM SPECIFIC
package-linux-x86_64: generate-proto
	@echo "Packaging Java SDK for Linux x86_64..."
	@mkdir -p $(PACKAGE_DIR)/linux-x86_64/native
	@cp -f $(REPO_ROOT)/target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so $(PACKAGE_DIR)/linux-x86_64/native/ 2>/dev/null || \
		(echo "Warning: Linux x86_64 binary not found. Build it first with: make -C $(REPO_ROOT)/sdk build-linux-x86_64" && exit 1)
	@cp -rf $(GENERATED_JAVA)/*.java $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
	@cp -rf $(GENERATED_KOTLIN)/*.kt $(PACKAGE_DIR)/linux-x86_64/ 2>/dev/null || true
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
	@cp -rf $(GENERATED_JAVA)/*.java $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
	@cp -rf $(GENERATED_KOTLIN)/*.kt $(PACKAGE_DIR)/macos-aarch64/ 2>/dev/null || true
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
