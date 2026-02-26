.PHONY: build-lib generate-bindings generate-proto setup clean pack pack-archive test-pack dist

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
	@echo "Setup complete. Run 'make test-pack' to build and test the package."

# Archive step only — assumes native/ has binaries and generated/ has UniFFI + proto stubs
pack-archive:
	@mkdir -p $(PACKAGE_DIR)
	@cd $(SDK_ROOT) && ./gradlew jar
	@cp $(SDK_ROOT)/build/libs/*.jar $(PACKAGE_DIR)/payments-client-0.1.0.jar
	@echo "JAR built in $(PACKAGE_DIR)/"

# Local dev: build everything, publish to Maven Local (for test-pack/example-run), and build dist JAR
pack: setup
	@./gradlew publishToMavenLocal
	@echo "Published to Maven Local (~/.m2/repository/com/hyperswitch/payments-client/0.1.0/)"
	@$(MAKE) pack-archive

# Test the packed JAR — verify it contains the expected classes and native lib
test-pack: pack
	@echo "Testing packed JAR..."
	@JAR=$$HOME/.m2/repository/com/hyperswitch/payments-client/0.1.0/payments-client-0.1.0.jar && \
	echo "  JAR: $$JAR" && \
	jar tf "$$JAR" | grep -q 'ConnectorClient.class' && echo "  ConnectorClient.class: found" && \
	jar tf "$$JAR" | grep -q 'native/libconnector_service_ffi' && echo "  native lib: found" && \
	jar tf "$$JAR" | grep -q 'uniffi/connector_service_ffi' && echo "  UniFFI bindings: found" && \
	jar tf "$$JAR" | grep -q 'ucs/v2/Payment' && echo "  Protobuf stubs: found"
	@echo "  Running smoke test from separate project..."
	@cd $(SDK_ROOT)/smoke-test && $(SDK_ROOT)/gradlew run --quiet
	@echo "Pack test passed."

# CI / cross-platform dist: copy all available binaries, then archive once
dist: generate-proto
	@echo "Building Java SDK distribution JAR..."
	@mkdir -p $(NATIVE_DIR)
	@cp -f $(REPO_ROOT)/target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so \
		$(NATIVE_DIR)/ 2>/dev/null || echo "  Note: Linux x86_64 binary not found (skipping)"
	@cp -f $(REPO_ROOT)/target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib \
		$(NATIVE_DIR)/ 2>/dev/null || echo "  Note: macOS aarch64 binary not found (skipping)"
	@$(MAKE) pack-archive
	@echo "Distribution JAR created in $(PACKAGE_DIR)/"

clean:
	@rm -rf $(GENERATED_KOTLIN) $(GENERATED_JAVA) $(NATIVE_DIR)
	@./gradlew clean 2>/dev/null || true
