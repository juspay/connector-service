.PHONY: install-deps build-ffi-lib generate-bindings generate-proto generate-all \
        pack-archive install test-package dist clean

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SDK_ROOT     := $(MAKEFILE_DIR)
REPO_ROOT    := $(shell cd $(MAKEFILE_DIR)../.. && pwd)

FFI_CRATE        := $(REPO_ROOT)/backend/ffi
PROTO_DIR        := $(REPO_ROOT)/backend/grpc-api-types/proto
GENERATED_KOTLIN := $(SDK_ROOT)src/main/kotlin/generated
GENERATED_JAVA   := $(SDK_ROOT)/src/main/java/generated
NATIVE_DIR       := $(SDK_ROOT)/src/main/resources/native
ARTIFACTS_DIR    := $(REPO_ROOT)/artifacts
PACKAGE_DIR      := $(ARTIFACTS_DIR)/sdk-java

# ---------------------------------------------------------------------------
# Platform detection
# Always building with --target <PLATFORM> keeps the artifact layout identical
# on CI runners and developer machines (target/<PLATFORM>/release/).
# ---------------------------------------------------------------------------
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S), Darwin)
  ifeq ($(UNAME_M), arm64)
    PLATFORM := aarch64-apple-darwin
  else
    PLATFORM := x86_64-apple-darwin
  endif
  LIB_EXT := dylib
else
  ifeq ($(UNAME_M), aarch64)
    PLATFORM := aarch64-unknown-linux-gnu
  else
    PLATFORM := x86_64-unknown-linux-gnu
  endif
  LIB_EXT := so
endif

# Pre-built FFI library for the current platform (output of build-ffi-lib).
LIBRARY := $(REPO_ROOT)/target/$(PLATFORM)/release/libconnector_service_ffi.$(LIB_EXT)

# uniffi-bindgen is compiled into an ISOLATED target directory so that cargo
# never overwrites the pre-built library as a side-effect of feature-set changes
# (uniffi-cli vs uniffi). Using a separate --target-dir guarantees LIBRARY
# always points to the original artifact produced by build-ffi-lib.
UNIFFI_CLI_DIR := $(REPO_ROOT)/target-uniffi-cli
BINDGEN        := $(UNIFFI_CLI_DIR)/$(PLATFORM)/release/uniffi-bindgen

# ---------------------------------------------------------------------------
# install-deps
# Checks for required build tools. In Nix environments tools are provided by
# the shell so this is effectively a no-op. Outside Nix it exits with a helpful
# message for any missing tool rather than failing silently mid-build.
# ---------------------------------------------------------------------------
install-deps:
	@command -v protoc >/dev/null 2>&1 || \
		(echo "Error: protoc not found. Install via nix or 'apt install protobuf-compiler'." && exit 1)
	@command -v java >/dev/null 2>&1 || \
		(echo "Error: java not found. Install via nix or a JDK package." && exit 1)
	@command -v cargo >/dev/null 2>&1 || \
		(echo "Error: cargo not found. Install Rust via rustup." && exit 1)
	@echo "All required tools present."

# ---------------------------------------------------------------------------
# build-ffi-lib
# Builds the Rust FFI shared library for the auto-detected platform.
# Output: target/<PLATFORM>/release/libconnector_service_ffi.<ext>
# Using --target consistently means local builds and CI builds share the same
# directory layout — no special-case LIBRARY= or TARGET_TRIPLE= variables needed.
# ---------------------------------------------------------------------------
build-ffi-lib:
	@echo "Building FFI shared library for $(PLATFORM)..."
	@cd $(FFI_CRATE) && cargo build --no-default-features --features uniffi \
		--release --target $(PLATFORM)
	@echo "Build complete: $(LIBRARY)"

# ---------------------------------------------------------------------------
# generate-bindings
# Builds the uniffi-bindgen binary (into $(UNIFFI_CLI_DIR)) then rebuilds the
# FFI library with --features uniffi to guarantee scaffolding symbols are
# present before running uniffi-bindgen generate. Building uniffi-bindgen uses
# --features uniffi-cli which can overwrite the cdylib in target/ despite
# --target-dir; the trailing build-ffi-lib call corrects that.
# ---------------------------------------------------------------------------
generate-bindings:
	@echo "Building uniffi-bindgen (isolated dir: $(UNIFFI_CLI_DIR))..."
	@cd $(FFI_CRATE) && cargo build --no-default-features --features uniffi-cli \
		--release --target $(PLATFORM) --bin uniffi-bindgen \
		--target-dir $(UNIFFI_CLI_DIR)
	@# The uniffi-cli build can overwrite the library in target/ (Cargo builds all declared
	@# crate-types: cdylib, rlib, staticlib). Rebuild with --features uniffi to ensure the
	@# scaffolding symbols are present before uniffi-bindgen generate reads the library.
	@$(MAKE) build-ffi-lib
	@echo "Generating UniFFI Kotlin bindings from $(LIBRARY)..."
	@mkdir -p $(GENERATED_KOTLIN) $(NATIVE_DIR)
	@cp -f $(LIBRARY) $(NATIVE_DIR)/
	@$(BINDGEN) generate \
		--library $(LIBRARY) \
		--language kotlin \
		--out-dir $(GENERATED_KOTLIN)
	@find $(GENERATED_KOTLIN) -name '*.kt' | grep -q . || \
		(echo "ERROR: uniffi-bindgen generated no Kotlin files." \
		 "Check that $(LIBRARY) was built with --features uniffi (uniffi::setup_scaffolding)." && exit 1)
	@# TODO: UniFFI 0.28 codegen produces IntegrationException(val message: String)
	@# which conflicts with the inherited Exception.message property. Patch until
	@# upstream fixes Kotlin codegen. See: https://github.com/mozilla/uniffi-rs/issues/2182
	@find $(GENERATED_KOTLIN) -name '*.kt' -exec sed -i.bak \
		's/^        val `message`: kotlin\.String/        override val `message`: kotlin.String/' {} +
	@find $(GENERATED_KOTLIN) -name '*.kt' -exec sed -i.bak \
		'/class IntegrationException/,/^    }/{/^        override val message/d;/^            get() = "message=/d;}' {} +
	@find $(GENERATED_KOTLIN) -name '*.kt.bak' -delete
	@echo "Kotlin bindings generated in $(GENERATED_KOTLIN)/"

# ---------------------------------------------------------------------------
# generate-proto
# Generates Java protobuf stubs from .proto files into the Java sources
# directory, where they are compiled alongside the UniFFI Kotlin bindings.
# ---------------------------------------------------------------------------
generate-proto:
	@echo "Generating Java protobuf stubs..."
	@mkdir -p $(GENERATED_JAVA)
	@protoc \
		-I $(PROTO_DIR) \
		--java_out=$(GENERATED_JAVA) \
		$(PROTO_DIR)/payment.proto $(PROTO_DIR)/payment_methods.proto $(PROTO_DIR)/sdk_options.proto
	@echo "Proto stubs generated in $(GENERATED_JAVA)/"

# ---------------------------------------------------------------------------
# generate-all
# Runs all code-generation steps: UniFFI Kotlin bindings and Java protobuf
# stubs. Proto is generated first since the Kotlin code may reference those
# types at compile time.
# ---------------------------------------------------------------------------
generate-all: generate-proto generate-bindings

# ---------------------------------------------------------------------------
# pack-archive
# Builds the SDK distribution JAR using Gradle.
# Assumes generated/ directories and native/ already contain the UniFFI
# bindings, proto stubs, and the native FFI library respectively.
# Does not rebuild any sources — call generate-all first if needed.
# ---------------------------------------------------------------------------
pack-archive:
	@mkdir -p $(PACKAGE_DIR)
	@cd $(SDK_ROOT) && $(SDK_ROOT)/gradlew jar
	@cp $(SDK_ROOT)/build/libs/*.jar $(PACKAGE_DIR)/payments-client-0.1.0.jar
	@echo "JAR built in $(PACKAGE_DIR)/"

# ---------------------------------------------------------------------------
# install
# Builds the SDK JAR and publishes it to the local Maven repository (~/.m2)
# so that other projects on this machine can depend on it via Maven coordinates
# (com.hyperswitch:payments-client:0.1.0).
# ---------------------------------------------------------------------------
install: pack-archive
	@$(SDK_ROOT)/gradlew publishToMavenLocal
	@echo "Published to ~/.m2/repository/com/hyperswitch/payments-client/0.1.0/"

# ---------------------------------------------------------------------------
# test-package
# Full end-to-end local test: builds the FFI library, generates all code
# artifacts, installs the SDK to local Maven, then runs the smoke-test Gradle
# project in isolation to verify the published package works correctly.
# ---------------------------------------------------------------------------
test-package: generate-all install
	@echo "Running smoke test..."
	@cd $(SDK_ROOT)/smoke-test && $(SDK_ROOT)/gradlew run --quiet
	@echo "Package test passed."

# ---------------------------------------------------------------------------
# dist
# Builds the distribution JAR for all supported platforms.
# Copies pre-built native binaries from each platform's target directory into
# native/, generates proto stubs, then packs the JAR. UniFFI Kotlin bindings
# are expected to be already present (generated by a prior generate-bindings
# step or downloaded from a CI artifact).
# ---------------------------------------------------------------------------
dist:
	@echo "Building Java SDK distribution JAR..."
	@mkdir -p $(NATIVE_DIR)
	@cp -f $(REPO_ROOT)/target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so \
		$(NATIVE_DIR)/ 2>/dev/null || echo "  Note: Linux x86_64 binary not found (skipping)"
	@cp -f $(REPO_ROOT)/target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib \
		$(NATIVE_DIR)/ 2>/dev/null || echo "  Note: macOS aarch64 binary not found (skipping)"
	@$(MAKE) -C $(SDK_ROOT) pack-archive
	@echo "Distribution JAR created in $(PACKAGE_DIR)/"

clean:
	@rm -rf $(GENERATED_KOTLIN) $(GENERATED_JAVA) $(NATIVE_DIR)
	@$(SDK_ROOT)/gradlew clean 2>/dev/null || true
