# Plan: Replace `dist` Zip Archives with Language-Native Pack Artifacts

## Context

Currently each SDK's `dist` target creates custom zip archives from loose files in `package-<platform>` directories. But we already have `make pack` targets that produce proper language-native archives (`.whl`, `.tgz`, `.jar`). The `dist` target should produce these instead — they're the actual installable artifacts that users and package managers expect.

The release workflow (`.github/workflows/release.yml`) calls `make -f sdk/<lang>/Makefile dist` and uploads `artifacts/sdk-<lang>/*.zip` to GitHub Releases. This needs to change to upload the native artifacts.

---

## Local vs CI Build Model

These two contexts have different binary availability and require different outcomes:

| Context | Binaries available | Expected output |
|---------|-------------------|-----------------|
| Local (`make dist`) | Current arch only (e.g. `aarch64-apple-darwin`) | Single archive with only that binary — warns on missing platforms, does not fail |
| CI (`package-sdk-*` job) | All platform binaries downloaded before `dist` runs | Single archive with all platforms embedded |

**Key principle**: `dist` copies all binaries it can find, then packs ONCE. The same Makefile target works in both contexts — CI just happens to provide more binaries before calling it.

---

## New Flow

```
dist (local):
  copy current-arch binary into package staging area
  warn if cross-arch binary missing (do not fail)
  pack once → single archive with available binaries

dist (CI):
  CI job has pre-downloaded ALL platform binaries
  copy all binaries into package staging area
  pack once → single archive with all platforms
```

**Output — one archive per SDK, regardless of context:**
```
Python:     artifacts/sdk-python/hyperswitch_payments-0.1.0.whl
JavaScript: artifacts/sdk-javascript/hyperswitch-payments-0.1.0.tgz
Java:       artifacts/sdk-java/payments-client-0.1.0.jar
Rust:       artifacts/sdk-rust/connector-service-rust-sdk.zip  (source-only, unchanged)
```

Runtime binary selection (`.so` vs `.dylib`) is handled by the loader in each SDK — JNA for Java, `ffi.CDLL` for Python, `ffi` for JavaScript — based on the current platform.

---

## Why `dist` can't simply call `pack` today

`pack` depends on `setup` → `generate-bindings` → requires a local Rust build. In CI's
packaging job there is no Rust toolchain — only pre-built binaries are downloaded. So calling
`pack` from `dist` would fail.

**Fix**: split the archive step out of `pack` into a shared helper target. Both `pack` and
`dist` call it; they differ only in what they do before calling it.

```
pack-archive  ← just the archive step (assumes binaries already staged)
     ↑                ↑
   pack             dist
(setup first)   (copy all available binaries first)
```

---

## 1. Python SDK — `sdk/python/Makefile`

### Remove
- `package-linux-x86_64`, `package-macos-aarch64`, `package-native` targets

### Add `pack-archive`, update `pack`, add `dist`
```make
# Archive step only — assumes generated/ already has binaries and proto stubs
pack-archive:
	@mkdir -p $(ARTIFACTS_DIR)/sdk-python
	@cd $(SDK_ROOT) && python3 -m pip wheel . --no-deps --wheel-dir $(ARTIFACTS_DIR)/sdk-python/
	@echo "Wheel built in $(ARTIFACTS_DIR)/sdk-python/"

# Local dev: build everything from scratch, then archive
pack: setup pack-archive

# CI / cross-platform dist: copy all available binaries, then archive once
dist: generate-proto
	@echo "Building Python SDK distribution archive..."
	@cp -f $(REPO_ROOT)/target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: Linux x86_64 binary not found (skipping)"
	@cp -f $(REPO_ROOT)/target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: macOS aarch64 binary not found (skipping)"
	@$(MAKE) pack-archive
	@echo "Distribution archive created in $(ARTIFACTS_DIR)/sdk-python/"
```

Note: `pack` previously wrote to `$(SDK_ROOT)/dist/`; it now writes to `$(ARTIFACTS_DIR)/sdk-python/`
alongside `dist`. Update `test-pack` to reference the new path.

---

## 2. JavaScript SDK — `sdk/javascript/Makefile`

### Remove
- `package-linux-x86_64`, `package-macos-aarch64`, `package-native` targets

### Add `pack-archive`, update `pack`, add `dist`
```make
# Archive step only — assumes generated/ already has binaries and proto stubs
pack-archive:
	@mkdir -p $(ARTIFACTS_DIR)/sdk-javascript
	@# Resolve any remaining symlinks before npm pack (npm does not follow symlinks)
	@if [ -L $(GENERATED_OUT)/libconnector_service_ffi.$(LIB_EXT) ]; then \
		cp -fL $(GENERATED_OUT)/libconnector_service_ffi.$(LIB_EXT) \
		       $(GENERATED_OUT)/libconnector_service_ffi.$(LIB_EXT).tmp && \
		mv -f  $(GENERATED_OUT)/libconnector_service_ffi.$(LIB_EXT).tmp \
		       $(GENERATED_OUT)/libconnector_service_ffi.$(LIB_EXT); \
	fi
	@cd $(SDK_ROOT) && npm pack --pack-destination $(ARTIFACTS_DIR)/sdk-javascript/
	@echo "Tarball built in $(ARTIFACTS_DIR)/sdk-javascript/"

# Local dev: build everything from scratch, then archive
pack: setup pack-archive

# CI / cross-platform dist: copy all available binaries, then archive once
dist: generate-proto install-deps
	@echo "Building JavaScript SDK distribution archive..."
	@cp -fL $(REPO_ROOT)/target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: Linux x86_64 binary not found (skipping)"
	@cp -fL $(REPO_ROOT)/target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib \
		$(GENERATED_OUT)/ 2>/dev/null || echo "  Note: macOS aarch64 binary not found (skipping)"
	@$(MAKE) pack-archive
	@echo "Distribution archive created in $(ARTIFACTS_DIR)/sdk-javascript/"
```

Note: `-fL` on the `cp` in `dist` dereferences symlinks when copying from the Rust target dir.
The `pack-archive` symlink-resolution guard handles the local-dev case where `generate-bindings`
left a symlink.

---

## 3. Java SDK — `sdk/java/Makefile`

### Remove
- `package-linux-x86_64`, `package-macos-aarch64`, `package-native` targets

### Add `pack-archive`, update `pack`, add `dist`
```make
# Archive step only — assumes native/ already has binaries and generated/ has UniFFI + proto stubs
pack-archive:
	@mkdir -p $(ARTIFACTS_DIR)/sdk-java
	@cd $(SDK_ROOT) && ./gradlew jar
	@cp $(SDK_ROOT)/build/libs/*.jar $(ARTIFACTS_DIR)/sdk-java/payments-client-0.1.0.jar
	@echo "JAR built in $(ARTIFACTS_DIR)/sdk-java/"

# Local dev: build everything from scratch, then archive
pack: setup pack-archive

# CI / cross-platform dist: copy all available binaries, then archive once
dist: generate-proto
	@echo "Building Java SDK distribution JAR..."
	@mkdir -p $(NATIVE_DIR)
	@cp -f $(REPO_ROOT)/target/x86_64-unknown-linux-gnu/release/libconnector_service_ffi.so \
		$(NATIVE_DIR)/ 2>/dev/null || echo "  Note: Linux x86_64 binary not found (skipping)"
	@cp -f $(REPO_ROOT)/target/aarch64-apple-darwin/release/libconnector_service_ffi.dylib \
		$(NATIVE_DIR)/ 2>/dev/null || echo "  Note: macOS aarch64 binary not found (skipping)"
	@$(MAKE) pack-archive
	@echo "Distribution JAR created in $(ARTIFACTS_DIR)/sdk-java/"
```

### Java UniFFI bindings in CI — open issue

`./gradlew jar` compiles `src/main/kotlin/generated/connector_service_ffi.kt` (the UniFFI bindings).
Locally this file exists because the developer ran `make setup`. In CI, `generate-bindings`
requires `uniffi-bindgen` (Rust). The `package-sdk-java` CI job currently has no Rust toolchain.

**Proposed CI fix**: In the `build-binaries` matrix job for `linux-x86_64`, after building the
library, also run `uniffi-bindgen` to generate the `.kt` file and upload it as a separate
artifact (`uniffi-kotlin-bindings`). The `package-sdk-java` job then downloads this artifact
and places the `.kt` file at `sdk/java/src/main/kotlin/generated/` before running `dist`.

The `.kt` bindings are platform-independent (pure Kotlin), so generating them once from any
platform binary is sufficient.

---

## 4. Rust SDK — `sdk/rust/Makefile` (no change)

Rust already zips source. Keep as-is (no native binary to embed — it's a source-level crate).

---

## 5. Release Workflow — `.github/workflows/release.yml`

### Changes per SDK packaging job

**Upload patterns** — change from `*.zip` to the native extension per SDK:

| Job | Old path | New path |
|-----|----------|----------|
| `package-sdk-java` | `artifacts/sdk-java/*.zip` | `artifacts/sdk-java/*.jar` |
| `package-sdk-python` | `artifacts/sdk-python/*.zip` | `artifacts/sdk-python/*.whl` |
| `package-sdk-javascript` | `artifacts/sdk-javascript/*.zip` | `artifacts/sdk-javascript/*.tgz` |
| `package-sdk-rust` | `artifacts/sdk-rust/*.zip` | `artifacts/sdk-rust/*.zip` (unchanged) |

### `package-sdk-java` job — add UniFFI bindings step

Add after "Organize binaries":
```yaml
- name: Download UniFFI Kotlin bindings
  uses: actions/download-artifact@v4
  with:
    name: uniffi-kotlin-bindings
    path: sdk/java/src/main/kotlin/generated/
```

### `build-binaries` job — add bindings upload (linux-x86_64 only)

Add at end of `linux` matrix step:
```yaml
- name: Generate and upload UniFFI Kotlin bindings
  if: matrix.target == 'x86_64-unknown-linux-gnu'
  run: make -f sdk/java/Makefile generate-bindings
- name: Upload UniFFI Kotlin bindings
  if: matrix.target == 'x86_64-unknown-linux-gnu'
  uses: actions/upload-artifact@v4
  with:
    name: uniffi-kotlin-bindings
    path: sdk/java/src/main/kotlin/generated/
```

### `collect-sdks` job

Change `path: artifacts/sdks/**/*.zip` → `path: artifacts/sdks/**/*`

### `create-release` job

Change `files: artifacts/sdks/*.zip` → `files: artifacts/sdks/**/*`

Also update the dry-run summary's `ls` command:
`ls -la artifacts/sdks/*.zip` → `ls -la artifacts/sdks/**/*`

---

## Summary of All Changes

| File | Changes |
|------|---------|
| `sdk/python/Makefile` | Remove `package-*` targets; add `pack-archive`; `pack` calls `setup` + `pack-archive`; `dist` copies all available binaries + calls `pack-archive` → `.whl` |
| `sdk/javascript/Makefile` | Remove `package-*` targets; add `pack-archive`; `pack` calls `setup` + `pack-archive`; `dist` copies all available binaries + calls `pack-archive` → `.tgz` |
| `sdk/java/Makefile` | Remove `package-*` targets; add `pack-archive`; `pack` calls `setup` + `pack-archive`; `dist` copies all available binaries + calls `pack-archive` → `.jar` |
| `sdk/rust/Makefile` | No change |
| `.github/workflows/release.yml` | Upload UniFFI bindings from linux build; provide to java packaging job; update all artifact path patterns |

---

## Verification

### Local (single arch)
```bash
# macOS developer — only dylib present
make -f sdk/python/Makefile dist
# → artifacts/sdk-python/hyperswitch_payments-0.1.0.whl  (contains only .dylib)
# → Note: Linux x86_64 binary not found (skipping)

make -f sdk/java/Makefile dist
# → artifacts/sdk-java/payments-client-0.1.0.jar  (contains only .dylib)
```

### CI (all archs)
```bash
# After CI organizes both binaries:
make -f sdk/python/Makefile dist
# → artifacts/sdk-python/hyperswitch_payments-0.1.0.whl  (contains .so + .dylib)

make -f sdk/java/Makefile dist
# → artifacts/sdk-java/payments-client-0.1.0.jar  (contains .so + .dylib)
```

### Installability
```bash
pip install artifacts/sdk-python/hyperswitch_payments-0.1.0.whl
npm install artifacts/sdk-javascript/hyperswitch-payments-0.1.0.tgz
# Java: add payments-client-0.1.0.jar to classpath
```
