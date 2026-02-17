#!/usr/bin/env bash
# -------------------------------------------------------------------
# setup.sh — Build the Rust native library and copy Kotlin bindings
#             into the Java/Gradle project so it can compile and run.
#
# Usage:
#   cd backend/ffi-uniffi/examples/java
#   ./setup.sh
# -------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
FFI_UNIFFI_DIR="$PROJECT_ROOT/backend/ffi-uniffi"
KOTLIN_BINDINGS="$FFI_UNIFFI_DIR/bindings/kotlin/io/juspay/connector/connector_ffi_uniffi.kt"
TARGET_DIR="$SCRIPT_DIR/src/main/kotlin/io/juspay/connector"

echo "============================================================"
echo " Connector FFI — Java Example Setup"
echo "============================================================"

# Step 1: Build the Rust native library
echo ""
echo "[1/3] Building Rust native library (release)..."
(cd "$PROJECT_ROOT" && cargo build --release -p connector-ffi-uniffi)

# Determine the shared library name based on OS
case "$(uname -s)" in
    Linux*)  LIB_NAME="libconnector_ffi_uniffi.so"   ;;
    Darwin*) LIB_NAME="libconnector_ffi_uniffi.dylib" ;;
    MINGW*|MSYS*|CYGWIN*) LIB_NAME="connector_ffi_uniffi.dll" ;;
    *) echo "Unsupported OS"; exit 1 ;;
esac

LIB_PATH="$PROJECT_ROOT/target/release/$LIB_NAME"
if [ ! -f "$LIB_PATH" ]; then
    echo "ERROR: Native library not found at $LIB_PATH"
    exit 1
fi
echo "  -> Built: $LIB_PATH"

# Step 2: Regenerate Kotlin bindings (optional — they may already exist)
echo ""
echo "[2/3] Checking Kotlin bindings..."
if [ ! -f "$KOTLIN_BINDINGS" ]; then
    echo "  Generating Kotlin bindings..."
    (cd "$PROJECT_ROOT" && cargo run --release --bin uniffi-bindgen -- generate \
        --library "$LIB_PATH" \
        --language kotlin \
        --out-dir "$FFI_UNIFFI_DIR/bindings/kotlin")
fi
echo "  -> Bindings: $KOTLIN_BINDINGS"

# Step 3: Copy Kotlin bindings into the Gradle project
echo ""
echo "[3/3] Copying Kotlin bindings into Gradle project..."
mkdir -p "$TARGET_DIR"
cp "$KOTLIN_BINDINGS" "$TARGET_DIR/"
echo "  -> Copied to: $TARGET_DIR/"

echo ""
echo "============================================================"
echo " Setup complete!  Run the example with:"
echo ""
echo "   cd $SCRIPT_DIR"
echo "   gradle run -PnativeLibDir=$PROJECT_ROOT/target/release"
echo ""
echo " Or without Gradle wrapper:"
echo "   ./gradlew run -PnativeLibDir=$PROJECT_ROOT/target/release"
echo "============================================================"
