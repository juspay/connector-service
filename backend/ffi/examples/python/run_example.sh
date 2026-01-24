#!/bin/bash
# Build and run the Python FFI example

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
FFI_DIR="$PROJECT_ROOT/backend/ffi"

echo "=================================="
echo "Connector FFI Python Example"
echo "=================================="
echo

# Build the FFI library
echo "Building connector-ffi library..."
cd "$PROJECT_ROOT"
cargo build --release -p connector-ffi

# Determine library name based on OS
case "$(uname -s)" in
    Linux*)
        LIB_NAME="libconnector_ffi.so"
        ;;
    Darwin*)
        LIB_NAME="libconnector_ffi.dylib"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        LIB_NAME="connector_ffi.dll"
        ;;
    *)
        echo "Unsupported OS"
        exit 1
        ;;
esac

LIB_PATH="$PROJECT_ROOT/target/release/$LIB_NAME"

if [ ! -f "$LIB_PATH" ]; then
    echo "Error: Library not found at $LIB_PATH"
    exit 1
fi

echo "Library built: $LIB_PATH"
echo

# Copy library to example directory for easy access
cp "$LIB_PATH" "$SCRIPT_DIR/"
echo "Copied library to $SCRIPT_DIR/"
echo

# Run the Python example
echo "Running Python example..."
echo
cd "$SCRIPT_DIR"
python3 connector_ffi.py
