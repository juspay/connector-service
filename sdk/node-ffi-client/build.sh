#!/bin/bash
set -e

# Navigate to project root (go up 2 directories from this script)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Build release binary
cd "$PROJECT_ROOT/backend/ffi"
cargo build --release --features napi
# cargo build --features napi


# Create artifacts directory
mkdir -p "$PROJECT_ROOT/sdk/node-ffi-client/artifacts"

# Copy binary to artifacts folder with .node extension
if [ -f "$PROJECT_ROOT/target/release/libconnector_service_ffi.dylib" ]; then
    cp "$PROJECT_ROOT/target/release/libconnector_service_ffi.dylib" \
       "$PROJECT_ROOT/sdk/node-ffi-client/artifacts/connector_service_ffi.node"
elif [ -f "$PROJECT_ROOT/target/release/libconnector_service_ffi.so" ]; then
    cp "$PROJECT_ROOT/target/release/libconnector_service_ffi.so" \
       "$PROJECT_ROOT/sdk/node-ffi-client/artifacts/connector_service_ffi.node"
elif [ -f "$PROJECT_ROOT/target/release/connector_service_ffi.dll" ]; then
    cp "$PROJECT_ROOT/target/release/connector_service_ffi.dll" \
       "$PROJECT_ROOT/sdk/node-ffi-client/artifacts/connector_service_ffi.node"
else
    echo "Error: Native binary not found in target/release/"
    exit 1
fi

echo "Build complete: connector_service_ffi.node → sdk/node-ffi-client/artifacts/"