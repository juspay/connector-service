#!/bin/bash
set -euo pipefail

echo "Regenerating SDK clients from proto files..."

# Rust SDK
echo "Generating Rust SDK..."
cargo run -p proto-codegen -- --output ./sdk/rust-grpc-client --clean

# Python SDK (if needed in future)
# echo "Generating Python SDK..."
# Add python generation command here

# Node SDK (if needed in future)  
# echo "Generating Node SDK..."
# Add node generation command here

echo "SDK regeneration complete!"

# Check if there were any changes
if git diff --quiet; then
    echo "No changes detected in generated files"
    exit 0
else
    echo "Changes detected in generated files:"
    git diff --name-only
    exit 1
fi