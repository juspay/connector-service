#!/bin/bash

# Exit immediately if a command fails
set -e

# Check for connector name
if [ -z "$CONNECTOR_NAME" ]; then
  echo "CONNECTOR_NAME is not set."
  echo "Example: export CONNECTOR_NAME=paypal"
  exit 1
fi

# GitHub repo info
REPO_URL="https://github.com/juspay/hyperswitch.git"
SPARSE_FILE_PATH="crates/hyperswitch_connectors/src/connectors/${CONNECTOR_NAME}.rs"

# Temporary directory (in current directory)
TEMP_DIR=".hyperswitch_tmp_clone"

# Clean up previous temp if it exists
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"

echo "Cloning '${CONNECTOR_NAME}' connector from Hyperswitch repository into $TEMP_DIR..."

# Perform sparse checkout
cd "$TEMP_DIR"
git init -q
git remote add origin "$REPO_URL"
git config core.sparseCheckout true
echo "$SPARSE_FILE_PATH" >> .git/info/sparse-checkout
git pull --depth=1 origin main -q

# Go back to the directory where the script was originally run
cd "$OLDPWD"

# Define destination path
TARGET_BASE="backend/connector-integration/src/connectors"

# Copy the connector file
cp "$TEMP_DIR/$SPARSE_FILE_PATH" "$TARGET_BASE"

echo "Connector file copied to: $TARGET_BASE"

# Final cleanup
rm -rf "$TEMP_DIR"