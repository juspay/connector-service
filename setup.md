# UCS (Unified Connector Service) Setup Guide

This guide helps you set up and run UCS locally for testing payment integrations with various payment processors.

## Overview

UCS is a stateless payments abstraction service built using gRPC that provides a unified contract for integrating with multiple payment processors. It supports the complete payment lifecycle: authorization, capture, refunds, status checks, and chargebacks.

## Prerequisites

### System Requirements

- **Rust** (latest stable version)
- **Protocol Buffers compiler**
- **PostgreSQL development libraries** (will be removed in future)

### Install Dependencies

#### macOS
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install dependencies via Homebrew
brew install protobuf postgresql
```

#### Ubuntu/Debian
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install dependencies
sudo apt-get update
sudo apt-get install build-essential protobuf-compiler pkg-config libssl-dev
```

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/juspay/connector-service.git
cd connector-service
```

### 2. Build the Project

```bash
# Build the project
cargo build
```

### 3. Run the UCS Server

Start the gRPC server (uses `config/development.toml` by default):

```bash
cargo run
```

#### Optional: Custom Configuration

Edit `config/development.toml` to disable optional features:

```toml
[log.kafka]
enabled = false  # Disable logging/tracing to Kafka topic as subscriber for local testing

[events]
enabled = false  # Disable audit events to Kafka topic for local testing
```

Then run with your custom config:

```bash
cargo run
```

The server will start on `http://localhost:8000` by default.

### 4. Install grpcurl (for testing)

#### macOS Installation

```bash
brew install grpcurl
```

#### Ubuntu Installation

Install grpcurl:

```bash
# Detect architecture and download appropriate version
ARCH=$(uname -m)
case $ARCH in
  x86_64) GRPC_ARCH="linux_x86_64" ;;
  aarch64) GRPC_ARCH="linux_arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Download and install grpcurl
curl -L "https://github.com/fullstorydev/grpcurl/releases/download/v1.9.3/grpcurl_1.9.3_${GRPC_ARCH}.tar.gz" -o grpcurl.tar.gz
tar -xzf grpcurl.tar.gz
sudo mv grpcurl /usr/local/bin/
rm grpcurl.tar.gz

# Verify installation
grpcurl --version
```

### 5. Verify Setup

Check if the server is running:

#### gRPC Health Check  
```bash
grpcurl -plaintext localhost:8000 grpc.health.v1.Health/Check
```

**Expected response:**
```json
{
  "status": "SERVING"
}
```

This confirms the gRPC server is running and ready to accept requests.

### Payment Testing

Test a payment authorization with automatic capture:

```bash
grpcurl -plaintext \
  -H "x-connector: braintree" \
  -H "x-auth: signature-key" \
  -H "x-api-key: your_public_key" \
  -H "x-key1: your_private_key" \
  -H "x-merchant-id: your_merchant_id" \
  -H "x-api-secret: your_api_secret" \
  -H "x-reference-id: test_ref_123" \
  -d '{
    "request_ref_id": {
      "id": "ref_000987654321"
    },
    "amount": 6540,
    "minor_amount": 6540,
    "currency": "USD",
    "capture_method": "AUTOMATIC",
    "auth_type": "NO_THREE_DS",
    "payment_method": {
      "card": {
        "credit": {
          "card_number": { "value": "4242424242424242"},
          "card_cvc": {"value": "123"},
          "card_exp_month": {"value": "10"},
          "card_exp_year": {"value": "2025" },
          "card_network":  "VISA" 
        }
      }
    },
    "address": {},
    "connector_customer_id": "customer123",
    "return_url": "https://google.com",
    "webhook_url": "https://google.com",
    "order_category": "pay",
    "enrolled_for_3ds": false,
    "request_incremental_authorization": false,
    "metadata": {
      "udf1": "value1",
      "new_customer": "true",
      "login_date": "2019-09-10T10:11:12Z",
      "description": "Test payment from setup guide",
      "merchant_account_id": "your_merchant_account"
    }
  }' \
  localhost:8000 ucs.v2.PaymentService/Authorize
```

**Expected Success Response:**
```json
{
  "transactionId": {
    "id": "dHJhbnNhY3Rpb25fOGs4ZXRjMzU"
  },
  "status": "CHARGED",
  "statusCode": 200,
  "rawConnectorResponse": {
    "value": "{\"data\":{\"chargeCreditCard\":{\"transaction\":{\"id\":\"dHJhbnNhY3Rpb25fOGs4ZXRjMzU\",\"legacyId\":\"8k8etc35\",\"amount\":{\"value\":\"65.40\",\"currencyCode\":\"USD\"},\"status\":\"SUBMITTED_FOR_SETTLEMENT\"}}}}"
  },
  "state": {
    "connectorCustomerId": "customer123"
  }
}
```

**⚠️ Security Notes:**
- Replace all placeholder values (`your_*`) with your actual Braintree credentials
- Use test/sandbox credentials only - never use production credentials for testing
- The card number `4242424242424242` is a test card number

### Supported Operations

UCS supports the following operations across multiple payment processors:

1. **Payment Authorization** - Create and authorize payments
2. **Payment Capture** - Capture authorized payments
3. **Payment Void** - Cancel authorized payments
4. **Refunds** - Full and partial refunds
5. **Payment Status** - Retrieve payment status
6. **Setup Mandates** - For recurring payments
7. **Repeat Payments** - Process subsequent payments

## Container Deployment

### Docker / OrbStack Setup

#### Building the Image

```bash
docker build -f Dockerfile -t ucs:latest .
```

#### Running the Container

```bash
# Run with port mapping (gRPC on 8000, metrics on 8080)
docker run --rm -p 8000:8000 -p 8080:8080 ucs:latest
```

#### Configuration Options

**Default**: Uses `development.toml` configuration (Kafka/events disabled, test URLs)

**Custom Environment**: Override with environment variable:

```bash
# Use sandbox configuration (config/sandbox.toml)
docker run --rm -p 8000:8000 -p 8080:8080 \
  -e CS__COMMON__ENVIRONMENT=sandbox \
  ucs:latest

# Use production configuration (config/production.toml)
docker run --rm -p 8000:8000 -p 8080:8080 \
  -e CS__COMMON__ENVIRONMENT=production \
  ucs:latest
```

#### Testing Docker Container

```bash
# Health check
grpcurl -plaintext localhost:8000 grpc.health.v1.Health/Check


### Podman Setup

**Memory Requirements:** 12GB minimum for successful build.

```bash
# Configure memory (one-time setup)
podman machine set --memory 12288

# Use same commands as Docker
podman build -f Dockerfile -t ucs:latest .
podman run --rm -p 8000:8000 -p 8080:8080 ucs:latest
```

**Configuration Files Available:**
- `development.toml` (default) - Local testing
- `sandbox.toml` - Test URLs
- `production.toml` - Production URLs

## Troubleshooting

### Common Issues

#### 1. Connection Refused

**Error**: `connection refused` when connecting to UCS

**Solution**: Ensure the gRPC server is running on the correct port (8000 by default)

#### 2. gRPC Status 404

**Error**: `grpc-status header missing, mapped from HTTP status code 404`

**Solution**: 
- Verify the server URL format: `http://localhost:8000` (not `https`)
- Ensure you're connecting to the gRPC port (8000), not the metrics port (8080)

#### 3. Build Errors

**Error**: Compilation or build failures

**Solution**:
```bash
# Clean and rebuild
cargo clean
cargo build

# Update dependencies
cargo update
```

#### 4. Missing Dependencies

**Error**: `protoc not found` or linking errors

**Solution**: Ensure all system dependencies are installed according to the Prerequisites section

### Logs and Debugging

Enable detailed logging by setting the log level in your configuration:

```toml
[log.console]
enabled = true
level = "DEBUG"
log_format = "default"
```

## Running Payment Flow Tests

UCS includes comprehensive integration tests for payment processors with centralized credential management.

### Test Credential Configuration

UCS tests require actual payment processor credentials to run successfully. These credentials are loaded from `.github/test/creds.json`.

#### Setting Up Your Credentials

1. **Copy the template file**:
   ```bash
   cp .github/test/template_creds.json .github/test/creds.json
   ```

2. **Replace placeholder values with real credentials**:
   
   Edit `.github/test/creds.json` and replace the `test_*` placeholder values with your actual sandbox/test credentials from each payment processor.

   **Example for Authorize.Net**:
   ```json
   {
     "authorizedotnet": { //connector name
       "connector_account_details": {
         "auth_type": "BodyKey", // or HeaderKey, SignatureKey, etc.
         "api_key": "your_actual_api_login_id",
         "key1": "your_actual_transaction_key"
       },
      "metadata": {
        "additional_field": "value_if_needed"
      }
     }
   }
   ```



#### Supported Authentication Types

- **TemporaryAuth**: Temporary authentication
- **HeaderKey**: Simple API key in headers
- **BodyKey**: API key + transaction key in body
- **SignatureKey**: API key + secret + additional key
- **MultiAuthKey**: Multiple authentication keys (api_key, key1, api_secret, key2)
- **CurrencyAuthKey**: Complex currency-based authentication
- **CertificateAuth**: Certificate and private key authentication
- **NoKey**: No authentication required

#### Running Tests

```bash
cargo test --test authorizedotnet_payment_flows_test
```

## Development Commands (Optional)

UCS includes a Makefile with convenient development commands:

```bash
# Format code (requires nightly Rust)
make fmt

# Run checks
make check

# Run linting
make clippy

# Run tests
make test

# Run all checks
make all
```

## Integration

### gRPC Client SDKs

UCS provides client SDKs for multiple programming languages in the `sdk/` directory:

- **Node.js**: `sdk/node-grpc-client/`
- **Python**: `sdk/python-grpc-client/`
- **Rust**: `sdk/rust-grpc-client/`

Each SDK includes README files with specific integration instructions.

### Example Implementations

The `examples/` directory contains sample implementations:

- **CLI**: `examples/example-cli/` - Command-line interface
- **JavaScript**: `examples/example-js/` - Node.js example
- **Python**: `examples/example-py/` - Python example
- **Rust**: `examples/example-rs/` - Rust example

## Notes

### PostgreSQL Dependency

Currently, PostgreSQL development libraries are required for compilation due to transitive dependencies from the [hyperswitch_masking crate](https://github.com/juspay/hyperswitch). Since UCS is a stateless service that doesn't use a database, this dependency will likely be removed in future versions.

### Platform Differences

Requirements may vary by platform depending on available system libraries. The dependencies listed above represent the verified minimal requirements for successful compilation and execution.
