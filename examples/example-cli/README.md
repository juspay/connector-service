# Example CLI for Connector Service

A command-line interface for interacting with the connector service. This CLI supports the same operations as the TUI version but via command-line arguments instead of an interactive shell.

## Building

```bash
cargo build
```

## Prerequisites

Before running the CLI, you need:

1. The connector service gRPC server running
2. The correct URL for the gRPC server (e.g., `http://localhost:8000`)

### Troubleshooting Connection Issues

If you see a connection error similar to:

```
Error during authorize call: Status {
    code: Unimplemented,
    message: "grpc-status header missing, mapped from HTTP status code 404",
    ...
}
```

This typically indicates one of the following issues:

1. The gRPC server is not running at the specified URL
2. The URL format is incorrect (should be `http://host:port` or `https://host:port`)
3. There's a network issue preventing connection to the server
4. The server is running but not accepting gRPC connections

Make sure the connector service is running and the URL is correct before trying again.

## Usage

The CLI supports two main commands: `pay` and `get`, with JSON file support for credentials and payment data.

### Development Invocation (with cargo run)

```bash
# Pay command
cargo run -- pay \
  --url http://localhost:8000 \
  --connector razorpay \
  --amount 1000 \
  --currency usd \
  --email user@example.com \
  --auth-type body-key \
  --api-key your_api_key \
  --key1 your_key1 \
  --number 5123456789012346 \
  --exp-month 03 \
  --exp-year 2030 \
  --cvc 100

# Get command
cargo run -- get \
  --url http://localhost:8000 \
  --connector razorpay \
  --resource-id payment_123 \
  --auth-type body-key \
  --api-key your_api_key \
  --key1 your_key1
```
### Authentication Options

The CLI supports three authentication types, specified by the `--auth-type` parameter:

1. Body Key Authentication (`--auth-type bodykey`):
   - Requires `--api-key` and `--key1` parameters

2. Header Key Authentication (`--auth-type headerkey`):
   - Requires only `--api-key` parameter

3. Signature Key Authentication (`--auth-type signaturekey`):
   - Requires `--api-key`, `--key1`, and `--api-secret` parameters

### JSON File Support

The CLI can read configuration from JSON files:

1. Credential File (`--cred-file`):
   - Contains connector and authentication details
   - Command-line arguments override values from the file
   - Example cred.json:
   ```json
   {
     "connector": "razorpay",
     "auth": {
       "api_key": "your_api_key",
       "key1": "your_key1",
       "auth_type": "body_key"
     }
   }
   ```

2. Payment File (`--payment-file`):
   - Contains payment details for authorize command
   - Command-line arguments override values from the file
   - Example payment.json:
   ```json
   {
     "amount": 1000,
     "currency": "usd",
     "email": "user@example.com",
     "card": {
       "number": "4111111111111111",
       "exp_month": "12",
       "exp_year": "2025",
       "cvc": "123"
     }
   }
   ```

3. Get File (`--get-file`):
   - Contains sync details for sync command
   - Command-line arguments override values from the file
   - Example sync.json:
   ```json
   {
     "resource_id": "pay_12345"
   }
   ```

## Examples

### Pay with Adyen:
```bash
# Using cargo run during development
cargo run -- pay \
  --url http://localhost:8000 \
  --connector adyen \
  --amount 1000 \
  --currency usd \
  --email user@example.com \
  --auth-type signature-key \
  --api-key your_api_key \
  --key1 your_key1 \
  --api-secret your_api_secret \
  --number 4111111111111111 \
  --exp-month 03 \
  --exp-year 2030 \
  --cvc 737
```
### Pay with Razorpay:
```bash
# Using cargo run during development
cargo run -- pay \
  --url http://localhost:8000 \
  --connector razorpay \
  --amount 1000 \
  --currency inr \
  --email user@example.com \
  --auth-type body-key \
  --api-key your_api_key \
  --key1 your_key1 \
  --number 5123456789012346 \
  --exp-month 03 \
  --exp-year 2030 \
  --cvc 100
```

### Get payment status:
```bash
# Using cargo run during development
cargo run -- get \
  --url http://localhost:8000 \
  --connector razorpay \
  --resource-id pay_12345 \
  --auth-type body-key \
  --api-key your_api_key \
  --key1 your_key1
```

### Using JSON files:
```bash
# Using credential and payment files
cargo run -- pay \
  --url http://localhost:8000 \
  --cred-file ./cred.json \
  --payment-file ./payment.json

# Using credential and sync files
cargo run -- get \
  --url http://localhost:8000 \
  --cred-file ./cred.json \
  --sync-file ./sync.json

# Mixing command-line arguments and files
cargo run -- pay \
  --url http://localhost:8000 \
  --cred-file ./cred.json \
  --amount 2000 \
  --currency eur \
  --number 5555555555554444
```
