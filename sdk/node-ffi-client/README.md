# connector-service-node-ffi

Node.js FFI bindings for connector-service using Rust native library.

This SDK provides native bindings to the Rust FFI library, allowing Node.js applications to directly call Rust functions for payment processing.

## Features

- Direct native bindings to Rust FFI functions
- TypeScript support with full type definitions
- Native binary optimized for performance (release build)
- Cross-platform support (macOS, Linux, Windows)

## Prerequisites

- [Rust](https://www.rust-lang.org/) (latest stable)
- [Cargo](https://doc.rust-lang.org/cargo/) (comes with Rust)
- [Node.js](https://nodejs.org/) >= 10
- [npm](https://www.npmjs.com/) or [yarn](https://yarnpkg.com/)

## Installation

1. Clone the repository:
```bash
git clone <repository_url>
cd connector-service
```

2. Install dependencies:
```bash
cd sdk/node-ffi-client
npm install
```

3. Build the native binary:
```bash
npm run build
```

This will:
- Build the Rust FFI library in release mode
- Copy the native binary to `artifacts/connector_service_ffi.node`

## Usage

### JavaScript

```javascript
const ffi = require('connector-service-node-ffi');

const payload = {
  request_ref_id: { id: "payment_123" },
  amount: 1000,
  currency: "USD",
  payment_method: {
    payment_method: {
      Card: {
        card_number: "4111111111111111",
        card_exp_month: "12",
        card_exp_year: "2025",
        card_cvc: "123",
        card_holder_name: "Test User",
        card_network: 1
      }
    }
  },
  capture_method: "AUTOMATIC",
  email: "customer@example.com",
  customer_name: "Test Customer",
  auth_type: "NO_THREE_DS",
  enrolled_for_3ds: false,
  return_url: "https://example.com/return",
  webhook_url: "https://example.com/webhook",
  description: "Test payment",
  test_mode: true,
  order_details: [],
  address: {
    shipping_address: null,
    billing_address: null
  }
};

const metadata = {
  connector: "Stripe",
  connector_auth_type: {
    auth_type: "HeaderKey",
    api_key: "sk_test_..."
  }
};

const result = ffi.authorize(payload, metadata);
console.log(result);
```

### TypeScript

```typescript
import { authorize, PaymentServiceAuthorizeRequest, MetadataPayload } from 'connector-service-node-ffi';

const payload: PaymentServiceAuthorizeRequest = {
  request_ref_id: { id: "payment_123" },
  amount: 1000,
  // ... rest of the payload
};

const metadata: MetadataPayload = {
  connector: "Stripe",
  connector_auth_type: {
    auth_type: "HeaderKey",
    api_key: "sk_test_..."
  }
};

const result = authorize(payload, metadata);
console.log(result);
```

## API Reference

### authorize(payload, extractedMetadata)

Authorizes a payment with the provided payload and extracted metadata.

**Parameters:**
- `payload` (PaymentServiceAuthorizeRequest): Payment authorization request
- `extractedMetadata` (MetadataPayload): Metadata containing connector and auth info

**Returns:** `string` - JSON string containing the response

**Throws:** Error if payload or extractedMetadata is empty or invalid

### _native

Access to the underlying native module for advanced use cases.

## Scripts

- `npm run build` - Build Rust FFI library and copy to artifacts
- `npm test` - Run the test suite

## Project Structure

```
sdk/node-ffi-client/
├── artifacts/              # Native binary (.node file)
├── src/
│   ├── index.ts           # TypeScript entry point
│   └── payment.ts         # Type definitions and authorize function
├── tests/
│   └── test_node.js       # Test suite
├── index.js               # JavaScript entry point (loads native module)
├── index.d.ts             # TypeScript definitions for native module
├── package.json           # NPM package configuration
├── tsconfig.json          # TypeScript configuration
└── build.sh               # Build script (Rust + copy binary)
```

## Building from Source

### Manual Build

```bash
# Build Rust library
cd backend/ffi
cargo build --release

# Copy binary to artifacts
cp target/release/libconnector_service_ffi.dylib ../sdk/node-ffi-client/artifacts/connector_service_ffi.node
```

### Using npm script

```bash
cd sdk/node-ffi-client
npm run build
```

## Platform-Specific Binaries

The build script automatically detects your platform and copies the appropriate binary:

- **macOS**: `libconnector_service_ffi.dylib` → `connector_service_ffi.node`
- **Linux**: `libconnector_service_ffi.so` → `connector_service_ffi.node`
- **Windows**: `connector_service_ffi.dll` → `connector_service_ffi.node`

## Testing

Run the test suite:

```bash
npm test
```

**Note:** Tests require the native binary to be built first. Run `npm run build` before testing.

## License

MIT