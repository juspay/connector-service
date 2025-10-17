# Payu Connector Implementation

## Overview

This is a comprehensive UCS v2 connector implementation for Payu payment gateway, migrated from the original Haskell implementation. The connector supports UPI payment methods and implements the core payment flows required for modern payment processing.

## Features Implemented

### Payment Methods Supported
- **UPI Collect**: Direct UPI payments using VPA (Virtual Payment Address)
- **UPI Intent**: UPI intent-based payments for mobile apps

### Transaction Flows
- **Authorize**: Payment initiation and processing
- **PaymentSync (PSync)**: Transaction status synchronization
- **RefundSync (RSync)**: Refund status tracking

### Core Capabilities
- SHA512 hash generation for request authentication
- Form URL encoded request format (Payu API requirement)
- Dynamic data extraction from router data (no hardcoded values)
- Comprehensive error handling and status mapping
- Webhook support with signature verification
- Test and production environment support

## Architecture

### File Structure
```
src/
├── connectors/
│   ├── payu.rs              # Main connector implementation
│   └── payu/
│       ├── constants.rs     # API constants and endpoints
│       └── transformers.rs  # Request/response transformers
├── types.rs                 # Domain types and enums
├── connectors.rs            # Connector registry
└── lib.rs                   # Library entry point
```

### Key Components

#### 1. Main Connector (`src/connectors/payu.rs`)
- `Payu<T>`: Generic connector struct with payment method data phantom type
- `PayuAuthType`: Authentication handling with key-secret pattern
- Request/Response types for all supported flows
- Webhook response handling

#### 2. Transformers (`src/connectors/payu/transformers.rs`)
- `RouterDataV2`: Router data structure for flow-specific data
- Request builders for Authorize, PSync, and RSync flows
- Response parsers converting Payu responses to domain types
- Payment method data handling for UPI

#### 3. Constants (`src/connectors/payu/constants.rs`)
- API endpoints for test and production environments
- Status codes and error mappings
- Payment method codes and helper functions

## Implementation Details

### Authentication Pattern
The connector uses Payu's key-secret authentication pattern:
```rust
PayuAuthType::KeySecret { 
    key: api_key, 
    salt: secret_salt 
}
```

### Hash Generation
SHA512 hash generation for request integrity:
```rust
let hash_string = format!("{}|{}|{}", key, command, transaction_id);
let hash = auth.generate_hash(&hash_string);
```

### Request Format
Form URL encoded requests following Payu's API specification:
```rust
PayuPaymentsRequest {
    key: String,
    command: String,
    hash: String,
    var1: String,  // JSON-encoded transaction data
}
```

### Dynamic Data Extraction
All request data is dynamically extracted from router data:
```rust
let amount = item.amount.get_amount_as_string();
let transaction_id = item.router_data.request.connector_transaction_id;
let customer_id = item.router_data.resource_common_data.customer_id;
```

## API Integration

### Endpoints
- **Production**: `https://info.payu.in/merchant/postservice.php?form=2`
- **Test**: `https://test.payu.in/merchant/postservice.php?form=2`

### Commands
- `create_transaction`: Payment authorization
- `verify_payment`: Transaction status verification
- `get_all_refunds_from_txn_id`: Refund status retrieval

## Error Handling

### Status Mapping
- `success` → `charged`
- `failure` → `failure`
- `pending` → `pending`
- Other → `authentication_pending`

### Error Codes
- `E001`: Invalid credentials
- `E002`: Invalid transaction details
- `E003`: Insufficient funds
- `E004`: Invalid VPA address

## Webhook Support

### Signature Verification
HMAC SHA512 signature validation for webhook authenticity:
```rust
pub fn verify_webhook_source(&self, body: &[u8], headers: &[(&str, &str)]) -> Result<bool, ConnectorError>
```

### Event Types
- `payment.success`: Successful payment
- `payment.failure`: Failed payment
- `payment.pending`: Pending payment

## Usage Example

```rust
use payu_connector::connectors::payu::Payu;
use payu_connector::connectors::payu::transformers::*;

// Create connector instance
let connector = Payu::<PaymentMethodData>::new();

// Build authorize request
let request = PayuPaymentsRequest::try_from(&router_data)?;

// Process response
let response = PaymentsResponseData::try_from(payu_response)?;
```

## Testing

Run compilation check:
```bash
cargo check
```

Run tests:
```bash
cargo test
```

## Migration Notes

This implementation successfully migrates from the original Haskell implementation while:
- Preserving all business logic and features
- Adapting to UCS v2 architecture patterns
- Implementing proper type safety and guard rails
- Using dynamic data extraction (no hardcoded values)
- Supporting only UPI and sync flows as specified

## Future Enhancements

Potential areas for expansion:
- Card payment support
- Net banking integration
- Wallet payment methods
- Advanced fraud detection
- Enhanced webhook processing
- Multi-currency support

## Compliance

- ✅ UCS v2 macro framework compliance
- ✅ Type safety with proper domain types
- ✅ Dynamic data extraction (no hardcoded values)
- ✅ Comprehensive error handling
- ✅ Security best practices
- ✅ Production-ready implementation