# Helcim Connector Implementation

This document provides comprehensive information about the Helcim connector implementation for the Universal Connector Service (UCS).

## Overview

The Helcim connector has been successfully converted from the Hyperswitch implementation to the modern Connector Service architecture. It supports 6 core payment flows with proper generic type handling and macro-based implementations.

## Supported Flows

The following flows have been implemented and tested:

### ✅ Implemented Flows

1. **Authorize** - Payment authorization with both automatic and manual capture support
2. **PSync** - Payment synchronization to check payment status
3. **Capture** - Manual capture of previously authorized payments
4. **Void** - Cancellation of authorized payments
5. **Refund** - Full or partial refund of captured payments
6. **RSync** - Refund synchronization to check refund status

### ❌ Not Implemented Flows

The following flows from the original Hyperswitch implementation were intentionally excluded as per requirements:

- Session creation
- Setup mandate
- Webhooks
- Payment method tokenization
- Disputes

## Architecture

### File Structure

```
backend/connector-integration/src/connectors/helcim/
├── mod.rs              # Main connector implementation
├── transformers.rs     # Request/response transformers
└── README.md          # This documentation
```

### Key Components

#### 1. Generic Connector Structure

```rust
pub struct Helcim<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> {
    _phantom: std::marker::PhantomData<T>,
}
```

#### 2. Trait Implementations

- `ConnectorServiceTrait<T>`
- `PaymentAuthorizeV2<T>`
- `PaymentSyncV2<T>`
- `PaymentCaptureV2<T>`
- `PaymentVoidV2<T>`
- `RefundExecuteV2<T>`
- `RefundSyncV2<T>`

#### 3. Macro-Based Implementation

Uses `create_all_prerequisites!` and `macro_connector_implementation!` macros for boilerplate generation and flow implementations.

## Authentication

### Authentication Type
- **Type**: HeaderKey
- **Required**: API Key only
- **Header**: `api-token`

### Authentication Structure

```rust
pub struct HelcimAuthType {
    pub api_key: Secret<String>,
}
```

## API Endpoints

| Flow | Method | Endpoint | Description |
|------|--------|----------|-------------|
| Authorize (Auto) | POST | `/v2/payment/purchase` | Direct payment with auto-capture |
| Authorize (Manual) | POST | `/v2/payment/preauth` | Authorization for manual capture |
| PSync | GET | `/v2/card-transactions/{id}` | Payment status check |
| Capture | POST | `/v2/payment/capture` | Capture authorized payment |
| Void | POST | `/v2/payment/reverse` | Cancel authorized payment |
| Refund | POST | `/v2/payment/refund` | Refund captured payment |
| RSync | GET | `/v2/card-transactions/{id}` | Refund status check |

## Request/Response Structures

### Payment Request

```rust
pub struct HelcimPaymentRequest<T> {
    pub amount: f64,
    pub currency: String,
    pub ip_address: Secret<String>,
    pub card_data: HelcimCard<T>,
    pub invoice: HelcimInvoice,
    pub billing_address: HelcimBillingAddress,
    pub ecommerce: Option<bool>,
}
```

### Payment Response

```rust
pub struct HelcimPaymentResponse {
    pub status: HelcimPaymentStatus,
    pub transaction_id: u64,
    pub invoice_number: Option<String>,
    pub transaction_type: HelcimTransactionType,
}
```

## Status Mapping

### Payment Status Mapping

| Helcim Status | Transaction Type | UCS Status |
|---------------|------------------|------------|
| APPROVED | Purchase/Verify | Charged |
| DECLINED | Purchase/Verify | Failure |
| APPROVED | PreAuth | Authorized |
| DECLINED | PreAuth | AuthorizationFailed |
| APPROVED | Capture | Charged |
| DECLINED | Capture | CaptureFailed |
| APPROVED | Reverse | Voided |
| DECLINED | Reverse | VoidFailed |

### Refund Status Mapping

| Helcim Status | UCS Status |
|---------------|------------|
| APPROVED | Success |
| DECLINED | Failure |

## Special Features

### 1. Idempotency Key
- Helcim requires an idempotency key of length 25
- Format: `HS_` prefix + 22 random characters
- Header: `Idempotency-Key`

### 2. Manual Capture Handling
- For manual capture, preauth transaction ID is stored in metadata
- Resource ID is set to `NoResponseId` initially
- After capture, resource ID is updated with capture transaction ID

### 3. Currency Support
- Currently supports USD only
- Currency validation is implemented in transformers

### 4. Invoice Generation
- Automatic invoice generation with line items
- Uses payment description or default "No Description"
- Single line item with quantity 1

## Error Handling

### Error Response Structure

```rust
pub enum HelcimErrorResponse {
    Payment(HelcimPaymentsErrorResponse),
    General(String),
}
```

### Error Types

```rust
pub enum HelcimErrorTypes {
    StringType(String),
    JsonType(serde_json::Value),
}
```

## Testing

### Test File Location
`backend/grpc-server/tests/helcim_payment_flows_test.rs`

### Test Coverage

1. **Health Check** - Server connectivity test
2. **Payment Authorization (Auto Capture)** - Direct payment processing
3. **Payment Authorization (Manual Capture)** - Authorization + Capture flow
4. **Payment Sync** - Payment status verification
5. **Refund** - Payment refund processing
6. **Refund Sync** - Refund status verification
7. **Payment Void** - Payment cancellation

### Test Configuration

#### Environment Variables
- `TEST_HELCIM_API_KEY` - Helcim API key for testing

#### Test Data
- Amount: $10.00 (1000 cents)
- Card: 4111111111111111 (Visa test card)
- Currency: USD

### Running Tests

```bash
# Run all Helcim tests
cd backend && cargo test --test helcim_payment_flows_test

# Run specific test
cd backend && cargo test --test helcim_payment_flows_test test_payment_authorization_auto_capture

# Run with verbose output
cd backend && cargo test --test helcim_payment_flows_test -- --nocapture
```

## Configuration

### Development Configuration
Add to `config/development.toml`:

```toml
[connectors]
helcim.base_url = "https://api.helcim.com/"
```

### Production Configuration
Update base URL for production environment as needed.

## Implementation Notes

### 1. Generic Type System
- Proper generic type bounds: `PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize`
- Uses `RawCardNumber<T>` for card numbers
- Maintains type safety throughout the flow

### 2. Macro Usage
- `create_all_prerequisites!` for boilerplate generation
- `macro_connector_implementation!` for each flow
- Reduces code duplication and ensures consistency

### 3. Context-Aware Status Mapping
- Considers transaction type for status determination
- Handles different capture methods appropriately
- Provides meaningful error messages

### 4. Security Considerations
- API key masking in logs
- Secure handling of sensitive card data
- Proper error message sanitization

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify API key is correct
   - Check header format (`api-token`)
   - Ensure key has required permissions

2. **Currency Errors**
   - Helcim connector only supports USD
   - Verify currency is set correctly in requests

3. **Amount Conversion**
   - Amounts are converted from minor units (cents) to major units (dollars)
   - Ensure proper conversion in transformers

4. **Transaction ID Issues**
   - For manual capture, transaction ID is in metadata
   - Check both resource_id and connector_metadata

### Debug Tips

1. Enable TRACE logging in configuration
2. Check connector metadata in responses
3. Verify request/response transformations
4. Test with different card numbers if needed

## Future Enhancements

### Potential Improvements

1. **Multi-Currency Support**
   - Extend currency validation
   - Add currency-specific formatting

2. **Enhanced Error Handling**
   - More specific error codes
   - Better error message mapping

3. **Additional Payment Methods**
   - Support for other payment methods beyond cards
   - ACH/bank transfer support

4. **Webhook Support**
   - Implement webhook handling for real-time updates
   - Add webhook signature verification

## Compliance and Standards

### Security Standards
- PCI DSS compliance considerations
- Secure data handling practices
- Proper masking of sensitive information

### Code Quality
- Comprehensive error handling
- Type safety with generics
- Consistent code formatting
- Thorough test coverage

## Support and Maintenance

### Monitoring
- Track success/failure rates
- Monitor response times
- Log error patterns

### Updates
- Regular dependency updates
- API version compatibility checks
- Test environment validation

This implementation follows the established patterns from the universal connector conversion guide and provides a robust, maintainable solution for Helcim payment processing.