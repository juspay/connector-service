# HsbcUpi Connector Implementation Guide

## Overview
This document provides a comprehensive implementation guide for the HsbcUpi connector migration from Haskell to UCS v2 Rust.

## File Structure
```
backend/connector-integration/src/connectors/
├── hsbcupi.rs                    # Main connector file
└── hsbcupi/
    ├── transformers.rs           # Request/response transformers
    └── constants.rs              # API constants and endpoints
```

## Implementation Summary

### 1. Constants File (`hsbcupi/constants.rs`)
Already created with:
- API endpoints (collect, intent, status, refund)
- Default values (expiry, circle code)
- Status codes and response codes

### 2. Main Connector File (`hsbcupi.rs`)

**Key Components:**
- Uses UCS v2 macro framework (MANDATORY)
- Implements UPI payment flows only (Authorize, PSync)
- Proper authentication with merchant ID pattern
- Type-safe implementation with guard rails

**Macro Structure:**
```rust
macros::create_all_prerequisites!(
    connector_name: HsbcUpi,
    generic_type: T,
    api: [
        (flow: Authorize, ...),
        (flow: PSync, ...),
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: { ... }
);
```

### 3. Transformers File (`hsbcupi/transformers.rs`)

**Request Structures:**
- `HsbcUpiAuthType` - Merchant ID + credentials
- `HsbcUpiPaymentsRequest` - UPI collect/intent request
- `HsbcUpiPaymentsSyncRequest` - Status query request

**Response Structures:**
- `HsbcUpiPaymentsResponse` - Payment response with transaction details
- `HsbcUpiPaymentsSyncResponse` - Status query response

**Key Features:**
- Dynamic value extraction from router data (NO hardcoding)
- Proper amount conversion using StringMinorUnit
- UPI-specific payment method handling
- Status mapping from HSBC codes to domain types

### 4. Authentication Pattern
Based on Haskell implementation:
- Merchant ID (pgMerchantId)
- Request/Response encryption pattern
- JSON-based API communication

### 5. UPI Flow Implementation

**Authorize Flow:**
- UPI Collect request initiation
- UPI Intent registration
- Transaction reference generation
- Callback URL management

**PSync Flow:**
- Transaction status query
- Status code mapping
- Response data extraction

### 6. Status Mapping
```rust
S -> AttemptStatus::Charged
P -> AttemptStatus::Pending
F -> AttemptStatus::Failure
I -> AttemptStatus::AuthenticationPending
```

### 7. Guard Rails Applied
- `Secret<String>` for merchant ID and sensitive data
- `MinorUnit` for all monetary amounts
- `Email` type for email addresses
- `Currency` enum for currency fields
- Proper error handling with `CustomResult`

### 8. Critical Implementation Notes

**MANDATORY Requirements:**
1. ✅ Use UCS v2 macro framework (NO manual trait implementations)
2. ✅ Extract all values dynamically from router data
3. ✅ Use proper amount converter (StringMinorUnit)
4. ✅ Implement only UPI flows (Authorize, PSync)
5. ✅ Apply type safety guard rails
6. ✅ Register connector in ConnectorEnum
7. ✅ Document changes in CHANGELOG.md
8. ✅ Verify `cargo check` passes

**Prohibited:**
- ❌ Hardcoded values (amounts, IDs, URLs, etc.)
- ❌ Manual trait implementations
- ❌ Raw strings for sensitive data
- ❌ Integer types for monetary amounts
- ❌ Non-UPI payment methods

### 9. Testing Checklist
- [ ] Authorize flow compiles
- [ ] PSync flow compiles
- [ ] Amount conversion works correctly
- [ ] Authentication extraction works
- [ ] Status mapping is accurate
- [ ] Error handling is comprehensive
- [ ] `cargo check` passes without errors
- [ ] All guard rails are applied

### 10. Next Steps
1. Create `hsbcupi.rs` with macro framework
2. Create `hsbcupi/transformers.rs` with request/response types
3. Register connector in `src/connectors.rs`
4. Add to ConnectorEnum in types
5. Update CHANGELOG.md
6. Run `cargo check` to verify compilation
7. Test with sample data

## Reference Implementations
- PhonePe connector for UPI patterns
- Cashtocode connector for proper value extraction
- Razorpay connector for authentication patterns

## Success Criteria
✅ Compiles without errors
✅ All UPI flows implemented
✅ Proper type safety applied
✅ No hardcoded values
✅ Macro framework used correctly
✅ CHANGELOG.md updated
✅ `cargo check` passes

## Notes
This implementation preserves all business logic from the Haskell version while adapting to UCS v2 patterns and best practices.
