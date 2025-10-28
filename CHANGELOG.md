# Changelog

## [2025-01-08] - EaseBuzz Connector Implementation

### Added
- Complete EaseBuzz connector implementation using UCS v2 macro framework
- Payment methods supported: UPI, UPI Collect, UPI Intent
- Implemented transaction flows: Authorize, PSync
- Stub implementations for all unsupported flows (Void, Capture, Refund, etc.)
- Comprehensive error handling and status mapping
- Full webhook support structure (implementation pending)

### Files Created/Modified
- `backend/connector-integration/src/connectors/easebuzz.rs` - Main connector implementation using UCS v2 macro framework
- `backend/connector-integration/src/connectors/easebuzz/transformers.rs` - Request/response transformers for EaseBuzz API
- `backend/connector-integration/src/connectors/easebuzz/constants.rs` - API constants and endpoints
- `backend/connector-integration/src/connectors.rs` - Added EaseBuzz connector registration
- `backend/connector-integration/src/types.rs` - Added EaseBuzz to connector conversion and imports
- `backend/domain_types/src/connector_types.rs` - Added EaseBuzz to ConnectorEnum

### Technical Implementation
- **Mandatory UCS v2 Macro Framework**: Uses `create_all_prerequisites!` and `macro_connector_implementation!` macros
- **No Manual Trait Implementations**: All traits implemented via macros (ConnectorServiceTrait, PaymentAuthorizeV2, etc.)
- **Dynamic Value Extraction**: All request values extracted from router data (no hardcoded values)
- **Type Safety**: Full guard rails with Secret<String>, MinorUnit, Email, Currency types
- **Authentication**: API key authentication with Base64 encoding
- **Environment Support**: Test and production environment handling
- **UPI-Specific**: UPI payment flows with VPA handling for Collect and Intent
- **Error Handling**: Comprehensive error response parsing and status mapping

### API Endpoints Implemented
- `/payment/initiateLink` - Payment initiation (Authorize flow)
- `/payment/txnSync` - Transaction status sync (PSync flow)
- Base URLs: Test (`https://testpay.easebuzz.in`) and Production (`https://pay.easebuzz.in`)

### Payment Method Support
- UPI Intent payments with redirect flow
- UPI Collect payments with VPA validation
- Virtual Payment Address (VPA) extraction from payment method data
- UPI QR code support structure

### Security & Compliance
- API key authentication with Secret<String> wrapping
- Hash-based request signing
- IP address and user agent tracking in UDF fields
- Webhook signature verification structure (implementation pending)
- No sensitive data exposure in logs

### Architecture Compliance
- **CRITICAL**: Uses mandatory UCS v2 macro framework - no manual implementations
- **Amount Framework**: Proper StringMinorUnit amount converter usage
- **Generic Types**: Full support for PaymentMethodDataTypes with proper trait bounds
- **Source Verification**: Stub implementations for all flows
- **Connector Registration**: Properly registered in ConnectorEnum and type system

### Known Limitations
- Webhook processing implementation pending
- Refund flows stubbed (return NotImplemented errors)
- Card payment flows not supported (UPI only as per requirements)
- Mandate flows stubbed (not implemented)
- Some authentication flows stubbed (PreAuthenticate, Authenticate, PostAuthenticate)

### API Endpoints
- `/payment/initiateLink` - Payment initiation
- `/payment/txnSync` - Transaction status sync
- Support for both test (`https://testpay.easebuzz.in`) and production (`https://pay.easebuzz.in`) environments

### Payment Method Support
- UPI Intent payments
- UPI Collect payments  
- UPI QR code generation
- Virtual Payment Address (VPA) handling

### Security Features
- API key authentication with Base64 encoding
- Hash-based request signing
- Secret type wrapping for sensitive data
- IP address and user agent tracking
- Webhook signature verification structure

### Known Limitations
- Webhook processing implementation pending
- Refund flows stubbed (not implemented)
- Card payment flows not supported (UPI only as per requirements)
- Mandate flows stubbed (not implemented)