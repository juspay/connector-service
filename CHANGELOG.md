# Changelog

## [2024-01-15] - EaseBuzz Connector Addition

### Added
- New EaseBuzz connector implementation for UCS v2
- Payment methods supported: UPI (Intent and Collect flows)
- Transaction flows: Authorize, PSync, Refund, RSync
- Comprehensive error handling and status mapping
- Hash-based authentication using SHA512
- Support for test and production environments

### Files Created/Modified
- `src/connectors/easebuzz.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/easebuzz/transformers.rs` - Request/response transformers with proper type safety
- `src/connectors/easebuzz/constants.rs` - API constants, endpoints, and validation functions
- `src/connectors.rs` - Added connector registration and exports
- `src/types.rs` - Added connector to ConnectorEnum and URL trait implementations

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for all trait implementations (no manual implementations)
- Implements proper error handling and status mapping from original Haskell code
- Full type safety with guard rails (Secret<String> for sensitive data, MinorUnit for amounts)
- Amount framework using StringMinorUnit converter for proper monetary value handling
- Dynamic extraction of all request values from router data (no hardcoded values)
- Comprehensive validation for transaction IDs, VPAs, and amounts
- Support for UPI-specific payment flows with proper hash generation

### API Integration
- Base URLs: Production (https://pay.easebuzz.in) and Test (https://testpay.easebuzz.in)
- Authentication: Key-based with SHA512 hash generation
- Supported currencies: INR only
- Request format: application/x-www-form-urlencoded
- Response handling: Comprehensive status mapping and error parsing

### Security Features
- Hash-based request authentication using merchant key and salt
- Sensitive data wrapped in Secret<String> type
- Input validation for all user-provided data
- Proper error message handling without exposing sensitive information

### Compliance
- Follows UCS v2 macro framework requirements strictly
- Implements all mandatory guard rails and type safety measures
- Proper amount handling using domain types
- Complete error handling with appropriate error types