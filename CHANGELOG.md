# Changelog

All notable changes to Connector Service will be documented here.

- - -

## [2025-01-XX] - TPSL Connector Migration

### Added
- New TPSL connector implementation migrated from Haskell euler-api-txns
- Payment methods supported: UPI (Intent/Collect)
- Transaction flows: Authorize, PSync
- Full UCS v2 macro framework compliance
- Proper amount framework implementation using StringMinorUnit
- Complete type safety with guard rails (Secret<String>, MinorUnit, Email, Currency)
- Dynamic request body value extraction from router data (no hardcoded values)
- Comprehensive error handling and status mapping

### Files Created/Modified
- `src/connectors/tpsl.rs` - Main connector implementation using UCS v2 macros
- `src/connectors/tpsl/transformers.rs` - Request/response transformers with proper amount handling
- `src/connectors/tpsl/constants.rs` - API constants and endpoints
- `src/connectors.rs` - TPSL already registered
- `src/types.rs` - TPSL already registered in ConnectorEnum

### Technical Details
- **Migrated from**: Hyperswitch/Euler Haskell implementation
- **Framework**: UCS v2 macro framework (mandatory compliance)
- **Authentication**: Merchant code-based authentication
- **Amount Handling**: StringMinorUnit converter for proper amount formatting
- **Type Safety**: All sensitive data wrapped in Secret<String>, amounts as MinorUnit
- **Request Extraction**: All values dynamically extracted from router data
- **Error Handling**: Comprehensive error response parsing and status mapping
- **Flows Implemented**: Authorize (UPI), PSync (payment status sync)
- **Test Mode**: Proper test/production URL switching based on test_mode flag

### API Endpoints
- Production: `https://www.tpsl-india.in`
- Test: `https://www.tekprocess.co.in`
- Authorize: `/PaymentGateway/merchant2.pg/:merchantCode`
- PSync: `/PaymentGateway/upiTokenGeneration`

### Compliance
- ✅ Uses UCS v2 macro framework (create_all_prerequisites!, macro_connector_implementation!)
- ✅ No manual trait implementations
- ✅ Proper amount framework usage
- ✅ Type safety with guard rails
- ✅ Dynamic value extraction (no hardcoded values)
- ✅ Registered in ConnectorEnum
- ✅ Complete error handling

- - -

## 2025.10.27.0

### Features

- **connector:** Diff check fixes for Stripe, Cybersource & Novalnet ([#226](https://github.com/juspay/connector-service/pull/226)) ([`2f8b321`](https://github.com/juspay/connector-service/commit/2f8b321665485d4ccf12a4ab06f4b8f36ece5135))

### Bug Fixes

- Fix typo in README.md ([`8f12995`](https://github.com/juspay/connector-service/commit/8f12995f0fd63e43ce2b15c049bc42bc9029661d))

**Full Changelog:** [`2025.10.23.0...2025.10.27.0`](https://github.com/juspay/connector-service/compare/2025.10.23.0...2025.10.27.0)

- - -

## 2025.10.23.0

### Features

- Adding_new_field_for_Merchant_account_metadata ([#228](https://github.com/juspay/connector-service/pull/228)) ([`46f7ddb`](https://github.com/juspay/connector-service/commit/46f7ddb6b533f887b4d9bcd218f3e16fd229d4ad))

### Bug Fixes

- **cybersource:** Use minor_refund_amount instead of minor_payment_amount in refund transformer ([#229](https://github.com/juspay/connector-service/pull/229)) ([`28d1e3e`](https://github.com/juspay/connector-service/commit/28d1e3e19c5bc7fae4cb431c531723e45b0970a0))
- Resolve disparity in Authorizedotnet flows (Authorize, RepeatPayment, SetupMandate) ([#225](https://github.com/juspay/connector-service/pull/225)) ([`2649fd8`](https://github.com/juspay/connector-service/commit/2649fd8902cdd812c1e4f7debfe4080c45a9fa55))

**Full Changelog:** [`2025.10.17.0...2025.10.23.0`](https://github.com/juspay/connector-service/compare/2025.10.17.0...2025.10.23.0)

- - -

## 2025.10.17.0

### Features

- **connector:** [CYBERSOURCE] Connector Integration ([#169](https://github.com/juspay/connector-service/pull/169)) ([`922d1c3`](https://github.com/juspay/connector-service/commit/922d1c3f786f9b83e005ea3a07d283817dd87833))
- **core:**
  - Added SecretString type for raw_connector_request and raw_connector_response ([#220](https://github.com/juspay/connector-service/pull/220)) ([`194c035`](https://github.com/juspay/connector-service/commit/194c0358122040f732ac23c9633a81eece63044c))
  - Added Create connector customer flow ([#222](https://github.com/juspay/connector-service/pull/222)) ([`29d8ad3`](https://github.com/juspay/connector-service/commit/29d8ad3771f4403431e7aaf52b4db9754a571884))

**Full Changelog:** [`2025.10.16.0...2025.10.17.0`](https://github.com/juspay/connector-service/compare/2025.10.16.0...2025.10.17.0)

- - -

## 2025.10.16.0