# Test Coverage Analysis

## Current State Summary

The codebase has **~210K lines of Rust** across 20 backend crates. Testing exists primarily as:
- **50 integration tests** in `grpc-server/tests/` (31 payment flows + 19 beta)
- **35 files** with inline `#[cfg(test)]` modules (~162 test functions)
- **11 global test suites** in `ucs-connector-tests` (authorize, capture, refund, void, etc.)
- **SDK sanity tests** across Python, JavaScript, Java, and Rust SDKs
- **Unit tests** concentrated in `field-probe`, `common_utils/crypto`, `common_utils/global_id`, `cards/validate`, `ucs_interface_common`, and `config_patch_derive`

## Coverage Gaps (by priority)

### Critical: Connector Integration Unit Tests (178K LOC, 6/78 connectors tested)

**Only 6 of 78 connectors have unit test files** (`test.rs`): Adyen, Calida, Cashfree, PPRO, Razorpay, Razorpayv2. The remaining **72 connectors have zero unit tests** for their request/response transformers.

While the `grpc-server/tests/` integration tests cover some connectors end-to-end, **only ~35 connectors have integration test coverage** (31 stable + 19 beta, with some overlap). That leaves **~40+ connectors with no test coverage at all**.

**Recommended actions:**
1. **Add transformer unit tests for high-traffic connectors first**: Stripe, Checkout, Braintree, PayPal, Cybersource, Worldpay, Globalpay, Nuvei
2. Focus on testing request body construction (correct field mapping, amount formatting, currency handling)
3. Focus on testing response parsing (status mapping, error code extraction, edge cases)
4. Test error/decline scenarios — not just happy paths

### Critical: Domain Types (22K LOC, 0 tests)

`backend/domain_types/` defines all core business models — payment requests, responses, router data, payment method data, error types, mandates, and addresses. **Zero test coverage.**

Key files needing tests:
| File | LOC | What it does |
|------|-----|-------------|
| `router_request_types.rs` | ~4K | Payment request type construction and validation |
| `router_response_types.rs` | ~3K | Response type mapping |
| `payment_method_data.rs` | ~3K | Payment method type definitions and conversions |
| `router_data.rs` | ~2K | Core router data structures |
| `errors.rs` | ~1K | Error type definitions and conversions |
| `utils.rs` | ~588 | Utility functions for data transformation |
| `mandates.rs` | ~1K | Mandate/recurring payment types |

**Recommended actions:**
1. Add unit tests for type conversions and `From`/`Into` implementations
2. Test error type construction and error message formatting
3. Test payment method data serialization/deserialization
4. Test mandate data validation

### High: Common Enums Transformers (2.4K LOC, 0 tests)

`backend/common_enums/src/transformers.rs` (257 lines) contains enum conversion logic between internal and connector-specific status codes. `enums.rs` (2,153 lines) defines all shared enumerations. **No tests.**

**Recommended actions:**
1. Test all `From` trait implementations in `transformers.rs`
2. Test enum serialization/deserialization (especially for API-facing enums)
3. Test edge cases in status code mappings

### High: External Services (3 files, 0 tests)

`backend/external-services/` handles all outbound HTTP calls to payment processors — authentication, encryption, retry logic, request building. **Zero test coverage.**

**Recommended actions:**
1. Unit test request construction (headers, auth, body encoding)
2. Test retry logic and error handling
3. Test response parsing and error extraction
4. Mock HTTP layer tests for failure scenarios (timeouts, 5xx, malformed responses)

### High: Common Utils (5.2K LOC, only 2/19 files tested)

Only `crypto.rs` and `global_id.rs` have tests. Notable untested files:
| File | LOC | What it does |
|------|-----|-------------|
| `ext_traits.rs` | 572 | Extension traits for Option/Result/String |
| `types.rs` | 473 | Core utility types |
| `id_type.rs` | 441 | ID type generation and validation |
| `events.rs` | 403 | Event handling utilities |
| `event_publisher.rs` | 375 | Kafka event publishing |
| `request.rs` | 339 | HTTP request utilities |
| `custom_serde.rs` | 200 | Custom serialization/deserialization |
| `pii.rs` | 149 | PII masking utilities |
| `errors.rs` | 205 | Error handling utilities |

**Recommended actions:**
1. Test `custom_serde.rs` — serialization bugs cause runtime failures
2. Test `pii.rs` — PII masking correctness is a compliance requirement
3. Test `id_type.rs` — ID generation and validation
4. Test `ext_traits.rs` — extension trait behavior on edge cases (None, empty strings, etc.)

### High: gRPC Server Core Logic (5.9K LOC, 0 inline tests)

`backend/grpc-server/src/server/payments.rs` alone is **3,873 lines** of payment orchestration logic with no inline unit tests. While integration tests exist, they test through the full gRPC stack and don't isolate individual functions.

**Recommended actions:**
1. Extract and unit test payment processing helper functions
2. Test config override resolution (`config_overrides.rs`, 81 lines)
3. Test HTTP error handling (`http/error.rs`, 65 lines)
4. Test request parsing and validation logic

### Medium: Interfaces Crate (2.9K LOC, 0 tests)

`backend/interfaces/` defines connector trait interfaces, webhook handling, authentication, and integrity verification. No tests.

**Recommended actions:**
1. Test webhook signature verification (`verification.rs`)
2. Test authentication trait implementations (`authentication.rs`)
3. Test integrity checking logic (`integrity.rs`)

### Medium: Composite Service (1.1K LOC, 1 schema test)

Only has `composite_request_schema_check.rs` (schema validation). The actual business logic in `payments.rs` (620 lines) and `transformers.rs` (444 lines) is untested.

**Recommended actions:**
1. Test composite payment flow orchestration
2. Test transformer logic for combining/splitting requests

### Low: FFI Layer, Tracing, Environment Setup

- `backend/ffi/` — Mostly generated code and macros; lower priority
- `backend/tracing-kafka/` — Infrastructure; test the builder/config
- `backend/ucs_env/` — Test config loading and logger setup

## Structural Recommendations

### 1. Establish a unit test convention for connectors

Create a test template that every connector must implement:
- `test_payment_request_body()` — validates the serialized request matches expected format
- `test_payment_response_parsing()` — validates response deserialization and status mapping
- `test_error_response_parsing()` — validates error handling
- `test_refund_request_body()` / `test_refund_response_parsing()`
- `test_webhook_body_parsing()` (for connectors with webhook support)

### 2. Add property-based testing for transformers

Use `proptest` or `quickcheck` to test that:
- Amount conversions are reversible where expected
- Currency code mappings are bijective
- Status code mappings cover all variants

### 3. Add serialization round-trip tests for domain types

For every type that crosses API boundaries, verify:
```rust
let original = SomeType::sample();
let serialized = serde_json::to_string(&original).unwrap();
let deserialized: SomeType = serde_json::from_str(&serialized).unwrap();
assert_eq!(original, deserialized);
```

### 4. Add negative/edge case tests

Current tests are predominantly happy-path. Add coverage for:
- Invalid currency codes
- Zero/negative/overflow amounts
- Missing required fields
- Malformed connector responses
- Network timeout scenarios
- Partial response data

### 5. Consider code coverage tooling

Integrate `cargo-llvm-cov` or `cargo-tarpaulin` into CI to track coverage metrics over time and enforce minimum thresholds for new code.
