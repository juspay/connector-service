# Error Handling Improvements for SDK Launch

This document describes the comprehensive error handling improvements made to prepare UCS for SDK launch with world-class developer experience.

## Overview

**Goal:** Enable fintech developers (and LLMs) to integrate UCS flawlessly with clear, actionable error messages that show ALL issues at once.

**Branch:** `feat/sdk-error-handling`

## What Was Implemented

### 1. ValidationError Helper (`backend/domain_types/src/validation.rs`)

A fluent validation helper that collects multiple field errors before returning, drastically improving developer experience.

#### Before (Bad DX):
```rust
// Developer sees errors one at a time - requires 3 iterations!
Request 1: "Missing required field: shipping.address.line1"
Request 2: "Missing required field: shipping.address.country"
Request 3: "Missing required field: shipping.address.zip"
```

#### After (Good DX):
```rust
// Developer sees ALL errors at once - fixed in 1 iteration!
{
  "code": "CE_VALIDATION_FAILED",
  "field_errors": {
    "shipping.address.line1": "Required for Afterpay/Clearpay payments",
    "shipping.address.country": "Required for Afterpay/Clearpay payments",
    "shipping.address.zip": "Required for Afterpay/Clearpay payments"
  }
}
```

#### Usage Example:
```rust
use domain_types::validation::ValidationError;

let mut validation = ValidationError::new();

validation
    .require_field("card.number", card.number.as_ref(), "Card number required")
    .require_field("card.expiry", card.expiry.as_ref(), "Expiry required")
    .require_field("card.cvv", card.cvv.as_ref(), "CVV required");

// Returns error only if there are failures
validation.check()?;
```

### 2. Error Categorization (`ErrorCategory` enum)

Errors are now categorized for SDK classification:

- `InvalidRequest` - Bad developer input (fix code)
- `ConfigurationError` - Auth/credentials issue
- `NotSupported` - Feature unavailable
- `NotImplemented` - Feature not coded yet
- `ProcessingError` - Internal UCS error
- `Timeout` - Request timeout
- `ConnectorError` - PSP-specific error
- `WebhookError` - Webhook processing error

### 3. Machine-Readable Error Codes

Every error now has a consistent error code for documentation lookup and LLM parsing:

```rust
ConnectorError::MissingRequiredField { .. } → "CE_MISSING_REQUIRED_FIELD"
ConnectorError::NotSupported { .. } → "CE_NOT_SUPPORTED"
ConnectorError::RequestTimeoutReceived → "CE_REQUEST_TIMEOUT"
// ... ~60 total codes
```

### 4. Actionable Error Messages

Every error includes:

**`description()`** - Technical explanation
```
"A required field was not provided in the request."
```

**`suggested_action()`** - What to do next
```
"Add the 'card_number' field to your payment request. Check the connector documentation for the expected format."
```

**`documentation_url()`** - Link to docs
```
"https://docs.ucs.com/errors/CE_MISSING_REQUIRED_FIELD"
```

### 5. Retry Logic

Errors now indicate if they're retryable:

```rust
error.is_retryable() → bool

// Retryable errors:
- RequestTimeoutReceived (network timeout)
- ResponseDeserializationFailed (might be transient)
- WebhookBodyDecodingFailed (PSP might retry)

// Not retryable:
- Validation errors (developer must fix)
- Configuration errors (manual intervention needed)
- Not supported/implemented (permanent limitation)
```

### 6. Field-Level Error Mapping

Extract structured field errors from any error:

```rust
let field_errors = error.get_field_errors();
// HashMap<String, String> {
//   "card_number": "This field is required",
//   "card_expiry": "This field is required"
// }
```

## Implementation Status

### ✅ Completed

- [x] `ValidationError` helper created and tested
- [x] `ValidationFailed` variant added to `ConnectorError`
- [x] `ErrorCategory` enum and `category()` method
- [x] `error_code()` method for all 77 error variants
- [x] `description()` method for all variants
- [x] `suggested_action()` method for all variants
- [x] `documentation_url()` method
- [x] `is_retryable()` method with retry logic
- [x] `get_field_errors()` method
- [x] `http_status_code()` method
- [x] Applied to Stripe AfterpayClearpay validation (reference implementation)
- [x] All code compiles successfully

### 🚧 Next Steps

1. **Apply to More Connectors**
   - Adyen (17 validations)
   - Cybersource (19 validations)
   - Other high-validation connectors

2. **Update Proto Definitions**
   - Add `ErrorCategory` enum to proto
   - Add `field_errors` map to `RequestError`/`ResponseError`
   - Add `suggested_action` and `documentation_url` fields

3. **Generate Error Documentation**
   - Create auto-generation script for error docs
   - Generate markdown docs for all error codes

4. **SDK Integration**
   - Generate language-specific error enums from error codes
   - Create type-safe error handlers in Python/TypeScript/etc.

## Example: Stripe AfterpayClearpay

### Before:
```rust
let missing_fields = collect_missing_value_keys!(
    ("shipping.address.line1", address.line1),
    ("shipping.address.country", address.country),
    ("shipping.address.zip", address.zip)
);

if !missing_fields.is_empty() {
    return Err(ConnectorError::MissingRequiredFields {
        field_names: missing_fields,
    }.into());
}
```

### After:
```rust
let mut validation = ValidationError::new();

validation
    .require_field("shipping.address.line1", address.line1.as_ref(),
                   "Required for Afterpay/Clearpay payments")
    .require_field("shipping.address.country", address.country.as_ref(),
                   "Required for Afterpay/Clearpay payments")
    .require_field("shipping.address.zip", address.zip.as_ref(),
                   "Required for Afterpay/Clearpay payments");

validation.check()?;  // Returns ValidationFailed with all errors
```

### Error Response (SDK):
```json
{
  "category": "INVALID_REQUEST",
  "code": "CE_VALIDATION_FAILED",
  "message": "Validation failed for fields: shipping.address.line1, shipping.address.country, shipping.address.zip",
  "description": "One or more required fields are missing or invalid. Review the field_errors for specific issues.",
  "suggested_action": "Fix the following fields: 'shipping.address.line1', 'shipping.address.country', 'shipping.address.zip'. Check the connector documentation for field requirements.",
  "documentation_url": "https://docs.ucs.com/errors/CE_VALIDATION_FAILED",
  "field_errors": {
    "shipping.address.line1": "Required for Afterpay/Clearpay payments",
    "shipping.address.country": "Required for Afterpay/Clearpay payments",
    "shipping.address.zip": "Required for Afterpay/Clearpay payments"
  },
  "retryable": false,
  "http_status_code": 400
}
```

## Benefits for SDK Developers

1. **Less Iteration** - See all errors at once, fix in one go
2. **Clear Guidance** - Every error tells you what to do
3. **LLM-Friendly** - Structured format for AI code assistants
4. **Type-Safe** - Error codes as enums in SDKs
5. **Self-Documenting** - Links to docs for every error
6. **Retry Logic** - Know which errors to retry automatically

## Benefits for UCS

1. **Reduced Support** - Better error messages = fewer support tickets
2. **Faster Integration** - Developers can fix issues themselves
3. **Competitive Advantage** - Best-in-class error handling
4. **Maintainability** - Centralized error logic, easy to update

## Testing

To test the new validation:

```bash
cd backend/domain_types
cargo test validation

# Expected output:
# test validation::tests::test_empty_validation_passes ... ok
# test validation::tests::test_single_field_error ... ok
# test validation::tests::test_multiple_field_errors ... ok
# test validation::tests::test_require_field ... ok
```

## Related Documentation

- [ERROR_RETRY_LOGIC.md](./ERROR_RETRY_LOGIC.md) - Retry decision tree
- [Connector Integration Guide](../README.md) - How to use ValidationError in connectors
- [Proto Definitions](../backend/grpc-api-types/proto/) - gRPC error structures

## Architecture Decision Records

### Why Not Centralize All Validation in a Trait?

**Decision:** Keep validation in transformers for context-dependent requirements.

**Reasoning:**
- 90% of validations are dynamic (depend on other field values)
- Only 2 cases of static multi-field validation found in codebase (Stripe Afterpay)
- Trait would return empty for most connectors (bad developer experience)
- Context-specific validation is inherently tied to transformation logic

**Alternative Considered:** Static requirements trait
**Why Rejected:** High maintenance cost for minimal benefit (helps 1-2 cases out of 150+ connectors)

### Why Separate `MissingRequiredField` and `ValidationFailed`?

**Decision:** Keep both for backward compatibility during transition.

**Reasoning:**
- 312 uses of `MissingRequiredField` in current codebase
- Gradual migration path (both work, choose based on context)
- Single field? Use `MissingRequiredField` or `ConnectorError::missing_field()`
- Multiple fields? Use `ValidationError` helper → `ValidationFailed`

**Future:** May deprecate `MissingRequiredField` once all connectors migrated.

---

**Last Updated:** 2026-03-17
**Status:** ✅ Phase 1 Complete, Ready for Connector Migration
