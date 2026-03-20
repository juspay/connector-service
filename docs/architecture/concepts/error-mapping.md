# Error Mapping

Payment processors speak different error languages. Stripe says "card_declined." Adyen says "Refused." PayPal says "INSTRUMENT_DECLINED." Prism translates all of them into a single set of error codes your application handles once.

## The Mapping Problem

Without unified error mapping, your code looks like this:

```javascript
// Without Prism—handle every connector's errors separately
if (connector === 'stripe') {
    if (error.code === 'card_declined') {
        // handle decline
    }
} else if (connector === 'adyen') {
    if (error.resultCode === 'Refused') {
        // handle decline
    }
} else if (connector === 'paypal') {
    if (error.details[0].issue === 'INSTRUMENT_DECLINED') {
        // handle decline
    }
}
// Repeat for 50+ connectors...
```

With Prism, you write the handling logic once:

```javascript
// With Prism—unified error codes
if (error.code === 'PAYMENT_DECLINED') {
    // Handles Stripe, Adyen, PayPal, and all others
    showError('Your payment was declined.');
}
```

## How Mapping Works

Each connector adapter includes an error mapper that translates connector-specific codes to unified codes:

```
Stripe Error ──────┐
                   ├──► Error Mapper ──► Unified Error
Adyen Error ───────┤
                   │
PayPal Error ──────┘
```

The mapper analyzes:
- HTTP status codes
- Error codes in the response body
- Error messages
- Decline reasons

Then selects the appropriate unified error code.

## Unified Error Structure

Every error follows this structure:

```rust
struct UnifiedError {
    code: ErrorCode,              // Unified error code
    message: String,              // Human-readable description
    category: ErrorCategory,      // Classification
    connector_code: String,       // Original connector code
    connector_message: String,    // Original connector message
    request_id: String,           // For support/debugging
    retryable: bool,              // Whether to retry
    suggested_action: String,     // Recommended fix
}
```

## Error Code Reference

| Unified Code | Description | Stripe Equivalent | Adyen Equivalent |
|--------------|-------------|--------------------|------------------|
| `PAYMENT_DECLINED` | Generic decline | `card_declined` | `Refused` |
| `INSUFFICIENT_FUNDS` | Not enough money | `card_declined` + `decline_code: insufficient_funds` | `Not enough balance` |
| `EXPIRED_CARD` | Card expired | `expired_card` | `Expiry Date not valid` |
| `INCORRECT_CVV` | Wrong security code | `incorrect_cvc` | `CVC Declined` |
| `INVALID_CARD_NUMBER` | Bad card number | `incorrect_number` | `Invalid card number` |
| `PROCESSING_ERROR` | Generic processor error | `processing_error` | `Error` |
| `NETWORK_TIMEOUT` | Request timed out | HTTP 504 | Timeout |
| `RATE_LIMITED` | Too many requests | HTTP 429 | HTTP 401 |
| `INVALID_API_KEY` | Auth failed | HTTP 401 | HTTP 401 |
| `VALIDATION_ERROR` | Bad request format | HTTP 400 | HTTP 422 |

## Mapping Examples

### Stripe Error Mapping

```rust
impl From<StripeError> for UnifiedError {
    fn from(stripe: StripeError) -> Self {
        match stripe.code.as_str() {
            "card_declined" => {
                let code = match stripe.decline_code.as_deref() {
                    Some("insufficient_funds") => ErrorCode::INSUFFICIENT_FUNDS,
                    Some("expired_card") => ErrorCode::EXPIRED_CARD,
                    Some("incorrect_cvc") => ErrorCode::INCORRECT_CVV,
                    _ => ErrorCode::PAYMENT_DECLINED,
                };
                
                UnifiedError {
                    code,
                    message: format!("Payment declined: {}", stripe.message),
                    category: ErrorCategory::PAYMENT_ERROR,
                    connector_code: stripe.code,
                    connector_message: stripe.message,
                    retryable: false,
                    suggested_action: "Ask customer for different payment method",
                    ..Default::default()
                }
            }
            "expired_card" => UnifiedError {
                code: ErrorCode::EXPIRED_CARD,
                message: "Your card has expired".to_string(),
                category: ErrorCategory::PAYMENT_ERROR,
                connector_code: stripe.code,
                connector_message: stripe.message,
                retryable: false,
                suggested_action: "Ask customer to check expiration date",
                ..Default::default()
            }
            // ... more mappings
            _ => UnifiedError {
                code: ErrorCode::UNKNOWN_ERROR,
                message: "An unexpected error occurred".to_string(),
                category: ErrorCategory::UNKNOWN,
                connector_code: stripe.code,
                connector_message: stripe.message,
                retryable: false,
                suggested_action: "Contact support",
                ..Default::default()
            }
        }
    }
}
```

### Adyen Error Mapping

```rust
impl From<AdyenResponse> for UnifiedError {
    fn from(adyen: AdyenResponse) -> Self {
        match adyen.result_code.as_str() {
            "Refused" => {
                let code = match adyen.refusal_reason.as_deref() {
                    Some(r) if r.contains("Not enough balance") => ErrorCode::INSUFFICIENT_FUNDS,
                    Some(r) if r.contains("Expiry Date") => ErrorCode::EXPIRED_CARD,
                    Some(r) if r.contains("CVC") => ErrorCode::INCORRECT_CVV,
                    _ => ErrorCode::PAYMENT_DECLINED,
                };
                
                UnifiedError {
                    code,
                    message: adyen.refusal_reason.unwrap_or_default(),
                    category: ErrorCategory::PAYMENT_ERROR,
                    connector_code: "Refused".to_string(),
                    connector_message: adyen.refusal_reason.unwrap_or_default(),
                    retryable: false,
                    suggested_action: "Ask customer for different payment method",
                    ..Default::default()
                }
            }
            // ... more mappings
            _ => UnifiedError::unknown(),
        }
    }
}
```

## Category Classification

Errors are classified into categories for routing and handling:

```rust
enum ErrorCategory {
    PAYMENT_ERROR,        // Customer's fault—bad card, no funds
    NETWORK_ERROR,        // Infrastructure—timeouts, connection issues
    CONFIGURATION_ERROR,  // Setup—invalid credentials, wrong settings
    VALIDATION_ERROR,     // Request—missing fields, bad format
    UNKNOWN,              // Unclassified—log and investigate
}
```

Category determines:
- **PAYMENT_ERROR**: Show customer-friendly message
- **NETWORK_ERROR**: Retry with exponential backoff
- **CONFIGURATION_ERROR**: Alert ops team immediately
- **VALIDATION_ERROR**: Fix request and retry
- **UNKNOWN**: Log everything, contact support

## Connector-Specific Details Preserved

While mapping to unified codes, Prism preserves original error details:

```javascript
{
    "error": {
        "code": "PAYMENT_DECLINED",
        "message": "Your payment was declined.",
        "category": "PAYMENT_ERROR",
        
        // Original Stripe details
        "connector_code": "card_declined",
        "connector_message": "Your card was declined.",
        
        // Additional context
        "connector": "stripe",
        "decline_code": "stolen_card"  // Stripe-specific field
    }
}
```

This lets you:
- Handle errors generically with unified codes
- Access original details for debugging
- Show connector-specific messaging if needed

## Adding New Error Mappings

When adding a new connector, you define error mappings in the adapter:

```rust
// In your connector adapter
fn map_error(&self, connector_error: ProviderError) -> UnifiedError {
    match connector_error {
        ProviderError::Declined { reason } => UnifiedError {
            code: ErrorCode::PAYMENT_DECLINED,
            message: reason.clone(),
            connector_code: "declined".to_string(),
            connector_message: reason,
            category: ErrorCategory::PAYMENT_ERROR,
            retryable: false,
            suggested_action: "Use different payment method",
            ..Default::default()
        },
        ProviderError::Timeout => UnifiedError {
            code: ErrorCode::NETWORK_TIMEOUT,
            message: "Request timed out".to_string(),
            category: ErrorCategory::NETWORK_ERROR,
            retryable: true,
            suggested_action: "Retry with backoff",
            ..Default::default()
        },
        // ... more mappings
    }
}
```

## Benefits

- **Single error handling path**: Write once, works for all connectors
- **Consistent customer experience**: Same messages regardless of processor
- **Debugging preserved**: Original error details available
- **Extensible**: Add new connectors without changing error handling code

Your application handles 50+ payment processors with one set of error handlers.
