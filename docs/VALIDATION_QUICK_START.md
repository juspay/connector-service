# ValidationError Helper - Quick Start Guide

Quick reference for connector developers on using the new validation pattern.

## When to Use ValidationError

✅ **Use when:**
- Validating multiple fields that might all be missing
- Complex nested validations (e.g., "if address exists, check line1, country, zip")
- Want to show developers ALL errors at once

❌ **Don't use when:**
- Single field validation with early return is fine
- Dynamic validation (token vs card - can't know upfront)

## Basic Usage

```rust
use domain_types::validation::ValidationError;

fn validate_payment_data(data: &PaymentData) -> Result<(), ConnectorError> {
    let mut validation = ValidationError::new();

    // Add errors for missing fields
    validation
        .require_field("card.number", data.card_number.as_ref(), "Card number required")
        .require_field("card.expiry", data.expiry.as_ref(), "Expiry required")
        .require_field("billing.email", data.email.as_ref(), "Email required for Klarna");

    // Check and return error if any validation failed
    validation.check()
}
```

## API Reference

### Creating a Validator

```rust
let mut validation = ValidationError::new();
```

### Adding Errors

```rust
// Add missing field error (default message)
validation.add_missing_field("card_number");

// Add field error with custom message
validation.add_field_error("card_number", "Must be 13-19 digits");

// Add error conditionally
validation.add_if(
    amount > 1000,
    "fraud_check",
    "Required for transactions over $1000"
);

// Require a field to be present
validation.require_field(
    "email",
    email.as_ref(),
    "Email required for this payment method"
);

// Require multiple fields at once
validation.require_all(&[
    ("field1", field1.is_some(), "Field 1 required"),
    ("field2", field2.is_some(), "Field 2 required"),
]);
```

### Checking Results

```rust
// Check if there are any errors
if validation.has_errors() {
    println!("Found {} errors", validation.error_count());
}

// Get field errors map
let errors: &HashMap<String, String> = validation.field_errors();

// Return error if validation failed
validation.check()?;  // Returns Result<(), ConnectorError>

// Convert to error without checking
let error = validation.into_error();  // Returns ConnectorError
```

## Real-World Examples

### Example 1: Stripe AfterpayClearpay

```rust
fn validate_afterpay_shipping(
    shipping: Option<&Address>
) -> Result<(), ConnectorError> {
    let mut validation = ValidationError::new();

    match shipping {
        Some(addr) => {
            // Validate nested fields
            validation
                .require_field(
                    "shipping.address.line1",
                    addr.line1.as_ref(),
                    "Required for Afterpay payments"
                )
                .require_field(
                    "shipping.address.country",
                    addr.country.as_ref(),
                    "Required for Afterpay payments"
                )
                .require_field(
                    "shipping.address.zip",
                    addr.zip.as_ref(),
                    "Required for Afterpay payments"
                );
        }
        None => {
            validation.add_field_error(
                "shipping.address",
                "Shipping address is required for Afterpay"
            );
        }
    }

    validation.check()
}
```

**Error Response (if all 3 missing):**
```json
{
  "code": "CE_VALIDATION_FAILED",
  "field_errors": {
    "shipping.address.line1": "Required for Afterpay payments",
    "shipping.address.country": "Required for Afterpay payments",
    "shipping.address.zip": "Required for Afterpay payments"
  },
  "suggested_action": "Fix the following fields: 'shipping.address.line1', 'shipping.address.country', 'shipping.address.zip'. Check the connector documentation for field requirements."
}
```

### Example 2: Conditional Validation

```rust
fn validate_card_data(
    card: &CardData,
    has_token: bool
) -> Result<(), ConnectorError> {
    // Only validate if NOT using token (dynamic requirement)
    if !has_token {
        let mut validation = ValidationError::new();

        validation
            .require_field("card.number", card.number.as_ref(), "Required when not using token")
            .require_field("card.expiry_month", card.expiry_month.as_ref(), "Required when not using token")
            .require_field("card.expiry_year", card.expiry_year.as_ref(), "Required when not using token")
            .require_field("card.cvv", card.cvv.as_ref(), "Required when not using token");

        validation.check()?;
    }

    Ok(())
}
```

### Example 3: Fallback Validation

```rust
fn validate_customer_name(
    billing: Option<&Address>,
    card_holder_name: Option<&str>
) -> Result<String, ConnectorError> {
    let mut validation = ValidationError::new();

    // Try billing name first
    if let Some(addr) = billing {
        if let Some(name) = &addr.first_name {
            return Ok(name.clone());
        }
    }

    // Fall back to card holder name
    if let Some(name) = card_holder_name {
        return Ok(name.to_string());
    }

    // Neither available - validation error
    validation.add_field_error(
        "billing.first_name or card_holder_name",
        "At least one name field is required by this connector"
    );

    Err(validation.into_error())
}
```

## Migration Guide

### Before (Old Pattern)

```rust
// Old: Single field at a time
let card_number = card.number
    .ok_or(ConnectorError::MissingRequiredField {
        field_name: "card_number"
    })?;

let expiry = card.expiry
    .ok_or(ConnectorError::MissingRequiredField {
        field_name: "card_expiry"
    })?;
// Developer sees errors one at a time ❌
```

### After (New Pattern)

```rust
// New: All fields at once
let mut validation = ValidationError::new();

validation
    .require_field("card_number", card.number.as_ref(), "Required for card payments")
    .require_field("card_expiry", card.expiry.as_ref(), "Required for card payments");

validation.check()?;  // Shows ALL missing fields ✅

// Now safely unwrap (we know they exist)
let card_number = card.number.as_ref().unwrap();
let expiry = card.expiry.as_ref().unwrap();
```

## Best Practices

### 1. Group Related Validations

```rust
// ✅ Good: Validate related fields together
fn validate_billing_address(addr: &Address) -> Result<(), ConnectorError> {
    let mut v = ValidationError::new();
    v.require_field("line1", addr.line1.as_ref(), "Required")
     .require_field("city", addr.city.as_ref(), "Required")
     .require_field("country", addr.country.as_ref(), "Required");
    v.check()
}

// ❌ Bad: Separate validations for related fields
let line1 = addr.line1.ok_or(...)?;
let city = addr.city.ok_or(...)?;
```

### 2. Use Descriptive Messages

```rust
// ✅ Good: Specific, actionable message
validation.add_field_error(
    "shipping.address",
    "Shipping address is required for Afterpay/Clearpay payments"
);

// ❌ Bad: Generic message
validation.add_missing_field("shipping.address");
```

### 3. Keep Dynamic Validation in Transformers

```rust
// ✅ Good: Dynamic logic in transformer
if payment_method_token.is_some() {
    // Use token - no card validation
} else {
    // Validate card fields
    validate_card_data(&card)?;
}

// ❌ Bad: Trying to centralize dynamic validation
// (Impossible - requirements depend on runtime values)
```

## Testing

```rust
#[test]
fn test_validation_shows_all_errors() {
    let mut validation = ValidationError::new();

    validation
        .add_missing_field("field1")
        .add_missing_field("field2")
        .add_field_error("field3", "Invalid format");

    assert_eq!(validation.error_count(), 3);
    assert!(validation.has_errors());

    let result = validation.check();
    assert!(result.is_err());

    if let Err(ConnectorError::ValidationFailed { field_errors }) = result {
        assert_eq!(field_errors.len(), 3);
        assert!(field_errors.contains_key("field1"));
    }
}
```

## FAQ

**Q: Should I always use ValidationError?**
A: No. Use it when you want to collect multiple errors. For single field checks with early return, the old pattern is fine.

**Q: Can I mix old and new patterns?**
A: Yes! Both work. Migrate gradually as you touch connector code.

**Q: What about backward compatibility?**
A: `MissingRequiredField` still works. `ValidationFailed` is additive, not breaking.

**Q: Does this work for dynamic validation?**
A: Yes, but ValidationError is most useful for static multi-field validation. Dynamic validation should still happen in transformers.

---

**See Also:**
- [ERROR_HANDLING_IMPROVEMENTS.md](./ERROR_HANDLING_IMPROVEMENTS.md) - Full implementation details
- [ERROR_RETRY_LOGIC.md](./ERROR_RETRY_LOGIC.md) - Retry decision tree
