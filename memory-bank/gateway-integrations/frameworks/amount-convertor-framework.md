# AmountConvertor Framework

## Overview

The AmountConvertor framework standardizes amount handling across different payment processors, which have varying requirements for amount formats and currency representations.

## Core Trait

```rust
pub trait AmountConvertor: Send {
    type Output;
    
    fn convert(
        &self,
        amount: MinorUnit,
        currency: enums::Currency,
    ) -> Result<Self::Output, error_stack::Report<ParsingError>>;

    fn convert_back(
        &self,
        amount: Self::Output,
        currency: enums::Currency,
    ) -> Result<MinorUnit, error_stack::Report<ParsingError>>;
}
```

## Available Implementations

1. **StringMinorUnitForConnector**: Converts amounts to string representation in minor units (cents)
   - Example: $10.50 → "1050"
   - Used by: Connectors that expect string amounts in smallest currency unit

2. **StringMajorUnitForConnector**: Converts amounts to string representation in major units (dollars)
   - Example: $10.50 → "10.50"
   - Used by: Adyen and other connectors expecting decimal string amounts

3. **FloatMajorUnitForConnector**: Converts amounts to float representation in major units
   - Example: $10.50 → 10.50 (float)
   - Used by: Connectors with numeric amount fields

4. **MinorUnitForConnector**: Pass-through for minor units (no conversion)
   - Example: $10.50 → 1050 (integer)
   - Used by: Razorpay and other connectors expecting integer cents

## Integration with Connectors

### Connector Definition
```rust
#[derive(Clone)]
pub struct Adyen {
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = String> + Sync),
}

impl Adyen {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &common_utils::types::StringMajorUnitForConnector,
        }
    }
}
```

### Usage in Request Transformation
```rust
// From Elavon connector transformer
fn build_payment_request(
    request_data: &PaymentsAuthorizeData,
    connector: &Elavon,
) -> Result<ElavonPaymentRequest> {
    let amount = connector
        .amount_converter
        .convert(request_data.minor_amount, request_data.currency)
        .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;
    
    Ok(ElavonPaymentRequest {
        ssl_amount: amount,
        ssl_currency_code: request_data.currency.to_string(),
        // ... other fields
    })
}
```

### Currency Handling
The framework automatically handles different currency characteristics:
- **Zero-decimal currencies** (JPY, KRW): No conversion needed
- **Two-decimal currencies** (USD, EUR): Standard /100 conversion
- **Three-decimal currencies** (BHD, KWD): /1000 conversion

## Benefits
- **Consistency**: All connectors receive amounts in their expected format
- **Currency Safety**: Automatic handling of currency-specific decimal places
- **Type Safety**: Compile-time guarantees about amount format conversions
- **Maintainability**: Centralized amount conversion logic

## Best Practices for Connector Developers

1. **Choose Appropriate AmountConvertor**: 
   - Use StringMajorUnit for decimal-based APIs
   - Use MinorUnit for integer-based APIs
   - Use FloatMajorUnit only when necessary