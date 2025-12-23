---
paths:
  - backend/connector-integration/src/connectors/**/*.rs
---
# Amount Conversion Patterns

All amounts inside UCS use `MinorUnit` (smallest currency unit, e.g., cents for USD).

## Converter Types

| Converter | API Expects | Example |
|-----------|-------------|---------|
| `StringMinorUnit` | String "1000" | $10.00 → "1000" |
| `StringMajorUnit` | String "10.00" | $10.00 → "10.00" |
| `FloatMajorUnit` | Float 10.00 | $10.00 → 10.00 |
| `MinorUnitI64` | Integer 1000 | $10.00 → 1000 |

## Decision Tree

```
Is amount a string? 
├── Yes → Has decimal point?
│         ├── Yes → StringMajorUnit
│         └── No  → StringMinorUnit
└── No  → Is it a float?
          ├── Yes → FloatMajorUnit
          └── No  → MinorUnitI64
```

## Implementation

```rust
macros::create_all_prerequisites!(
    // Match converter to API expectation
    amount_converters: [amount_converter: StringMinorUnit],
);

#[derive(Serialize)]
pub struct Request {
    // Converter handles serialization automatically
    pub amount: MinorUnit,
}
```

## Common Mistakes

```rust
// ❌ WRONG - Never use primitives
pub struct Request {
    pub amount: i64,
}

// ❌ WRONG - Don't manually convert
let amount_major = router_data.request.amount.get_amount_as_i64() / 100;

// ✅ CORRECT - Use MinorUnit with converter
pub struct Request {
    pub amount: MinorUnit,
}
let amount = router_data.request.amount;  // Converter serializes correctly
```

## Currency-Specific Scales

| Currency | Minor Unit Scale | $10 equivalent |
|----------|-----------------|----------------|
| USD, EUR | 100 | 1000 |
| JPY | 1 | 10 |
| KWD | 1000 | 10000 |

UCS handles this automatically via `MinorUnit`.
