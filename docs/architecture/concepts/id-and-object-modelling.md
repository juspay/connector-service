# ID and Object Modeling

Payment processors can't agree on how to name their IDs. Stripe uses `pi_3MqSCR2eZvKYlo2C1`. Adyen uses `7914073381344578`. Razorpay uses `pay_ABCdef123`. This inconsistency breaks code completion, confuses LLMs, and forces you to maintain different ID handling logic for each connector.

Prism solves this with a unified ID system that uses strongly-typed, self-describing identifiers regardless of the underlying processor.

## The ID Problem

Without unified IDs, your code looks like this:

```javascript
// Which ID goes where? Easy to mix up.
const stripePaymentId = 'pi_3MqSCR2eZvKYlo2C1';
const adyenPaymentId = '7914073381344578';
const razorpayPaymentId = 'pay_ABCdef123';

// Oops—passed the wrong ID type
await client.refunds.create({
    paymentId: adyenPaymentId,  // But we're using Stripe!
    amount: 1000
});
// Error: Payment not found (because IDs aren't interchangeable)
```

LLMs hallucinate valid IDs when they see inconsistent patterns. Ask an LLM to "create a Stripe PaymentIntent ID" and it might generate `pay_123abc` (Razorpay format) or just make up a random number.

## Connector ID Chaos

| Connector | Payment ID Example | Customer ID Example | Refund ID Example |
|-----------|-------------------|---------------------|-------------------|
| **Stripe** | `pi_3MqSCR2eZvKYlo2C1` | `cus_ABC123def456` | `re_3NabcDEF456` |
| **Adyen** | `7914073381344578` | `1234567890123456` | `8814073381344578` |
| **Razorpay** | `pay_ABCdef123ghi` | `cust_ABC123` | `ref_ABCdef123` |
| **PayPal** | `PAYID-ABC123DEF456` | `CUST-123-456-789` | `REFUND-ABC-123` |
| **Braintree** | `f2ekdhg3sk5m` | `customer_id_123` | `refund_id_456` |

Each has different length constraints, prefixes, and validation rules. Your validation logic becomes a nightmare of regex patterns.

## The entity_domain_id Pattern

Prism uses typed IDs with a consistent format: `entity_domain_id`

| ID Type | Format | Example |
|---------|--------|---------|
| **PaymentId** | `pay_{nano_id}` | `pay_abc123def456ghi` |
| **CustomerId** | `cus_{nano_id}` | `cus_xyz789uvw012jkl` |
| **RefundId** | `ref_{nano_id}` | `ref_def456ghi789mno` |
| **MandateId** | `man_{nano_id}` | `man_ghi789mno345pqr` |

The prefix tells you exactly what the ID represents. The NanoID provides collision-resistant unique identifiers.

## Typed ID Safety

Prism implements strongly-typed IDs at the language level:

```rust
// These are distinct types, not just Strings
struct PaymentId(LengthId<64, 1>);
struct CustomerId(String);
struct RefundId(LengthId<64, 1>);

// Compiler prevents mixing them up
fn process_payment(id: PaymentId) { ... }
fn process_customer(id: CustomerId) { ... }

process_payment(customer_id);  // Compile error!
process_customer(payment_id);  // Compile error!
```

In your SDK:

```javascript
// TypeScript knows the difference
type PaymentId = `pay_${string}`;
type CustomerId = `cus_${string}`;

function authorize(paymentId: PaymentId): Promise<AuthorizeResponse>;
function createCustomer(customerId: CustomerId): Promise<Customer>;

// IDE autocomplete and type checking prevent mistakes
client.payments.authorize({ paymentId: 'cus_abc123' });
// Error: Argument of type 'CustomerId' is not assignable to parameter of type 'PaymentId'
```

## Global IDs for Distributed Systems

For multi-instance deployments, Prism uses Global IDs with a cell prefix:

```
Format: {cell_id}_{entity_prefix}_{uuid}

Example: cell1_pay_uu1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p
         │     │  │
         │     │  └─ Time-ordered UUID (enables DB indexing)
         │     └──── Entity type (pay, cus, ref, etc.)
         └────────── Cell identifier (for distributed deployments)
```

This lets you route requests to the correct data center and maintain uniqueness across regions.

## ID Types in Key Operations

### Authorization Flow IDs

```javascript
const response = await client.payments.authorize({
    amount: { minorAmount: 1000, currency: 'USD' },
    paymentMethod: { card: { ... } }
});

// Returns:
{
    paymentId: 'pay_abc123def456ghi',     // Prism unified ID
    connectorPaymentId: 'pi_3MqSCR...',    // Stripe's native ID (for reference)
    status: 'AUTHORIZED'
}
```

Use `paymentId` for all follow-up operations. Prism tracks the mapping to Stripe's `pi_` ID internally.

### Refund Flow IDs

```javascript
const refund = await client.payments.refund({
    paymentId: 'pay_abc123def456ghi',
    amount: { minorAmount: 500, currency: 'USD' }
});

// Returns:
{
    refundId: 'ref_def456ghi789mno',      // Prism unified ID
    connectorRefundId: 're_3Nabc...',     // Stripe's refund ID
    status: 'PENDING'
}
```

### Customer IDs

```javascript
const customer = await client.customers.create({
    email: 'john@example.com',
    name: 'John Doe'
});

// Returns:
{
    customerId: 'cus_xyz789uvw012jkl',    // Prism unified ID
    connectorCustomerId: 'cus_ABC123...',  // Stripe's customer ID
}

// Use unified ID for future operations
await client.payments.authorize({
    customerId: 'cus_xyz789uvw012jkl',    // Not 'cus_ABC123...'
    amount: { ... }
});
```

## Connector ID Mapping

Prism maintains a mapping table internally:

| Unified ID | Connector | Connector-Specific ID |
|------------|-----------|----------------------|
| `pay_abc123` | Stripe | `pi_3MqSCR2eZvKYlo2C1` |
| `pay_abc123` | Adyen | `7914073381344578` |
| `cus_xyz789` | Stripe | `cus_ABC123def456` |
| `cus_xyz789` | Adyen | `1234567890123456` |

You never deal with connector-specific IDs directly. The unified ID works across all connectors.

## Benefits

| Without Unified IDs | With Unified IDs |
|--------------------|------------------|
| Regex validation per connector | Single format validation |
| Type confusion bugs | Compile-time type safety |
| LLM hallucination | Predictable ID patterns |
| Connector-specific code paths | One code path for all connectors |
| Difficult debugging | Clear ID semantics |

## ID Constraints

| ID Type | Max Length | Min Length | Prefix |
|---------|-----------|-----------|--------|
| PaymentId | 64 | 17 | `pay_` |
| CustomerId | 64 | 17 | `cus_` |
| RefundId | 64 | 17 | `ref_` |
| MandateId | 64 | 17 | `man_` |
| GlobalId | 64 | 32 | `{cell}_{entity}_` |

These constraints prevent buffer overflows and ensure IDs fit in database indexes.

## Best Practices

1. **Always use unified IDs** in your application code
2. **Store connector-specific IDs** only for reconciliation with processor dashboards
3. **Validate ID format** at API boundaries (prefix + length checks)
4. **Use type-safe wrappers** in strongly-typed languages
5. **Never construct IDs manually**—always get them from Prism responses

Your ID handling becomes simple, safe, and portable across all 50+ connectors.
