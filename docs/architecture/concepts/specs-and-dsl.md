<!--
@doc-guidance
────────────────────────────────────────────────────
PAGE INTENT:  Explain the specification of the connector service in terms of the domain specific language that it uses to enable LLMs and developers to code with relevant type checkx, ensiuring that all minimal implementation are covered for each connector integration, catch error in compile time as much as possible to avoid errors on production. Explain each sub concept with example.

AUDIENCE: Payment developers and architects
TONE: Direct, conversational, opinionated. Write like explaining to a colleague over coffee.
PRIOR READING: [What pages should the reader have seen before this one? Link them.]
LEADS INTO: [What page comes next?]
────────────────────────────────────────────────────
LENGTH: 1.5–2 pages max (~600–800 words prose, tables and code blocks don't count toward this).
         If you need more space, the page is doing too much — split it.

WRITING RULES:
1. FIRST SENTENCE RULE — Open with what the reader gains, not what the thing is.
   Bad:  "The Prism SDK provides a unified interface..."
   Good: "You call one method. It works with Stripe, Adyen, or any of 50+ processors."

2. NO HEDGING — Delete: "can be", "may", "it is possible to", "in some cases", "typically".
   Say what IS. If something is conditional, state the condition.

3. VERB OVER NOUN — "lets you configure" not "provides configuration capabilities".
   "transforms the request" not "performs request transformation".

4. ONE IDEA PER SECTION — If a section has more than one takeaway, split it.

5. SHOW THEN TELL — Code example or diagram first, explanation after.
   The reader should see what it looks like before reading why.

6. EARN EVERY SENTENCE — If removing a sentence doesn't lose information, remove it.
   No "In this section, we will discuss..." No "As mentioned earlier..."
   No "It is important to note that..."

7. SPECIFICS OVER CLAIMS — Never say "supports many payment methods".
   Say "supports cards, wallets (Apple Pay, Google Pay), bank transfers, BNPL, and UPI".

8. ERRORS ARE FEATURES — When documenting a flow, show what goes wrong too.
   Include at least one error scenario with the actual error message.

9. NAME THE PRODUCT "Prism" — Not "UCS", not "the service", not "our platform".

10. TABLES FOR COMPARISON, PROSE FOR NARRATIVE — Don't put a story in a table.
    Don't write paragraphs when a 3-row table would be clearer.

CODE EXAMPLE RULES:
- Every code block must be runnable or clearly marked as pseudocode
- Use test credentials: Stripe key as $STRIPE_API_KEY, card 4242424242424242
- Show the output, not just the input
- If the example needs setup, show the setup

ANTI-PATTERNS TO REJECT:
- "Comprehensive", "robust", "seamless", "leverage", "utilize", "facilitate"
- Starting paragraphs with "Additionally", "Furthermore", "Moreover"
- Any sentence that describes the documentation itself ("This guide covers...")
- Repeating the heading as the first sentence of a section
────────────────────────────────────────────────────
-->

# Specs and DSL

Prism uses a domain-specific language (DSL) built on Protocol Buffers that catches integration errors at compile time. Instead of discovering you forgot a required field in production, you get a compiler error immediately.

## The Problem with Weak Typing

Traditional payment integrations use JSON over HTTP. This works until it doesn't:

```javascript
// Valid code, but will fail at runtime
const response = await fetch('/api/payments', {
    method: 'POST',
    body: JSON.stringify({
        amount: 1000,
        // Oops—forgot currency. Stripe rejects this.
        // Oops—forgot payment_method. Required field missing.
    })
});
// HTTP 400: Missing required param: currency
```

You only find out when you run the code. In production. With real customers.

## The Prism DSL

Prism defines payment operations as Protocol Buffer schemas. These generate type-safe bindings in every supported language.

**Proto definition:**
```protobuf
message AuthorizeRequest {
    Money amount = 1;                    // Required
    string merchant_order_id = 2;        // Required
    PaymentMethod payment_method = 3;    // Required
    CaptureMethod capture_method = 4;    // Required
    AuthenticationType authentication_type = 5;  // Optional, defaults to NO_THREE_DS
    string customer_id = 6;              // Optional
    string email = 7;                    // Optional
    string description = 8;              // Optional
    map<string, string> metadata = 9;    // Optional
    string return_url = 10;              // Optional, required for 3DS
}

message Money {
    int64 minor_amount = 1;    // Required
    string currency = 2;       // Required, ISO 4217 format
}
```

**Generated TypeScript:**
```typescript
interface AuthorizeRequest {
    amount: Money;                    // Required—TypeScript enforces this
    merchantOrderId: string;          // Required
    paymentMethod: PaymentMethod;     // Required
    captureMethod: CaptureMethod;     // Required
    authenticationType?: AuthenticationType;  // Optional
    customerId?: string;              // Optional
    email?: string;                   // Optional
    description?: string;             // Optional
    metadata?: Record<string, string>; // Optional
    returnUrl?: string;               // Optional
}

interface Money {
    minorAmount: number;    // Required
    currency: string;       // Required
}
```

Now missing required fields cause compile-time errors, not runtime failures.

## Compile-Time Guarantees

| Issue | Without DSL | With Prism DSL |
|-------|-------------|---------------------------|
| Missing required field | Runtime HTTP 400 | Compile-time error |
| Wrong field type | Runtime type error | Compile-time type mismatch |
| Invalid enum value | Runtime validation error | Auto-complete + type checking |
| Typos in field names | Silent failure (undefined) | Compile-time "property doesn't exist" |
| Breaking API changes | Runtime errors post-deploy | Compile-time errors during build |

## Type-Safe Enum Handling

Payment status is an enum, not a string:

```protobuf
enum PaymentStatus {
    STARTED = 0;
    AUTHORIZED = 1;
    CAPTURED = 2;
    FAILED = 3;
    VOIDED = 4;
    CHARGED = 5;
}
```

```typescript
// TypeScript knows valid values
if (response.status === PaymentStatus.AUTHORIZED) {
    // IDE auto-completed this
}

// This causes a compile-time error
if (response.status === 'authorzied') {  // Typo!
    // Error: Type '"authorzied"' is not assignable to type 'PaymentStatus'
}
```

## Oneof Types for Exclusive Fields

The DSL uses `oneof` to enforce mutually exclusive fields:

```protobuf
message PaymentMethod {
    oneof method {
        Card card = 1;
        Wallet wallet = 2;
        BankTransfer bank_transfer = 3;
        BNPLData bnpl = 4;
    }
}
```

```typescript
// Valid: exactly one payment method
const request: AuthorizeRequest = {
    paymentMethod: {
        card: { cardNumber: '4242424242424242', ... }
    }
};

// Compile error: can't specify multiple methods
const request: AuthorizeRequest = {
    paymentMethod: {
        card: { ... },
        wallet: { ... }  // Error: Only one field can be set
    }
};
```

## Required vs Optional Fields

The proto schema makes requirements explicit:

| Field | Required? | Validation |
|-------|-----------|------------|
| `amount` | Yes | Must be present, must have `minor_amount` and `currency` |
| `merchant_order_id` | Yes | Non-empty string |
| `payment_method` | Yes | One payment method must be specified |
| `capture_method` | Yes | Must be `MANUAL` or `AUTOMATIC` |
| `customer_id` | No | Can be omitted |
| `metadata` | No | Optional key-value map |

## DSL for Connector Development

Prism also uses a DSL internally for building connectors. The macro system enforces that adapters implement required methods:

```rust
// This macro generates compile-time checks
macros::macro_connector_implementation!(
    connector: Stripe,
    flow_name: Authorize,
    http_method: Post,
    // ... other parameters
);
```

If you forget to implement `build_error_response`, the macro invocation fails at compile time with a clear error message: "Connector Stripe is missing required method build_error_response for flow Authorize".

## Validation at the Schema Level

The proto schema includes validation constraints:

```protobuf
message Money {
    int64 minor_amount = 1 [(validate.rules).int64 = {gt: 0}];  // Must be positive
    string currency = 2 [(validate.rules).string = {len: 3}];   // Exactly 3 chars (ISO 4217)
}

message Card {
    string card_number = 1 [(validate.rules).string = {pattern: "^[0-9]{13,19}$"}];
    string expiry_month = 2 [(validate.rules).string = {pattern: "^(0[1-9]|1[0-2])$"}];
    string expiry_year = 3 [(validate.rules).string = {pattern: "^[0-9]{4}$"}];
}
```

These generate validation code that runs before any network request. Invalid card numbers are caught immediately, not after a round-trip to the payment processor.

## Benefits for LLMs

The DSL makes Prism code more LLM-friendly:

- **Explicit types**: LLMs see exactly what fields exist and their types
- **Clear requirements**: Required vs optional is unambiguous
- **Valid examples**: Generated types show valid usage patterns
- **No hallucination**: Type constraints prevent invalid field names

An LLM generating Prism code has a clear spec to follow—the proto definitions provide a complete, unambiguous API contract.

## Schema Evolution

When the DSL changes, the compiler tells you what broke:

```bash
# Proto field renamed: merchant_id -> merchant_order_id
$ make generate
$ cargo build

error[E0560]: struct `AuthorizeRequest` has no field named `merchant_id`
  --> src/main.rs:42:9
   |
42 |         merchant_id: "order-123",
   |         ^^^^^^^^^^^ unknown field
   |
   = note: available fields are: `amount`, `merchant_order_id`, ...
```

You fix it before deploying, not after customers complain.

## The DSL in Practice

The Prism DSL spans multiple layers:

1. **Proto definitions**: Service contracts and message types
2. **Generated types**: Language-specific bindings (TypeScript, Python, Java, etc.)
3. **Validation rules**: Schema-level constraints
4. **Connector macros**: Compile-time checks for adapter implementations

Together, these ensure that payment integrations work correctly the first time, without runtime surprises.
