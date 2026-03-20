<!--
@doc-guidance
────────────────────────────────────────────────────
PAGE INTENT: Explain how the connector integration code generation for connectors work with juspay/grace. Expand on the CLI adn skill which any developer can use by connecting thier own LLM model.
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

# Code Generation

You get a working connector adapter in hours instead of weeks. Prism uses Grace, a code generation tool that reads payment provider API specs and produces Rust connector integration code with proper request/response transformations.

## The Problem with Manual Integration

Writing a connector adapter requires understanding:
- The payment provider's authentication scheme
- How their API maps to unified types (amounts, currencies, payment methods)
- Error code mappings
- Webhook payload structures
- Testing patterns

For a typical connector like Stripe or Adyen, this is 2,000-5,000 lines of Rust code. Done manually, it takes weeks and introduces bugs. Grace automates the repetitive 80% so developers focus on the interesting 20%.

## Grace Architecture

Grace has two interfaces: a CLI tool and a skill/prompt system for LLMs.

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   API Spec      │────▶│  Grace Parser    │────▶│  Rust Adapter   │
│ (OpenAPI/JSON)  │     │  + Templates     │     │  Code           │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         │                       │                        │
         ▼                       ▼                        ▼
   Provider docs           LLM Skill              Connector-specific
   and examples           augmentation             business logic
```

## CLI Usage

Generate a connector scaffold from an OpenAPI spec:

```bash
# Generate from OpenAPI spec
grace generate \
  --spec ./adyen-openapi.json \
  --connector adyen \
  --output ./backend/connector-integration/src/connectors/adyen/

# Generate with custom LLM model
grace generate \
  --spec ./adyen-openapi.json \
  --connector adyen \
  --model gpt-4 \
  --api-key $OPENAI_API_KEY \
  --output ./backend/connector-integration/src/connectors/adyen/
```

The CLI produces:
- `connector.rs` — The adapter struct and trait implementation
- `transformers.rs` — Request/response mapping functions
- `types.rs` — Connector-specific type definitions
- `test.rs` — Generated test scaffolding

## LLM Skill Integration

Grace includes a skill definition that any LLM can use. Connect your own model:

```bash
# Start Grace with custom model endpoint
grace server \
  --model-endpoint https://api.anthropic.com/v1/messages \
  --model claude-3-opus-20240229 \
  --api-key $ANTHROPIC_API_KEY

# Use via the skill
grace skill generate-connector \
  --spec ./provider-api.json \
  --name "new-provider"
```

The skill prompt includes:
- Prism's unified type system
- Common transformation patterns
- Error mapping conventions
- Rust code templates

Your LLM generates code that follows Prism conventions without training on proprietary code.

## What Gets Generated

### Request Transformers

```rust
impl TryFrom<AuthorizeRequest> for AdyenPaymentRequest {
    type Error = ConnectorError;
    
    fn try_from(req: AuthorizeRequest) -> Result<Self, Self::Error> {
        Ok(AdyenPaymentRequest {
            amount: req.amount.minor_amount,
            currency: req.amount.currency.to_string(),
            payment_method: req.payment_method.try_into()?,
            reference: req.merchant_order_id,
            // ... additional fields
        })
    }
}
```

### Response Transformers

```rust
impl TryFrom<AdyenPaymentResponse> for AuthorizeResponse {
    type Error = ConnectorError;
    
    fn try_from(resp: AdyenPaymentResponse) -> Result<Self, Self::Error> {
        Ok(AuthorizeResponse {
            payment_id: resp.psp_reference.into(),
            status: resp.result_code.into(),
            amount: resp.amount.try_into()?,
            // ... additional fields
        })
    }
}
```

### Error Mapping

```rust
impl From<AdyenErrorCode> for UnifiedError {
    fn from(code: AdyenErrorCode) -> Self {
        match code {
            AdyenErrorCode::Refused => UnifiedError::PaymentDeclined,
            AdyenErrorCode::ExpiredCard => UnifiedError::ExpiredCard,
            AdyenErrorCode::InvalidCardNumber => UnifiedError::InvalidCard,
            // ... additional mappings
        }
    }
}
```

## Customization Points

Generated code includes `TODO` markers for connector-specific logic:

```rust
fn authenticate(&self, creds: &ConnectorCredentials) -> Result<AuthHeader, Error> {
    // TODO: Implement authentication for this connector
    // Most providers use API key in header, some use OAuth
    todo!("Implement authentication")
}
```

You fill in the blanks. The boilerplate structure is done.

## Validation

Grace validates generated code:
- Type checks against Prism interfaces
- Serialization roundtrips (unified → connector → unified)
- Required field coverage
- Error case handling

```bash
# Validate generated connector
grace validate \
  --connector ./backend/connector-integration/src/connectors/adyen/
```

## Adding a New Connector

```bash
# 1. Obtain API spec from provider
# 2. Generate scaffold
grace generate --spec ./spec.json --connector new-provider --output ./connectors/

# 3. Implement TODOs (authentication, special cases)
# 4. Validate
grace validate --connector ./connectors/new-provider/

# 5. Run tests
make test-connector CONNECTOR=new-provider
```

A basic connector adapter takes 1-2 days instead of 2-3 weeks.

## Benefits

- **Speed**: Days instead of weeks for new connectors
- **Consistency**: All adapters follow the same patterns
- **Correctness**: Generated code passes type checks and validation
- **Maintainability**: Update the spec, regenerate the code
- **Flexibility**: Bring your own LLM, no vendor lock-in

Connector integration becomes configuration, not implementation.
