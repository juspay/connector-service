# Webhook Testing Suite (handle_event)

This suite tests webhook event handling via `EventService.HandleEvent`.

## Architecture

### Generic Scenarios (`scenario.json`)
Contains **connector-agnostic** test scenarios that work for all connectors:
- `payment_succeeded` - Tests successful payment webhooks
- `payment_failed` - Tests failed payment webhooks
- `refund_succeeded` - Tests refund webhooks
- `invalid_signature` - Tests signature verification failure

### Connector-Specific Payloads (`payloads/*.json`)
Each connector has its own payload file with actual webhook data:
- `payloads/stripe.json` - Stripe webhook payloads
- `payloads/adyen.json` - Adyen webhook payloads
- `payloads/authorizedotnet.json` - Authorize.Net payloads
- `payloads/paypal.json` - PayPal payloads

## How It Works

```
1. Test runner loads generic scenario (e.g., "payment_succeeded")
2. Test runner loads connector-specific payload (e.g., stripe.json)
3. Test runner generates signature dynamically using webhook_signatures module
4. Test runner constructs EventServiceHandleRequest with:
   - Connector-specific payload body
   - Dynamically generated signature
   - Webhook secret from credentials
5. Test runner sends to EventService.HandleEvent
6. Assert using generic expectations from scenario.json
```

## Adding a New Connector

### Step 1: Create Payload File

Create `payloads/new_connector.json`:

```json
{
  "connector": "new_connector",
  "webhook_config": {
    "signature_header": "X-Connector-Signature",
    "signature_algorithm": "hmac_sha256",
    "webhook_secret_key": "webhook_secret"
  },
  "scenarios": {
    "payment_succeeded": {
      "body": {
        "event": "payment.success",
        "data": { ... }
      },
      "merchant_event_id": "new_connector_payment_001"
    },
    "refund_succeeded": {
      "body": {
        "event": "refund.success",
        "data": { ... }
      },
      "merchant_event_id": "new_connector_refund_001"
    }
  }
}
```

### Step 2: Add Signature Generation

In `src/webhook_signatures.rs`, add:

```rust
pub fn generate_signature(connector: &str, payload: &[u8], secret: &str, timestamp: Option<i64>) -> Result<String, String> {
    match connector {
        // ... existing connectors ...
        "new_connector" => generate_new_connector_signature(payload, secret),
        _ => Err(format!("Unsupported connector: {}", connector)),
    }
}

fn generate_new_connector_signature(payload: &[u8], secret: &str) -> Result<String, String> {
    // Implement signature algorithm based on connector docs
    // Look at connector's IncomingWebhook::verify_webhook_source() for the algorithm
}
```

### Step 3: Add to Connector Specs

In `connector_specs/new_connector/specs.json`:

```json
{
  "connector": "new_connector",
  "supported_suites": [
    "authorize",
    "capture",
    "handle_event"  // Add this
  ]
}
```

### Step 4: Test

```bash
cargo run --bin test_ucs -- \
  --connector new_connector \
  --suite handle_event \
  --scenario payment_succeeded \
  --endpoint localhost:50051
```

## Getting Real Webhook Payloads

### Method 1: Connector Dashboard
Most connectors have webhook testing tools:
- **Stripe**: Dashboard → Developers → Webhooks → Test webhook
- **Adyen**: Customer Area → Developers → Webhooks → Test Notification
- **PayPal**: Developer Dashboard → Webhooks → Simulate Events

### Method 2: Webhook Inspection Services
1. Go to https://webhook.site
2. Copy your unique URL
3. Configure in connector dashboard as webhook endpoint
4. Trigger test payment
5. Copy the webhook payload

### Method 3: Connector Documentation
- **Stripe**: https://stripe.com/docs/webhooks/stripe-events
- **Adyen**: https://docs.adyen.com/development-resources/webhooks/
- **PayPal**: https://developer.paypal.com/api/rest/webhooks/event-names/

## Payload File Format

```json
{
  "connector": "connector_name",
  "webhook_config": {
    "signature_header": "Header-Name",           // Where signature goes (or null if in body)
    "signature_location": "header|body",          // Optional: defaults to "header"
    "signature_path": "path.to.signature",       // For body signatures (Adyen)
    "signature_algorithm": "algorithm_name",     // Used by test runner
    "signature_format": "format_string",         // Optional: how signature is formatted
    "signature_encoding": "hex|base64",          // How to encode signature bytes
    "webhook_secret_key": "secret_key_name",     // Key in credentials file
    "requires_external_verification": false      // PayPal needs external API call
  },
  "scenarios": {
    "scenario_name": {
      "body": { ... },                           // Webhook JSON payload
      "merchant_event_id": "unique_id",          // Event identifier
      "signature_override": "...",               // Optional: for invalid_signature tests
      "notes": "Human-readable description"      // Optional: documentation
    }
  }
}
```

## Signature Algorithms

| Connector | Algorithm | Format | Header |
|-----------|-----------|--------|--------|
| Stripe | HMAC-SHA256 | `t={timestamp},v1={hex}` | `Stripe-Signature` |
| Authorize.Net | HMAC-SHA512 | `sha512={hex_lowercase}` | `X-ANET-Signature` |
| PayPal | HMAC-SHA256 | base64 | `PAYPAL-TRANSMISSION-SIG` |
| Adyen | HMAC-SHA256 | base64 (in body) | N/A (in `additionalData.hmacSignature`) |

## Troubleshooting

### Signature Verification Fails
1. Check webhook secret in `creds.json` matches what connector expects
2. Verify payload hasn't been modified (whitespace, encoding, etc.)
3. Check signature algorithm in `webhook_signatures.rs` matches connector's verification
4. Enable debug logging: `RUST_LOG=webhook=debug`

### Payload Decoding Fails
1. Ensure JSON structure matches connector's webhook format
2. Check all required fields are present
3. Validate against connector's webhook schema documentation

### Event Type Mismatch
1. Check connector's `IncomingWebhook::get_event_type()` implementation
2. Verify event type mapping in `scenario.json` assertions
3. Some connectors may return different event types than expected

## Testing Checklist

When adding a new connector's webhooks:

- [ ] Create `payloads/{connector}.json` with all scenario payloads
- [ ] Implement signature generation in `webhook_signatures.rs`
- [ ] Add `handle_event` to `connector_specs/{connector}/specs.json`
- [ ] Test `payment_succeeded` scenario
- [ ] Test `refund_succeeded` scenario (if supported)
- [ ] Test `invalid_signature` scenario
- [ ] Verify signature generation matches connector's verification
- [ ] Document any connector-specific quirks in payload file notes
- [ ] Run `cargo run --bin check_connector_specs` to verify

## Future Improvements

### Dynamic Signature Generation (TODO)
Currently signatures need to be pre-computed. Future enhancement:
- Test runner should generate signatures at runtime
- Use `webhook_signatures::generate_signature()` automatically
- Replace `signature_override` with dynamic generation

### Signature Validation (TODO)
Add test that verifies generated signatures match expected:
```rust
let generated = webhook_signatures::generate_signature(connector, payload, secret)?;
assert_eq!(generated, expected_signature);
```

### Helper Script (TODO)
Create `scripts/generate_webhook_payload.sh`:
```bash
./generate_webhook_payload.sh stripe payment_succeeded
# Outputs formatted JSON ready for payloads/stripe.json
```
