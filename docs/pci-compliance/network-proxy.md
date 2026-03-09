# Network Proxy (VGS, Evervault)

> Zero-code vault integration at the network layer. Simply route requests through the proxy—tokens are automatically detokenized in transit.

---

## Overview

**Network Proxy** is the simplest vault integration approach. You change the destination URL from your Payment Service Provider (PSP) to the vault's proxy URL. The vault transparently intercepts requests, detokenizes tokens, and forwards real card data to the PSP.

| Aspect | Description |
|--------|-------------|
| **Integration Level** | Network/Transport layer |
| **Code Changes** | **None**—just change the URL |
| **Token Handling** | Automatic—happens transparently |
| **Request Flow** | Your App → VGS Proxy → PSP |

---

## How It Works

```mermaid
sequenceDiagram
    autonumber
    participant FE as Merchant Frontend
    participant VSDK as VGS Collect.js
    participant VGS as VGS Vault
    participant BE as Merchant Backend
    participant UCS as Connector Service
    participant PSP as Payment Provider

    Note over FE,VGS: Step 1: Card Tokenization
    FE->>VSDK: Render secure card fields
    VSDK->>VGS: Tokenize card data
    VGS-->>VSDK: tok_sandbox_4242...
    VSDK-->>FE: Return token to frontend

    Note over BE,PSP: Step 2: Payment via Network Proxy
    FE->>BE: Send token + payment request
    BE->>UCS: authorize(token, amount)
    UCS->>VGS: POST tenant.vgs.example.com/v1/payment_intents
    Note right of UCS: Same payload structure,<br/>just different URL
    VGS->>VGS: Auto-detokenize in transit
    VGS->>PSP: POST api.stripe.com/v1/payment_intents<br/>(with real card data)
    PSP-->>VGS: Authorization response
    VGS-->>UCS: Return response
    UCS-->>BE: Unified response
    BE-->>FE: Payment result
```

---

## Example Providers

### VGS (Very Good Security)

| Attribute | Value |
|-----------|-------|
| **Documentation** | [VGS Docs](https://www.verygoodsecurity.com/docs) |
| **Proxy Type** | Outbound (forward) proxy |
| **Token Format** | `tok_sandbox_xxxx` (Luhn-valid) |
| **Configuration** | Dashboard route mapping |

#### Token Format

VGS tokens look like real card numbers for maximum compatibility:

```
Real Card:     4242424242424242
VGS Token:     tok_sandbox_4242xxxxxxxx4242
               └─ looks like a card, but is a token
```

### Evervault

| Attribute | Value |
|-----------|-------|
| **Documentation** | [Evervault Docs](https://docs.evervault.com) |
| **Proxy Type** | HTTP CONNECT Relay Proxy |
| **Token Format** | `ev:encrypted:<base64>` (Encrypted strings) |
| **Configuration** | Team ID + App ID based routing |

#### Token Format

Evervault uses encrypted tokens that are fully encrypted at rest and in transit:

```
Real Card:     4242424242424242
Evervault:     ev:encrypted:AQECAHh7X2y...base64...
               └─ Fully encrypted payload
```

Evervault's approach differs from other vaults—instead of tokenizing, they use **client-side encryption**. The encrypted payload can only be decrypted inside Evervault's secure enclaves. When routed through the Evervault Relay, the data is automatically decrypted before reaching the destination.

---

## UCS Integration Flow

When integrating with UCS, the merchant never calls the PSP (or vault proxy) directly. Instead:

1. **Merchant Backend** → Calls UCS with tokens
2. **UCS** → Routes to the Network Proxy (instead of direct to PSP)
3. **Network Proxy** → Detokenizes and forwards to PSP

```mermaid
sequenceDiagram
    autonumber
    participant FE as Merchant Frontend
    participant BE as Merchant Backend
    participant UCS as Connector Service
    participant VGS as VGS Proxy
    participant PSP as Payment Provider

    Note over FE,PSP: Network Proxy Flow via UCS

    FE->>BE: Send vault_token + payment data
    Note right of FE: Token from VGS Collect.js

    BE->>UCS: POST /payments<br/>{ token, amount, currency, connector }
    Note right of BE: Merchant calls UCS,<br/>not Stripe directly

    UCS->>UCS: Lookup connector config<br/>base_url = VGS proxy URL

    UCS->>VGS: POST tnt.vgs.com/v1/payment_intents<br/>(with token in payload)
    Note right of UCS: UCS routes to VGS proxy<br/>instead of api.stripe.com

    VGS->>VGS: Auto-detokenize token<br/>in transit

    VGS->>PSP: POST api.stripe.com/v1/payment_intents<br/>(with real card data)
    PSP-->>VGS: PaymentIntent response

    VGS-->>UCS: Response (tokenized if configured)
    UCS-->>UCS: Transform to unified format
    UCS-->>BE: Unified payment response
    BE-->>FE: Payment result
```

---

## Code Examples

<details>
<summary><b>1. Direct Stripe Payment (Without Vault - DON'T DO THIS)</b></summary>

```bash
# DON'T: Direct API call to Stripe with raw card data
# This puts you in full PCI scope!

curl "https://api.stripe.com/v1/payment_intents" \
  -H "Authorization: Bearer sk_test_xxx" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -X "POST" \
  -d "amount=1000" \
  -d "currency=usd" \
  -d "payment_method_data[type]=card" \
  -d "payment_method_data[card][number]=4242424242424242" \
  -d "payment_method_data[card][exp_month]=12" \
  -d "payment_method_data[card][exp_year]=2025" \
  -d "confirm=true"
```

**Problem:** Your server handles raw card data → Full PCI scope (SAQ D) ❌
</details>

<details>
<summary><b>2. Tokenize with VGS (Frontend SDK)</b></summary>

```javascript
// VGS Collect.js - runs in browser, not on your server
const form = VGSCollect.create("tntSANDBOX123", "sandbox", function(state) {});

// Create secure fields (iframes)
form.field("#card-number", {
  type: "card-number",
  name: "card.number",
  placeholder: "4242 4242 4242 4242"
});

form.field("#card-cvc", {
  type: "card-security-code",
  name: "card.cvc",
  placeholder: "123"
});

// Submit to VGS (not to your server!)
form.submit("/post", {}, function(status, response) {
  // Response contains tokens, NOT card data
  console.log(response.data);
  // {
  //   "card.number": "tok_sandbox_4242xxxxxxxx4242",
  //   "card.cvc": "tok_sandbox_cvc123"
  // }

  // Send token to YOUR backend (safe - it's just a token)
  fetch('/api/payment', {
    method: 'POST',
    body: JSON.stringify({
      token: response.data['card.number'],
      amount: 1000,
      currency: 'usd'
    })
  });
});
```

**Key Point:** Card data never touches your frontend code or backend—only tokens do.
</details>

<details>
<summary><b>3. Payment via UCS + Network Proxy (RECOMMENDED)</b></summary>

```bash
# Merchant Backend calls UCS (not Stripe directly!)
# UCS handles routing to VGS proxy

curl "https://api.connector-service.juspay.net/payments" \
  -H "Authorization: Bearer ${UCS_API_KEY}" \
  -H "Content-Type: application/json" \
  -X "POST" \
  -d '{
    "amount": 1000,
    "currency": "USD",
    "connector": "stripe",
    "payment_method": {
      "type": "card",
      "card": {
        "token": "tok_sandbox_4242xxxxxxxx4242"
      }
    }
  }'
```

**What happens behind the scenes:**
1. UCS receives your request with the VGS token
2. UCS looks up connector config: `base_url = https://tntSANDBOX123.sandbox.verygoodproxy.com`
3. UCS sends request to VGS proxy URL (not Stripe directly)
4. VGS detokenizes `tok_sandbox_4242...` → `4242424242424242`
5. VGS forwards to Stripe with real card data
6. Response flows back: Stripe → VGS → UCS → Your Backend

**Result:** You only handle tokens. UCS + VGS handle PCI compliance.
</details>

<details>
<summary><b>4. Direct VGS Call (Without UCS)</b></summary>

```bash
# If you called VGS directly (without UCS), it would look like this:
# This is what UCS does internally for you

# For HTTP Proxy outbound, you need the VGS CA certificate
# Download from: https://www.verygoodsecurity.com/docs/ca-certificates

curl "https://tntSANDBOX123.sandbox.verygoodproxy.com" \
  --cacert vgs-sandbox-ca.pem \
  -H "VGS-Requested-URL: https://api.stripe.com/v1/payment_intents" \
  -H "Authorization: Bearer sk_test_xxx" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -X "POST" \
  -d "amount=1000" \
  -d "currency=usd" \
  -d "payment_method_data[type]=card" \
  -d "payment_method_data[card][number]=tok_sandbox_4242xxxxxxxx4242" \
  -d "confirm=true"

# VGS HTTP Proxy automatically:
# 1. Receives the request (verified with CA cert)
# 2. Reads VGS-Requested-URL header for destination
# 3. Detokenizes tok_sandbox_4242... → 4242424242424242
# 4. Forwards to Stripe with real card data
# 5. Returns Stripe's response
```

**Note:** When using UCS, you don't make this call directly—UCS handles the proxy routing and CA certificate for you!
</details>

<details>
<summary><b>5. Tokenize with Evervault (Frontend SDK)</b></summary>

```javascript
// Evervault.js - runs in browser, not on your server
import Evervault from '@evervault/browser';

// Initialize with your team ID and app ID
const evervault = new Evervault('team_123', 'app_456');

// Encrypt card data (client-side encryption)
const encryptedCard = await evervault.encrypt({
  number: '4242424242424242',
  exp_month: '12',
  exp_year: '2025',
  cvc: '123'
});

// encryptedCard contains an ev:encrypted:... string
// Send to YOUR backend (safe - it's encrypted)
fetch('/api/payment', {
  method: 'POST',
  body: JSON.stringify({
    token: encryptedCard,
    amount: 1000,
    currency: 'usd'
  })
});
```

**Key Point:** Evervault uses client-side encryption rather than traditional tokenization. The encrypted data can only be decrypted inside Evervault's secure enclaves.
</details>

<details>
<summary><b>6. Direct Evervault Call (Without UCS)</b></summary>

```bash
# If you called Evervault Relay directly (without UCS), it would look like this:
# This is what UCS does internally for you

# Evervault Relay acts as an HTTP CONNECT proxy
# You route through relay.evervault.com:443 with your credentials

export http_proxy="https://team_123:api_key@relay.evervault.com:443"
export https_proxy="https://team_123:api_key@relay.evervault.com:443"

curl "https://api.stripe.com/v1/payment_intents" \
  -H "Authorization: Bearer sk_test_xxx" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -X "POST" \
  -d "amount=1000" \
  -d "currency=usd" \
  -d "payment_method_data[type]=card" \
  -d "payment_method_data[card][number]=ev:encrypted:AQECAHh7X2y..." \
  -d "confirm=true"

# Evervault Relay automatically:
# 1. Intercepts the request
# 2. Decrypts ev:encrypted:... inside secure enclave
# 3. Forwards to Stripe with real card data
# 4. Returns Stripe's response
```

**Note:** When using UCS, you don't configure proxy settings—UCS handles the Evervault Relay routing for you!
</details>

---

## Configuration

### VGS Route Configuration

```yaml
# VGS Dashboard: Route Configuration
routes:
  - name: stripe-outbound
    # When request goes TO this host...
    destination_override: "api.stripe.com"
    # ...route through VGS proxy
    host: "tntSANDBOX123.sandbox.verygoodproxy.com"
    protocol: "https"

    filters:
      # Detokenize outbound requests
      - type: "DETOKENIZE"
        fields:
          - "payment_method_data[card][number]"
          - "payment_method_data[card][cvc]"

      # Tokenize inbound responses (optional)
      - type: "TOKENIZE"
        fields:
          - "payment_method.id"
```

### UCS Configuration

The key to Network Proxy integration is pointing the connector's `base_url` to the **vault proxy endpoint** instead of the PSP's direct URL:

```yaml
# UCS config.yaml

# The vault section identifies which proxy mode to use
vault:
  provider: vgs
  mode: network_proxy
  tenant_id: tntSANDBOX123
  environment: sandbox

# The connector base_url points to VGS proxy, not Stripe directly
connectors:
  stripe:
    # ❌ Without VGS: base_url would be https://api.stripe.com
    # ✅ With VGS: base_url is the VGS proxy URL
    base_url: https://tntSANDBOX123.sandbox.verygoodproxy.com
    api_key: ${STRIPE_API_KEY}

  adyen:
    # Same VGS proxy can route to multiple PSPs
    base_url: https://tntSANDBOX123.sandbox.verygoodproxy.com
    api_key: ${ADYEN_API_KEY}
    merchant_account: ${ADYEN_MERCHANT_ACCOUNT}
```

**How it works:**
- Merchant calls UCS: `POST /payments` with VGS tokens
- UCS looks up connector config → finds VGS proxy URL as `base_url`
- UCS makes request to VGS proxy instead of Stripe directly
- VGS detokenizes in transit and forwards to Stripe
- Response flows back through the same chain

### Evervault Configuration

```yaml
# UCS config.yaml - Evervault Network Proxy

# The vault section for Evervault
vault:
  provider: evervault
  mode: network_proxy
  team_id: team_123
  app_id: app_456
  api_key: ${EVERVAULT_API_KEY}

# For Evervault, base_url remains the PSP's URL
# Evervault Relay intercepts traffic at the network layer
connectors:
  stripe:
    # base_url is still Stripe's direct URL
    base_url: https://api.stripe.com
    api_key: ${STRIPE_API_KEY}
```

**How it works:**
- Merchant calls UCS: `POST /payments` with Evervault-encrypted data
- UCS routes requests through Evervault's HTTP CONNECT Relay
- Evervault decrypts inside secure enclaves before reaching Stripe
- Response flows back through the same chain

---

## Provider Comparison

| Aspect | VGS | Evervault |
|--------|-----|-----------|
| **Token Format** | `tok_sandbox_xxxx` | `ev:encrypted:<base64>` |
| **Mechanism** | Tokenization | Client-side encryption |
| **Proxy Type** | Forward proxy | HTTP CONNECT Relay |
| **Config Required** | Tenant ID + Route setup | Team ID + App ID |
| **Encryption** | Vault-side | Client-side |

## Comparison: Before vs After

| Aspect | Without Vault | With Network Proxy |
|--------|---------------|--------------------|
| **URL** | `api.stripe.com` | Via proxy endpoint |
| **Payload** | Raw card numbers | Tokens/encrypted data |
| **Code Changes** | None (baseline) | **None** |
| **PCI Scope** | SAQ D (Full) | SAQ A or A-EP (Reduced) |
| **Card Data on Server** | Yes ❌ | No ✅ |

---

## When to Use Network Proxy

| Scenario | Recommendation |
|----------|----------------|
| Want **zero code changes** | ✅ Perfect fit |
| Already using VGS or Evervault | ✅ Perfect fit |
| Need quick integration | ✅ Ideal |
| Have infrastructure access | ✅ Required |
| Need custom transformations | ❌ Use Application Proxy |
| Multiple vault providers | ❌ Use Application Proxy |

### Choose VGS if:
- You want format-preserving tokens that look like real cards
- You need dashboard-based route configuration
- You want Luhn-valid tokens for maximum compatibility

### Choose Evervault if:
- You prefer client-side encryption over tokenization
- You want data encrypted from browser to PSP
- You need outbound proxy via HTTP CONNECT
- You want to avoid managing token lifecycles

---

## Limitations

| Limitation | Details | Mitigation |
|------------|---------|------------|
| **Vendor Lock-in** | Tightly coupled to VGS infrastructure | Abstract vault config in UCS |
| **Debug Visibility** | Black box transformation | Enable VGS request logging |
| **Regional Latency** | Extra network hop | Choose nearest VGS region |
| **No Custom Logic** | Can't modify request structure | Use Transform Proxy instead |

---

## Quick Reference

### VGS Flow
```
┌─────────────────┐     ┌──────────────┐     ┌─────────────┐
│  Your Backend   │────▶│  VGS Proxy   │────▶│    Stripe   │
│                 │     │              │     │             │
│ Sends: tokens   │     │ Detokenizes  │     │ Receives:   │
│                 │     │ in transit   │     │ real card   │
└─────────────────┘     └──────────────┘     └─────────────┘
```

### Evervault Flow
```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐
│  Your Backend   │────▶│  Evervault Relay │────▶│    Stripe   │
│                 │     │   (enclaves)     │     │             │
│ Sends: encrypted│     │   Decrypts       │     │ Receives:   │
│     data        │     │   in enclave     │     │ real card   │
└─────────────────┘     └──────────────────┘     └─────────────┘
```

**One-line Summary:** Route through the proxy. The vault handles decryption/detokenization automatically.

---

## Related Documentation

- [Overview](./README.md) - PCI Compliance overview
- [Application Proxy](./application-proxy.md) - Alternative: UCS handles vault-specific routing (Basis Theory, TokenEx, Hyperswitch Vault)

---

_Need help? Join our [Discord](https://discord.gg/hyperswitch) or open a [GitHub Discussion](https://github.com/juspay/connector-service/discussions)._
