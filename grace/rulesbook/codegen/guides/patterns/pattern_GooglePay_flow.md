# Google Pay Authorize Flow Pattern

**Payment Method**: `WalletData::GooglePay(GooglePayWalletData)`
**Flow**: Authorize

---

## Overview

Google Pay integrations come in two fundamentally different modes. **You must read the tech spec to determine which mode(s) the connector supports** before writing any code.

| Mode | Enum Variant | What the connector receives |
|------|-------------|-----------------------------|
| **PAYMENT_GATEWAY** | `GpayTokenizationData::Encrypted(GpayEncryptedTokenizationData)` | An encrypted token blob — the connector decrypts it server-side |
| **DIRECT** | `GpayTokenizationData::Decrypted(GooglePayDecryptedData)` | Pre-decrypted card fields: PAN, expiry, cryptogram, ECI |

> **Rule**: If the tech spec shows the connector passing the token to Google Pay's server for decryption, it is **PAYMENT_GATEWAY**. If the connector expects plain card fields from a decrypted Google Pay token, it is **DIRECT**.

Always handle the opposite variant with `IntegrationError::NotImplemented` — never silently ignore it.

---

## Type Reference

```rust
// From crates/types-traits/domain_types/src/payment_method_data.rs

pub struct GooglePayWalletData {
    pub pm_type: String,
    pub description: String,
    pub info: GooglePayPaymentMethodInfo,
    pub tokenization_data: GpayTokenizationData,
}

pub enum GpayTokenizationData {
    Decrypted(GooglePayDecryptedData),   // DIRECT mode
    Encrypted(GpayEncryptedTokenizationData),  // PAYMENT_GATEWAY mode
}

// PAYMENT_GATEWAY — pass this token as-is to the connector
pub struct GpayEncryptedTokenizationData {
    pub token_type: String,  // e.g. "PAYMENT_GATEWAY"
    pub token: String,       // JSON string — the full Google Pay token blob
}

// DIRECT — Hyperswitch pre-decrypted the token; use these card fields
pub struct GooglePayDecryptedData {
    pub card_exp_month: Secret<String>,
    pub card_exp_year: Secret<String>,
    pub application_primary_account_number: cards::CardNumber,
    pub cryptogram: Option<Secret<String>>,
    pub eci_indicator: Option<String>,
}
```

### Helper methods on `GooglePayDecryptedData`

```rust
// 4-digit year (YYYY) — normalizes both 2-digit and 4-digit input
decrypted.get_four_digit_expiry_year()?   // -> Secret<String>

// 2-digit year (YY)
decrypted.get_two_digit_expiry_year()?    // -> Secret<String>

// MMYY combined format
decrypted.get_expiry_date_as_mmyy()?      // -> Secret<String>

// Month as 0-padded string
decrypted.get_expiry_month()?             // -> Secret<String>
```

### Helper method on `GpayTokenizationData`

```rust
// Extracts the encrypted token string (PAYMENT_GATEWAY only)
gpay_data.tokenization_data.get_encrypted_google_pay_token()?  // -> String
```

---

## Pattern A — PAYMENT_GATEWAY

Use when: connector docs show a field like `googlePayToken`, `encryptedGooglePay`, `fluidData`, `google_pay_token`, or describe passing the token to Google's servers for decryption.

### Request transformer

```rust
WalletData::GooglePay(ref gpay_data) => {
    match &gpay_data.tokenization_data {
        GpayTokenizationData::Encrypted(encrypted_data) => {
            let token = encrypted_data.token.clone();
            // Build connector-specific request with token
            // Field name varies by connector — see examples below
            Ok(ConnectorRequest {
                // ... other fields ...
                payment_method: ConnectorGpayMethod::GooglePay {
                    // e.g. Mollie: google_pay_payment_token: token
                    // e.g. Celero/NMI: payment_token: Secret::new(token)
                    // e.g. Barclaycard/Adyen: google_pay_token: token
                    // e.g. BofA/CyberSource: fluid_data_value: base64::encode(token)
                },
            })
        }
        GpayTokenizationData::Decrypted(_) => {
            Err(IntegrationError::NotImplemented(
                "Google Pay DIRECT (decrypted) mode is not supported by this connector"
                    .to_string(),
                Default::default(),
            ))?
        }
    }
}
```

### Connector-specific field mapping (PAYMENT_GATEWAY)

| Connector | Token field name | Notes |
|-----------|-----------------|-------|
| **Mollie** | `googlePayPaymentToken` (plain string) | `method: "creditcard"` |
| **Datatrans** | Nested in `PAY: { type: "GOOGLEPAY", token: ... }` | POST `/v1/transactions/authorize` |
| **Fiserv EMEA** | `walletPaymentMethod.encryptedGooglePay.data` | Includes `encryptedMessage`, `ephemeralPublicKey`, `tag`, `signature`, `version` — parse from token JSON |
| **Barclaycard (via Adyen)** | `paymentMethod.googlePayToken` | `paymentMethod.type: "paywithgoogle"` |
| **Bank of America (via CyberSource)** | `paymentInformation.fluidData.value` | Base64-encoded token; `processingInformation.paymentSolution: "012"` |
| **Celero (via NMI)** | `payment_method.google_pay_token` | Plain token string |

---

## Pattern B — DIRECT

Use when: connector docs describe accepting PAN, expiry, cryptogram, and ECI indicator fields directly (card-like flow with cryptogram).

### Request transformer

```rust
WalletData::GooglePay(ref gpay_data) => {
    match &gpay_data.tokenization_data {
        GpayTokenizationData::Decrypted(ref decrypted_data) => {
            let card_number = decrypted_data.application_primary_account_number.clone();
            // Choose year format based on what the connector expects:
            let exp_year = decrypted_data.get_four_digit_expiry_year()
                .change_context(IntegrationError::RequestEncodingFailed {
                    context: Default::default(),
                })?;
            // OR: let exp_year = decrypted_data.get_two_digit_expiry_year()...?;
            // OR: let exp_mmyy = decrypted_data.get_expiry_date_as_mmyy()...?;
            let exp_month = decrypted_data.get_expiry_month()
                .change_context(IntegrationError::RequestEncodingFailed {
                    context: Default::default(),
                })?;
            let cryptogram = decrypted_data.cryptogram.clone();
            let eci = decrypted_data.eci_indicator.clone();

            Ok(ConnectorRequest {
                // Build card-like request using the decrypted fields
                // Field names vary — see examples below
                payment_method: ConnectorDirectGpayMethod {
                    // e.g. TSYS: digital_wallet.token, token_format, cryptogram, eci, provider
                    // e.g. Authipay: decryptedGooglePay.accountNumber, expiration (MMYYYY), cryptogram, eciIndicator
                    // e.g. Redsys DIRECT: DS_XPAYDECODEDDATA JSON with cryptogram, eciInd, token, paymentMethod
                },
            })
        }
        GpayTokenizationData::Encrypted(_) => {
            Err(IntegrationError::NotImplemented(
                "Google Pay PAYMENT_GATEWAY (encrypted) mode is not supported by this connector"
                    .to_string(),
                Default::default(),
            ))?
        }
    }
}
```

### Connector-specific field mapping (DIRECT)

| Connector | PAN field | Expiry format | Cryptogram field | ECI field | Notes |
|-----------|-----------|---------------|-----------------|-----------|-------|
| **TSYS (Global Payments)** | `payment_method.digital_wallet.token` | MM/YYYY | `cryptogram` | `eci` | `token_format: "CARD_NUMBER"`, `provider: "PAY_BY_GOOGLE"` |
| **Authipay (First Data)** | `decryptedGooglePay.accountNumber` | `expiration: MMYYYY` | `cryptogram` | `eciIndicator` | — |
| **Redsys DIRECT** | `DS_XPAYDECODEDDATA.token` | included in token | `DS_XPAYDECODEDDATA.cryptogram` | `DS_XPAYDECODEDDATA.eciInd` | `DS_XPAYDECODEDDATA` is a JSON blob, Base64-encoded |

---

## Pattern C — BOTH (PAYMENT_GATEWAY + DIRECT)

Use when: the tech spec explicitly describes both integration methods, or the connector supports both encrypted and decrypted Google Pay tokens.

```rust
WalletData::GooglePay(ref gpay_data) => {
    match &gpay_data.tokenization_data {
        GpayTokenizationData::Encrypted(ref encrypted_data) => {
            // PAYMENT_GATEWAY path — see Pattern A
            let token = encrypted_data.token.clone();
            Ok(ConnectorRequest {
                payment_method: ConnectorMethod::EncryptedGooglePay {
                    token: Secret::new(token),
                },
            })
        }
        GpayTokenizationData::Decrypted(ref decrypted_data) => {
            // DIRECT path — see Pattern B
            let card_number = decrypted_data.application_primary_account_number.clone();
            let exp_year = decrypted_data.get_four_digit_expiry_year()
                .change_context(IntegrationError::RequestEncodingFailed {
                    context: Default::default(),
                })?;
            let exp_month = decrypted_data.get_expiry_month()
                .change_context(IntegrationError::RequestEncodingFailed {
                    context: Default::default(),
                })?;
            Ok(ConnectorRequest {
                payment_method: ConnectorMethod::DecryptedGooglePay {
                    card_number,
                    exp_year,
                    exp_month,
                    cryptogram: decrypted_data.cryptogram.clone(),
                    eci: decrypted_data.eci_indicator.clone(),
                },
            })
        }
    }
}
```

### Connectors supporting BOTH

| Connector | PG field | DIRECT field | Notes |
|-----------|----------|-------------|-------|
| **Barclaycard (via Adyen)** | `paymentMethod.googlePayToken` | PAN + cryptogram + ECI | DIRECT requires PCI DSS; PG is the default |
| **Redsys** | `DS_XPAYDATA` (Base64 blob) | `DS_XPAYDECODEDDATA` (JSON) | Choose based on merchant configuration |
| **Authipay (First Data)** | `encryptedGooglePay.data.*` | `decryptedGooglePay.*` | Both documented in GBSEcom SDK |

---

## Full Implementation Example (NMI — BOTH)

This is a real connector example from the codebase for reference:

```rust
// From crates/integrations/connector-integration/src/connectors/nmi/transformers.rs
PaymentMethodData::Wallet(WalletData::GooglePay(google_pay_data)) => {
    match &google_pay_data.tokenization_data {
        GpayTokenizationData::Decrypted(decrypted_data) => {
            let ccexp = decrypted_data.get_expiry_date_as_mmyy().change_context(
                IntegrationError::RequestEncodingFailed {
                    context: Default::default(),
                },
            )?;
            (
                NmiPaymentMethod::GooglePayDecrypt(Box::new(
                    GooglePayDecryptedData {
                        decrypted_googlepay_data: DecryptedDataIndicator::Decrypted,
                        ccnumber: Secret::new(
                            decrypted_data
                                .application_primary_account_number
                                .get_card_no(),
                        ),
                        ccexp,
                        cavv: decrypted_data.cryptogram.clone(),
                        eci: decrypted_data.eci_indicator.clone(),
                    },
                )),
                TransactionType::Sale,
            )
        }
        GpayTokenizationData::Encrypted(encrypted_data) => (
            NmiPaymentMethod::GooglePay(Box::new(GooglePayData {
                payment_token: Secret::new(encrypted_data.token.clone()),
            })),
            if router_data.request.is_auto_capture() {
                TransactionType::Sale
            } else {
                TransactionType::Auth
            },
        ),
    }
}
```

---

## grpcurl Test Payloads

Use these as fallback templates when no `field_probe` file exists for the connector.

### PAYMENT_GATEWAY (Encrypted)

```bash
grpcurl -plaintext \
  -H 'x-connector: {connector}' \
  -H 'x-api-key: <from_creds>' \
  -d '{
    "request_ref_id": {"id": "test_{connector}_gpay_pg_001"},
    "amount": 100,
    "minor_amount": 10000,
    "currency": "USD",
    "webhook_url": "https://example.com/webhook",
    "payment_method": {
      "wallet": {
        "google_pay": {
          "pm_type": "CARD",
          "description": "Visa •••• 4242",
          "info": {
            "card_network": "VISA",
            "card_details": "4242"
          },
          "tokenization_data": {
            "encrypted": {
              "token_type": "PAYMENT_GATEWAY",
              "token": "{\"signature\":\"MEYCIQCtest\",\"intermediateSigningKey\":{\"signedKey\":\"{\\\"keyValue\\\":\\\"testkey\\\"}\",\"signatures\":[\"testsig\"]},\"protocolVersion\":\"ECv2\",\"signedMessage\":\"{\\\"encryptedMessage\\\":\\\"testmsg\\\",\\\"ephemeralPublicKey\\\":\\\"testkey\\\",\\\"tag\\\":\\\"testtag\\\"}\"}"
            }
          }
        }
      }
    },
    "email": {"value": "test@example.com"},
    "address": {
      "billing_address": {
        "first_name": {"value": "John"},
        "last_name": {"value": "Doe"},
        "line1": {"value": "123 Test St"},
        "city": {"value": "Test City"},
        "state": {"value": "CA"},
        "zip_code": {"value": "12345"},
        "country_alpha2_code": "US"
      }
    },
    "capture_method": "AUTOMATIC",
    "auth_type": "NO_THREE_DS",
    "enrolled_for_3ds": false,
    "return_url": "https://example.com/return"
  }' \
  localhost:8000 \
  types.PaymentService/Authorize
```

### DIRECT (Decrypted)

```bash
grpcurl -plaintext \
  -H 'x-connector: {connector}' \
  -H 'x-api-key: <from_creds>' \
  -d '{
    "request_ref_id": {"id": "test_{connector}_gpay_direct_001"},
    "amount": 100,
    "minor_amount": 10000,
    "currency": "USD",
    "webhook_url": "https://example.com/webhook",
    "payment_method": {
      "wallet": {
        "google_pay": {
          "pm_type": "CARD",
          "description": "Visa •••• 4111",
          "info": {
            "card_network": "VISA",
            "card_details": "4111"
          },
          "tokenization_data": {
            "decrypted": {
              "card_exp_month": {"value": "12"},
              "card_exp_year": {"value": "2026"},
              "application_primary_account_number": {"value": "4111111111111111"},
              "cryptogram": {"value": "AgAAAAAB/AAAAAAAAAA="},
              "eci_indicator": "07"
            }
          }
        }
      }
    },
    "email": {"value": "test@example.com"},
    "address": {
      "billing_address": {
        "first_name": {"value": "John"},
        "last_name": {"value": "Doe"},
        "line1": {"value": "123 Test St"},
        "city": {"value": "Test City"},
        "state": {"value": "CA"},
        "zip_code": {"value": "12345"},
        "country_alpha2_code": "US"
      }
    },
    "capture_method": "AUTOMATIC",
    "auth_type": "NO_THREE_DS",
    "enrolled_for_3ds": false,
    "return_url": "https://example.com/return"
  }' \
  localhost:8000 \
  types.PaymentService/Authorize
```

> **Note**: If `field_probe` data exists for this connector, always use that proto_request instead of the templates above — it is the authoritative source.

---

## Decision Flowchart

```
Read tech spec for Google Pay integration method
          |
          v
  Does it show encrypted token → connector server decrypts?
          |
     YES  |  NO
          |
    PAYMENT_GATEWAY    Does it show PAN + expiry + cryptogram?
                                   |
                              YES  |  NO
                                   |
                               DIRECT    Does it show both?
                                              |
                                         YES  |  NO
                                              |
                                           BOTH    → Error: unclear spec, check docs
```

---

## Common Mistakes

1. **Do NOT call `get_encrypted_google_pay_token()` on a `GpayTokenizationData::Decrypted` variant** — it will return an error. Match the enum first.

2. **Do NOT assume the year format** — connectors differ. Check tech spec and use the appropriate helper: `get_four_digit_expiry_year()`, `get_two_digit_expiry_year()`, or `get_expiry_date_as_mmyy()`.

3. **Do NOT leave the `NotImplemented` arm empty** — always return an explicit error with a descriptive message for the unsupported variant.

4. **Do NOT parse the encrypted token as JSON yourself** — for PAYMENT_GATEWAY, pass `encrypted_data.token` as a raw string to the connector. The connector or Google's servers handle decryption.

5. **Do NOT confuse `application_primary_account_number` with a plain string** — it is of type `cards::CardNumber`. Use `.get_card_no()` to extract the raw number string, or pass it directly if the field type is `cards::CardNumber`.

---

## Cross-References

- `payment_method_data.rs` — `GpayTokenizationData`, `GooglePayDecryptedData`, `GpayEncryptedTokenizationData`
- `crates/integrations/connector-integration/src/connectors/nmi/transformers.rs` — real BOTH implementation
- `crates/integrations/connector-integration/src/connectors/cybersource/transformers.rs` — real DIRECT implementation
- `grace/rulesbook/codegen/guides/patterns/authorize/wallet/pattern_authorize_wallet.md` — general wallet patterns
