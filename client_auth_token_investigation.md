# CreateClientAuthenticationToken — CardToken Authorize Support Investigation

## Context

PR #957 (Globalpay) introduced `CardToken` support in the Authorize flow, allowing tokenized card payments via hosted fields. The question is: does every connector that implements `CreateClientAuthenticationToken` also need a corresponding `CardToken` handler in its Authorize transformer?

**Answer: No.** The `CardToken` pattern only applies to connectors whose client-side SDK performs **card tokenization** (hosted fields / secure fields). Connectors that use hosted checkout, redirects, wallets, or API-level OAuth tokens do not need this change.

---

## PR #957 Changes Summary

| Commit | Description | Scope |
|--------|-------------|-------|
| `e91a77a` | Add `CardToken` match arm + `id` field to `GlobalpayPaymentMethod` | Globalpay-specific |
| `fe598f7` | Propagate `connector_token` as `payment_method_token` in `tokenized_authorize_to_base` | **Global** (all connectors) |
| `39ca1af` | TODO comment on `CardToken` struct rename | Documentation |
| `9e49966` | Whitespace formatting | Cosmetic |

**Commit 2 is already global** — all connectors automatically get `payment_method_token` populated in `tokenized_authorize_to_base`. No per-connector work needed for that.

**Commit 1 is the per-connector pattern** — each connector that supports hosted-fields tokenization needs a similar `PaymentMethodData::CardToken` match arm in its Authorize transformer.

---

## Group 1: Card Tokenization — CardToken Handler REQUIRED

These connectors return a session/context for **client-side hosted fields** that tokenize the card and return a token ID. The Authorize flow needs a `PaymentMethodData::CardToken` handler to consume that token.

| Connector | SDK Type | Token Returned | How Token Is Used in Authorize |
|-----------|----------|----------------|-------------------------------|
| **Globalpay** | GlobalPayments.js Hosted Fields | `access_token` → token ID | Token ID passed as `id` field in payment method (**already done in PR #957**) |
| **Cybersource** | Flex Microform v2 | `capture_context` JWT → transient token | Transient token passed in payment request instead of raw card data |
| **BankOfAmerica** | Flex Microform v2 | `capture_context` JWT → transient token | Same as Cybersource (shared API) |
| **Wellsfargo** | Flex Microform v2 | `capture_context` JWT → transient token | Same as Cybersource (shared API) |
| **Barclaycard** | Flex Microform v2 | `capture_context` JWT → transient token | Same as Cybersource (shared API) |
| **Bluesnap** | Hosted Payment Fields | `pf_token` (JWT) | pfToken passed in card transaction request |
| **Datatrans** | Secure Fields | `transactionId` | Transaction ID used to reference tokenized card in authorize call |
| **Bambora** | Tokenization API | `token` (e.g. `c55-...`) | Token replaces raw card number in payment request |
| **Bamboraapac** | SOAP TokeniseCreditCard | `token` | Token used in place of card data in SOAP payment request |

### Implementation Pattern (from PR #957 — Globalpay reference)

```rust
PaymentMethodData::CardToken(CardToken { .. }) => {
    let token = item
        .resource_common_data
        .payment_method_token
        .as_ref()
        .and_then(|t| match t {
            PaymentMethodToken::Token(s) => Some(s.clone()),
        })
        .ok_or_else(|| {
            error_stack::report!(IntegrationError::MissingRequiredField {
                field_name: "payment_method_token",
                context: Default::default(),
            })
        })?;

    // Build connector-specific payment method struct using `token`
    // instead of raw card data
}
```

Each connector needs to adapt this pattern to its own payment method struct.

---

## Group 2: Hosted Checkout / Redirect — CardToken Handler NOT Needed

These connectors return a **checkout URL or hosted session** where the entire payment happens externally. The customer is redirected to the connector's hosted page, completes payment there, and the result comes back via webhook or redirect callback. No token is passed back to the Authorize flow.

| Connector | What CreateClientAuthenticationToken Returns | Why CardToken Does Not Apply |
|-----------|----------------------------------------------|------------------------------|
| **Mollie** | `payment_id` + `checkout_url` | Redirect to Mollie's hosted checkout page |
| **Rapyd** | `checkout_id` + `redirect_url` | Redirect to Rapyd's hosted checkout page |
| **Noon** | `order_id` + `checkout_url` | Redirect to Noon's hosted checkout |
| **Elavon** | `txn_auth_token` | Hosted payment page (Converge) |
| **Mifinity** | iframe init data | Payment completed inside iframe |
| **Redsys** | `merchant_parameters` + `signature` | Signed form POST to Redsys hosted page |
| **Billwerk** | `session_id` (e.g. `cs_...`) | Redirect to Billwerk/Reepay checkout |
| **Nexinets** | `order_id` | Redirect to Nexinets hosted checkout |
| **Nexixpay** | `security_token` + `hosted_page` URL | Redirect to Nexixpay hosted payment page |
| **Ppro** | `charge_id` + redirect URL | Redirect-based alternative payment method flow |
| **PayPal** | `client_token` (Braintree JWT) | PayPal wallet/Braintree SDK — uses nonce, not CardToken. Different PMD type (`PaymentMethodData::Wallet`) |
| **Paytm** | `txn_token` | Paytm checkout SDK handles payment end-to-end |
| **Peachpayments** | `access_token` (OAuth) | OAuth token for API auth, not a payment method reference |
| **Jpmorgan** | `access_token` (OAuth JWT) | OAuth token for API authentication, not card tokenization |
| **Multisafepay** | `api_token` | API token for client-side auth, not card tokenization |

---

## Group 3: SDK-Based — Needs Further Investigation

These connectors return SDK initialization data, but the exact mechanism for how the SDK returns payment data back to the server varies. Whether the resulting data maps to `CardToken` or a different payment method data type needs per-connector investigation.

| Connector | What Is Returned | Investigation Notes |
|-----------|-----------------|---------------------|
| **Adyen** | `session_id` + `session_data` from `/v68/sessions` | Adyen Drop-in/Components SDK collects card data and returns **encrypted card fields** (`encryptedCardNumber`, `encryptedExpiryMonth`, `encryptedExpiryYear`, `encryptedSecurityCode`), not a single token. The Authorize flow already handles these encrypted fields. CardToken may not be the right mapping — Adyen uses a fundamentally different pattern (encrypted fields vs token ID). |
| **Checkout** | `payment_session_id` + `payment_session_token` + `payment_session_secret` | Checkout.com Frames SDK tokenizes card and returns a `token` (e.g. `tok_...`). This token COULD map to `CardToken`. Needs verification of whether the existing Authorize flow already handles Frames tokens via a different path. |
| **Shift4** | `client_secret` from `/checkout-sessions` | Shift4's JS SDK uses the `client_secret` to initialize checkout. The SDK may return a charge ID or token after payment. Need to check Shift4 docs for whether there's a token-based Authorize path. |
| **Nuvei** | `session_token` from `/getSessionToken.do` | Nuvei Web SDK uses the session token for subsequent API calls. Card data can be collected via Nuvei Fields (hosted fields) which returns a `ccTempToken`. If Nuvei Fields is used, CardToken COULD apply. If Simply Connect (full hosted) is used, it does not apply. |
| **Fiserv** | `session_id` from security credentials | Fiserv's client-side SDK (Connected Commerce) uses the session for hosted fields. Could return a token. Needs Fiserv Commerce Hub docs verification. |
| **Payload** | `client_token` from `/access_tokens` | Payload's JS SDK uses the client token for Payload.js secure inputs. Likely returns a payment method ID after tokenization. CardToken COULD apply. |
| **Revolut** | `order_id` + `token` from `/api/orders` | Revolut's checkout SDK can operate in popup or embedded mode. The `token` is used to initialize RevolutCheckout. Card data is collected by Revolut's SDK and payment is completed. May return a token for server-side confirmation. Needs investigation. |

### Recommended Next Steps for Group 3

1. **Adyen** — Likely does NOT need CardToken. Verify that the existing encrypted-fields path in Authorize is sufficient.
2. **Checkout** — Likely DOES need CardToken. Verify Frames token flow.
3. **Shift4** — Check if Shift4 supports a token-based server-side Authorize after client-side collection.
4. **Nuvei** — Check if Nuvei Fields `ccTempToken` is being used; if so, add CardToken support.
5. **Fiserv** — Check Commerce Hub hosted fields token flow.
6. **Payload** — Check Payload.js secure inputs token flow.
7. **Revolut** — Check if server-side confirmation uses a token or if payment completes client-side.

---

## Summary

| Group | Count | CardToken Needed? | Action |
|-------|-------|-------------------|--------|
| Card Tokenization (hosted fields) | 9 | **Yes** | Add `PaymentMethodData::CardToken` handler in Authorize transformer (1 already done — Globalpay) |
| Hosted Checkout / Redirect | 15 | **No** | No changes needed |
| SDK-Based (ambiguous) | 7 | **Maybe** | Per-connector investigation required |
| Skipped (no credentials) | 7 | N/A | Cannot assess without implementation |
| **Total** | **38** | | |
