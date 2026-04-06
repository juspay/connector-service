# ClientAuthentication Flow Pattern for Connector Implementation

**GENERIC PATTERN FILE FOR ANY NEW CONNECTOR**

This document provides comprehensive, reusable patterns for implementing the ClientAuthentication (CreateClientAuthenticationToken) flow in **ANY** payment connector within the UCS (Universal Connector Service) system. These patterns are extracted from the Stripe connector implementation (PR #855) and can be consumed by AI to generate consistent, production-ready ClientAuthentication flow code for any payment gateway.

> **UCS-Specific:** This pattern is tailored for UCS architecture using RouterDataV2, ConnectorIntegrationV2, and domain_types. The ClientAuthentication flow provides client-side SDK initialization data (e.g., Stripe's `client_secret`) so the browser/app can complete payment confirmation directly with the connector.

## Quick Start Guide

To implement a new connector ClientAuthentication flow using these patterns:

1. **Choose Your Pattern**: Use [Modern Macro-Based Pattern](#modern-macro-based-pattern-recommended) for 95% of connectors
2. **Replace Placeholders**: Follow the [Placeholder Reference Guide](#placeholder-reference-guide)
3. **Select Components**: Choose auth type, request format, and amount converter based on your connector's API
4. **Follow Checklist**: Use the [Integration Checklist](#integration-checklist) to ensure completeness

### Example: Implementing "NewPayment" Connector ClientAuthentication Flow

```bash
# Replace placeholders:
{ConnectorName} → NewPayment
{connector_name} → new_payment
{AmountType} → MinorUnit (if API expects 1000 for $10.00)
{content_type} → "application/json" (if API uses JSON)
{client_auth_endpoint} → "v1/payment_intents" (your API endpoint for creating unconfirmed payments)
```

**Result**: Complete, production-ready connector ClientAuthentication flow implementation in ~20 minutes

### Placeholder Reference Guide

| Placeholder | Description | Examples |
|-------------|-------------|----------|
| `{ConnectorName}` | PascalCase connector name | `Stripe`, `Adyen`, `Checkout` |
| `{connector_name}` | snake_case connector name | `stripe`, `adyen`, `checkout` |
| `{AmountType}` | Amount type used by connector | `MinorUnit`, `StringMinorUnit`, `StringMajorUnit` |
| `{content_type}` | HTTP Content-Type header | `"application/json"`, `"application/x-www-form-urlencoded"` |
| `{client_auth_endpoint}` | API endpoint for creating unconfirmed payment/session | `"v1/payment_intents"`, `"v1/sessions"`, `"payments/init"` |
| `{client_secret_field}` | Response field containing client SDK token | `client_secret`, `session_id`, `sdk_token` |

## Table of Contents

1. [Overview](#overview)
2. [Difference from CreateSessionToken and CreateOrder](#difference-from-createsessiontoken-and-createorder)
3. [ClientAuthentication Flow Implementation Analysis](#clientauthentication-flow-implementation-analysis)
4. [Modern Macro-Based Pattern (Recommended)](#modern-macro-based-pattern-recommended)
5. [Request/Response Format Variations](#requestresponse-format-variations)
6. [Adding a New Connector Variant to ConnectorSpecificClientAuthenticationResponse](#adding-a-new-connector-variant)
7. [Error Handling Patterns](#error-handling-patterns)
8. [Testing Patterns](#testing-patterns)
9. [Integration Checklist](#integration-checklist)

## Overview

The ClientAuthentication flow is a **client-side SDK initialization** flow that:
1. Receives a request with payment parameters (amount, currency, etc.) from the router
2. Creates an **unconfirmed** payment resource on the connector side (e.g., a PaymentIntent)
3. Returns SDK initialization data (e.g., `client_secret`) to the frontend
4. The frontend SDK (e.g., `stripe.confirmPayment()`) completes payment confirmation directly with the connector
5. The server later syncs the payment status via the PSync flow

### When to Use ClientAuthentication

Use this flow when the connector's payment model requires:
- **Browser-side SDK confirmation**: The connector provides a JavaScript/native SDK that must be initialized with a secret/token
- **Unconfirmed payment creation**: The server creates a payment resource, but confirmation happens client-side
- **Non-PCI client auth**: The client needs connector-specific credentials to complete payment without handling raw card data

**Examples:**
- **Stripe**: Creates unconfirmed PaymentIntent, returns `client_secret` for `stripe.confirmPayment()`
- **Adyen**: Creates a session, returns `session_id` and `session_data` for Adyen Drop-in/Components
- **Checkout.com**: Creates a payment session, returns `session_token` for Frames SDK

### Key Components:
- **Main Connector File**: Implements `ClientAuthentication` trait and flow logic
- **Transformers File**: Handles request/response data transformations
- **Authentication**: Manages API credentials and headers
- **Error Handling**: Processes and maps error responses
- **Domain Types**: `ClientAuthenticationTokenRequestData` (input), `ClientAuthenticationTokenData` (output)
- **Response Envelope**: `PaymentsResponseData::ClientAuthenticationTokenResponse`

### Flow Sequence:
```
                               Server Side
┌──────────┐     ┌─────────────────────────────────┐     ┌─────────────┐
│  gRPC    │────▶│ CreateClientAuthenticationToken  │────▶│  Connector  │
│  Client  │     │  (ClientAuthentication flow)     │     │  API        │
└──────────┘     └─────────────────────────────────┘     └──────┬──────┘
                                                                │
                                                         ┌──────▼──────┐
                                                         │  Returns    │
                                                         │  Unconfirmed│
                                                         │  Payment +  │
                                                         │  SDK Token  │
                                                         └──────┬──────┘
                               Client Side                      │
┌──────────┐     ┌─────────────────────────────────┐     ┌──────▼──────┐
│  User    │◀────│  Connector JS/Native SDK         │◀────│  SDK Token  │
│  Browser │     │  (e.g. stripe.confirmPayment())  │     │  Returned   │
└──────────┘     └──────────────┬──────────────────┘     └─────────────┘
                                │
                         ┌──────▼──────┐
                         │  PSync      │  Server syncs final status
                         │  Flow       │
                         └─────────────┘
```

## Difference from CreateSessionToken and CreateOrder

The UCS system has three distinct pre-authorization flows that serve different purposes:

| Flow | Purpose | Who Confirms Payment | Response Contains |
|------|---------|---------------------|-------------------|
| **CreateSessionToken** | Server-side session initialization for multi-step flows | Server (via Authorize flow) | Session token stored in `PaymentFlowData.session_token` |
| **CreateOrder** | Server-side order/intent creation before authorization | Server (via Authorize flow) | Order ID stored in `PaymentCreateOrderResponse.order_id` |
| **ClientAuthentication** | Client-side SDK initialization | **Client** (browser/app SDK) | SDK init data returned to frontend via `ClientAuthenticationTokenData` |

**Key distinction**: ClientAuthentication is the ONLY flow where payment confirmation happens on the **client side**. The server creates the payment resource but does NOT confirm it — the frontend SDK does.

### When to Choose Each Flow

- **CreateSessionToken**: Connector requires a session/token exchange BEFORE the server-side Authorize call (e.g., Paytm, Nuvei)
- **CreateOrder**: Connector requires creating an order/intent that the server-side Authorize call references (e.g., some multi-step APIs)
- **ClientAuthentication**: Connector provides a browser SDK that needs initialization data to complete payment client-side (e.g., Stripe, Adyen Drop-in)

## ClientAuthentication Flow Implementation Analysis

Based on comprehensive analysis of all connectors in the connector service, here's the implementation status:

### Full ClientAuthentication Implementation (1 connector)
These connectors have complete ClientAuthentication flow implementations:

1. **Stripe** - Creates unconfirmed PaymentIntent with `automatic_payment_methods[enabled]=true`
   - Returns `client_secret` for browser-side `stripe.confirmPayment()`
   - Uses form-urlencoded POST to `/v1/payment_intents`
   - Status: `requires_payment_method` (correct for unconfirmed intent)
   - Metadata includes `order_id` from session reference

### Stub/Trait Implementation Only (87+ connectors)
All other connectors implement the `ClientAuthentication` trait with empty/stub implementations:
- ACI, Adyen, Airwallex, Authipay, AuthorizeDotNet, Bambora, BamboraAPAC, BankOfAmerica, Barclaycard, Billwerk, Bluesnap, Braintree, Calida, Cashfree, CashtoCode, Celero, Checkout, Cryptopay, Cybersource, Datatrans, Dlocal, Elavon, Fiserv, FiservCommerceHub, FiservMEA, Fiuu, Forte, Getnet, Gigadat, GlobalPay, Helcim, Hipay, HyperPG, IataPay, JPMorgan, Loonio, Mifinity, Mollie, Multisafepay, Nexinets, Nexixpay, NMI, Noon, Novalnet, Paybox, Payload, Payme, Paypal, Paysafe, PayU, PhonePe, Placetopay, Powertranz, Rapyd, Razorpay, RazorpayV2, Redsys, Revolut, Shift4, Silverflow, Stax, Trustpay, Trustpayments, Tsys, etc.

### Implementation Statistics
- **Complete implementations**: 1/88 (~1%)
- **Stub implementations**: 87/88 (~99%)
- **Reference implementation**: Stripe (form-urlencoded POST)

## Core Type Reference

### Flow Marker
```rust
// Location: domain_types::connector_flow
#[derive(Debug, Clone)]
pub struct ClientAuthenticationToken;
```

### Trait Definition
```rust
// Location: interfaces::connector_types
pub trait ClientAuthentication:
    ConnectorIntegrationV2<
    connector_flow::ClientAuthenticationToken,
    PaymentFlowData,
    ClientAuthenticationTokenRequestData,
    PaymentsResponseData,
>
{
}
```

### Request Data
```rust
// Location: domain_types::connector_types
#[derive(Debug, Clone)]
pub struct ClientAuthenticationTokenRequestData {
    pub amount: MinorUnit,
    pub currency: Currency,
    pub country: Option<CountryAlpha2>,
    pub order_details: Option<Vec<OrderDetailsWithAmount>>,
    pub email: Option<Email>,
    pub customer_name: Option<Secret<String>>,
    pub order_tax_amount: Option<MinorUnit>,
    pub shipping_cost: Option<MinorUnit>,
    pub payment_method_type: Option<PaymentMethodType>,
}
```

### Response Data (envelope)
```rust
// Location: domain_types::connector_types
pub enum PaymentsResponseData {
    // ... other variants ...
    ClientAuthenticationTokenResponse {
        session_data: ClientAuthenticationTokenData,
        status_code: u16,
    },
}
```

### Response Data (session data)
```rust
// Location: domain_types::connector_types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "sdk_type")]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthenticationTokenData {
    /// Google Pay SDK initialization
    GooglePay(Box<GpayClientAuthenticationResponse>),
    /// PayPal SDK initialization
    Paypal(Box<PaypalClientAuthenticationResponse>),
    /// Apple Pay SDK initialization
    ApplePay(Box<ApplepayClientAuthenticationResponse>),
    /// Generic connector-specific SDK initialization data
    ConnectorSpecific(Box<ConnectorSpecificClientAuthenticationResponse>),
}

/// Per-connector discriminated union
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "connector")]
#[serde(rename_all = "snake_case")]
pub enum ConnectorSpecificClientAuthenticationResponse {
    Stripe(StripeClientAuthenticationResponse),
    // Add new connectors here:
    // Adyen(AdyenClientAuthenticationResponse),
    // Checkout(CheckoutClientAuthenticationResponse),
}
```

### gRPC Server Handler
```rust
// Location: grpc-server/src/server/payments.rs
impl MerchantAuthenticationOperational for MerchantAuthentication {
    implement_connector_operation!(
        fn_name: internal_sdk_session_token,
        log_prefix: "SDK_SESSION",
        request_type: MerchantAuthenticationServiceCreateClientAuthenticationTokenRequest,
        response_type: MerchantAuthenticationServiceCreateClientAuthenticationTokenResponse,
        flow_marker: ClientAuthenticationToken,
        resource_common_data_type: PaymentFlowData,
        request_data_type: ClientAuthenticationTokenRequestData,
        response_data_type: PaymentsResponseData,
        request_data_constructor: ClientAuthenticationTokenRequestData::foreign_try_from,
        common_flow_data_constructor: PaymentFlowData::foreign_try_from,
        generate_response_fn: generate_payment_sdk_session_token_response,
        all_keys_required: None
    );
}
```

## Modern Macro-Based Pattern (Recommended)

### File Structure Template

```
connector-service/crates/integrations/connector-integration/src/connectors/
├── {connector_name}.rs           # Main connector implementation
└── {connector_name}/
    └── transformers.rs           # Data transformation logic
```

### Main Connector File Pattern

#### Step 1: Add Imports

```rust
// In the imports section of {connector_name}.rs, add:
use domain_types::{
    connector_flow::{
        // ... existing flows ...
        ClientAuthenticationToken,  // ADD THIS
    },
    connector_types::{
        // ... existing types ...
        ClientAuthenticationTokenRequestData,  // ADD THIS
    },
};
```

#### Step 2: Implement ClientAuthentication Trait

```rust
// Empty trait impl — actual work is done via macros + transformers
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ClientAuthentication for {ConnectorName}<T>
{
}
```

#### Step 3: Register Flow in create_all_prerequisites!

```rust
macros::create_all_prerequisites!(
    connector_name: {ConnectorName},
    generic_type: T,
    api: [
        // ... existing flows ...
        (
            flow: ClientAuthenticationToken,
            request_body: {ConnectorName}ClientAuthRequest,
            response_body: {ConnectorName}ClientAuthResponse,
            router_data: RouterDataV2<ClientAuthenticationToken, PaymentFlowData, ClientAuthenticationTokenRequestData, PaymentsResponseData>,
        ),
    ],
    // ... rest of macro unchanged ...
);
```

#### Step 4: Implement Flow with macro_connector_implementation!

```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: {ConnectorName},
    curl_request: Json({ConnectorName}ClientAuthRequest),  // Or FormUrlEncoded for form-based APIs
    curl_response: {ConnectorName}ClientAuthResponse,
    flow_name: ClientAuthenticationToken,
    resource_common_data: PaymentFlowData,
    flow_request: ClientAuthenticationTokenRequestData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<ClientAuthenticationToken, PaymentFlowData, ClientAuthenticationTokenRequestData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<ClientAuthenticationToken, PaymentFlowData, ClientAuthenticationTokenRequestData, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!(
                "{}{}",
                self.connector_base_url_payments(req),
                "{client_auth_endpoint}"
            ))
        }
    }
);
```

### Transformers File Pattern

#### Step 1: Add Imports

```rust
// In the imports section of transformers.rs, add:
use domain_types::{
    connector_flow::ClientAuthenticationToken,
    connector_types::{
        ClientAuthenticationTokenRequestData,
        ClientAuthenticationTokenData,
        ConnectorSpecificClientAuthenticationResponse,
        // Import the domain response type for your connector (you must add this to domain_types first):
        {ConnectorName}ClientAuthenticationResponse as {ConnectorName}ClientAuthenticationResponseDomain,
    },
};
```

#### Step 2: Define Request Type

```rust
// ---- ClientAuthenticationToken flow types ----

/// Creates an unconfirmed payment/session. Confirmation happens client-side
/// via the connector's browser/native SDK using the returned initialization data.
#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize)]
pub struct {ConnectorName}ClientAuthRequest {
    pub amount: {AmountType},
    pub currency: String,
    // Add connector-specific fields from the API docs.
    // CRITICAL: Only include fields actually required by the connector API.
    // Do NOT add fields "just in case" or set them to None.
}
```

#### Step 3: Implement Request Transformer

```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        {ConnectorName}RouterData<
            RouterDataV2<
                ClientAuthenticationToken,
                PaymentFlowData,
                ClientAuthenticationTokenRequestData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for {ConnectorName}ClientAuthRequest
{
    type Error = error_stack::Report<IntegrationError>;
    fn try_from(
        item: {ConnectorName}RouterData<
            RouterDataV2<
                ClientAuthenticationToken,
                PaymentFlowData,
                ClientAuthenticationTokenRequestData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;

        // Convert amount using the connector's amount converter
        let amount = {ConnectorName}AmountConvertor::convert(
            router_data.request.amount,
            router_data.request.currency,
        )?;

        let currency = router_data.request.currency.to_string().to_lowercase();

        Ok(Self {
            amount,
            currency,
            // Map other fields from router_data.request as needed
        })
    }
}
```

#### Step 4: Define Response Type

```rust
/// Wraps the connector's response for the ClientAuthenticationToken flow.
/// The inner type can be shared with other flows if the connector returns the same
/// response format (e.g., Stripe reuses PaymentIntentResponse).
#[derive(Debug, Deserialize, Serialize)]
pub struct {ConnectorName}ClientAuthResponse {
    pub id: String,
    pub {client_secret_field}: Option<Secret<String>>,
    pub status: Option<String>,
    // Add other fields from the connector's response that you need
}
```

#### Step 5: Implement Response Transformer

```rust
impl TryFrom<ResponseRouterData<{ConnectorName}ClientAuthResponse, Self>>
    for RouterDataV2<
        ClientAuthenticationToken,
        PaymentFlowData,
        ClientAuthenticationTokenRequestData,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<ConnectorResponseTransformationError>;
    fn try_from(
        item: ResponseRouterData<{ConnectorName}ClientAuthResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;

        // Extract the SDK initialization token/secret
        let client_secret = response.{client_secret_field}.ok_or(
            ConnectorResponseTransformationError::ResponseDeserializationFailed {
                context: Default::default(),
            },
        )?;

        // Wrap in the domain response type
        let session_data = ClientAuthenticationTokenData::ConnectorSpecific(Box::new(
            ConnectorSpecificClientAuthenticationResponse::{ConnectorName}(
                {ConnectorName}ClientAuthenticationResponseDomain { client_secret },
            ),
        ));

        Ok(Self {
            response: Ok(PaymentsResponseData::ClientAuthenticationTokenResponse {
                session_data,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}
```

## Request/Response Format Variations

### Pattern 1: Form URL-Encoded (Stripe)

**Use when**: Connector API expects `application/x-www-form-urlencoded` body.

```rust
// In create_all_prerequisites! macro:
curl_request: FormUrlEncoded({ConnectorName}ClientAuthRequest),

// Request type with serde flatten for form params:
#[serde_with::skip_serializing_none]
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct StripeClientAuthRequest {
    pub amount: MinorUnit,
    pub currency: String,
    #[serde(rename = "automatic_payment_methods[enabled]")]
    pub automatic_payment_methods_enabled: Option<bool>,
    #[serde(flatten)]
    pub meta_data: HashMap<String, String>,
}
```

**Response**: Stripe reuses its `PaymentIntentResponse` struct (which contains `client_secret`):
```rust
#[derive(Debug, Deserialize, Serialize)]
pub struct StripeClientAuthResponse(PaymentIntentResponse);
```

### Pattern 2: JSON (Most Connectors)

**Use when**: Connector API expects `application/json` body.

```rust
// In macro_connector_implementation!:
curl_request: Json({ConnectorName}ClientAuthRequest),

// Standard JSON request:
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenClientAuthRequest {
    pub amount: AdyenAmount,
    pub merchant_account: Secret<String>,
    pub reference: String,
    pub return_url: String,
    pub country_code: Option<String>,
    // etc.
}
```

### Pattern 3: Reusing Existing Response Types

If the connector returns the same response format as another flow (e.g., Stripe's ClientAuth response is a PaymentIntent), wrap the existing type:

```rust
// Wrap existing type to avoid trait impl conflicts:
#[derive(Debug, Deserialize, Serialize)]
pub struct {ConnectorName}ClientAuthResponse({ConnectorName}PaymentResponse);

// Access inner fields:
impl TryFrom<ResponseRouterData<{ConnectorName}ClientAuthResponse, Self>>
    for RouterDataV2<ClientAuthenticationToken, ...>
{
    fn try_from(item: ...) -> Result<Self, Self::Error> {
        let response = item.response.0;  // Access inner type
        let client_secret = response.client_secret.ok_or(...)?;
        // ...
    }
}
```

## Adding a New Connector Variant

When implementing ClientAuthentication for a new connector, you must add your connector's response type to the domain types.

### Step 1: Add Domain Response Type

In `crates/types-traits/domain_types/src/connector_types.rs`:

```rust
/// {ConnectorName}'s SDK initialization data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct {ConnectorName}ClientAuthenticationResponse {
    pub client_secret: Secret<String>,  // Or whatever field the SDK needs
    // Add other fields the frontend SDK requires
}
```

### Step 2: Add Variant to ConnectorSpecificClientAuthenticationResponse

In the same file, add your connector to the enum:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "connector")]
#[serde(rename_all = "snake_case")]
pub enum ConnectorSpecificClientAuthenticationResponse {
    Stripe(StripeClientAuthenticationResponse),
    {ConnectorName}({ConnectorName}ClientAuthenticationResponse),  // ADD THIS
}
```

### Step 3: Update Proto Definition (if needed)

In `crates/types-traits/grpc-api-types/proto/payment.proto`, add the connector-specific message:

```protobuf
message ConnectorSpecificClientAuthenticationResponse {
  oneof connector {
    StripeClientAuthenticationResponse stripe = 1;
    {ConnectorName}ClientAuthenticationResponse {connector_name} = 2;  // ADD THIS
  }
}

message {ConnectorName}ClientAuthenticationResponse {
  SecretString client_secret = 1;
  // Add other fields as needed
}
```

### Step 4: Update Proto-to-Domain Conversion

In `crates/types-traits/domain_types/src/types.rs`, update the `ForeignTryFrom` implementations to handle the new variant in both directions (proto-to-domain and domain-to-proto).

## Reference Implementation: Stripe

### Stripe Request Transformer
```rust
/// Creates an unconfirmed PaymentIntent. `confirm` is intentionally omitted -
/// confirmation happens browser-side via `stripe.confirmPayment()` using the
/// returned `client_secret`.
#[serde_with::skip_serializing_none]
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct StripeClientAuthRequest {
    pub amount: MinorUnit,
    pub currency: String,
    #[serde(rename = "automatic_payment_methods[enabled]")]
    pub automatic_payment_methods_enabled: Option<bool>,
    #[serde(flatten)]
    pub meta_data: HashMap<String, String>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<StripeRouterData<RouterDataV2<ClientAuthenticationToken, PaymentFlowData, ClientAuthenticationTokenRequestData, PaymentsResponseData>, T>>
    for StripeClientAuthRequest
{
    type Error = error_stack::Report<IntegrationError>;
    fn try_from(item: StripeRouterData<...>) -> Result<Self, Self::Error> {
        let router_data = item.router_data;

        let amount = StripeAmountConvertor::convert(
            router_data.request.amount,
            router_data.request.currency,
        )?;
        let currency = router_data.request.currency.to_string().to_lowercase();
        let order_id = router_data.resource_common_data.connector_request_reference_id.clone();
        let meta_data = get_transaction_metadata(None, order_id);

        Ok(Self {
            amount,
            currency,
            automatic_payment_methods_enabled: Some(true),
            meta_data,
        })
    }
}
```

### Stripe Response Transformer
```rust
#[derive(Debug, Deserialize, Serialize)]
pub struct StripeClientAuthResponse(PaymentIntentResponse);

impl TryFrom<ResponseRouterData<StripeClientAuthResponse, Self>>
    for RouterDataV2<ClientAuthenticationToken, PaymentFlowData, ClientAuthenticationTokenRequestData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorResponseTransformationError>;
    fn try_from(item: ResponseRouterData<StripeClientAuthResponse, Self>) -> Result<Self, Self::Error> {
        let response = item.response.0;

        let client_secret = response.client_secret.ok_or(
            ConnectorResponseTransformationError::ResponseDeserializationFailed {
                context: Default::default(),
            },
        )?;

        let session_data = ClientAuthenticationTokenData::ConnectorSpecific(Box::new(
            ConnectorSpecificClientAuthenticationResponse::Stripe(
                StripeClientAuthenticationResponseDomain { client_secret },
            ),
        ));

        Ok(Self {
            response: Ok(PaymentsResponseData::ClientAuthenticationTokenResponse {
                session_data,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}
```

### Stripe macro_connector_implementation!
```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Stripe,
    curl_request: FormUrlEncoded(StripeClientAuthRequest),
    curl_response: StripeClientAuthResponse,
    flow_name: ClientAuthenticationToken,
    resource_common_data: PaymentFlowData,
    flow_request: ClientAuthenticationTokenRequestData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<ClientAuthenticationToken, PaymentFlowData, ClientAuthenticationTokenRequestData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<ClientAuthenticationToken, PaymentFlowData, ClientAuthenticationTokenRequestData, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!(
                "{}{}",
                self.connector_base_url_payments(req),
                "v1/payment_intents"
            ))
        }
    }
);
```

## Error Handling Patterns

### Missing SDK Token in Response

```rust
// If the connector response is missing the expected SDK initialization field:
let client_secret = response.client_secret.ok_or(
    ConnectorResponseTransformationError::ResponseDeserializationFailed {
        context: Default::default(),
    },
)?;
```

### Connector Returns Error Response

```rust
// Use the standard error response handling via get_error_response_v2
// provided by the macro_connector_implementation! default implementations.
// The connector's standard error response struct is used.
```

### Common Error Scenarios

| Error | Cause | Resolution |
|-------|-------|------------|
| `ResponseDeserializationFailed` | Connector response missing required SDK token field | Ensure response struct matches connector API docs |
| `FailedToObtainAuthType` | Wrong auth type variant | Verify `TryFrom<&ConnectorAuthType>` handles correct variant |
| `AmountConversionFailed` | Amount/currency conversion error | Check amount converter matches connector's expected format |

## Testing Patterns

### Manual gRPC Test

```bash
grpcurl -plaintext \
  -H 'x-connector-config: {"config":{"{ConnectorName}":{"api_key":"your_test_key"}}}' \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: client_auth_test_001" \
  -H "x-connector-request-reference-id: client_auth_ref" \
  -d '{"session_id":"test_session_001","payment":{"amount":{"minor_amount":"1000","currency":"USD"}}}' \
  localhost:8000 types.MerchantAuthenticationService/CreateClientAuthenticationToken
```

### Expected Response Structure

```json
{
  "sessionData": {
    "connectorSpecific": {
      "{connector_name}": {
        "clientSecret": {
          "value": "<sdk_initialization_token>"
        }
      }
    }
  },
  "statusCode": 200,
  "rawConnectorResponse": { "value": "..." },
  "rawConnectorRequest": { "value": "..." }
}
```

### Verification Checklist

- [ ] SDK token/secret is present in `sessionData.connectorSpecific.{connector_name}`
- [ ] `statusCode` is 200
- [ ] Payment resource created on connector side is **unconfirmed**
- [ ] `rawConnectorResponse` contains valid connector response JSON
- [ ] `rawConnectorRequest` shows correct endpoint, method, and redacted auth headers

## Integration Checklist

### Pre-Implementation

- [ ] Connector API documentation reviewed for SDK initialization endpoint
- [ ] Identified which field the frontend SDK needs (e.g., `client_secret`, `session_id`)
- [ ] Verified connector uses a client-side SDK confirmation model
- [ ] Confirmed this is NOT a server-side session flow (use CreateSessionToken instead)

### Connector Files (connector.rs)

- [ ] `ClientAuthenticationToken` imported from `domain_types::connector_flow`
- [ ] `ClientAuthenticationTokenRequestData` imported from `domain_types::connector_types`
- [ ] `connector_types::ClientAuthentication` trait implemented (empty impl)
- [ ] Flow registered in `create_all_prerequisites!` macro with correct types
- [ ] `macro_connector_implementation!` added with correct endpoint, method, and content type
- [ ] `get_headers` delegates to `self.build_headers(req)`
- [ ] `get_url` returns the correct SDK initialization endpoint

### Transformer Files (transformers.rs)

- [ ] Request struct defined with only connector-required fields
- [ ] Response struct defined matching connector API response format
- [ ] Request transformer (`TryFrom<{Connector}RouterData<...>>`) implemented
- [ ] Response transformer (`TryFrom<ResponseRouterData<...>>`) implemented
- [ ] SDK token extracted and wrapped in `ClientAuthenticationTokenData::ConnectorSpecific`
- [ ] Missing SDK token handled with appropriate error

### Domain Types (connector_types.rs)

- [ ] Connector-specific response struct added (e.g., `{ConnectorName}ClientAuthenticationResponse`)
- [ ] Variant added to `ConnectorSpecificClientAuthenticationResponse` enum

### Proto (payment.proto) — if gRPC response needs the new connector

- [ ] Connector-specific message added
- [ ] Variant added to `ConnectorSpecificClientAuthenticationResponse` oneof
- [ ] Proto-to-domain conversion updated in `types.rs`
- [ ] Domain-to-proto conversion updated in `types.rs`

### Build and Validation

- [ ] `cargo build` succeeds
- [ ] `cargo clippy` passes with no warnings
- [ ] No references to old names (SdkSessionToken, PaymentsSdkSessionTokenData, etc.)
- [ ] gRPC test returns valid SDK initialization data
- [ ] Payment resource on connector side is unconfirmed after the call
