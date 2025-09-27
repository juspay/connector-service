# Worldpay Connector - Authorize Flow Implementation Memory

## Overview

This document provides comprehensive documentation about the Worldpay connector's authorize flow implementation in Hyperswitch. It covers the architecture, data transformations, authentication, error handling, and all technical details required to understand and maintain the Worldpay payment integration.

## Table of Contents

1. [Connector Architecture](#connector-architecture)
2. [Authorize Flow Implementation](#authorize-flow-implementation)
3. [Request Transformation](#request-transformation)
4. [Response Handling](#response-handling)
5. [Authentication](#authentication)
6. [3DS Support](#3ds-support)
7. [Payment Methods](#payment-methods)
8. [Error Handling](#error-handling)
9. [Status Mapping](#status-mapping)
10. [Webhook Processing](#webhook-processing)
11. [Configuration](#configuration)
12. [Testing](#testing)
13. [Common Patterns](#common-patterns)
14. [Troubleshooting](#troubleshooting)

## Connector Architecture

### File Structure

```
hyperswitch/crates/hyperswitch_connectors/src/connectors/worldpay/
├── worldpay.rs              # Main connector implementation
├── transformers.rs          # Data transformation logic
├── requests.rs              # Request structures
└── response.rs              # Response structures
```

### Main Connector Structure

The Worldpay connector is implemented as a struct that implements multiple traits:

```rust
#[derive(Clone)]
pub struct Worldpay {
    amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
}

impl Worldpay {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &MinorUnitForConnector,
        }
    }
}
```

### Key Traits Implemented

- `ConnectorCommon`: Basic connector information and configuration
- `ConnectorCommonExt`: Extended common functionality
- `ConnectorValidation`: Mandate and webhook validation
- `ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData>`: Authorize flow implementation
- `IncomingWebhook`: Webhook processing
- `ConnectorRedirectResponse`: Redirect handling
- `ConnectorSpecifications`: Connector metadata and capabilities

## Authorize Flow Implementation

### Flow Overview

The authorize flow in Worldpay follows this sequence:

1. **Request Reception**: gRPC server receives authorize request
2. **Data Transformation**: Convert router data to Worldpay format
3. **Request Construction**: Build HTTP request with headers and body
4. **API Call**: Send POST request to Worldpay's `/api/payments` endpoint
5. **Response Processing**: Parse and transform Worldpay response
6. **Status Determination**: Map Worldpay status to Hyperswitch status
7. **Response Return**: Return processed response to gRPC client

### Core Implementation

```rust
impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Worldpay {
    fn get_headers(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()  // "application/json"
    }

    fn get_url(
        &self,
        _req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}api/payments", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let connector_router_data = worldpay::WorldpayRouterData::try_from((
            &self.get_currency_unit(),
            req.request.currency,
            req.request.minor_amount,
            req,
        ))?;
        let auth = worldpay::WorldpayAuthType::try_from(&req.connector_auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let connector_req =
            WorldpayPaymentsRequest::try_from((&connector_router_data, &auth.entity_id))?;

        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn handle_response(
        &self,
        data: &PaymentsAuthorizeRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsAuthorizeRouterData, errors::ConnectorError> {
        let response: WorldpayPaymentsResponse = res
            .response
            .parse_struct("Worldpay PaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        let optional_correlation_id = res.headers.and_then(|headers| {
            headers
                .get(WP_CORRELATION_ID)
                .and_then(|header_value| header_value.to_str().ok())
                .map(|id| id.to_string())
        });

        RouterData::foreign_try_from((
            ResponseRouterData {
                response,
                data: data.clone(),
                http_code: res.status_code,
            },
            optional_correlation_id,
            data.request.amount,
        ))
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }
}
```

## Request Transformation

### Router Data to Worldpay Request

The transformation process involves several steps:

1. **Create WorldpayRouterData**: Wrap router data with amount conversion
2. **Extract Authentication**: Get entity ID from authentication type
3. **Build WorldpayPaymentsRequest**: Transform data into Worldpay format

### Key Request Structure

```rust
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayPaymentsRequest {
    pub transaction_reference: String,
    pub merchant: Merchant,
    pub instruction: Instruction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer: Option<Customer>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Instruction {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement: Option<AutoSettlement>,
    pub method: PaymentMethod,
    pub payment_instrument: PaymentInstrument,
    pub narrative: InstructionNarrative,
    pub value: PaymentValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debt_repayment: Option<bool>,
    #[serde(rename = "threeDS", skip_serializing_if = "Option::is_none")]
    pub three_ds: Option<ThreeDSRequest>,
    pub token_creation: Option<TokenCreation>,
    pub customer_agreement: Option<CustomerAgreement>,
}
```

### Payment Instrument Transformation

Different payment methods are handled differently:

```rust
fn fetch_payment_instrument(
    payment_method: PaymentMethodData,
    billing_address: Option<&address::Address>,
    mandate_ids: Option<MandateIds>,
) -> CustomResult<PaymentInstrument, errors::ConnectorError> {
    match payment_method {
        PaymentMethodData::Card(card) => Ok(PaymentInstrument::Card(CardPayment {
            raw_card_details: RawCardDetails {
                payment_type: PaymentType::Plain,
                expiry_date: ExpiryDate {
                    month: card.get_expiry_month_as_i8()?,
                    year: card.get_expiry_year_as_4_digit_i32()?,
                },
                card_number: card.card_number,
            },
            cvc: card.card_cvc,
            card_holder_name: billing_address.and_then(|address| address.get_optional_full_name()),
            billing_address: /* address transformation */,
        })),
        PaymentMethodData::Wallet(wallet) => match wallet {
            WalletData::GooglePay(data) => Ok(PaymentInstrument::Googlepay(WalletPayment {
                payment_type: PaymentType::Encrypted,
                wallet_token: Secret::new(
                    data.tokenization_data.get_encrypted_google_pay_token()?,
                ),
                ..WalletPayment::default()
            })),
            WalletData::ApplePay(data) => Ok(PaymentInstrument::Applepay(WalletPayment {
                payment_type: PaymentType::Encrypted,
                wallet_token: data.get_applepay_decoded_payment_data()?,
                ..WalletPayment::default()
            })),
            // Other wallet types return NotImplemented error
        },
        PaymentMethodData::MandatePayment => {
            // Handle mandate payments using stored tokens
        },
        // Other payment methods return NotImplemented error
    }
}
```

### Settlement Configuration

Settlement behavior is determined by capture method:

```rust
fn get_settlement_info(&self, amount: i64) -> Option<AutoSettlement> {
    match (self.request.capture_method.unwrap_or_default(), amount) {
        (_, 0) => None,
        (enums::CaptureMethod::Automatic, _)
        | (enums::CaptureMethod::SequentialAutomatic, _) => Some(AutoSettlement { auto: true }),
        (enums::CaptureMethod::Manual, _) | (enums::CaptureMethod::ManualMultiple, _) => {
            Some(AutoSettlement { auto: false })
        }
        _ => None,
    }
}
```

## Response Handling

### Response Structure

Worldpay responses use a complex nested structure:

```rust
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayPaymentsResponse {
    pub outcome: PaymentOutcome,
    pub transaction_reference: Option<String>,
    #[serde(flatten)]
    pub other_fields: Option<WorldpayPaymentResponseFields>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WorldpayPaymentResponseFields {
    RefusedResponse(RefusedResponse),
    DDCResponse(DDCResponse),
    ThreeDsChallenged(ThreeDsChallengedResponse),
    FraudHighRisk(FraudHighRiskResponse),
    AuthorizedResponse(Box<AuthorizedResponse>),
}
```

### Payment Outcomes

```rust
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PaymentOutcome {
    #[serde(alias = "authorized", alias = "Authorized")]
    Authorized,
    Refused,
    SentForSettlement,
    SentForRefund,
    FraudHighRisk,
    #[serde(alias = "3dsDeviceDataRequired")]
    ThreeDsDeviceDataRequired,
    SentForCancellation,
    #[serde(alias = "3dsAuthenticationFailed")]
    ThreeDsAuthenticationFailed,
    SentForPartialRefund,
    #[serde(alias = "3dsChallenged")]
    ThreeDsChallenged,
    #[serde(alias = "3dsUnavailable")]
    ThreeDsUnavailable,
}
```

### Response Transformation Logic

The response transformation handles different response types:

```rust
let (description, redirection_data, mandate_reference, network_txn_id, error) = router_data
    .response
    .other_fields
    .as_ref()
    .map(|other_fields| match other_fields {
        WorldpayPaymentResponseFields::AuthorizedResponse(res) => (
            res.description.clone(),
            None,
            res.token.as_ref().map(|mandate_token| MandateReference {
                connector_mandate_id: Some(mandate_token.href.clone().expose()),
                payment_method_id: Some(mandate_token.token_id.clone()),
                mandate_metadata: None,
                connector_mandate_request_reference_id: None,
            }),
            res.scheme_reference.clone(),
            None,
        ),
        WorldpayPaymentResponseFields::DDCResponse(res) => (
            None,
            Some(RedirectForm::WorldpayDDCForm {
                endpoint: res.device_data_collection.url.clone(),
                method: common_utils::request::Method::Post,
                collection_id: Some("SessionId".to_string()),
                form_fields: HashMap::from([
                    ("Bin".to_string(), res.device_data_collection.bin.clone().expose()),
                    ("JWT".to_string(), res.device_data_collection.jwt.clone().expose()),
                ]),
            }),
            None,
            None,
            None,
        ),
        WorldpayPaymentResponseFields::ThreeDsChallenged(res) => (
            None,
            Some(RedirectForm::Form {
                endpoint: res.challenge.url.to_string(),
                method: common_utils::request::Method::Post,
                form_fields: HashMap::from([(
                    "JWT".to_string(),
                    res.challenge.jwt.clone().expose(),
                )]),
            }),
            None,
            None,
            None,
        ),
        WorldpayPaymentResponseFields::RefusedResponse(res) => (
            None,
            None,
            None,
            None,
            Some((
                res.refusal_code.clone(),
                res.refusal_description.clone(),
                res.advice.as_ref().and_then(|advice_code| advice_code.code.clone()),
            )),
        ),
        WorldpayPaymentResponseFields::FraudHighRisk(_) => (None, None, None, None, None),
    })
    .unwrap_or((None, None, None, None, None));
```

## Authentication

### Authentication Types Supported

Worldpay supports two authentication methods:

1. **BodyKey (Legacy)**: For backwards compatibility
2. **SignatureKey**: Recommended approach

```rust
impl TryFrom<&ConnectorAuthType> for WorldpayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            // Legacy support
            ConnectorAuthType::BodyKey { api_key, key1 } => {
                let auth_key = format!("{}:{}", key1.peek(), api_key.peek());
                let auth_header = format!("Basic {}", BASE64_ENGINE.encode(auth_key));
                Ok(Self {
                    api_key: Secret::new(auth_header),
                    entity_id: Secret::new("default".to_string()),
                })
            }
            // Recommended approach
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => {
                let auth_key = format!("{}:{}", key1.peek(), api_key.peek());
                let auth_header = format!("Basic {}", BASE64_ENGINE.encode(auth_key));
                Ok(Self {
                    api_key: Secret::new(auth_header),
                    entity_id: api_secret.clone(),
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType)?,
        }
    }
}
```

### Header Construction

The connector builds standard headers for all requests:

```rust
fn build_headers(
    &self,
    req: &RouterData<Flow, Request, Response>,
    _connectors: &Connectors,
) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
    let mut headers = vec![
        (headers::ACCEPT.to_string(), self.get_content_type().to_string().into()),
        (headers::CONTENT_TYPE.to_string(), self.get_content_type().to_string().into()),
        (headers::WP_API_VERSION.to_string(), "2024-06-01".into()),
    ];
    let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
    headers.append(&mut api_key);
    Ok(headers)
}
```

## 3DS Support

### 3DS Request Creation

3DS support is comprehensive with device data collection and challenge handling:

```rust
fn create_three_ds_request<T: WorldpayPaymentsRequestData>(
    router_data: &T,
    is_mandate_payment: bool,
) -> Result<Option<ThreeDSRequest>, error_stack::Report<errors::ConnectorError>> {
    match (
        router_data.get_auth_type(),
        router_data.get_payment_method_data(),
    ) {
        // 3DS for NTI flow
        (_, PaymentMethodData::CardDetailsForNetworkTransactionId(_)) => Ok(None),
        // 3DS for regular payments
        (enums::AuthenticationType::ThreeDs, _) => {
            let browser_info = router_data.get_browser_info().ok_or(
                errors::ConnectorError::MissingRequiredField {
                    field_name: "browser_info",
                },
            )?;

            Ok(Some(ThreeDSRequest {
                three_ds_type: THREE_DS_TYPE.to_string(),    // "integrated"
                mode: THREE_DS_MODE.to_string(),             // "always"
                device_data: ThreeDSRequestDeviceData {
                    accept_header: browser_info.accept_header.clone().get_required_value("accept_header")?,
                    user_agent_header: browser_info.user_agent.clone().get_required_value("user_agent")?,
                    browser_language: browser_info.language.clone(),
                    browser_screen_width: browser_info.screen_width,
                    browser_screen_height: browser_info.screen_height,
                    browser_color_depth: browser_info.color_depth.map(|depth| depth.to_string()),
                    time_zone: browser_info.time_zone.map(|tz| tz.to_string()),
                    browser_java_enabled: browser_info.java_enabled,
                    browser_javascript_enabled: browser_info.java_script_enabled,
                    channel: Some(ThreeDSRequestChannel::Browser),
                },
                challenge: ThreeDSRequestChallenge {
                    return_url: router_data.get_return_url()?,
                    preference: if is_mandate_payment {
                        Some(ThreeDsPreference::ChallengeMandated)
                    } else {
                        None
                    },
                },
            }))
        }
        // Non 3DS
        _ => Ok(None),
    }
}
```

### 3DS Response Types

Worldpay returns different response types for 3DS:

1. **Device Data Collection (DDC)**: Initial step for 3DS
2. **Challenge**: When 3DS challenge is required
3. **Authentication Failed**: When 3DS fails
4. **Frictionless**: When 3DS passes without challenge

## Payment Methods

### Supported Payment Methods

```rust
static WORLDPAY_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(|| {
        let supported_capture_methods = vec![
            enums::CaptureMethod::Automatic,
            enums::CaptureMethod::Manual,
            enums::CaptureMethod::SequentialAutomatic,
        ];

        let supported_card_network = vec![
            common_enums::CardNetwork::AmericanExpress,
            common_enums::CardNetwork::CartesBancaires,
            common_enums::CardNetwork::DinersClub,
            common_enums::CardNetwork::JCB,
            common_enums::CardNetwork::Maestro,
            common_enums::CardNetwork::Mastercard,
            common_enums::CardNetwork::Visa,
        ];

        let mut worldpay_supported_payment_methods = SupportedPaymentMethods::new();

        // Credit Cards
        worldpay_supported_payment_methods.add(
            enums::PaymentMethod::Card,
            enums::PaymentMethodType::Credit,
            PaymentMethodDetails {
                mandates: enums::FeatureStatus::Supported,
                refunds: enums::FeatureStatus::Supported,
                supported_capture_methods: supported_capture_methods.clone(),
                specific_features: Some(
                    api_models::feature_matrix::PaymentMethodSpecificFeatures::Card({
                        api_models::feature_matrix::CardSpecificFeatures {
                            three_ds: common_enums::FeatureStatus::Supported,
                            no_three_ds: common_enums::FeatureStatus::Supported,
                            supported_card_networks: supported_card_network.clone(),
                        }
                    }),
                ),
            },
        );

        // Debit Cards
        worldpay_supported_payment_methods.add(
            enums::PaymentMethod::Card,
            enums::PaymentMethodType::Debit,
            PaymentMethodDetails {
                mandates: enums::FeatureStatus::Supported,
                refunds: enums::FeatureStatus::Supported,
                supported_capture_methods: supported_capture_methods.clone(),
                specific_features: Some(
                    api_models::feature_matrix::PaymentMethodSpecificFeatures::Card({
                        api_models::feature_matrix::CardSpecificFeatures {
                            three_ds: common_enums::FeatureStatus::Supported,
                            no_three_ds: common_enums::FeatureStatus::Supported,
                            supported_card_networks: supported_card_network.clone(),
                        }
                    }),
                ),
            },
        );

        // Google Pay
        worldpay_supported_payment_methods.add(
            enums::PaymentMethod::Wallet,
            enums::PaymentMethodType::GooglePay,
            PaymentMethodDetails {
                mandates: enums::FeatureStatus::NotSupported,
                refunds: enums::FeatureStatus::Supported,
                supported_capture_methods: supported_capture_methods.clone(),
                specific_features: None,
            },
        );

        // Apple Pay
        worldpay_supported_payment_methods.add(
            enums::PaymentMethod::Wallet,
            enums::PaymentMethodType::ApplePay,
            PaymentMethodDetails {
                mandates: enums::FeatureStatus::NotSupported,
                refunds: enums::FeatureStatus::Supported,
                supported_capture_methods: supported_capture_methods.clone(),
                specific_features: None,
            },
        );

        worldpay_supported_payment_methods
    });
```

### Payment Method Mapping

```rust
impl TryFrom<(enums::PaymentMethod, Option<enums::PaymentMethodType>)> for PaymentMethod {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        src: (enums::PaymentMethod, Option<enums::PaymentMethodType>),
    ) -> Result<Self, Self::Error> {
        match (src.0, src.1) {
            (enums::PaymentMethod::Card, _) => Ok(Self::Card),
            (enums::PaymentMethod::Wallet, pmt) => {
                let pm = pmt.ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "payment_method_type",
                })?;
                match pm {
                    enums::PaymentMethodType::ApplePay => Ok(Self::ApplePay),
                    enums::PaymentMethodType::GooglePay => Ok(Self::GooglePay),
                    _ => Err(errors::ConnectorError::NotImplemented(
                        utils::get_unimplemented_payment_method_error_message("worldpay"),
                    )),
                }
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("worldpay"),
            )),
        }
    }
}
```

## Error Handling

### Error Response Structure

```rust
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayErrorResponse {
    pub error_name: String,
    pub message: String,
    pub validation_errors: Option<serde_json::Value>,
}

impl WorldpayErrorResponse {
    pub fn default(status_code: u16) -> Self {
        match status_code {
            code @ 404 => Self {
                error_name: format!("{code} Not found"),
                message: "Resource not found".to_string(),
                validation_errors: None,
            },
            code => Self {
                error_name: code.to_string(),
                message: "Unknown error".to_string(),
                validation_errors: None,
            },
        }
    }
}
```

### Error Response Building

```rust
fn build_error_response(
    &self,
    res: Response,
    event_builder: Option<&mut ConnectorEvent>,
) -> CustomResult<ErrorResponse, errors::ConnectorError> {
    let response = if !res.response.is_empty() {
        res.response
            .parse_struct("WorldpayErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?
    } else {
        WorldpayErrorResponse::default(res.status_code)
    };

    event_builder.map(|i| i.set_error_response_body(&response));
    router_env::logger::info!(connector_response=?response);

    Ok(ErrorResponse {
        status_code: res.status_code,
        code: response.error_name,
        message: response.message,
        reason: response.validation_errors.map(|e| e.to_string()),
        attempt_status: Some(enums::AttemptStatus::Failure),
        connector_transaction_id: None,
        network_advice_code: None,
        network_decline_code: None,
        network_error_message: None,
        connector_metadata: None,
    })
}
```

## Status Mapping

### Payment Status Mapping

```rust
impl From<PaymentOutcome> for enums::AttemptStatus {
    fn from(item: PaymentOutcome) -> Self {
        match item {
            PaymentOutcome::Authorized => Self::Authorized,
            PaymentOutcome::SentForSettlement => Self::Charged,
            PaymentOutcome::ThreeDsDeviceDataRequired => Self::DeviceDataCollectionPending,
            PaymentOutcome::ThreeDsAuthenticationFailed => Self::AuthenticationFailed,
            PaymentOutcome::ThreeDsChallenged => Self::AuthenticationPending,
            PaymentOutcome::SentForCancellation => Self::VoidInitiated,
            PaymentOutcome::SentForPartialRefund | PaymentOutcome::SentForRefund => {
                Self::AutoRefunded
            }
            PaymentOutcome::Refused | PaymentOutcome::FraudHighRisk => Self::Failure,
            PaymentOutcome::ThreeDsUnavailable => Self::AuthenticationFailed,
        }
    }
}
```

### Event Type Status Mapping

```rust
impl From<&EventType> for enums::AttemptStatus {
    fn from(value: &EventType) -> Self {
        match value {
            EventType::SentForAuthorization => Self::Authorizing,
            EventType::SentForSettlement => Self::Charged,
            EventType::Settled => Self::Charged,
            EventType::Authorized => Self::Authorized,
            EventType::Refused
            | EventType::SettlementFailed
            | EventType::Expired
            | EventType::Cancelled
            | EventType::Error => Self::Failure,
            EventType::SentForRefund
            | EventType::RefundFailed
            | EventType::Refunded
            | EventType::Unknown => Self::Pending,
        }
    }
}
```

### Refund Status Mapping

```rust
impl From<PaymentOutcome> for enums::RefundStatus {
    fn from(item: PaymentOutcome) -> Self {
        match item {
            PaymentOutcome::SentForPartialRefund | PaymentOutcome::SentForRefund => Self::Success,
            PaymentOutcome::Refused
            | PaymentOutcome::FraudHighRisk
            | PaymentOutcome::Authorized
            | PaymentOutcome::SentForSettlement
            | PaymentOutcome::ThreeDsDeviceDataRequired
            | PaymentOutcome::ThreeDsAuthenticationFailed
            | PaymentOutcome::ThreeDsChallenged
            | PaymentOutcome::SentForCancellation
            | PaymentOutcome::ThreeDsUnavailable => Self::Failure,
        }
    }
}
```

## Webhook Processing

### Webhook Verification

Worldpay webhooks are verified using HMAC-SHA256:

```rust
async fn verify_webhook_source(
    &self,
    request: &IncomingWebhookRequestDetails<'_>,
    merchant_id: &common_utils::id_type::MerchantId,
    connector_webhook_details: Option<common_utils::pii::SecretSerdeValue>,
    _connector_account_details: crypto::Encryptable<masking::Secret<serde_json::Value>>,
    connector_label: &str,
) -> CustomResult<bool, errors::ConnectorError> {
    let connector_webhook_secrets = self
        .get_webhook_source_verification_merchant_secret(
            merchant_id,
            connector_label,
            connector_webhook_details,
        )
        .await
        .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;
    let signature = self
        .get_webhook_source_verification_signature(request, &connector_webhook_secrets)
        .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;
    let message = self
        .get_webhook_source_verification_message(
            request,
            merchant_id,
            &connector_webhook_secrets,
        )
        .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;
    let secret_key = hex::decode(connector_webhook_secrets.secret)
        .change_context(errors::ConnectorError::WebhookVerificationSecretInvalid)?;

    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, &secret_key);
    let signed_message = hmac::sign(&signing_key, &message);
    let computed_signature = hex::encode(signed_message.as_ref());

    Ok(computed_signature.as_bytes() == hex::encode(signature).as_bytes())
}
```

### Webhook Event Processing

```rust
fn get_webhook_event_type(
    &self,
    request: &IncomingWebhookRequestDetails<'_>,
) -> CustomResult<IncomingWebhookEvent, errors::ConnectorError> {
    let body: WorldpayWebhookEventType = request
        .body
        .parse_struct("WorldpayWebhookEventType")
        .change_context(errors::ConnectorError::WebhookReferenceIdNotFound)?;
    match body.event_details.event_type {
        EventType::Authorized => Ok(IncomingWebhookEvent::PaymentIntentAuthorizationSuccess),
        EventType::Settled => Ok(IncomingWebhookEvent::PaymentIntentSuccess),
        EventType::SentForSettlement | EventType::SentForAuthorization => {
            Ok(IncomingWebhookEvent::PaymentIntentProcessing)
        }
        EventType::Error | EventType::Expired | EventType::SettlementFailed => {
            Ok(IncomingWebhookEvent::PaymentIntentFailure)
        }
        EventType::Unknown
        | EventType::Cancelled
        | EventType::Refused
        | EventType::Refunded
        | EventType::SentForRefund
        | EventType::RefundFailed => Ok(IncomingWebhookEvent::EventNotSupported),
    }
}
```

### Webhook Structure

```rust
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayWebhookEventType {
    pub event_id: String,
    pub event_timestamp: String,
    pub event_details: EventDetails,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventDetails {
    #[serde(rename = "type")]
    pub event_type: EventType,
    pub transaction_reference: String,
    pub token: Option<MandateToken>,
    pub scheme_reference: Option<Secret<String>>,
}
```

## Mandate Handling

### Token Creation and Customer Agreement

The connector supports mandate payments through token creation and customer agreements:

```rust
fn get_token_and_agreement(
    payment_method_data: &PaymentMethodData,
    setup_future_usage: Option<enums::FutureUsage>,
    off_session: Option<bool>,
    mandate_ids: Option<MandateIds>,
) -> (Option<TokenCreation>, Option<CustomerAgreement>) {
    match (payment_method_data, setup_future_usage, off_session) {
        // CIT (Customer Initiated Transaction)
        (PaymentMethodData::Card(_), Some(enums::FutureUsage::OffSession), _) => (
            Some(TokenCreation {
                token_type: TokenCreationType::Worldpay,
            }),
            Some(CustomerAgreement {
                agreement_type: CustomerAgreementType::Subscription,
                stored_card_usage: Some(StoredCardUsageType::First),
                scheme_reference: None,
            }),
        ),
        // MIT (Merchant Initiated Transaction)
        (PaymentMethodData::Card(_), _, Some(true)) => (
            None,
            Some(CustomerAgreement {
                agreement_type: CustomerAgreementType::Subscription,
                stored_card_usage: Some(StoredCardUsageType::Subsequent),
                scheme_reference: None,
            }),
        ),
        // NTI (Network Transaction ID) with raw card data
        (PaymentMethodData::CardDetailsForNetworkTransactionId(_), _, _) => (
            None,
            mandate_ids.and_then(|mandate_ids| {
                mandate_ids
                    .mandate_reference_id
                    .and_then(|mandate_id| match mandate_id {
                        MandateReferenceId::NetworkMandateId(network_transaction_id) => {
                            Some(CustomerAgreement {
                                agreement_type: CustomerAgreementType::Unscheduled,
                                scheme_reference: Some(network_transaction_id.into()),
                                stored_card_usage: None,
                            })
                        }
                        _ => None,
                    })
            }),
        ),
        _ => (None, None),
    }
}
```

### Mandate Payment Processing

```rust
PaymentMethodData::MandatePayment => mandate_ids
    .and_then(|mandate_ids| {
        mandate_ids
            .mandate_reference_id
            .and_then(|mandate_id| match mandate_id {
                MandateReferenceId::ConnectorMandateId(connector_mandate_id) => {
                    connector_mandate_id.get_connector_mandate_id().map(|href| {
                        PaymentInstrument::CardToken(CardToken {
                            payment_type: PaymentType::Token,
                            href,
                            cvc: None,
                        })
                    })
                }
                _ => None,
            })
    })
    .ok_or(
        errors::ConnectorError::MissingRequiredField {
            field_name: "connector_mandate_id",
        }
        .into(),
    ),
```

## Configuration

### Connector Metadata Requirements

The Worldpay connector requires specific metadata configuration:

```rust
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WorldpayConnectorMetadataObject {
    pub merchant_name: Option<Secret<String>>,
}
```

**Required Configuration:**
- `merchant_name`: Required field used in payment narrative

### Authentication Configuration

**SignatureKey Authentication (Recommended):**
```json
{
  "auth_type": "SignatureKey",
  "api_key": "your_username",
  "key1": "your_password", 
  "api_secret": "your_entity_id"
}
```

**BodyKey Authentication (Legacy):**
```json
{
  "auth_type": "BodyKey",
  "api_key": "your_username",
  "key1": "your_password"
}
```

### API Version

The connector uses API version `2024-06-01` as specified in the headers.

### Supported Flows

```rust
static WORLDPAY_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 1] = [enums::EventClass::Payments];
```

## Testing

### Test Cards

Worldpay provides test card numbers for different scenarios:

**Successful Authorization:**
- Visa: `4111111111111111`
- Mastercard: `5555555555554444`
- American Express: `378282246310005`

**3DS Test Cards:**
- Challenge Required: `4000000000001091`
- Frictionless: `4000000000001000`

### Test Environments

- **Sandbox URL**: Use sandbox base URL for testing
- **Test Credentials**: Use test authentication credentials
- **Mock Webhooks**: Worldpay provides webhook testing tools

### Unit Testing Patterns

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_outcome_mapping() {
        assert_eq!(
            enums::AttemptStatus::from(PaymentOutcome::Authorized),
            enums::AttemptStatus::Authorized
        );
        assert_eq!(
            enums::AttemptStatus::from(PaymentOutcome::Refused),
            enums::AttemptStatus::Failure
        );
    }

    #[test]
    fn test_auth_header_construction() {
        // Test authentication header construction
    }

    #[test]
    fn test_request_transformation() {
        // Test router data to Worldpay request transformation
    }
}
```

## Common Patterns

### Resource ID Extraction

A utility function extracts resource IDs from various response types:

```rust
pub fn get_resource_id<T, F>(
    response: WorldpayPaymentsResponse,
    connector_transaction_id: Option<String>,
    transform_fn: F,
) -> Result<T, error_stack::Report<errors::ConnectorError>>
where
    F: Fn(String) -> T,
{
    let optional_reference_id = response
        .other_fields
        .as_ref()
        .and_then(|other_fields| match other_fields {
            WorldpayPaymentResponseFields::AuthorizedResponse(res) => res
                .links
                .as_ref()
                .and_then(|link| link.self_link.href.rsplit_once('/').map(|(_, h)| h)),
            WorldpayPaymentResponseFields::DDCResponse(res) => {
                res.actions.supply_ddc_data.href.split('/').nth_back(1)
            }
            WorldpayPaymentResponseFields::ThreeDsChallenged(res) => res
                .actions
                .complete_three_ds_challenge
                .href
                .split('/')
                .nth_back(1),
            WorldpayPaymentResponseFields::FraudHighRisk(_)
            | WorldpayPaymentResponseFields::RefusedResponse(_) => None,
        })
        .map(|href| {
            urlencoding::decode(href)
                .map(|s| transform_fn(s.into_owned()))
                .change_context(errors::ConnectorError::ResponseHandlingFailed)
        })
        .transpose()?;
    optional_reference_id
        .or_else(|| connector_transaction_id.map(transform_fn))
        .ok_or_else(|| {
            errors::ConnectorError::MissingRequiredField {
                field_name: "_links.self.href",
            }
            .into()
        })
}
```

### Amount Conversion

The connector uses `MinorUnitForConnector` for amount handling:

```rust
let amount_to_capture = convert_amount(
    self.amount_converter,
    req.request.minor_amount_to_capture,
    req.request.currency,
)?;
```

### Correlation ID Handling

Worldpay provides correlation IDs in response headers:

```rust
let optional_correlation_id = res.headers.and_then(|headers| {
    headers
        .get(WP_CORRELATION_ID)  // "WP-CorrelationId"
        .and_then(|header_value| header_value.to_str().ok())
        .map(|id| id.to_string())
});
```

## Troubleshooting

### Common Issues

#### 1. Authentication Failures

**Symptoms:**
- 401 Unauthorized responses
- "Invalid credentials" errors

**Solutions:**
- Verify API credentials are correct
- Ensure proper Base64 encoding of username:password
- Check entity ID is valid for SignatureKey auth

#### 2. 3DS Issues

**Symptoms:**
- 3DS not triggering when expected
- Device data collection failures
- Challenge flow not working

**Solutions:**
- Verify browser_info is properly populated
- Check return_url is accessible
- Ensure 3DS is enabled in Worldpay configuration

#### 3. Webhook Verification Failures

**Symptoms:**
- Webhook signature verification fails
- "Invalid webhook source" errors

**Solutions:**
- Verify webhook secret is correct
- Check HMAC-SHA256 signature calculation
- Ensure webhook URL is properly configured

#### 4. Payment Method Not Supported

**Symptoms:**
- "NotImplemented" errors for certain payment methods
- Unsupported payment method type errors

**Solutions:**
- Check payment method is in supported list
- Verify payment method configuration
- Review Worldpay account capabilities

### Debug Logging

Enable debug logging to trace request/response flow:

```rust
router_env::logger::info!(connector_response=?response);
router_env::logger::debug!(raw_connector_request=?connector_req_object);
```

### Response Validation

Check response status codes:
- `200`: Success
- `202`: Accepted (for async operations)
- `400`: Bad Request
- `401`: Unauthorized
- `404`: Not Found
- `422`: Unprocessable Entity

### Network Transaction ID (NTI) Flow

For NTI payments, ensure:
- Network transaction ID is available
- Card details match the original transaction
- Proper customer agreement setup

### Mandate Payment Debugging

For mandate payment issues:
- Verify connector mandate ID is valid
- Check token expiration
- Ensure proper stored card usage type

---

## Summary

The Worldpay connector provides comprehensive support for:

1. **Payment Authorization**: Full card, wallet, and mandate payment support
2. **3DS Authentication**: Device data collection and challenge handling
3. **Multiple Payment Methods**: Cards, Google Pay, Apple Pay
4. **Mandate Management**: Token creation and subsequent payments
5. **Webhook Processing**: Secure webhook verification and event handling
6. **Error Handling**: Comprehensive error mapping and status handling
7. **Network Transaction ID**: Support for NTI-based payments

The implementation follows Hyperswitch patterns and provides robust error handling, comprehensive logging, and extensive status mapping to ensure reliable payment processing through the Worldpay platform.
