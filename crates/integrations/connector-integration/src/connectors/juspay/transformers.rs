use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, CardNetwork, RefundStatus};
use common_utils::{request::Method, types::StringMajorUnit};
use domain_types::{
    connector_flow::{Authorize, Capture, CreateOrder, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorSpecificConfig,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::connectors::juspay::JuspayAmountConvertor;

#[derive(Debug, Clone)]
pub struct JuspayAuthType {
    pub api_key: Secret<String>,
    pub merchant_id: Secret<String>,
}

impl TryFrom<&ConnectorSpecificConfig> for JuspayAuthType {
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Juspay {
                api_key,
                merchant_id,
                ..
            } => Ok(Self {
                api_key: api_key.to_owned(),
                merchant_id: merchant_id.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::IntegrationError::FailedToObtainAuthType {
                    context: errors::IntegrationErrorContext::default()
                }
            )),
        }
    }
}

/// Juspay error envelope.
///
/// Juspay APIs return errors in (at least) two shapes:
///
/// 1. Order/payment errors:
///    `{ "status": "ERROR", "error_code": "...", "error_message": "...",
///       "error_info": { "code": "...", "user_message": "...",
///                       "developer_message": "..." } }`
///
/// 2. HTTP-level / auth errors:
///    `{ "status": "ERROR", "error_message": "..." }` (no `error_code`)
///
/// Every field is optional so deserialization never fails on a missing key.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JuspayErrorResponse {
    pub status: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub error_info: Option<JuspayErrorInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JuspayErrorInfo {
    pub code: Option<String>,
    pub user_message: Option<String>,
    pub developer_message: Option<String>,
    pub fields: Option<serde_json::Value>,
}

// =============================================================================
// JuspayOrderStatus
// =============================================================================
//
// Juspay normalises every order / transaction state into a single status
// string (and matching numeric `status_id`). The enum below covers the full
// set documented in the EC tech spec; it is shared across CreateOrder,
// Authorize, PSync, Capture and Void so each flow can apply its own
// `From<JuspayOrderStatus> for AttemptStatus` mapping without re-parsing.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JuspayOrderStatus {
    /// 10 - Order created, no transaction attempted yet.
    New,
    /// 20 - Transaction initiated but not progressed to authentication.
    Started,
    /// 22 - Transaction declined by Juspay's risk engine.
    JuspayDeclined,
    /// 23 - 3DS challenge issued; redirect URL is in `payment.authentication.url`.
    PendingVbv,
    /// 24 - 3DS challenge succeeded; authorization typically follows.
    VbvSuccessful,
    /// 25 - Funds held on the cardholder (pre-auth).
    Authorized,
    /// 26 - 3DS / authentication failed.
    AuthenticationFailed,
    /// 27 - Authorization (post-auth) failed at the issuer.
    AuthorizationFailed,
    /// 28 - Authorization in flight at the gateway.
    Authorizing,
    /// 21 - Funds captured.
    Charged,
    /// 29 - Cash-on-delivery flow initiated; not relevant for cards.
    CodInitiated,
    /// 31 - Authorization voided successfully.
    Voided,
    /// 32 - Void pending at the gateway.
    VoidInitiated,
    /// 35 - Void declined by the gateway.
    VoidFailed,
    /// 33 - Capture pending at the gateway.
    CaptureInitiated,
    /// 34 - Capture failed.
    CaptureFailed,
    /// 36 - Juspay auto-refunded the held funds (timeout / risk).
    AutoRefunded,
    /// 40 - Order not found.
    NotFound,
}

/// Map the order envelope status returned by `POST /orders` to a UCS
/// `AttemptStatus`. CreateOrder almost always returns `NEW`, but the same
/// status enum is shared with PSync/Authorize/Capture/Void so we cover every
/// terminal state here. Downstream flows can refine the mapping (e.g. PSync
/// distinguishes capture / void transitions) by adding their own
/// `From<JuspayOrderStatus> for AttemptStatus` if needed.
impl From<JuspayOrderStatus> for AttemptStatus {
    fn from(status: JuspayOrderStatus) -> Self {
        match status {
            JuspayOrderStatus::New => Self::Started,
            JuspayOrderStatus::Started
            | JuspayOrderStatus::Authorizing
            | JuspayOrderStatus::VbvSuccessful
            | JuspayOrderStatus::CodInitiated => Self::Pending,
            JuspayOrderStatus::PendingVbv => Self::AuthenticationPending,
            JuspayOrderStatus::Authorized => Self::Authorized,
            JuspayOrderStatus::Charged => Self::Charged,
            JuspayOrderStatus::Voided => Self::Voided,
            JuspayOrderStatus::VoidInitiated => Self::VoidInitiated,
            JuspayOrderStatus::CaptureInitiated => Self::CaptureInitiated,
            JuspayOrderStatus::CaptureFailed => Self::CaptureFailed,
            JuspayOrderStatus::VoidFailed => Self::VoidFailed,
            JuspayOrderStatus::AutoRefunded => Self::AutoRefunded,
            JuspayOrderStatus::AuthenticationFailed
            | JuspayOrderStatus::AuthorizationFailed
            | JuspayOrderStatus::JuspayDeclined
            | JuspayOrderStatus::NotFound => Self::Failure,
        }
    }
}

// =============================================================================
// CreateOrder - Request
// =============================================================================
//
// Juspay's `POST /orders` endpoint expects `application/x-www-form-urlencoded`
// with nested fields flattened using dot notation (e.g.
// `metadata.txns.auto_capture=false`). serde_urlencoded does not flatten
// structs, so the nested keys are spelled out one-per-field via
// `#[serde(rename = "...")]`. Every optional field is `Option<_>` so that
// `serde_urlencoded` omits the key entirely when unset (preventing empty
// `field=` pairs that Juspay rejects on some endpoints).

#[derive(Debug, Clone, Serialize)]
pub struct JuspayCreateOrderRequest {
    /// Merchant-supplied unique order identifier (<= 21 chars, alphanumeric).
    /// We use the UCS `connector_request_reference_id` which is generated
    /// upstream and persisted on the attempt, giving us a stable, unique id
    /// per Juspay order.
    pub order_id: String,

    /// Major-unit amount, e.g. "100.00". Juspay's global EC docset expects
    /// major units regardless of currency.
    pub amount: StringMajorUnit,

    /// ISO-4217 alpha-3 code (INR, HKD, SGD, EUR, USD, GBP). Defaults to INR
    /// server-side if omitted, but we always send it explicitly.
    pub currency: String,

    /// Merchant's customer identifier. Empty string is accepted by Juspay for
    /// guest checkouts -- we fall back to the UCS payment_id when no customer
    /// is bound to the attempt.
    pub customer_id: String,

    /// Optional post-payment redirect URL. Populated from
    /// `PaymentFlowData::return_url` when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_url: Option<String>,

    /// Optional dynamic webhook destination. Populated from
    /// `PaymentCreateOrderData::webhook_url` when present.
    #[serde(rename = "metadata.webhook_url", skip_serializing_if = "Option::is_none")]
    pub metadata_webhook_url: Option<String>,

    /// `false` puts the order in pre-auth mode so that the subsequent /txns
    /// call yields `AUTHORIZED` rather than `CHARGED`, leaving Capture/Void
    /// available downstream. UCS always requires pre-auth here because the
    /// capture / cancel decision is made later in the flow.
    #[serde(rename = "metadata.txns.auto_capture")]
    pub metadata_txns_auto_capture: bool,
}

// =============================================================================
// CreateOrder - Response
// =============================================================================
//
// On success Juspay returns the Juspay-internal order handle (`id`, prefixed
// with `ord_`), echoes the merchant `order_id`, and optionally includes hosted
// payment links. We retain the payment links struct for forward compatibility
// (downstream redirect-based wallet flows can surface `payment_links.web`),
// but only `order_id` is required for the Authorize / PSync calls that
// follow.

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JuspayCreateOrderResponse {
    /// Juspay-internal order handle, opaque, e.g. `ord_e294a2...`. Not used
    /// for downstream calls (Authorize / PSync / Capture / Void take the
    /// merchant `order_id` instead) but persisted for debugging.
    pub id: String,
    /// Echo of the merchant `order_id` we sent. This is the value the rest of
    /// the EC API expects.
    pub order_id: String,
    /// Always `NEW` on a fresh create. Modelled as the shared
    /// `JuspayOrderStatus` so the value can be mapped to `AttemptStatus`.
    pub status: JuspayOrderStatus,
    /// Hosted payment-page URLs. Optional because not every account / API
    /// version returns them. Retained for forward compatibility with future
    /// redirect-based payment-method flows (e.g. wallets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_links: Option<JuspayPaymentLinks>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JuspayPaymentLinks {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mobile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iframe: Option<String>,
}

// =============================================================================
// CreateOrder - Request transformation
// =============================================================================
//
// The macro hands us a `JuspayRouterData<...>` wrapper produced by
// `create_all_prerequisites!`. That wrapper holds both the connector (so
// shared helpers stay accessible) and the inner `RouterDataV2`. We pull
// the inner `RouterDataV2` out and build the form body from
// `PaymentCreateOrderData` + the shared `PaymentFlowData`.
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        crate::connectors::juspay::JuspayRouterData<
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
            T,
        >,
    > for JuspayCreateOrderRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        wrapper: crate::connectors::juspay::JuspayRouterData<
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = wrapper.router_data;

        // Amount conversion: PaymentCreateOrderData carries a MinorUnit but
        // Juspay expects major units as a stringified decimal. The shared
        // `JuspayAmountConvertor` (created via `create_amount_converter_wrapper!`)
        // routes through the StringMajorUnit converter.
        let amount = JuspayAmountConvertor::convert(
            router_data.request.amount,
            router_data.request.currency,
        )?;

        // Customer id: Juspay requires the field but allows an empty string
        // for guest checkouts. Prefer the bound CustomerId; fall back to the
        // payment_id so we always have a stable, non-empty identifier on the
        // dashboard rather than blank guest rows.
        let customer_id = router_data
            .resource_common_data
            .customer_id
            .as_ref()
            .map(|cid| cid.get_string_repr().to_string())
            .unwrap_or_else(|| router_data.resource_common_data.payment_id.clone());

        Ok(Self {
            order_id: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount,
            currency: router_data.request.currency.to_string(),
            customer_id,
            return_url: router_data.resource_common_data.return_url.clone(),
            metadata_webhook_url: router_data.request.webhook_url.clone(),
            // Always create the order in pre-auth mode so the subsequent
            // Authorize / Capture / Void state machine is available. UCS makes
            // the capture-vs-cancel decision later in the flow; Juspay's
            // single-step auto-capture mode would skip that.
            metadata_txns_auto_capture: false,
        })
    }
}

// =============================================================================
// CreateOrder - Response transformation
// =============================================================================
//
// On success we return the merchant `order_id` as the connector order id so
// downstream Authorize / PSync / Capture / Void calls can reference it via
// `connector_order_id`. We also mirror it into `reference_id` to match the
// pattern other order-create connectors (e.g. Cashfree) follow.
impl TryFrom<ResponseRouterData<JuspayCreateOrderResponse, Self>>
    for RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<JuspayCreateOrderResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let attempt_status = AttemptStatus::from(response.status);
        let order_id = response.order_id;

        Ok(Self {
            response: Ok(PaymentCreateOrderResponse {
                connector_order_id: order_id.clone(),
                session_data: None,
            }),
            resource_common_data: PaymentFlowData {
                status: attempt_status,
                reference_id: Some(order_id.clone()),
                connector_order_id: Some(order_id),
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// =============================================================================
// Authorize - Request
// =============================================================================
//
// Juspay `POST /txns` is form-urlencoded. The shape below covers the
// new-card path (saved-card / token / wallet variants land in a future
// add-payment-method pass). Optional fields are `Option<_>` so
// `serde_urlencoded` omits them entirely rather than emitting bare `key=`
// pairs, which Juspay rejects on some endpoints.

#[derive(Debug, Clone, Serialize)]
pub struct JuspayAuthorizeRequest {
    /// Merchant `order_id` previously created via `POST /orders`. Sourced
    /// from `PaymentFlowData::connector_order_id` (set by the CreateOrder
    /// response handler), falling back to `connector_request_reference_id`
    /// because both carry the same value.
    pub order_id: String,
    /// Merchant id (same value as the `x-merchantid` header). Juspay
    /// requires it in both the header and the form body on `/txns`.
    pub merchant_id: String,
    /// `CARD` for the card flow. New payment-method support extends this.
    pub payment_method_type: String,
    /// Card brand, e.g. `VISA`, `MASTERCARD`, `AMEX`. Derived from
    /// `Card::card_network`; the request fails with `MissingRequiredField`
    /// if the brand is unknown so we never send an empty value.
    pub payment_method: String,
    pub card_number: Secret<String>,
    pub card_exp_month: Secret<String>,
    pub card_exp_year: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_on_card: Option<Secret<String>>,
    pub card_security_code: Secret<String>,
    /// Pins the response to JSON regardless of `Accept`. Required by Juspay.
    pub format: String,
    /// `THREE_DS` for 3DS, `NO_THREE_DS` otherwise. Derived from
    /// `PaymentFlowData::auth_type`.
    pub auth_type: String,
    /// Asks Juspay to issue a redirect to `return_url` after 3DS / hosted
    /// flows complete. Only sent on 3DS to keep no-3DS calls minimal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_after_payment: Option<bool>,
}

// =============================================================================
// Authorize - Response
// =============================================================================
//
// On success the body carries `order_id`, the display `txn_id`, the opaque
// `txn_uuid` (needed for Capture/Void), and a `status` from the shared
// `JuspayOrderStatus` enum. For 3DS, the `payment.authentication` sub-object
// surfaces the redirect URL the orchestrator must navigate the cardholder to.
//
// `txn_uuid` is defensively `Option<String>` because the EC docs note it may
// occasionally be absent on `/txns` and only guaranteed on Order Status; when
// it is missing we fall back to `txn_id` so downstream Capture/Void calls
// still have something to look up.

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JuspayAuthorizeResponse {
    pub order_id: String,
    pub txn_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txn_uuid: Option<String>,
    pub status: JuspayOrderStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment: Option<JuspayAuthorizePayment>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JuspayAuthorizePayment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<JuspayAuthentication>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JuspayAuthentication {
    /// Usually `GET`; defaulted defensively so a missing key does not fail
    /// deserialization. Mapped to `common_utils::request::Method` when we
    /// build the `RedirectForm`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The 3DS challenge URL. Required for the `PENDING_VBV` case.
    pub url: String,
}

// =============================================================================
// Authorize - Request transformation
// =============================================================================
//
// The macro hands us the `JuspayRouterData<...>` wrapper holding both the
// converted amount and the inner `RouterDataV2`. (The /txns endpoint itself
// does not carry the amount in the body -- the order already does -- so we
// only consume the inner `RouterDataV2` here.)
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        crate::connectors::juspay::JuspayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for JuspayAuthorizeRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        wrapper: crate::connectors::juspay::JuspayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = wrapper.router_data;

        let auth = JuspayAuthType::try_from(&router_data.connector_config)?;

        // CreateOrder mirrors the merchant `order_id` into `connector_order_id`
        // (and `reference_id`). Prefer that, but fall back to
        // `connector_request_reference_id` (the source value) so the request
        // is well-formed even if a future caller skips CreateOrder.
        let order_id = router_data
            .resource_common_data
            .connector_order_id
            .clone()
            .unwrap_or_else(|| {
                router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone()
            });

        let card = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => {
                return Err(error_stack::report!(errors::IntegrationError::NotImplemented(
                    "Selected payment method for Juspay".to_string(),
                    Default::default(),
                )));
            }
        };

        // Juspay requires the brand as an explicit string ("VISA", "MASTERCARD",
        // etc.). UCS resolves it during card-network detection; if it is
        // missing the upstream caller did not run the detection step, in which
        // case we cannot safely guess and surface a missing-field error.
        let payment_method = card
            .card_network
            .as_ref()
            .map(card_network_to_juspay)
            .ok_or_else(|| {
                error_stack::report!(errors::IntegrationError::MissingRequiredField {
                    field_name: "payment_method_data.card.card_network",
                    context: Default::default(),
                })
            })?;

        // Juspay expects a 2-digit YY; UCS may carry the full 4-digit year.
        // Trim if needed.
        let card_exp_year_raw = card.card_exp_year.peek().clone();
        let card_exp_year = if card_exp_year_raw.len() == 4 {
            Secret::new(card_exp_year_raw[2..].to_string())
        } else {
            Secret::new(card_exp_year_raw)
        };

        let is_three_ds = matches!(
            router_data.resource_common_data.auth_type,
            common_enums::AuthenticationType::ThreeDs
        );
        let auth_type = if is_three_ds {
            "THREE_DS".to_string()
        } else {
            "NO_THREE_DS".to_string()
        };
        // Only opt in to the post-payment redirect on 3DS; for frictionless
        // flows the response is synchronous and a redirect is unnecessary.
        let redirect_after_payment = if is_three_ds { Some(true) } else { None };

        Ok(Self {
            order_id,
            merchant_id: auth.merchant_id.expose(),
            payment_method_type: "CARD".to_string(),
            payment_method,
            card_number: Secret::new(card.card_number.peek().to_string()),
            card_exp_month: card.card_exp_month.clone(),
            card_exp_year,
            name_on_card: card.card_holder_name.clone(),
            card_security_code: card.card_cvc.clone(),
            format: "json".to_string(),
            auth_type,
            redirect_after_payment,
        })
    }
}

/// Map UCS `CardNetwork` to the brand strings Juspay accepts on `/txns`.
/// Anything unmappable surfaces as a `NotImplemented` error in the caller --
/// silently sending an empty `payment_method` would otherwise be rejected by
/// Juspay with a generic validation error.
fn card_network_to_juspay(network: &CardNetwork) -> String {
    match network {
        CardNetwork::Visa => "VISA".to_string(),
        CardNetwork::Mastercard => "MASTERCARD".to_string(),
        CardNetwork::AmericanExpress => "AMEX".to_string(),
        CardNetwork::JCB => "JCB".to_string(),
        CardNetwork::DinersClub => "DINERS".to_string(),
        CardNetwork::Discover => "DISCOVER".to_string(),
        CardNetwork::UnionPay => "UNIONPAY".to_string(),
        CardNetwork::RuPay => "RUPAY".to_string(),
        CardNetwork::Maestro => "MAESTRO".to_string(),
        // Other networks (Interac, Star, Pulse, Accel, NYCE, CartesBancaires, etc.)
        // are not in Juspay's documented `payment_method` set; uppercase the
        // serialized form as a best-effort fallback so the request still goes
        // out with a non-empty value.
        other => format!("{other:?}").to_uppercase(),
    }
}

// =============================================================================
// Authorize - Response transformation
// =============================================================================
//
// Status is mapped via the shared `From<JuspayOrderStatus> for AttemptStatus`.
// For 3DS (`PENDING_VBV`) we surface the redirect URL in `redirection_data`
// as a `RedirectForm::Form` so the orchestrator can navigate the customer.
//
// `txn_uuid` is the value Capture / Void use. We mirror it into
// `connector_response_reference_id` (the documented secondary-id slot) so
// downstream flows can pull it back from `PaymentFlowData::reference_id`
// independently of the `resource_id` slot. The display `txn_id` goes into
// `resource_id` as the `connector_transaction_id` per the connector field
// mapping in the tech spec.
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<JuspayAuthorizeResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<JuspayAuthorizeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let status = AttemptStatus::from(response.status);

        // Build the 3DS redirect form when Juspay returned an authentication
        // URL. `payment.authentication.method` defaults to GET per the spec;
        // we parse it case-insensitively and fall back to GET.
        let redirection_data = response
            .payment
            .as_ref()
            .and_then(|p| p.authentication.as_ref())
            .map(|auth| {
                let method = auth
                    .method
                    .as_deref()
                    .and_then(|m| match m.to_ascii_uppercase().as_str() {
                        "GET" => Some(Method::Get),
                        "POST" => Some(Method::Post),
                        _ => None,
                    })
                    .unwrap_or(Method::Get);
                RedirectForm::Form {
                    endpoint: auth.url.clone(),
                    method,
                    form_fields: HashMap::new(),
                }
            });

        // `connector_transaction_id` should be the `txn_uuid` (Capture/Void
        // take it in the URL); we keep the display `txn_id` as the secondary
        // identifier. If `txn_uuid` is absent on this response, fall back to
        // `txn_id` so downstream flows still have an identifier and a
        // follow-up Order Status call can refresh it.
        let connector_txn_id = response.txn_uuid.clone().unwrap_or_else(|| response.txn_id.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_txn_id),
                redirection_data: redirection_data.map(Box::new),
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                // Secondary id slot: holds the display `txn_id` so dashboards
                // and PSync responses stay correlated even when we use
                // `txn_uuid` as the primary connector transaction id.
                connector_response_reference_id: Some(response.txn_id),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// =============================================================================
// PSync (Order Status) - Response
// =============================================================================
//
// `GET /orders/{order_id}` returns the full Juspay order envelope: the
// authoritative `status` (mapped via the shared `JuspayOrderStatus`), both
// transaction identifiers (`txn_uuid` for Capture/Void, `txn_id` for
// dashboards), amount/currency, and -- critically for RSync -- the
// `refunds[]` array. Every field below is defensively optional because
// Juspay only populates many of them once a transaction has actually been
// attempted on the order (a freshly-created `NEW` order returns most as
// nulls).
//
// `JuspayRefundEntry` is intentionally modelled to cover the full refund
// payload documented in the EC spec (RSync section) so the same struct can
// be reused without modification once the Refund / RSync flows are added.

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JuspayOrderStatusResponse {
    /// Juspay-internal order handle, opaque (e.g. `ordeh_4b95...`). Not
    /// reused for downstream calls; persisted for debugging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Echo of the merchant `order_id` we created.
    pub order_id: String,
    /// Authoritative order envelope status. Juspay applies a precedence
    /// rule across multiple txn attempts (NEW < PENDING_VBV < CHARGED) so
    /// this is the terminal-most status known to Juspay for the order.
    pub status: JuspayOrderStatus,
    /// Numeric form of `status` -- kept for parity with the spec; not
    /// currently consumed by the connector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_id: Option<i32>,
    /// Display txn identifier (`<merchant_id>-<order_id>-<n>`). Present
    /// once a transaction has been attempted on the order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txn_id: Option<String>,
    /// Opaque ~16-char Juspay txn UUID. **Required for Capture / Void**.
    /// Present once a transaction has been attempted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txn_uuid: Option<String>,
    /// Order amount in major units (e.g. `100.00`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<f64>,
    /// Cumulative refunded amount in major units.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_refunded: Option<f64>,
    /// Whether ANY refund has been initiated on this order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refunded: Option<bool>,
    /// ISO-4217 alpha-3 currency code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    /// PG-side identifier; suggested as `connector_reference_id` in the
    /// spec field mapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_reference_id: Option<String>,
    /// Underlying gateway response; carries `rrn`, `epg_txn_id`, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_gateway_response: Option<JuspayPaymentGatewayResponse>,
    /// Full refund history. **Reused by RSync** -- the connector matches a
    /// refund by `unique_request_id` and reads `status` + `ref` to surface
    /// the latest refund state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refunds: Option<Vec<JuspayRefundEntry>>,
}

/// Subset of `payment_gateway_response` that the connector currently
/// surfaces. Modelled defensively (every field optional) because Juspay
/// only populates these once the underlying PG has processed the txn.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JuspayPaymentGatewayResponse {
    /// Retrieval reference number; mapped to `network_txn_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rrn: Option<String>,
    /// Gateway-side transaction id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epg_txn_id: Option<String>,
    /// Issuer authorization code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_id_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resp_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resp_message: Option<String>,
}

/// Single entry inside `refunds[]` on an Order Status response. The full
/// shape is documented under the Refund / RSync sections of the tech
/// spec; the struct here is sized to cover both so RSync can adopt it
/// without modification.
///
/// Notes:
/// - `unique_request_id` is the connector's `refund_id` (idempotency key
///   supplied to `POST /orders/{order_id}/refunds`).
/// - `status` is modelled as `Option<JuspayRefundStatus>` so RSync can
///   reuse the same `From<JuspayRefundStatus> for RefundStatus` mapping
///   that the dedicated Refund response uses. It is optional because
///   Juspay only populates the field once a refund actually exists.
/// - `ref` is renamed because `ref` is a Rust keyword.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JuspayRefundEntry {
    /// Idempotency key supplied when the refund was created. The
    /// connector uses this to locate the refund inside `refunds[]` during
    /// RSync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_request_id: Option<String>,
    /// Refund state. See `JuspayRefundStatus` for the full taxonomy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<JuspayRefundStatus>,
    /// Refund amount in major units.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<f64>,
    /// Gateway-side refund reference. Populated only once Juspay has
    /// dispatched the refund to the underlying PG.
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub ref_id: Option<String>,
    /// `STANDARD` or `INSTANT`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refund_type: Option<String>,
    /// Source gateway (e.g. `STRIPE`, `HDFC`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refund_source: Option<String>,
    /// `false` while the refund is queued at Juspay; `true` once dispatched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_to_gateway: Option<bool>,
    /// `API`, `DASHBOARD`, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiated_by: Option<String>,
    /// Juspay-internal refund id; not always populated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// ISO-8601 creation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// ISO-8601 timestamp at which the PG processed the refund.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pg_processed_at: Option<String>,
}

// =============================================================================
// PSync - Response transformation
// =============================================================================
//
// Status is mapped via the shared `From<JuspayOrderStatus> for AttemptStatus`.
//
// `resource_id` mirrors the Authorize handler: prefer `txn_uuid` (the
// identifier Capture / Void take in their URLs) and fall back to `txn_id`
// (the display id) when `txn_uuid` is absent. If Juspay returns neither
// (the order has not been transacted on yet) we surface the merchant
// `order_id` so the orchestrator still has a stable identifier.
//
// `connector_response_reference_id` mirrors `txn_id` -- the display id is
// what shows up on Juspay's dashboard and is useful for support / ops
// correlation.
//
// `network_txn_id` is sourced from `payment_gateway_response.rrn` when
// present (per the connector field-mapping section of the tech spec).
impl TryFrom<ResponseRouterData<JuspayOrderStatusResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<JuspayOrderStatusResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let status = AttemptStatus::from(response.status);

        let connector_txn_id = response
            .txn_uuid
            .clone()
            .or_else(|| response.txn_id.clone())
            .unwrap_or_else(|| response.order_id.clone());

        let network_txn_id = response
            .payment_gateway_response
            .as_ref()
            .and_then(|pg| pg.rrn.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_txn_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id,
                // Display txn id (or fall back to gateway_reference_id when
                // the txn has not been attempted yet) so the dashboard and
                // PSync remain correlated.
                connector_response_reference_id: response
                    .txn_id
                    .clone()
                    .or_else(|| response.gateway_reference_id.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// =============================================================================
// Capture - Request
// =============================================================================
//
// `POST /v2/txns/{txn_uuid}/capture` is form-urlencoded. The body is empty for
// a full capture and carries a single `amount` field for a partial capture.
// We model both shapes with one struct + `skip_serializing_if = Option::is_none`
// so the macro path stays uniform (always serialize a request body, even if
// the result is an empty body for full captures). `amount` is a
// `StringMajorUnit` because Juspay's global EC API expects major-unit
// decimals across the board.

#[derive(Debug, Clone, Serialize)]
pub struct JuspayCaptureRequest {
    /// Major-unit amount string ("1.00"). Sent only for partial captures.
    /// Omitted entirely for a full capture (Juspay treats an absent `amount`
    /// as "capture the full authorized amount").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<StringMajorUnit>,
}

// =============================================================================
// Capture - Response
// =============================================================================
//
// Juspay echoes back the canonical txn handles (`txn_id`, `txn_uuid`), the
// merchant `order_id`, the captured amount, and the post-capture `status`
// (mapped via the shared `JuspayOrderStatus`).
//
// `txn_uuid` is defensively `Option<String>` for symmetry with Authorize /
// PSync; in practice the capture endpoint always echoes it back because it
// is the URL path parameter.

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JuspayCaptureResponse {
    /// Display txn id (`<merchant_id>-<order_id>-<n>`).
    pub txn_id: String,
    /// Opaque Juspay txn UUID -- the value Capture / Void take in their URL.
    /// Always present on a capture response in practice; modelled as
    /// `Option<String>` for parity with Authorize / PSync so a missing key
    /// does not fail deserialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txn_uuid: Option<String>,
    /// Merchant order id this txn belongs to.
    pub order_id: String,
    /// Post-capture status. Mapped via the shared
    /// `From<JuspayOrderStatus> for AttemptStatus`.
    pub status: JuspayOrderStatus,
    /// Captured amount in major units. Surfaced as informational only --
    /// `AttemptStatus` already encodes whether the capture succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<f64>,
}

// =============================================================================
// Capture - Request transformation
// =============================================================================
//
// Distinguishes full vs partial capture by comparing
// `PaymentsCaptureData::minor_amount_to_capture` against the original
// authorized amount carried on `PaymentFlowData::amount` (a `Money` whose
// inner `amount` is a `MinorUnit`). If they match -- or the original amount
// is unknown to the orchestrator -- we omit the `amount` field and send an
// empty form body (full capture). Otherwise we serialise the partial amount
// via `JuspayAmountConvertor` (StringMajorUnit) to match the rest of the
// connector.
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        crate::connectors::juspay::JuspayRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for JuspayCaptureRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        wrapper: crate::connectors::juspay::JuspayRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = wrapper.router_data;

        // `PaymentFlowData::amount` is the original (authorized) amount; if
        // present and equal to `minor_amount_to_capture` we treat the request
        // as a full capture and omit the body field. If the original is
        // unknown (None) we also omit -- "capture the authorized amount" is
        // the safer default than risking an over-capture rejection.
        let amount_to_capture = router_data.request.minor_amount_to_capture;
        let original_amount = router_data
            .resource_common_data
            .amount
            .as_ref()
            .map(|money| money.amount);

        let amount = match original_amount {
            Some(total) if total == amount_to_capture => None,
            _ => Some(JuspayAmountConvertor::convert(
                amount_to_capture,
                router_data.request.currency,
            )?),
        };

        Ok(Self { amount })
    }
}

// =============================================================================
// Capture - Response transformation
// =============================================================================
//
// Mirrors the Authorize response handler: status is derived from the shared
// `JuspayOrderStatus` mapping, `resource_id` prefers `txn_uuid` (the
// Capture/Void URL parameter) and falls back to `txn_id` so downstream calls
// always have a usable identifier, and the display `txn_id` is mirrored into
// `connector_response_reference_id` for dashboard correlation.
impl TryFrom<ResponseRouterData<JuspayCaptureResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<JuspayCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let status = AttemptStatus::from(response.status);

        // Prefer `txn_uuid` (downstream Void uses it in the URL); fall back to
        // `txn_id` if the field was omitted so we never lose the identifier.
        let connector_txn_id = response
            .txn_uuid
            .clone()
            .unwrap_or_else(|| response.txn_id.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_txn_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(response.txn_id),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// =============================================================================
// Refund - Status enum
// =============================================================================
//
// Juspay's refund flow uses a small, distinct status enum (different from
// `JuspayOrderStatus`). Only `PENDING` is confirmed verbatim in the Refund API
// page; the other variants are documented elsewhere in the EC ecosystem and
// reused on RSync's `refunds[].status`. The enum is shared between the
// dedicated Refund response and the `refunds[]` array on Order Status so
// downstream RSync inherits the same mapping without duplication.
//
// `TRANSFER_SCHEDULED` is mapped to `Pending` -- the refund has been accepted
// but not yet settled to the underlying gateway, so the merchant should keep
// polling.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JuspayRefundStatus {
    /// Queued at Juspay or in flight at the underlying gateway. Initial state.
    Pending,
    /// Refund settled to the cardholder.
    Success,
    /// Refund declined by the underlying gateway.
    Failure,
    /// Stuck; requires Juspay ops intervention.
    ManualReview,
    /// Scheduled for the next settlement window. Still pending from the
    /// merchant's perspective.
    TransferScheduled,
}

impl From<JuspayRefundStatus> for RefundStatus {
    fn from(status: JuspayRefundStatus) -> Self {
        match status {
            JuspayRefundStatus::Success => Self::Success,
            JuspayRefundStatus::Failure => Self::Failure,
            JuspayRefundStatus::ManualReview => Self::ManualReview,
            // Both PENDING and TRANSFER_SCHEDULED are non-terminal states
            // from the merchant's perspective; map both to `Pending` so
            // RSync polls until the refund settles or fails.
            JuspayRefundStatus::Pending | JuspayRefundStatus::TransferScheduled => Self::Pending,
        }
    }
}

// =============================================================================
// Refund - Request
// =============================================================================
//
// `POST /orders/{order_id}/refunds` is form-urlencoded with two required
// fields: `unique_request_id` (idempotency key, <= 21 chars) and `amount`
// (major-unit string). The URL itself carries the `order_id`, so the body
// only needs the two values.
//
// `unique_request_id` doubles as the connector's refund reference id -- the
// RSync flow matches by `refunds[].unique_request_id` per the tech spec, so
// keeping the round-trip exact is critical.

#[derive(Debug, Clone, Serialize)]
pub struct JuspayRefundRequest {
    /// Idempotency key. Reusing the same value across two calls returns
    /// `duplicate.call` from Juspay. We use `RefundsData::refund_id` (the UCS
    /// merchant-supplied refund id) so the value survives a retry and so
    /// RSync can find the same refund by `unique_request_id` later.
    pub unique_request_id: String,
    /// Refund amount in major units (e.g. "100.00"). Always sent: the docs
    /// list the field as required, and partial refunds need it explicitly
    /// regardless.
    pub amount: StringMajorUnit,
}

// =============================================================================
// Refund - Response
// =============================================================================
//
// Juspay's Refund response wraps an Order Status-shaped envelope around a
// `refunds[]` array. The freshly-created refund is the last entry in that
// array; we look it up by `unique_request_id` so the parsing still works if
// Juspay ever returns the refunds in a different order or includes prior
// refunds on the same order.
//
// Every field below is defensively optional because Juspay only populates
// envelope-level fields once the underlying gateway has processed the call.
// The `refunds` field itself is treated as required because the response is
// meaningless without it.

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JuspayRefundResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    /// Order envelope status (e.g. `CHARGED`). Not consumed -- the refund
    /// status lives inside `refunds[]`. Retained for forward compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<JuspayOrderStatus>,
    /// Original order amount in major units.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<f64>,
    /// Cumulative amount refunded across all refunds on this order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_refunded: Option<f64>,
    /// True once any refund exists on the order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refunded: Option<bool>,
    /// Full refund history on the order. The just-created refund is matched
    /// by `unique_request_id`.
    pub refunds: Vec<JuspayRefundEntry>,
}

// =============================================================================
// Refund - Request transformation
// =============================================================================
//
// `RefundsData::refund_id` is the UCS merchant refund id (extracted by the
// orchestrator from the gRPC `merchant_refund_id`), which we forward verbatim
// as Juspay's `unique_request_id`. The amount is converted from MinorUnit to
// the connector's shared `StringMajorUnit` converter so behaviour stays
// consistent with the other Juspay flows.
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        crate::connectors::juspay::JuspayRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for JuspayRefundRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        wrapper: crate::connectors::juspay::JuspayRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = wrapper.router_data;

        let amount = JuspayAmountConvertor::convert(
            router_data.request.minor_refund_amount,
            router_data.request.currency,
        )?;

        Ok(Self {
            unique_request_id: router_data.request.refund_id.clone(),
            amount,
        })
    }
}

// =============================================================================
// Refund - Response transformation
// =============================================================================
//
// Locate the freshly-created refund inside `refunds[]` by `unique_request_id`
// (which we just sent in the request). Fall back to the last entry if the
// match fails -- Juspay's docs imply a single-entry array on a fresh create,
// so this only matters as a defensive guard.
//
// `connector_refund_id` MUST round-trip the `unique_request_id` because RSync
// looks the refund up by that field on the Order Status response. The
// gateway-side `ref` is not always present (it is populated only once Juspay
// dispatches the refund to the underlying PG) so it cannot be used as the
// primary id; we still prefer `unique_request_id` even when `ref` is set so
// the round-trip stays unambiguous.
impl TryFrom<ResponseRouterData<JuspayRefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<JuspayRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let router_data = item.router_data;
        let unique_request_id = router_data.request.refund_id.clone();

        // Prefer the entry whose `unique_request_id` matches the one we sent;
        // fall back to the last entry (the most-recent refund) if the field
        // is omitted from the response.
        let entry = response
            .refunds
            .iter()
            .find(|r| {
                r.unique_request_id
                    .as_deref()
                    .map(|id| id == unique_request_id)
                    .unwrap_or(false)
            })
            .or_else(|| response.refunds.last())
            .ok_or_else(|| {
                error_stack::report!(crate::utils::response_deserialization_fail(
                    item.http_code,
                    "juspay refund response did not contain any refund entries",
                ))
            })?;

        // `RefundStatus::Pending` is the safe default when Juspay omits the
        // status field -- the spec only confirms `PENDING` verbatim and the
        // refund is always async, so we never claim premature success.
        let refund_status = entry
            .status
            .map(RefundStatus::from)
            .unwrap_or(RefundStatus::Pending);

        // Round-trip `unique_request_id` so the subsequent RSync can locate
        // the same refund inside the Order Status `refunds[]` array. Fall
        // back to the request's `refund_id` if the response field is missing.
        let connector_refund_id = entry
            .unique_request_id
            .clone()
            .unwrap_or(unique_request_id);

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: item.http_code,
            }),
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

// =============================================================================
// RSync (Order Status reuse) - Response newtype
// =============================================================================
//
// Juspay's RSync hits the same `GET /orders/{order_id}` endpoint as PSync and
// returns the same JSON shape. The connector-integration `create_all_prerequisites!`
// macro derives a `<ResponseBody>Templating` type per registered response and
// uses it to specialise the per-flow `Bridge` impl. Registering the same
// concrete response type for two flows produces a duplicate-Templating /
// conflicting-Bridge-impl error.
//
// To keep the type-system happy without duplicating the payload model, we wrap
// `JuspayOrderStatusResponse` in a distinct newtype that delegates serde to
// the inner. The transparent deserialize means the wire format is identical to
// PSync.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct JuspayRefundSyncResponse(pub JuspayOrderStatusResponse);

// =============================================================================
// RSync (Order Status reuse) - Response transformation
// =============================================================================
//
// Juspay has no dedicated refund-status endpoint. RSync re-issues the Order
// Status call (`GET /orders/{order_id}`) and reuses the shared
// `JuspayOrderStatusResponse` shape. The refund being synced is located inside
// the `refunds[]` array by `unique_request_id`, which Refund round-tripped as
// `connector_refund_id`.
//
// Defensive behaviour:
//   * If the matching entry is missing (Juspay's refund queue can take up to
//     ~15 minutes to reflect into Order Status, per the tech spec), we return
//     `RefundStatus::Pending` and echo back the input `connector_refund_id` so
//     the caller can poll again. This is a valid transient state, not an
//     error.
//   * If the entry is present but `status` is None, we also default to
//     `RefundStatus::Pending` -- consistent with the Refund flow handler.
impl TryFrom<ResponseRouterData<JuspayRefundSyncResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<JuspayRefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = item.response.0;
        let router_data = item.router_data;
        let connector_refund_id = router_data.request.connector_refund_id.clone();

        // Locate the refund inside `refunds[]` by `unique_request_id`. The
        // array itself is optional on the envelope -- Juspay omits it
        // entirely on orders that have never been refunded.
        let matching_entry = response.refunds.as_ref().and_then(|entries| {
            entries.iter().find(|r| {
                r.unique_request_id
                    .as_deref()
                    .map(|id| id == connector_refund_id)
                    .unwrap_or(false)
            })
        });

        let (refund_status, resolved_refund_id) = match matching_entry {
            Some(entry) => {
                // `status` may be absent before the underlying gateway has
                // acknowledged the refund; default to Pending in that case so
                // RSync keeps polling rather than claiming a terminal state.
                let status = entry
                    .status
                    .map(RefundStatus::from)
                    .unwrap_or(RefundStatus::Pending);
                let id = entry
                    .unique_request_id
                    .clone()
                    .unwrap_or_else(|| connector_refund_id.clone());
                (status, id)
            }
            // Refund not yet visible on the order envelope. Per the tech
            // spec this is an expected transient state (Juspay's queue can
            // take up to ~15 minutes to reflect the refund). Surface it as
            // Pending and echo the input id so the caller can poll again.
            None => (RefundStatus::Pending, connector_refund_id.clone()),
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: resolved_refund_id,
                refund_status,
                status_code: item.http_code,
            }),
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

// =============================================================================
// Void - Request
// =============================================================================
//
// `POST /v2/txns/{txn_uuid}/void` carries no request body -- the void is fully
// described by the URL path parameter. We still register the empty struct with
// the macro (`FormUrlEncoded(JuspayVoidRequest)`) so the macro path stays
// uniform with the other write flows and so a dedicated TryFrom exists for the
// flow. `serde_urlencoded` serialises a unit-shaped struct (no fields) to an
// empty string, which is exactly what Juspay expects.
#[derive(Debug, Clone, Serialize)]
pub struct JuspayVoidRequest {}

// =============================================================================
// Void - Response
// =============================================================================
//
// Juspay echoes back the canonical txn handles (`txn_id`, `txn_uuid`), the
// merchant `order_id`, and the post-void `status` mapped via the shared
// `JuspayOrderStatus`. Fields are defensively optional where the spec allows
// them to be absent; `status` is required because it is the entire purpose of
// the response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JuspayVoidResponse {
    /// Display txn id (`<merchant_id>-<order_id>-<n>`). Always populated in
    /// practice; modelled as `Option<String>` for symmetry with the other
    /// flows so a missing key does not fail deserialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txn_id: Option<String>,
    /// Opaque Juspay txn UUID -- echoes the path parameter. Modelled as
    /// `Option<String>` for parity with Authorize / Capture / PSync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txn_uuid: Option<String>,
    /// Merchant order id this txn belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    /// Post-void status: `VOIDED`, `VOID_INITIATED`, `VOID_FAILED`, or
    /// `AUTHORIZED` (gateway timed out; retry). Mapped via the shared
    /// `From<JuspayOrderStatus> for AttemptStatus`.
    pub status: JuspayOrderStatus,
}

// =============================================================================
// Void - Request transformation
// =============================================================================
//
// Trivial: the void body is empty. We still consume the wrapper so the macro
// hands us a consistent input across all flows.
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        crate::connectors::juspay::JuspayRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for JuspayVoidRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        _wrapper: crate::connectors::juspay::JuspayRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

// =============================================================================
// Void - Response transformation
// =============================================================================
//
// Mirrors the Authorize / Capture response handlers: status is derived from
// the shared `JuspayOrderStatus` mapping (which already covers `VOIDED`,
// `VOID_INITIATED`, `VOID_FAILED`, and the timeout-`AUTHORIZED` retry case),
// `resource_id` prefers `txn_uuid` (the Capture / Void URL parameter) and
// falls back to `txn_id`, ultimately to the input `connector_transaction_id`
// so the orchestrator always has a usable identifier. The display `txn_id` is
// mirrored into `connector_response_reference_id` for dashboard correlation.
impl TryFrom<ResponseRouterData<JuspayVoidResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<JuspayVoidResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let router_data = item.router_data;
        let status = AttemptStatus::from(response.status);

        // Prefer `txn_uuid` (the Capture / Void URL parameter) and fall back
        // to `txn_id`, then to the input `connector_transaction_id` (which was
        // the `txn_uuid` we just sent in the URL) so the response always
        // carries a stable identifier even if Juspay omits both echo fields.
        let connector_txn_id = response
            .txn_uuid
            .clone()
            .or_else(|| response.txn_id.clone())
            .unwrap_or_else(|| router_data.request.connector_transaction_id.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_txn_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                // Display txn id for dashboard correlation. Omitted (None) if
                // Juspay did not echo it back, rather than substituting a
                // less-meaningful value.
                connector_response_reference_id: response.txn_id.clone(),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}
