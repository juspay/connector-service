use super::PaypalRouterData;
use crate::{
    types::ResponseRouterData,
    utils::{to_connector_meta, ErrorCodeAndMessage},
};
use base64::Engine;
use cards;
use common_enums;
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    types::{MinorUnit, StringMajorUnit},
    CustomResult, Method,
};
use domain_types::{
    connector_flow::{
        Authorize, Capture, ClientAuthenticationToken, CreateOrder, PSync, PaymentMethodToken,
        PostAuthenticate, RepeatPayment, VerifyWebhookSource, Void,
    },
    connector_types::{
        ClientAuthenticationTokenData, ClientAuthenticationTokenRequestData, MandateReference,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsPostAuthenticateData,
        PaymentsResponseData, PaymentsSyncData,
        PaypalClientAuthenticationResponse as PaypalClientAuthenticationResponseDomain,
        PaypalFlow as PaypalFlowDomain, PaypalTransactionInfo as PaypalTransactionInfoDomain,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        ResponseId, SdkNextAction, ServerAuthenticationTokenResponseData, SetupMandateRequestData,
        VerifyWebhookSourceFlowData,
    },
    errors::{ConnectorError, IntegrationError, IntegrationErrorContext},
    merchant_authentication_flow_data::MerchantAuthenticationFlowData,
    payment_method_data::{
        BankDebitData, BankRedirectData, BankTransferData, CardRedirectData, GiftCardData,
        GpayTokenizationData, PayLaterData, PaymentMethodData, PaymentMethodDataTypes,
        RawCardNumber, VoucherData, WalletData,
    },
    router_data::{
        AdditionalPaymentMethodConnectorResponse, ConnectorResponseData, ConnectorSpecificConfig,
        FlowStatus,
    },
    router_data_v2::RouterDataV2,
    router_request_types::{AuthenticationData, VerifyWebhookSourceRequestData},
    router_response_types::{RedirectForm, VerifyWebhookSourceResponseData, VerifyWebhookStatus},
    utils,
};
use error_stack::{Report, ResultExt};
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use url::Url;
pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
trait GetRequestIncrementalAuthorization {
    fn get_request_incremental_authorization(&self) -> Option<bool>;
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    GetRequestIncrementalAuthorization for PaymentsAuthorizeData<T>
{
    fn get_request_incremental_authorization(&self) -> Option<bool> {
        self.request_incremental_authorization
    }
}

impl GetRequestIncrementalAuthorization for PaymentsSyncData {
    fn get_request_incremental_authorization(&self) -> Option<bool> {
        None
    }
}

impl<
        T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize + Serialize,
    > GetRequestIncrementalAuthorization for RepeatPaymentData<T>
{
    fn get_request_incremental_authorization(&self) -> Option<bool> {
        Some(false)
    }
}

pub mod auth_headers {
    pub const PAYPAL_PARTNER_ATTRIBUTION_ID: &str = "PayPal-Partner-Attribution-Id";
    pub const PREFER: &str = "Prefer";
    pub const PAYPAL_REQUEST_ID: &str = "PayPal-Request-Id";
    pub const PAYPAL_AUTH_ASSERTION: &str = "PayPal-Auth-Assertion";
}

/// Maximum `PayPal-Request-Id` length accepted by the Vault v3 API.
/// Doc: https://developer.paypal.com/docs/api/payment-tokens/v3/
const PAYPAL_VAULT_REQUEST_ID_MAX_LEN: usize = 108;

/// The PayPal API call a `PayPal-Request-Id` is derived for.
///
/// PayPal requires the idempotency key to be unique per request *and per API call
/// type* ("authorize payment vs capture authorized payment need different IDs"); a
/// replayed id returns the latest state of the earlier call instead of acting again.
/// Doc: https://developer.paypal.com/api/rest/reference/idempotency/
#[derive(Debug, Clone, Copy)]
pub enum PaypalRequestIdKind<'a> {
    /// `POST /v2/checkout/orders` (Authorize create-order, RepeatPayment). No PayPal
    /// resource exists yet, so the key is the caller's reference.
    CreateOrder,
    /// `POST /v2/checkout/orders/{order_id}/capture|authorize` (approved-order completion).
    CompleteOrder {
        order_id: Option<&'a str>,
        intent: &'a PaypalPaymentIntent,
    },
    /// `POST /v2/payments/authorizations/{authorization_id}/capture`.
    Capture { authorization_id: Option<&'a str> },
    /// `POST /v2/payments/authorizations/{authorization_id}/void`.
    Void { authorization_id: Option<&'a str> },
    /// `POST /v2/payments/captures/{capture_id}/refund`; carries the refund's own id so
    /// two partial refunds of one capture never share a key.
    Refund {
        capture_id: Option<&'a str>,
        refund_id: &'a str,
    },
    /// `POST /v3/vault/setup-tokens`.
    VaultSetupToken,
    /// `POST /v3/vault/payment-tokens`; `setup_token_id` is the setup token being
    /// exchanged (`None` for a raw-card payment token).
    VaultPaymentToken { setup_token_id: Option<&'a str> },
}

/// Derive the `PayPal-Request-Id` for one (PayPal resource, API call type) pair.
///
/// Key = `<resource>-<call>[-<reference>]`, where `<resource>` is the PayPal id the call
/// acts on (the id in the URL). `reference` is `connector_request_reference_id`, which
/// is optional upstream (`unwrap_or_default`) and so is never the only discriminator: a
/// key that is only a suffix is shared by every payment, and PayPal then replays the
/// first payment's capture/void/setup-token result for the next one. Calls with no
/// resource id use the reference, or a fresh UUID v4 when the reference is empty
/// (retry dedup is lost for that call, which beats a cross-payment replay). The key
/// stays deterministic whenever a resource id or reference exists, so a retry of the
/// same operation replays rather than duplicates. Vault v3 keys are truncated to the
/// documented 108-character limit.
/// Doc: https://developer.paypal.com/api/rest/reference/idempotency/
pub fn paypal_idempotency_key(reference: &str, kind: PaypalRequestIdKind<'_>) -> String {
    let with_ref = |base: String| {
        if reference.is_empty() {
            base
        } else {
            format!("{base}-{reference}")
        }
    };
    // `<resource>-<call>[-<ref>]`; without a resource id, `<ref>-<call>`, and without
    // either a fresh UUID, so the result is never a bare suffix.
    let on_resource = |resource: Option<&str>, call: &str| match resource
        .filter(|resource| !resource.is_empty())
    {
        Some(resource) => with_ref(format!("{resource}-{call}")),
        None if !reference.is_empty() => format!("{reference}-{call}"),
        None => common_utils::fp_utils::generate_uuid_v4(),
    };
    match kind {
        PaypalRequestIdKind::CreateOrder => {
            if reference.is_empty() {
                common_utils::fp_utils::generate_uuid_v4()
            } else {
                reference.to_string()
            }
        }
        PaypalRequestIdKind::CompleteOrder { order_id, intent } => on_resource(
            order_id,
            match intent {
                PaypalPaymentIntent::Capture => "capture",
                PaypalPaymentIntent::Authorize => "authorize",
                PaypalPaymentIntent::Authenticate => "authenticate",
            },
        ),
        PaypalRequestIdKind::Capture { authorization_id } => {
            on_resource(authorization_id, "capture")
        }
        PaypalRequestIdKind::Void { authorization_id } => on_resource(authorization_id, "void"),
        PaypalRequestIdKind::Refund {
            capture_id,
            refund_id,
        } => match capture_id.filter(|capture_id| !capture_id.is_empty()) {
            _ if refund_id.is_empty() => common_utils::fp_utils::generate_uuid_v4(),
            Some(capture_id) => format!("{capture_id}-refund-{refund_id}"),
            None => format!("refund-{refund_id}"),
        },
        PaypalRequestIdKind::VaultSetupToken => {
            if reference.is_empty() {
                common_utils::fp_utils::generate_uuid_v4()
            } else {
                truncate_chars(
                    &format!("{reference}-setup"),
                    PAYPAL_VAULT_REQUEST_ID_MAX_LEN,
                )
            }
        }
        PaypalRequestIdKind::VaultPaymentToken { setup_token_id } => truncate_chars(
            &on_resource(setup_token_id, "payment-token"),
            PAYPAL_VAULT_REQUEST_ID_MAX_LEN,
        ),
    }
}

/// Intent a PayPal order is created with for a payment: `CAPTURE` for automatic
/// capture, `AUTHORIZE` otherwise (same rule as the create-order request).
pub fn paypal_order_intent(is_auto_capture: bool) -> PaypalPaymentIntent {
    if is_auto_capture {
        PaypalPaymentIntent::Capture
    } else {
        PaypalPaymentIntent::Authorize
    }
}

/// Intent to complete an existing order with (`orders/{id}/capture|authorize`).
///
/// PayPal rejects a completion whose action differs from the order's intent
/// (`ACTION_DOES_NOT_MATCH_INTENT`), so the intent recorded on `PaypalMeta.order_intent`
/// when the 3DS order was created wins. Orders without a recorded intent (redirect /
/// SDK flows) keep deriving it from the payment's capture method.
/// doc: https://developer.paypal.com/docs/api/orders/v2/#orders_capture
pub fn paypal_completion_intent(
    connector_feature_data: Option<&serde_json::Value>,
    is_auto_capture: bool,
) -> PaypalPaymentIntent {
    let recorded = connector_feature_data
        .and_then(|data| data.get("order_intent"))
        .and_then(|intent| serde_json::from_value::<PaypalPaymentIntent>(intent.clone()).ok());
    match recorded {
        Some(intent @ (PaypalPaymentIntent::Capture | PaypalPaymentIntent::Authorize)) => intent,
        Some(PaypalPaymentIntent::Authenticate) | None => paypal_order_intent(is_auto_capture),
    }
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

/// Which flow an error response belongs to; selects the issue -> attempt-status table
/// of [`paypal_error_attempt_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaypalErrorFlow {
    /// Orders v2 create / complete (Authorize and RepeatPayment).
    Authorize,
    Capture,
    Void,
    Refund,
    /// Vault v3 payment-token creation.
    SetupMandate,
    /// Vault v3 setup-token creation.
    PaymentMethodToken,
    /// Read-only calls (PSync, RSync, PostAuthenticate): an error there is inconclusive.
    Sync,
}

/// Map a PayPal error response to the attempt status of the flow that received it.
///
/// An error without an attempt status lets the caller default a call that actually
/// succeeded (an idempotent replay answered "already captured") to FAILED, so every
/// documented issue gets an explicit status. HTTP 409 (`PREVIOUS_REQUEST_IN_PROGRESS`)
/// and 5xx are an unknown outcome and stay non-terminal; sync flows return `None`.
/// Doc: https://developer.paypal.com/api/rest/reference/orders/v2/errors/ ,
/// https://developer.paypal.com/docs/api/payments/v2/#errors
/// The PayPal `details[].issue` values that select a money-moving attempt status in
/// [`paypal_error_attempt_status`]. Typed so the compiler checks every issue name the
/// decision table reads; any other issue is `Unknown` (b4-07).
/// Doc: https://developer.paypal.com/api/rest/reference/orders/v2/errors/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalErrorIssue {
    OrderAlreadyCaptured,
    OrderAlreadyAuthorized,
    PayerActionRequired,
    ContingencyNotSuccessful,
    AuthorizationAlreadyCaptured,
    PreviouslyVoided,
    #[serde(other)]
    Unknown,
}

impl PaypalErrorIssue {
    /// Classify one raw `details[].issue` string; unrecognised issues are `Unknown`.
    pub fn from_issue(issue: &str) -> Self {
        serde_json::from_value(serde_json::Value::String(issue.to_owned())).unwrap_or(Self::Unknown)
    }
}

pub fn paypal_error_attempt_status(
    flow: PaypalErrorFlow,
    http_status: u16,
    issues: &[PaypalErrorIssue],
) -> Option<FlowStatus> {
    use common_enums::AttemptStatus as A;
    let has = |issue: PaypalErrorIssue| issues.contains(&issue);
    let unknown_outcome = http_status == 409 || http_status >= 500;
    match flow {
        PaypalErrorFlow::Sync => None,
        PaypalErrorFlow::Refund => Some(FlowStatus::Refund(if unknown_outcome {
            common_enums::RefundStatus::Pending
        } else {
            common_enums::RefundStatus::Failure
        })),
        PaypalErrorFlow::Authorize => Some(FlowStatus::Payment(
            // `Pending`, not `Charged`: the replay proves the capture happened but carries no
            // amount, and `Charged` is terminal in the router's PSync workflow -- it retires
            // the already-scheduled sync task and leaves `amount_captured` null forever
            // (B058). `Pending` is non-terminal, so PSync establishes the true captured
            // amount, which matters most for a partial capture the replay cannot describe.
            if has(PaypalErrorIssue::OrderAlreadyCaptured) {
                A::Pending
            } else if has(PaypalErrorIssue::OrderAlreadyAuthorized) {
                A::Authorized
            } else if has(PaypalErrorIssue::PayerActionRequired) {
                A::AuthenticationPending
            } else if has(PaypalErrorIssue::ContingencyNotSuccessful) {
                A::AuthenticationFailed
            } else if unknown_outcome {
                A::Pending
            } else {
                A::Failure
            },
        )),
        PaypalErrorFlow::Capture => Some(FlowStatus::Payment(
            // AUTHORIZATION_ALREADY_CAPTURED joins `unknown_outcome` rather than reporting
            // `Charged`: as in Authorize/ORDER_ALREADY_CAPTURED above, the captured amount is
            // unknown, so stay non-terminal and let PSync establish it (B058).
            if has(PaypalErrorIssue::AuthorizationAlreadyCaptured) || unknown_outcome {
                A::Pending
            } else {
                A::CaptureFailed
            },
        )),
        PaypalErrorFlow::Void => Some(FlowStatus::Payment(
            if has(PaypalErrorIssue::PreviouslyVoided) {
                A::Voided
            } else if unknown_outcome {
                A::Pending
            } else {
                A::VoidFailed
            },
        )),
        PaypalErrorFlow::SetupMandate | PaypalErrorFlow::PaymentMethodToken => {
            Some(FlowStatus::Payment(if unknown_outcome {
                A::Pending
            } else {
                A::Failure
            }))
        }
    }
}

/// Constants for PayPal connector.
pub mod constants {
    pub const DEFAULT_NOTIFICATION_LANGUAGE: &str = "en-US";
    pub const DEFAULT_PARTNER_ATTRIBUTION_ID: &str = "HyperSwitchPPCP_SP";
    pub const DEFAULT_LEGACY_PARTNER_ATTRIBUTION_ID: &str = "HyperSwitchlegacy_Ecom";
}

const ORDER_QUANTITY: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaypalPaymentIntent {
    Capture,
    Authorize,
    Authenticate,
}

#[derive(Default, Debug, Clone, Serialize, Eq, PartialEq, Deserialize)]
pub struct OrderAmount {
    pub currency_code: common_enums::Currency,
    pub value: StringMajorUnit,
}

#[derive(Default, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct OrderRequestAmount {
    pub currency_code: common_enums::Currency,
    pub value: StringMajorUnit,
    pub breakdown: AmountBreakdown,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        &PaypalRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for OrderRequestAmount
{
    type Error = Report<IntegrationError>;
    fn try_from(
        item: &PaypalRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let value = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.amount.amount,
                item.router_data.request.currency,
            )
            .change_context(IntegrationError::AmountConversionFailed {
                context: Default::default(),
            })?;
        // Hyperswitch treats `shipping_cost` as optional for the Authorize flow,
        // defaulting to zero when absent (req.request.shipping_cost.as_ref().map(|money| money.amount).unwrap_or(MinorUnit::zero())).
        // Mirror that here instead of hard-failing with MissingRequiredField, otherwise UCS
        // returns gRPC InvalidArgument for card payments that carry no shipping_cost.
        let shipping_value = item
            .connector
            .amount_converter
            .convert(
                item.router_data
                    .request
                    .shipping_cost
                    .as_ref()
                    .map(|money| money.amount)
                    .unwrap_or(MinorUnit::zero()),
                item.router_data.request.currency,
            )
            .change_context(IntegrationError::AmountConversionFailed {
                context: Default::default(),
            })?;
        // PayPal: value = item_total + tax_total + shipping (422 AMOUNT_MISMATCH otherwise),
        // so item_total is the amount net of shipping (B023; HS sends the full amount).
        let item_total_value = get_authorize_item_total(item)?;
        Ok(Self {
            currency_code: item.router_data.request.currency,
            value,
            breakdown: AmountBreakdown {
                item_total: OrderAmount {
                    currency_code: item.router_data.request.currency,
                    value: item_total_value,
                },
                tax_total: None,
                shipping: Some(OrderAmount {
                    currency_code: item.router_data.request.currency,
                    value: shipping_value,
                }),
            },
        })
    }
}

// OrderRequestAmount for RepeatPayment: value = item_total + shipping (PayPal AMOUNT_MISMATCH otherwise)
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        &PaypalRouterData<
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for OrderRequestAmount
{
    type Error = Report<IntegrationError>;
    fn try_from(
        item: &PaypalRouterData<
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let value = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.amount.amount,
                item.router_data.request.currency,
            )
            .change_context(IntegrationError::AmountConversionFailed {
                context: Default::default(),
            })?;
        let shipping_value = item
            .connector
            .amount_converter
            .convert(
                item.router_data
                    .request
                    .shipping_cost
                    .as_ref()
                    .map(|money| money.amount)
                    .unwrap_or(MinorUnit::zero()),
                item.router_data.request.currency,
            )
            .change_context(IntegrationError::AmountConversionFailed {
                context: Default::default(),
            })?;
        // PayPal: value = item_total + tax_total + shipping (422 AMOUNT_MISMATCH otherwise),
        // so item_total is the amount net of shipping (P-RepeatPayment-05; HS sends the full amount).
        let item_total_value = get_repeat_payment_item_total(item)?;
        Ok(Self {
            currency_code: item.router_data.request.currency,
            value,
            breakdown: AmountBreakdown {
                item_total: OrderAmount {
                    currency_code: item.router_data.request.currency,
                    value: item_total_value,
                },
                tax_total: None,
                shipping: Some(OrderAmount {
                    currency_code: item.router_data.request.currency,
                    value: shipping_value,
                }),
            },
        })
    }
}

#[derive(Default, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AmountBreakdown {
    item_total: OrderAmount,
    tax_total: Option<OrderAmount>,
    shipping: Option<OrderAmount>,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct PurchaseUnitRequest {
    reference_id: Option<String>, //reference for an item in purchase_units
    invoice_id: Option<String>, //The API caller-provided external invoice number for this order. Appears in both the payer's transaction history and the emails that the payer receives.
    custom_id: Option<String>,  //Used to reconcile client transactions with PayPal transactions.
    amount: OrderRequestAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    payee: Option<Payee>,
    shipping: Option<ShippingAddress>,
    items: Vec<ItemDetails>,
    /// Dynamic descriptor shown on the card statement (PayPal keeps at most 22 characters).
    #[serde(skip_serializing_if = "Option::is_none")]
    soft_descriptor: Option<String>,
    /// Level 2 / Level 3 card data.
    #[serde(skip_serializing_if = "Option::is_none")]
    supplementary_data: Option<PaypalSupplementaryDataRequest>,
}

/// Maximum soft descriptor length PayPal keeps.
/// Doc: https://developer.paypal.com/docs/api/orders/v2/#orders_create!path=purchase_units/soft_descriptor&t=request
const PAYPAL_SOFT_DESCRIPTOR_MAX_LEN: usize = 22;

/// `purchase_units[].supplementary_data`.
/// Doc: https://developer.paypal.com/docs/api/orders/v2/#definition-supplementary_data
#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct PaypalSupplementaryDataRequest {
    card: PaypalCardSupplementaryData,
}

/// `supplementary_data.card` — Level 2 and Level 3 processing data.
/// Doc: https://developer.paypal.com/docs/api/orders/v2/#definition-card_supplementary_data
#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct PaypalCardSupplementaryData {
    #[serde(skip_serializing_if = "Option::is_none")]
    level_2: Option<PaypalLevel2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    level_3: Option<PaypalLevel3>,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct PaypalLevel2 {
    #[serde(skip_serializing_if = "Option::is_none")]
    invoice_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tax_total: Option<OrderAmount>,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct PaypalLevel3 {
    #[serde(skip_serializing_if = "Option::is_none")]
    shipping_amount: Option<OrderAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duty_amount: Option<OrderAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discount_amount: Option<OrderAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shipping_address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line_items: Option<Vec<PaypalLevel3LineItem>>,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct PaypalLevel3LineItem {
    name: String,
    quantity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sku: Option<String>,
    unit_amount: OrderAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    tax: Option<OrderAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    commodity_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discount_amount: Option<OrderAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_amount: Option<OrderAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unit_of_measure: Option<String>,
}

/// `purchase_units[].soft_descriptor` from the caller's statement descriptor,
/// truncated to the 22 characters PayPal keeps.
fn get_paypal_soft_descriptor(
    billing_descriptor: Option<&domain_types::connector_types::BillingDescriptor>,
) -> Option<String> {
    billing_descriptor
        .and_then(|descriptor| descriptor.statement_descriptor.as_ref())
        .map(|descriptor| truncate_chars(descriptor, PAYPAL_SOFT_DESCRIPTOR_MAX_LEN))
        .filter(|descriptor| !descriptor.is_empty())
}

/// Build `purchase_units[].supplementary_data.card` (Level 2 / Level 3) from the
/// caller's `l2_l3_data`. Returns `None` when the caller sent no Level 2/3 input, so the
/// object is omitted rather than sent empty.
fn get_paypal_supplementary_data(
    l2_l3_data: Option<&domain_types::connector_types::L2L3Data>,
    invoice_id: &str,
    currency: common_enums::Currency,
    amount_converter: &dyn common_utils::types::AmountConvertor<Output = StringMajorUnit>,
) -> Result<Option<PaypalSupplementaryDataRequest>, Report<IntegrationError>> {
    let Some(l2_l3_data) = l2_l3_data else {
        return Ok(None);
    };
    let to_amount = |minor: MinorUnit| -> Result<OrderAmount, Report<IntegrationError>> {
        amount_converter
            .convert(minor, currency)
            .change_context(IntegrationError::AmountConversionFailed {
                context: IntegrationErrorContext {
                    suggested_action: Some(
                        "Check the Level 2/3 amounts in l2_l3_data are valid minor units for \
                         the payment currency"
                            .to_string(),
                    ),
                    doc_url: Some(
                        "https://developer.paypal.com/docs/api/orders/v2/#definition-money"
                            .to_string(),
                    ),
                    additional_context: Some("PayPal supplementary_data.card".to_string()),
                },
            })
            .map(|value| OrderAmount {
                currency_code: currency,
                value,
            })
    };
    // A Money is converted with the payment currency, so a different currency is
    // refused rather than relabelled (b4-08).
    let to_money = |money: Option<&common_utils::types::Money>| {
        money
            .map(|money| {
                if money.currency != currency {
                    return Err(error_stack::report!(IntegrationError::InvalidDataFormat {
                        field_name: "l2_l3_data amount currency",
                        context: IntegrationErrorContext {
                            suggested_action: Some(
                                "L2/L3 amounts must be in the payment currency".to_string(),
                            ),
                            doc_url: Some(
                                "https://developer.paypal.com/docs/api/orders/v2/#definition-money"
                                    .to_string(),
                            ),
                            additional_context: Some(format!(
                                "l2_l3_data amount currency {} differs from payment currency {currency}",
                                money.currency
                            )),
                        },
                    }));
                }
                to_amount(money.amount)
            })
            .transpose()
    };

    let order_info = l2_l3_data.order_info.as_ref();
    let tax_total = to_money(
        l2_l3_data
            .tax_info
            .as_ref()
            .and_then(|tax| tax.order_tax_amount.as_ref()),
    )?;
    let level_2 = tax_total.map(|tax_total| PaypalLevel2 {
        invoice_id: Some(invoice_id.to_string()),
        tax_total: Some(tax_total),
    });

    let line_items = order_info
        .and_then(|order| order.order_details.as_ref())
        .map(|details| {
            details
                .iter()
                .map(|detail| {
                    Ok(PaypalLevel3LineItem {
                        name: detail.product_name.clone(),
                        quantity: detail.quantity.to_string(),
                        description: detail.description.clone(),
                        sku: detail.sku.clone().or_else(|| detail.product_id.clone()),
                        unit_amount: to_amount(detail.amount)?,
                        tax: detail.total_tax_amount.map(to_amount).transpose()?,
                        commodity_code: detail.commodity_code.clone(),
                        discount_amount: detail.unit_discount_amount.map(to_amount).transpose()?,
                        total_amount: detail.total_amount.map(to_amount).transpose()?,
                        unit_of_measure: detail.unit_of_measure.clone(),
                    })
                })
                .collect::<Result<Vec<_>, Report<IntegrationError>>>()
        })
        .transpose()?
        .filter(|line_items| !line_items.is_empty());
    let shipping_address = l2_l3_data.shipping_details.as_ref().and_then(|address| {
        address.country.map(|country_code| Address {
            address_line_1: address.line1.clone(),
            address_line_2: address.line2.clone(),
            postal_code: address.zip.clone(),
            country_code,
            admin_area_2: address.city.clone(),
            admin_area_1: address.state.clone(),
        })
    });
    let level_3 = PaypalLevel3 {
        shipping_amount: to_money(order_info.and_then(|order| order.shipping_cost.as_ref()))?,
        duty_amount: to_money(order_info.and_then(|order| order.duty_amount.as_ref()))?,
        discount_amount: to_money(order_info.and_then(|order| order.discount_amount.as_ref()))?,
        shipping_address,
        line_items,
    };
    // PayPal requires 1..100 line_items whenever level_3 is present (live 400 otherwise).
    let line_item_count = level_3.line_items.as_ref().map_or(0, Vec::len);
    let level_3_supplied = level_3.shipping_amount.is_some()
        || level_3.duty_amount.is_some()
        || level_3.discount_amount.is_some()
        || level_3.shipping_address.is_some()
        || line_item_count > 0;
    let level_3 = level_3
        .line_items
        .as_ref()
        .is_some_and(|items| (1..=100).contains(&items.len()))
        .then_some(level_3);
    // Never drop merchant-supplied Level 3 data silently (b4-09).
    if level_3.is_none() && level_3_supplied {
        tracing::warn!(
            line_item_count,
            "PayPal level_3 omitted: requires 1..=100 line items"
        );
    }

    Ok(
        (level_2.is_some() || level_3.is_some()).then_some(PaypalSupplementaryDataRequest {
            card: PaypalCardSupplementaryData { level_2, level_3 },
        }),
    )
}

/// `breakdown.item_total` (and the synthetic item's `unit_amount`) shared by Authorize
/// and RepeatPayment: the order amount net of `shipping_cost`, so
/// `value == item_total + shipping` (P-foundation-12). Refused before any HTTP call when
/// `shipping_cost` is negative, exceeds the amount, or is in another currency
/// (G-Authorize-04, G-RepeatPayment-03; B043/B057). One helper so the guard cannot land
/// in one flow only.
fn item_total_net_of_shipping(
    amount: MinorUnit,
    currency: common_enums::Currency,
    shipping_cost: Option<&common_utils::types::Money>,
    amount_converter: &dyn common_utils::types::AmountConvertor<Output = StringMajorUnit>,
) -> Result<StringMajorUnit, Report<IntegrationError>> {
    let shipping_error = |additional_context: String| {
        error_stack::report!(IntegrationError::InvalidDataFormat {
            field_name: "shipping_cost",
            context: IntegrationErrorContext {
                suggested_action: Some(
                    "Send a shipping_cost between 0 and the payment amount, in the payment \
                     currency"
                        .to_string(),
                ),
                doc_url: Some(
                    "https://developer.paypal.com/docs/api/orders/v2/#definition-amount_breakdown"
                        .to_string(),
                ),
                additional_context: Some(additional_context),
            },
        })
    };
    if let Some(shipping_cost) = shipping_cost {
        if shipping_cost.currency != currency {
            return Err(shipping_error(format!(
                "shipping_cost currency {} differs from payment currency {currency}",
                shipping_cost.currency
            )));
        }
    }
    let shipping = shipping_cost
        .map(|money| money.amount)
        .unwrap_or(MinorUnit::zero());
    let item_total = amount
        .get_amount_as_i64()
        .checked_sub(shipping.get_amount_as_i64())
        .filter(|item_total| *item_total >= 0 && shipping.get_amount_as_i64() >= 0)
        .map(MinorUnit::new)
        .ok_or_else(|| {
            shipping_error(
                "PayPal requires amount.value = item_total + shipping with no negative \
                 amount (CANNOT_BE_NEGATIVE); a negative shipping_cost or one greater than \
                 amount is refused"
                    .to_string(),
            )
        })?;
    amount_converter
        .convert(item_total, currency)
        .change_context(IntegrationError::AmountConversionFailed {
            context: IntegrationErrorContext {
                suggested_action: Some(
                    "Check amount and shipping_cost are valid minor units for the currency"
                        .to_string(),
                ),
                doc_url: Some(
                    "https://developer.paypal.com/docs/api/orders/v2/#definition-money".to_string(),
                ),
                additional_context: Some(
                    "PayPal purchase_units[].amount.breakdown.item_total".to_string(),
                ),
            },
        })
}

/// Authorize `breakdown.item_total` (P-Authorize-11, P-Authorize-16): delegates to
/// [`item_total_net_of_shipping`] (G-Authorize-04).
fn get_authorize_item_total<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
>(
    item: &PaypalRouterData<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        T,
    >,
) -> Result<StringMajorUnit, Report<IntegrationError>> {
    item_total_net_of_shipping(
        item.router_data.request.amount.amount,
        item.router_data.request.currency,
        item.router_data.request.shipping_cost.as_ref(),
        item.connector.amount_converter,
    )
}

/// RepeatPayment `breakdown.item_total` (P-RepeatPayment-05, P-RepeatPayment-07): delegates
/// to [`item_total_net_of_shipping`] (G-RepeatPayment-03), in every mandate arm, because
/// the purchase unit amount is built before the arm dispatch.
fn get_repeat_payment_item_total<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
>(
    item: &PaypalRouterData<
        RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>,
        T,
    >,
) -> Result<StringMajorUnit, Report<IntegrationError>> {
    item_total_net_of_shipping(
        item.router_data.request.amount.amount,
        item.router_data.request.currency,
        item.router_data.request.shipping_cost.as_ref(),
        item.connector.amount_converter,
    )
}

#[derive(Default, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Payee {
    merchant_id: Secret<String>,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct ItemDetails {
    name: String,
    quantity: u16,
    unit_amount: OrderAmount,
    tax: Option<OrderAmount>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        &PaypalRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for ItemDetails
{
    type Error = Report<IntegrationError>;
    fn try_from(
        item: &PaypalRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // The single synthetic item must equal breakdown.item_total (ITEM_TOTAL_MISMATCH).
        let value = get_authorize_item_total(item)?;
        Ok(Self {
            name: format!(
                "Payment for invoice {}",
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
            ),
            quantity: ORDER_QUANTITY,
            unit_amount: OrderAmount {
                currency_code: item.router_data.request.currency,
                value,
            },
            tax: None,
        })
    }
}

// ItemDetails for RepeatPayment
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        &PaypalRouterData<
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for ItemDetails
{
    type Error = Report<IntegrationError>;
    fn try_from(
        item: &PaypalRouterData<
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // The single synthetic item must equal breakdown.item_total (ITEM_TOTAL_MISMATCH).
        let value = get_repeat_payment_item_total(item)?;
        Ok(Self {
            name: format!(
                "Payment for invoice {}",
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
            ),
            quantity: ORDER_QUANTITY,
            unit_amount: OrderAmount {
                currency_code: item.router_data.request.currency,
                value,
            },
            tax: None,
        })
    }
}

#[derive(Default, Debug, Serialize, Eq, PartialEq, Deserialize)]
pub struct Address {
    address_line_1: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address_line_2: Option<Secret<String>>,
    postal_code: Option<Secret<String>>,
    country_code: common_enums::CountryAlpha2,
    admin_area_2: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    admin_area_1: Option<Secret<String>>,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct ShippingAddress {
    address: Option<Address>,
    name: Option<ShippingName>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    From<
        &PaypalRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for ShippingAddress
{
    fn from(
        item: &PaypalRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Self {
        Self {
            address: get_address_info(
                item.router_data
                    .resource_common_data
                    .get_optional_shipping(),
            ),
            name: Some(ShippingName {
                full_name: item
                    .router_data
                    .resource_common_data
                    .get_optional_shipping()
                    .and_then(|inner_data| inner_data.address.as_ref())
                    .and_then(|inner_data| inner_data.first_name.clone()),
            }),
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    From<
        &PaypalRouterData<
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for ShippingAddress
{
    fn from(
        item: &PaypalRouterData<
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Self {
        Self {
            address: get_address_info(
                item.router_data
                    .resource_common_data
                    .get_optional_shipping(),
            ),
            name: Some(ShippingName {
                full_name: item
                    .router_data
                    .resource_common_data
                    .get_optional_shipping()
                    .and_then(|inner_data| inner_data.address.as_ref())
                    .and_then(|inner_data| inner_data.first_name.clone()),
            }),
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct PaypalUpdateOrderRequest(Vec<Operation>);

impl PaypalUpdateOrderRequest {
    pub fn get_inner_value(self) -> Vec<Operation> {
        self.0
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Operation {
    pub op: PaypalOperationType,
    pub path: String,
    pub value: Value,
}

#[derive(Debug, Serialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum PaypalOperationType {
    Add,
    Remove,
    Replace,
    Move,
    Copy,
    Test,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Value {
    Amount(OrderRequestAmount),
    Items(Vec<ItemDetails>),
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct ShippingName {
    full_name: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct CardRequestStruct<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    billing_address: Option<Address>,
    expiry: Option<Secret<String>>,
    name: Option<Secret<String>>,
    number: Option<RawCardNumber<T>>,
    security_code: Option<Secret<String>>,
    attributes: Option<CardRequestAttributes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stored_credential: Option<PaypalStoredCredential>,
}

/// `payment_source.card.stored_credential`.
/// Doc: https://developer.paypal.com/docs/api/orders/v2/#definition-card_stored_credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalStoredCredential {
    payment_initiator: PaypalPaymentInitiator,
    payment_type: PaypalStoredPaymentType,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<PaypalStoredCredentialUsage>,
    /// Scheme reference of the earlier transaction an NTID MIT chains to. PayPal
    /// accepts it only with `payment_initiator = MERCHANT`.
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_network_transaction_reference: Option<PaypalPreviousNetworkTransactionReference>,
}

/// `stored_credential.previous_network_transaction_reference`.
/// `id` is 9-36 characters; `date` (4 digits) is mandatory for Mastercard and
/// Discover and is not carried by UCS, so those networks are refused before the call
/// (see `get_paypal_ntid_card_request`).
/// Doc: https://developer.paypal.com/docs/api/orders/v2/#definition-network_transaction_reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalPreviousNetworkTransactionReference {
    id: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<PaypalCardBrand>,
}

/// PayPal `card_brand` values used for `previous_network_transaction_reference.network`.
/// Doc: https://developer.paypal.com/docs/api/orders/v2/#definition-card_brand
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalCardBrand {
    Visa,
    Mastercard,
    Discover,
    Amex,
    Jcb,
    Star,
    Maestro,
    ChinaUnionPay,
    Diners,
    Rupay,
    CarteBancaire,
    Pulse,
    Nyce,
    Accel,
}

impl PaypalCardBrand {
    /// The PayPal brand for a UCS card network; `None` when PayPal's `card_brand`
    /// enum has no value for it (the optional `network` field is then omitted).
    fn from_card_network(network: &common_enums::CardNetwork) -> Option<Self> {
        use common_enums::CardNetwork as N;
        match network {
            N::Visa => Some(Self::Visa),
            N::Mastercard => Some(Self::Mastercard),
            N::AmericanExpress => Some(Self::Amex),
            N::JCB => Some(Self::Jcb),
            N::DinersClub => Some(Self::Diners),
            N::Discover => Some(Self::Discover),
            N::CartesBancaires => Some(Self::CarteBancaire),
            N::UnionPay => Some(Self::ChinaUnionPay),
            N::RuPay => Some(Self::Rupay),
            N::Maestro => Some(Self::Maestro),
            N::Star => Some(Self::Star),
            N::Pulse => Some(Self::Pulse),
            N::Accel => Some(Self::Accel),
            N::Nyce => Some(Self::Nyce),
            N::Interac | N::Prop | N::PrivateLabel | N::Dinacard => None,
        }
    }

    /// The PayPal brand for a BIN-detected issuer (used when the request names no
    /// card network).
    fn from_card_issuer(issuer: &utils::CardIssuer) -> Option<Self> {
        use utils::CardIssuer as I;
        match issuer {
            I::AmericanExpress => Some(Self::Amex),
            I::Master => Some(Self::Mastercard),
            I::Maestro => Some(Self::Maestro),
            I::Visa => Some(Self::Visa),
            I::Discover => Some(Self::Discover),
            I::DinersClub => Some(Self::Diners),
            I::JCB => Some(Self::Jcb),
            I::CartesBancaires => Some(Self::CarteBancaire),
            I::UnionPay => Some(Self::ChinaUnionPay),
            I::CarteBlanche => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalPaymentInitiator {
    Customer,
    Merchant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalStoredPaymentType {
    OneTime,
    Recurring,
    Unscheduled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalStoredCredentialUsage {
    First,
    Subsequent,
    Derived,
}

/// `payment_source.card.attributes.vault` — for cards PayPal documents only
/// `store_in_vault` (`vault_instruction_base`); `usage_type` and
/// `permit_multiple_payment_tokens` belong to the PayPal-wallet vault object.
/// Doc: https://developer.paypal.com/docs/api/orders/v2/#definition-vault_instruction_base
#[derive(Debug, Serialize)]
pub struct CardVaultAttribute {
    store_in_vault: StoreInVault,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardVaultStruct {
    vault_id: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attributes: Option<VaultRequestAttributes>,
    /// MIT indicators for a charge against a vaulted card.
    #[serde(skip_serializing_if = "Option::is_none")]
    stored_credential: Option<PaypalStoredCredential>,
}

/// `payment_source.apple_pay` for a merchant-initiated charge against a vaulted
/// Apple Pay token.
/// Doc: https://developer.paypal.com/docs/api/orders/v2/#definition-apple_pay_request
#[derive(Debug, Serialize)]
pub struct PaypalApplePayVaultRequest {
    vault_id: Secret<String>,
    stored_credential: PaypalStoredCredential,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRequestAttributes {
    customer: Option<CustomerRequestData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerRequestData {
    merchant_customer_id: Option<common_utils::id_type::CustomerId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalVaultStruct {
    vault_id: Secret<String>,
    // Buyer-return context for a vaulted PayPal (wallet) charge that requires
    // re-approval. Only valid on `payment_source.paypal`.
    #[serde(skip_serializing_if = "Option::is_none")]
    experience_context: Option<ContextStruct>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum CardRequest<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    CardRequestStruct(CardRequestStruct<T>),
    CardVaultStruct(CardVaultStruct),
}
#[derive(Debug, Serialize)]
pub struct CardRequestAttributes {
    vault: Option<CardVaultAttribute>,
    verification: Option<ThreeDsMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    customer: Option<CustomerRequestData>,
}

#[derive(Debug, Serialize)]
pub struct ThreeDsMethod {
    method: ThreeDsType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThreeDsType {
    ScaAlways,
}

#[derive(Debug, Serialize)]
pub struct RedirectRequest {
    name: Secret<String>,
    country_code: common_enums::CountryAlpha2,
    experience_context: ContextStruct,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextStruct {
    return_url: Option<String>,
    cancel_url: Option<String>,
    user_action: Option<UserAction>,
    shipping_preference: ShippingPreference,
}

#[derive(Debug, Serialize)]
pub struct GooglePayRequest {
    pub decrypted_token: GooglePayDecryptedToken,
}

#[derive(Debug, Serialize)]
pub struct ApplePayRequest {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Secret<String>>,
    pub decrypted_token: ApplePayDecryptedToken,
}

#[derive(Debug, Serialize)]
pub struct ApplePayDecryptedToken {
    pub tokenized_card: ApplePayTokenizedCard,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_data_type: Option<String>,
    pub payment_data: ApplePayPaymentDataRequest,
    pub transaction_amount: OrderAmount,
    // Required by PayPal for customer-initiated payments.
    // This is the deviceManufacturerIdentifier from Apple's decrypted token.
    // UCS domain_types does not currently carry this field through the gRPC layer,
    // so we use the well-known Apple Pay identifier. A future improvement would
    // thread the real value from ApplePayDecryptedData.
    pub device_manufacturer_id: String,
}

#[derive(Debug, Serialize)]
pub struct ApplePayTokenizedCard {
    pub number: Secret<String>,
    pub expiry: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct ApplePayPaymentDataRequest {
    pub cryptogram: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eci_indicator: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GooglePayPaymentMethod {
    Card,
}

#[derive(Debug, Serialize)]
pub struct GooglePayDecryptedToken {
    pub message_id: String,
    pub message_expiration: String,
    pub payment_method: GooglePayPaymentMethod,
    pub authentication_method: common_enums::GooglePayAuthMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptogram: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eci_indicator: Option<String>,
    pub card: GooglePayDecryptedCard,
}

#[derive(Debug, Serialize)]
pub struct GooglePayDecryptedCard {
    pub number: Secret<String>,
    pub expiry: Secret<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserAction {
    #[serde(rename = "PAY_NOW")]
    PayNow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShippingPreference {
    #[serde(rename = "SET_PROVIDED_ADDRESS")]
    SetProvidedAddress,
    #[serde(rename = "GET_FROM_FILE")]
    GetFromFile,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum PaypalRedirectionRequest {
    PaypalRedirectionStruct(PaypalRedirectionStruct),
    PaypalVaultStruct(PaypalVaultStruct),
}

#[derive(Debug, Serialize)]
pub struct PaypalRedirectionStruct {
    experience_context: ContextStruct,
    attributes: Option<Attributes>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Attributes {
    vault: PaypalVault,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaypalRedirectionResponse {
    attributes: Option<AttributeResponse>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EpsRedirectionResponse {
    name: Option<Secret<String>>,
    country_code: Option<common_enums::CountryAlpha2>,
    bic: Option<Secret<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdealRedirectionResponse {
    name: Option<Secret<String>>,
    country_code: Option<common_enums::CountryAlpha2>,
    bic: Option<Secret<String>>,
    iban_last_chars: Option<Secret<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttributeResponse {
    vault: PaypalVaultResponse,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaypalVault {
    store_in_vault: StoreInVault,
    usage_type: UsageType,
    // required for vaulting multiple payment tokens for a customer, as per Paypal's documentation. If false or not provided, only one payment token can be vaulted for a customer. If true, multiple payment tokens can be vaulted for a customer. and this will be required for returning customer flow.
    permit_multiple_payment_tokens: Option<bool>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaypalVaultResponse {
    id: Option<String>,
    status: String,
    customer: Option<CustomerId>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomerId {
    id: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreInVault {
    OnSuccess,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UsageType {
    Merchant,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PaymentSourceItem<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    Card(CardRequest<T>),
    Paypal(PaypalRedirectionRequest),
    #[serde(rename = "google_pay")]
    GooglePay(GooglePayRequest),
    #[serde(rename = "apple_pay")]
    ApplePay(ApplePayRequest),
    #[serde(rename = "apple_pay")]
    ApplePayVault(PaypalApplePayVaultRequest),
    IDeal(RedirectRequest),
    Eps(RedirectRequest),
    Giropay(RedirectRequest),
    Sofort(RedirectRequest),
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CardVaultResponse {
    attributes: Option<AttributeResponse>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GooglePaySourceResponse {
    card: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApplePaySourceResponse {
    pub name: Option<Secret<String>>,
    pub card: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum PaymentSourceItemResponse {
    Card(CardVaultResponse),
    Paypal(PaypalRedirectionResponse),
    Eps(EpsRedirectionResponse),
    Ideal(IdealRedirectionResponse),
    GooglePay(GooglePaySourceResponse),
    ApplePay(ApplePaySourceResponse),
}

// ============================================================================
// CreateOrder Request/Response Types
// ============================================================================

/// CreateOrder request — creates a PayPal order without payment source.
/// The order_id returned is then used in the Authorize step.
#[derive(Debug, Serialize)]
pub struct PaypalOrderCreateRequest {
    intent: PaypalPaymentIntent,
    purchase_units: Vec<PaypalOrderCreatePurchaseUnit>,
}

/// Simplified purchase unit for CreateOrder (no payment-method-specific fields).
#[derive(Debug, Serialize)]
pub struct PaypalOrderCreatePurchaseUnit {
    reference_id: Option<String>,
    invoice_id: Option<String>,
    amount: PaypalOrderCreateAmount,
}

/// Amount block for CreateOrder (no breakdown required).
#[derive(Debug, Serialize)]
pub struct PaypalOrderCreateAmount {
    currency_code: common_enums::Currency,
    value: StringMajorUnit,
}

/// CreateOrder response — we only need the order id and status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalOrderCreateResponse {
    pub id: String,
    pub status: PaypalOrderStatus,
}

// --- TryFrom: RouterDataV2 -> PaypalOrderCreateRequest (via macro wrapper) ---

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PaypalRouterData<
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
            T,
        >,
    > for PaypalOrderCreateRequest
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: PaypalRouterData<
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        let value = item
            .connector
            .amount_converter
            .convert(
                router_data.request.amount.amount,
                router_data.request.currency,
            )
            .change_context(IntegrationError::AmountConversionFailed {
                context: Default::default(),
            })?;

        let connector_request_reference_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let purchase_units = vec![PaypalOrderCreatePurchaseUnit {
            reference_id: Some(connector_request_reference_id.clone()),
            invoice_id: Some(connector_request_reference_id),
            amount: PaypalOrderCreateAmount {
                currency_code: router_data.request.currency,
                value,
            },
        }];

        // Default to Authorize intent so we can capture later
        let intent = PaypalPaymentIntent::Authorize;

        Ok(Self {
            intent,
            purchase_units,
        })
    }
}

// --- TryFrom: PaypalOrderCreateResponse -> PaymentCreateOrderResponse ---

impl TryFrom<PaypalOrderCreateResponse> for PaymentCreateOrderResponse {
    type Error = Report<ConnectorError>;

    fn try_from(response: PaypalOrderCreateResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            connector_order_id: response.id,
            session_data: None,
        })
    }
}

// --- TryFrom: ResponseRouterData -> RouterDataV2 (CreateOrder response handler) ---

impl TryFrom<ResponseRouterData<PaypalOrderCreateResponse, Self>>
    for RouterDataV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    >
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<PaypalOrderCreateResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let order_response = PaymentCreateOrderResponse::try_from(response.clone())?;

        // Extract order_id before moving
        let order_id = order_response.connector_order_id.clone();

        Ok(Self {
            response: Ok(order_response),
            resource_common_data: PaymentFlowData {
                status: common_enums::AttemptStatus::Pending,
                // KEY: Store order ID so Authorize flow can use it via connector_order_id
                connector_order_id: Some(order_id),
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ============================================================================

#[derive(Debug, Serialize)]
pub struct PaypalPaymentsRequest<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    intent: PaypalPaymentIntent,
    purchase_units: Vec<PurchaseUnitRequest>,
    payment_source: Option<PaymentSourceItem<T>>,
}

#[derive(Debug, Serialize)]
pub struct PaypalZeroMandateRequest {
    payment_source: ZeroMandateSourceItem,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ZeroMandateSourceItem {
    Card(CardMandateRequest),
    Paypal(PaypalMandateStruct),
    /// `payment_source.token`: converts an APPROVED Vault v3 setup token (from
    /// PaymentMethodService/Tokenize) into a payment token.
    /// Doc: https://developer.paypal.com/docs/api/payment-tokens/v3/#payment-tokens_create
    Token(PaypalSetupTokenRef),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaypalSetupTokenRef {
    id: Secret<String>,
    #[serde(rename = "type")]
    token_type: PaypalVaultTokenType,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalVaultTokenType {
    SetupToken,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaypalMandateStruct {
    experience_context: Option<ContextStruct>,
    usage_type: UsageType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CardMandateRequest {
    billing_address: Option<Address>,
    expiry: Option<Secret<String>>,
    name: Option<Secret<String>>,
    number: Option<cards::CardNumber>,
}

/// `POST /v3/vault/payment-tokens` response. `payment_source` is `card` for a raw
/// card or a card setup token and `apple_pay` for an Apple Pay setup token; it is
/// not read, so it is kept untyped to accept either shape.
/// Doc: https://developer.paypal.com/docs/api/payment-tokens/v3/#payment-tokens_create
#[derive(Debug, Deserialize, Serialize)]
pub struct PaypalSetupMandatesResponse {
    id: String,
    customer: Customer,
    payment_source: Option<serde_json::Value>,
    links: Vec<PaypalLinks>,
}

// RepeatPayment - reuses Authorize request/response types
pub type PaypalRepeatPaymentRequest<T> = PaypalPaymentsRequest<T>;
pub type PaypalRepeatPaymentResponse = PaypalAuthResponse;

// Response handling for RepeatPayment - delegates to PaypalOrdersResponse
impl<
        T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize + Serialize,
    > TryFrom<ResponseRouterData<PaypalAuthResponse, Self>>
    for RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<PaypalAuthResponse, Self>) -> Result<Self, Self::Error> {
        // RepeatPayment returns PaypalOrdersResponse variant (direct capture)
        match item.response {
            PaypalAuthResponse::PaypalOrdersResponse(orders_response) => {
                Self::try_from(ResponseRouterData {
                    response: orders_response,
                    router_data: item.router_data,
                    http_code: item.http_code,
                })
            }
            // A PayPal wallet MIT (payment_source.paypal.vault_id) may require buyer
            // re-approval, in which case PayPal returns a redirect response instead of a
            // direct capture. Mirror the Authorize redirect handler so we surface an
            // AuthenticationPending redirect instead of hard-failing (parity with the
            // reference, where MIT flows through the Authorize response handler).
            PaypalAuthResponse::PaypalRedirectResponse(redirect_response) => {
                let status = get_order_status(
                    redirect_response.status.clone(),
                    redirect_response.intent.clone(),
                );
                let link = get_redirect_url(redirect_response.links.clone())?;
                let connector_meta = serde_json::json!(PaypalMeta {
                    authorize_id: None,
                    capture_id: None,
                    incremental_authorization_id: None,
                    psync_flow: redirect_response.intent.clone(),
                    next_action: None,
                    order_id: None,
                    order_intent: None,
                });
                let purchase_units = redirect_response.purchase_units.first();
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        ..item.router_data.resource_common_data
                    },
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            redirect_response.id.clone(),
                        ),
                        redirection_data: link
                            .map(|url| Box::new(RedirectForm::from((url, Method::Get)))),
                        mandate_reference: None,
                        connector_metadata: Some(connector_meta),
                        network_txn_id: None,
                        network_txn_link_id: None,
                        connector_response_reference_id: Some(
                            purchase_units
                                .map_or(redirect_response.id, |item| item.invoice_id.clone()),
                        ),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                        splits: None,
                        payment_account_reference: None,
                    }),
                    ..item.router_data
                })
            }
            // A card MIT can surface a 3DS challenge; mirror the Authorize 3DS handler so the
            // buyer can complete authentication instead of hard-failing. RepeatPaymentData has
            // no `complete_authorize_url`, so the merchant `router_return_url` is used as the
            // post-challenge return target.
            PaypalAuthResponse::PaypalThreeDsResponse(threeds_response) => {
                let connector_meta = serde_json::json!(PaypalMeta {
                    authorize_id: None,
                    capture_id: None,
                    incremental_authorization_id: None,
                    psync_flow: PaypalPaymentIntent::Authenticate,
                    next_action: None,
                    order_id: None,
                    order_intent: None,
                });
                let status = get_order_status(
                    threeds_response.status.clone(),
                    PaypalPaymentIntent::Authenticate,
                );
                let link = get_redirect_url(threeds_response.links.clone())?;
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        ..item.router_data.resource_common_data
                    },
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(threeds_response.id),
                        redirection_data: Some(Box::new(paypal_threeds_link(
                            (link, item.router_data.request.router_return_url.clone()),
                            item.http_code,
                        )?)),
                        mandate_reference: None,
                        connector_metadata: Some(connector_meta),
                        network_txn_id: None,
                        network_txn_link_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                        splits: None,
                        payment_account_reference: None,
                    }),
                    ..item.router_data
                })
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Customer {
    id: String,
}

// Apple Pay (decrypted) for PayPal.
//
// Uses PayPal's dedicated `payment_source.apple_pay.decrypted_token` structure
// (https://developer.paypal.com/docs/api/orders/v2/#definition-apple_pay_decrypted_token_data)
// which carries the DPAN, expiry, cryptogram, and ECI indicator — preserving
// the 3DS liability shift and correct interchange treatment.
// Encrypted Apple Pay tokens are refused here (NotSupported); see the Vault v3 path below.
fn build_paypal_apple_pay_source<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
>(
    apple_pay_data: &domain_types::payment_method_data::ApplePayWalletData,
    router_data: &RouterDataV2<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    >,
    amount_value: StringMajorUnit,
    currency: common_enums::Currency,
) -> Result<PaymentSourceItem<T>, Report<IntegrationError>> {
    // Orders v2 apple_pay_request has no field for the encrypted Apple Pay token; PayPal
    // accepts it only on Vault v3 setup-tokens (apple_pay.token). That path is served by
    // the PaymentMethodService/Tokenize -> PaymentService/TokenSetupRecurring ->
    // RecurringPaymentService/Charge chain, so this arm refuses before any HTTP call.
    let apple_pay_decrypted_data = apple_pay_data
        .payment_data
        .get_decrypted_apple_pay_payment_data_optional()
        .ok_or_else(|| {
            error_stack::report!(IntegrationError::NotSupported {
                message: "Apple Pay encrypted token (PSP decryption) on Authorize: PayPal \
                          Orders v2 apple_pay_request accepts only decrypted_token or vault_id"
                    .to_string(),
                connector: "Paypal",
                context: IntegrationErrorContext {
                    suggested_action: Some(
                        "Use PaymentMethodService/Tokenize (Vault v3 setup token with \
                         apple_pay.token) -> PaymentService/TokenSetupRecurring -> \
                         RecurringPaymentService/Charge, or send the decrypted Apple Pay data"
                            .to_string(),
                    ),
                    doc_url: Some(
                        "https://developer.paypal.com/docs/api/payment-tokens/v3/".to_string(),
                    ),
                    additional_context: Some(
                        "Checked https://developer.paypal.com/api/orders/v2/definitions/apple_pay_request"
                            .to_string(),
                    ),
                },
            })
        })?;

    // PayPal decrypted_token expiry format is YYYY-MM.
    let expiry = apple_pay_decrypted_data.get_expiry_date_as_yyyymm("-");

    let card_number = Secret::new(
        apple_pay_decrypted_data
            .application_primary_account_number
            .get_card_no(),
    );

    let cardholder_name = router_data
        .resource_common_data
        .get_optional_payment_billing_full_name();

    let cryptogram = apple_pay_decrypted_data
        .payment_data
        .online_payment_cryptogram
        .clone();
    let eci_indicator = apple_pay_decrypted_data.payment_data.eci_indicator.clone();

    Ok(PaymentSourceItem::ApplePay(ApplePayRequest {
        id: apple_pay_data.transaction_identifier.clone(),
        name: cardholder_name.clone(),
        decrypted_token: ApplePayDecryptedToken {
            tokenized_card: ApplePayTokenizedCard {
                number: card_number,
                expiry,
                name: cardholder_name,
            },
            // PayPal supports two payment_data_type values: "3DSECURE" (cryptogram + ECI,
            // standard outside China) and "EMV" (emv_data + pin, China only).
            // UCS exclusively receives pre-decrypted Apple Pay tokens over gRPC, which
            // always carry online_payment_cryptogram + eci_indicator — the 3DS Secure
            // path. The EMV/China path is not supported by UCS.
            payment_data_type: Some("3DSECURE".to_string()),
            payment_data: ApplePayPaymentDataRequest {
                cryptogram,
                eci_indicator,
            },
            transaction_amount: OrderAmount {
                currency_code: currency,
                value: amount_value,
            },
            // TODO(#1149): Hardcoded fallback — `deviceManufacturerIdentifier` from Apple's
            // decrypted token is not currently propagated through the UCS proto / domain_types.
            // This works in sandbox but will cause failures in production where PayPal validates
            // the field. Fix requires adding the field to `ApplePayDecryptedData` in
            // payment_methods.proto, domain_types, and the HS decryption path.
            // See: https://github.com/juspay/hyperswitch-prism/issues/1149
            device_manufacturer_id: "040010030273".to_string(),
        },
    }))
}

fn get_address_info(
    payment_address: Option<&domain_types::payment_address::Address>,
) -> Option<Address> {
    let address = payment_address.and_then(|payment_address| payment_address.address.as_ref());
    match address {
        Some(address) => address.get_optional_country().map(|country| Address {
            country_code: country.to_owned(),
            address_line_1: address.line1.clone(),
            address_line_2: address.line2.clone(),
            postal_code: address.zip.clone(),
            admin_area_2: address.city.clone(),
            admin_area_1: address.state.clone(),
        }),
        None => None,
    }
}
fn get_payment_source<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
>(
    item: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    bank_redirection_data: &BankRedirectData,
) -> Result<PaymentSourceItem<T>, Report<IntegrationError>> {
    match bank_redirection_data {
        BankRedirectData::Eps { .. } => Ok(PaymentSourceItem::Eps(RedirectRequest {
            name: item.resource_common_data.get_billing_full_name()?,
            country_code: item.resource_common_data.get_billing_country()?,
            experience_context: ContextStruct {
                return_url: item.request.complete_authorize_url.clone(),
                cancel_url: item.request.complete_authorize_url.clone(),
                shipping_preference: if item
                    .resource_common_data
                    .get_optional_shipping_country()
                    .is_some()
                {
                    ShippingPreference::SetProvidedAddress
                } else {
                    ShippingPreference::GetFromFile
                },
                user_action: Some(UserAction::PayNow),
            },
        })),
        BankRedirectData::Giropay { .. } => Ok(PaymentSourceItem::Giropay(RedirectRequest {
            name: item.resource_common_data.get_billing_full_name()?,
            country_code: item.resource_common_data.get_billing_country()?,
            experience_context: ContextStruct {
                return_url: item.request.complete_authorize_url.clone(),
                cancel_url: item.request.complete_authorize_url.clone(),
                shipping_preference: if item
                    .resource_common_data
                    .get_optional_shipping_country()
                    .is_some()
                {
                    ShippingPreference::SetProvidedAddress
                } else {
                    ShippingPreference::GetFromFile
                },
                user_action: Some(UserAction::PayNow),
            },
        })),
        BankRedirectData::Ideal { .. } => Ok(PaymentSourceItem::IDeal(RedirectRequest {
            name: item.resource_common_data.get_billing_full_name()?,
            country_code: item.resource_common_data.get_billing_country()?,
            experience_context: ContextStruct {
                return_url: item.request.complete_authorize_url.clone(),
                cancel_url: item.request.complete_authorize_url.clone(),
                shipping_preference: if item
                    .resource_common_data
                    .get_optional_shipping_country()
                    .is_some()
                {
                    ShippingPreference::SetProvidedAddress
                } else {
                    ShippingPreference::GetFromFile
                },
                user_action: Some(UserAction::PayNow),
            },
        })),
        BankRedirectData::Sofort { .. } => Ok(PaymentSourceItem::Sofort(RedirectRequest {
            name: item.resource_common_data.get_billing_full_name()?,
            country_code: item.resource_common_data.get_billing_country()?,
            experience_context: ContextStruct {
                return_url: item.request.complete_authorize_url.clone(),
                cancel_url: item.request.complete_authorize_url.clone(),
                shipping_preference: if item
                    .resource_common_data
                    .get_optional_shipping_country()
                    .is_some()
                {
                    ShippingPreference::SetProvidedAddress
                } else {
                    ShippingPreference::GetFromFile
                },
                user_action: Some(UserAction::PayNow),
            },
        })),
        BankRedirectData::BancontactCard { .. }
        | BankRedirectData::Blik { .. }
        | BankRedirectData::Przelewy24 { .. } => Err(IntegrationError::NotImplemented(
            utils::get_unimplemented_payment_method_error_message("Paypal"),
            Default::default(),
        )
        .into()),
        BankRedirectData::Bizum {}
        | BankRedirectData::Eft { .. }
        | BankRedirectData::Interac { .. }
        | BankRedirectData::OnlineBankingCzechRepublic { .. }
        | BankRedirectData::OnlineBankingFinland { .. }
        | BankRedirectData::OnlineBankingPoland { .. }
        | BankRedirectData::OnlineBankingSlovakia { .. }
        | BankRedirectData::OpenBankingUk { .. }
        | BankRedirectData::Trustly { .. }
        | BankRedirectData::OnlineBankingFpx { .. }
        | BankRedirectData::OnlineBankingThailand { .. }
        | BankRedirectData::LocalBankRedirect {}
        | BankRedirectData::OpenBanking { .. }
        | BankRedirectData::Netbanking { .. } => Err(IntegrationError::NotImplemented(
            utils::get_unimplemented_payment_method_error_message("Paypal"),
            Default::default(),
        ))?,
    }
}

fn get_payee(auth_type: &PaypalAuthType) -> Option<Payee> {
    auth_type
        .get_credentials()
        .ok()
        .and_then(|credentials| credentials.get_payer_id())
        .map(|payer_id| Payee {
            merchant_id: payer_id,
        })
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PaypalRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for PaypalPaymentsRequest<T>
{
    type Error = Report<IntegrationError>;
    fn try_from(
        item: PaypalRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let paypal_auth: PaypalAuthType =
            PaypalAuthType::try_from(&item.router_data.connector_config)?;
        let payee = get_payee(&paypal_auth);

        let amount = OrderRequestAmount::try_from(&item)?;

        let intent = if item.router_data.request.is_auto_capture() {
            PaypalPaymentIntent::Capture
        } else {
            PaypalPaymentIntent::Authorize
        };

        let connector_request_reference_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let shipping_address = ShippingAddress::from(&item);
        let item_details = vec![ItemDetails::try_from(&item)?];
        let soft_descriptor =
            get_paypal_soft_descriptor(item.router_data.request.billing_descriptor.as_ref());
        let supplementary_data = get_paypal_supplementary_data(
            item.router_data.resource_common_data.l2_l3_data.as_deref(),
            &connector_request_reference_id,
            item.router_data.request.currency,
            item.connector.amount_converter,
        )?;

        let purchase_units = vec![PurchaseUnitRequest {
            reference_id: Some(connector_request_reference_id.clone()),
            custom_id: item.router_data.request.merchant_order_id.clone(),
            invoice_id: Some(connector_request_reference_id),
            amount,
            payee,
            shipping: Some(shipping_address),
            items: item_details,
            soft_descriptor,
            supplementary_data,
        }];

        match item.router_data.request.payment_method_data {
            PaymentMethodData::Card(ref ccard) => {
                // G-Authorize-01: PayPal's card request has no field for merchant-supplied
                // 3DS results (cavv / eci / ds_transaction_id). Sending the order anyway
                // would create an unauthenticated card payment, so refuse before any call.
                if item.router_data.request.authentication_data.is_some() {
                    return Err(error_stack::report!(IntegrationError::NotSupported {
                        message: "External 3DS authentication data (cavv/eci) for card payments"
                            .to_string(),
                        connector: "Paypal",
                        context: IntegrationErrorContext {
                            suggested_action: Some(
                                "Let PayPal run 3DS (auth_type THREE_DS) instead of passing \
                                 authentication_data; PayPal Orders v2 card_request carries no \
                                 cavv/eci/ds_transaction_id field"
                                    .to_string(),
                            ),
                            doc_url: Some(
                                "https://developer.paypal.com/docs/api/orders/v2/#definition-card_request"
                                    .to_string(),
                            ),
                            additional_context: None,
                        },
                    }));
                }
                // G-Authorize-02: PayPal returns the payer to `redirect_uri` after the 3DS
                // challenge; without it the order would be created and then stranded.
                // gRPC maps an unset string to Some(""), so an empty or whitespace URL is
                // treated as absent (b4-11, B044).
                if item.router_data.resource_common_data.auth_type
                    == common_enums::AuthenticationType::ThreeDs
                    && item
                        .router_data
                        .request
                        .complete_authorize_url
                        .as_deref()
                        .is_none_or(|url| url.trim().is_empty())
                {
                    return Err(error_stack::report!(IntegrationError::MissingRequiredField {
                        field_name: "complete_authorize_url",
                        context: IntegrationErrorContext {
                            suggested_action: Some(
                                "Provide complete_authorize_url for a 3DS card payment so the \
                                 payer can be returned after the PayPal challenge"
                                    .to_string(),
                            ),
                            doc_url: Some(
                                "https://developer.paypal.com/docs/checkout/advanced/customize/3d-secure/api/"
                                    .to_string(),
                            ),
                            additional_context: Some(
                                "complete_authorize_url is absent or empty".to_string(),
                            ),
                        },
                    }));
                }
                let card = item.router_data.request.get_card()?;
                let expiry = Some(card.get_expiry_date_as_yyyymm("-"));
                let is_cit_off_session = item.router_data.request.setup_future_usage
                    == Some(common_enums::FutureUsage::OffSession);

                let verification = match item.router_data.resource_common_data.auth_type {
                    common_enums::AuthenticationType::ThreeDs => Some(ThreeDsMethod {
                        method: ThreeDsType::ScaAlways,
                    }),
                    common_enums::AuthenticationType::NoThreeDs => None,
                };

                let payment_source = Some(PaymentSourceItem::Card(CardRequest::CardRequestStruct(
                    CardRequestStruct {
                        billing_address: get_address_info(
                            item.router_data
                                .resource_common_data
                                .get_optional_payment_billing(),
                        ),
                        expiry,
                        name: item
                            .router_data
                            .resource_common_data
                            .get_optional_payment_billing_full_name(),
                        number: Some(ccard.card_number.clone()),
                        security_code: Some(ccard.card_cvc.clone()),
                        attributes: Some(CardRequestAttributes {
                            vault: is_cit_off_session.then_some(CardVaultAttribute {
                                store_in_vault: StoreInVault::OnSuccess,
                            }),
                            verification,
                            customer: item
                                .router_data
                                .resource_common_data
                                .customer_id
                                .clone()
                                .map(|customer_id| CustomerRequestData {
                                    merchant_customer_id: Some(customer_id),
                                }),
                        }),
                        // CIT that saves the card for later merchant-initiated use.
                        stored_credential: is_cit_off_session.then_some(PaypalStoredCredential {
                            payment_initiator: PaypalPaymentInitiator::Customer,
                            payment_type: PaypalStoredPaymentType::Unscheduled,
                            usage: Some(PaypalStoredCredentialUsage::First),
                            previous_network_transaction_reference: None,
                        }),
                    },
                )));

                Ok(Self {
                    intent,
                    purchase_units,
                    payment_source,
                })
            }
            PaymentMethodData::Wallet(ref wallet_data) => match wallet_data {
                WalletData::PaypalRedirect(_) => {
                    let payment_source = Some(PaymentSourceItem::Paypal(
                        PaypalRedirectionRequest::PaypalRedirectionStruct(
                            PaypalRedirectionStruct {
                                experience_context: ContextStruct {
                                    return_url: item
                                        .router_data
                                        .request
                                        .complete_authorize_url
                                        .clone(),
                                    cancel_url: item
                                        .router_data
                                        .request
                                        .complete_authorize_url
                                        .clone(),
                                    shipping_preference: if item
                                        .router_data
                                        .resource_common_data
                                        .get_optional_shipping()
                                        .is_some()
                                    {
                                        ShippingPreference::SetProvidedAddress
                                    } else {
                                        ShippingPreference::GetFromFile
                                    },
                                    user_action: Some(UserAction::PayNow),
                                },
                                attributes: match item.router_data.request.setup_future_usage {
                                    Some(setup_future_usage) => match setup_future_usage {
                                        common_enums::FutureUsage::OffSession => Some(Attributes {
                                            vault: PaypalVault {
                                                store_in_vault: StoreInVault::OnSuccess,
                                                usage_type: UsageType::Merchant,
                                                permit_multiple_payment_tokens: Some(true),
                                            },
                                        }),
                                        common_enums::FutureUsage::OnSession => None,
                                    },
                                    None => None,
                                },
                            },
                        ),
                    ));

                    Ok(Self {
                        intent,
                        purchase_units,
                        payment_source,
                    })
                }
                WalletData::PaypalSdk(_) => {
                    let payment_source = Some(PaymentSourceItem::Paypal(
                        PaypalRedirectionRequest::PaypalRedirectionStruct(
                            PaypalRedirectionStruct {
                                experience_context: ContextStruct {
                                    return_url: None,
                                    cancel_url: None,
                                    shipping_preference: ShippingPreference::GetFromFile,
                                    user_action: Some(UserAction::PayNow),
                                },
                                attributes: match item.router_data.request.setup_future_usage {
                                    Some(setup_future_usage) => match setup_future_usage {
                                        common_enums::FutureUsage::OffSession => Some(Attributes {
                                            vault: PaypalVault {
                                                store_in_vault: StoreInVault::OnSuccess,
                                                usage_type: UsageType::Merchant,
                                                permit_multiple_payment_tokens: Some(true),
                                            },
                                        }),
                                        common_enums::FutureUsage::OnSession => None,
                                    },
                                    None => None,
                                },
                            },
                        ),
                    ));

                    Ok(Self {
                        intent,
                        purchase_units,
                        payment_source,
                    })
                }
                WalletData::GooglePay(gpay_data) => match &gpay_data.tokenization_data {
                    GpayTokenizationData::Decrypted(decrypted_data) => {
                        let expiry = decrypted_data
                            .get_expiry_date_as_yyyymm("-")
                            .change_context(IntegrationError::InvalidWalletToken {
                                wallet_name: "Google Pay".to_string(),
                                context: Default::default(),
                            })?;
                        let authentication_method = if decrypted_data.cryptogram.is_some() {
                            common_enums::GooglePayAuthMethod::Cryptogram
                        } else {
                            common_enums::GooglePayAuthMethod::PanOnly
                        };
                        let payment_source = Some(PaymentSourceItem::GooglePay(GooglePayRequest {
                            decrypted_token: GooglePayDecryptedToken {
                                message_id: common_utils::fp_utils::generate_uuid_v4(),
                                // TODO: message_expiration is hardcoded because HS does not currently
                                // forward this field from the decrypted GPay payload through the gRPC
                                // interface. Tracked in https://github.com/juspay/hyperswitch/issues/11684
                                message_expiration: "9999999999999".to_string(),
                                payment_method: GooglePayPaymentMethod::Card,
                                authentication_method,
                                cryptogram: decrypted_data.cryptogram.clone(),
                                eci_indicator: decrypted_data.eci_indicator.clone(),
                                card: GooglePayDecryptedCard {
                                    number: Secret::new(
                                        decrypted_data
                                            .application_primary_account_number
                                            .get_card_no(),
                                    ),
                                    expiry,
                                },
                            },
                        }));
                        Ok(Self {
                            intent,
                            purchase_units,
                            payment_source,
                        })
                    }
                    // PayPal REST has no request field for an encrypted Google Pay token.
                    // Checked: Orders v2 google_pay_request {name, email_address,
                    // phone_number, card, decrypted_token, assurance_details,
                    // experience_context}; Vault v3 setup/payment-token payment_source
                    // {card, paypal, venmo, apple_pay, token, bank}.
                    GpayTokenizationData::Encrypted(_) => {
                        Err(error_stack::report!(IntegrationError::NotSupported {
                            message: "Google Pay encrypted token (PSP decryption): PayPal \
                                      Orders v2 google_pay_request accepts only decrypted_token"
                                .to_string(),
                            connector: "Paypal",
                            context: IntegrationErrorContext {
                                suggested_action: Some(
                                    "Decrypt the Google Pay token before calling (send \
                                     tokenization_data.decrypted_data)"
                                        .to_string(),
                                ),
                                doc_url: Some(
                                    "https://developer.paypal.com/api/orders/v2/definitions/google_pay_request"
                                        .to_string(),
                                ),
                                additional_context: None,
                            },
                        }))
                    }
                },
                WalletData::ApplePay(apple_pay_data) => {
                    let amount_value = item
                        .connector
                        .amount_converter
                        .convert(
                            item.router_data.request.amount.amount,
                            item.router_data.request.currency,
                        )
                        .change_context(IntegrationError::AmountConversionFailed {
                            context: Default::default(),
                        })?;
                    let payment_source = Some(build_paypal_apple_pay_source(
                        apple_pay_data,
                        &item.router_data,
                        amount_value,
                        item.router_data.request.currency,
                    )?);
                    Ok(Self {
                        intent,
                        purchase_units,
                        payment_source,
                    })
                }
                WalletData::AliPayQr(_)
                | WalletData::AliPayRedirect(_)
                | WalletData::AliPayHkRedirect(_)
                | WalletData::AmazonPayRedirect(_)
                | WalletData::MomoRedirect(_)
                | WalletData::KakaoPayRedirect(_)
                | WalletData::GoPayRedirect(_)
                | WalletData::GcashRedirect(_)
                | WalletData::ApplePayRedirect(_)
                | WalletData::ApplePayThirdPartySdk(_)
                | WalletData::DanaRedirect {}
                | WalletData::GrabpayRedirect {}
                | WalletData::BluecodeRedirect {}
                | WalletData::GooglePayRedirect(_)
                | WalletData::GooglePayThirdPartySdk(_)
                | WalletData::MbWayRedirect(_)
                | WalletData::MobilePayRedirect(_)
                | WalletData::SamsungPay(_)
                | WalletData::TwintRedirect {}
                | WalletData::VippsRedirect {}
                | WalletData::TouchNGoRedirect(_)
                | WalletData::WeChatPayRedirect(_)
                | WalletData::WeChatPayQr(_)
                | WalletData::CashappQr(_)
                | WalletData::SwishQr(_)
                | WalletData::Mifinity(_)
                | WalletData::RevolutPay(_)
                | WalletData::Paze(_)
                | WalletData::MbWay(_)
                | WalletData::Satispay(_)
                | WalletData::Wero(_)
                | WalletData::LazyPayRedirect(_)
                | WalletData::PhonePeRedirect(_)
                | WalletData::BillDeskRedirect(_)
                | WalletData::CashfreeRedirect(_)
                | WalletData::PayURedirect(_)
                | WalletData::EaseBuzzRedirect(_)
                | WalletData::PaymayaRedirect(_)
                | WalletData::PayhereRedirect {}
                | WalletData::QwikcilverWalletDirect(_)
                | WalletData::Skrill(_)
                | WalletData::Neteller(_) => {
                    Err(error_stack::report!(IntegrationError::NotSupported {
                        message: utils::get_unimplemented_payment_method_error_message("Paypal"),
                        connector: "Paypal",
                        context: Default::default(),
                    }))?
                }
            },
            PaymentMethodData::BankRedirect(ref bank_redirection_data) => {
                // G-Authorize-03: PayPal APMs are auto-capture only; refuse before building
                // the payment source so no request is made.
                if !item.router_data.request.is_auto_capture() {
                    return Err(error_stack::report!(IntegrationError::FlowNotSupported {
                        flow: "Manual capture method for Bank Redirect".to_string(),
                        connector: "Paypal".to_string(),
                        context: IntegrationErrorContext {
                            suggested_action: Some(
                                "Use capture_method AUTOMATIC for EPS/Giropay/iDEAL/Sofort"
                                    .to_string(),
                            ),
                            doc_url: Some(
                                "https://developer.paypal.com/docs/checkout/apm/".to_string(),
                            ),
                            additional_context: None,
                        },
                    }));
                }
                let payment_source = Some(get_payment_source(
                    item.router_data.clone(),
                    bank_redirection_data,
                )?);

                Ok(Self {
                    intent: PaypalPaymentIntent::Capture,
                    purchase_units,
                    payment_source,
                })
            }
            PaymentMethodData::CardRedirect(ref card_redirect_data) => {
                Self::try_from(card_redirect_data)
            }
            PaymentMethodData::PayLater(ref paylater_data) => Self::try_from(paylater_data),
            PaymentMethodData::BankDebit(ref bank_debit_data) => Self::try_from(bank_debit_data),
            PaymentMethodData::BankTransfer(ref bank_transfer_data) => {
                Self::try_from(bank_transfer_data.as_ref())
            }
            PaymentMethodData::Voucher(ref voucher_data) => Self::try_from(voucher_data),
            PaymentMethodData::GiftCard(ref giftcard_data) => {
                Self::try_from(giftcard_data.as_ref())
            }
            PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::CardWithNoCvc(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::PaymentMethodToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::DecryptedWalletTokenDetailsForNetworkTransactionId(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Err(error_stack::report!(IntegrationError::NotSupported {
                    message: utils::get_unimplemented_payment_method_error_message("Paypal"),
                    connector: "Paypal",
                    context: Default::default(),
                }))
            }
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<&CardRedirectData> for PaypalPaymentsRequest<T>
{
    type Error = Report<IntegrationError>;
    fn try_from(value: &CardRedirectData) -> Result<Self, Self::Error> {
        match value {
            CardRedirectData::Knet {}
            | CardRedirectData::Benefit {}
            | CardRedirectData::MomoAtm {}
            | CardRedirectData::CardRedirect {}
            | CardRedirectData::Webpay {} => {
                Err(error_stack::report!(IntegrationError::NotSupported {
                    message: utils::get_unimplemented_payment_method_error_message("Paypal"),
                    connector: "Paypal",
                    context: Default::default(),
                }))
            }
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<&PayLaterData> for PaypalPaymentsRequest<T>
{
    type Error = Report<IntegrationError>;
    fn try_from(value: &PayLaterData) -> Result<Self, Self::Error> {
        match value {
            PayLaterData::KlarnaRedirect { .. }
            | PayLaterData::KlarnaSdk { .. }
            | PayLaterData::AffirmRedirect {}
            | PayLaterData::AfterpayClearpayRedirect { .. }
            | PayLaterData::PayBrightRedirect {}
            | PayLaterData::WalleyRedirect {}
            | PayLaterData::AlmaRedirect {}
            | PayLaterData::TamaraRedirect {}
            | PayLaterData::AtomeRedirect {} => {
                Err(error_stack::report!(IntegrationError::NotSupported {
                    message: utils::get_unimplemented_payment_method_error_message("Paypal"),
                    connector: "Paypal",
                    context: Default::default(),
                }))
            }
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<&BankDebitData> for PaypalPaymentsRequest<T>
{
    type Error = Report<IntegrationError>;
    fn try_from(value: &BankDebitData) -> Result<Self, Self::Error> {
        match value {
            BankDebitData::AchBankDebit { .. }
            | BankDebitData::SepaBankDebit { .. }
            | BankDebitData::EftBankDebit { .. }
            | BankDebitData::SepaGuaranteedBankDebit { .. }
            | BankDebitData::BecsBankDebit { .. }
            | BankDebitData::BacsBankDebit { .. } => {
                Err(error_stack::report!(IntegrationError::NotSupported {
                    message: utils::get_unimplemented_payment_method_error_message("Paypal"),
                    connector: "Paypal",
                    context: Default::default(),
                }))
            }
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<&BankTransferData> for PaypalPaymentsRequest<T>
{
    type Error = Report<IntegrationError>;
    fn try_from(value: &BankTransferData) -> Result<Self, Self::Error> {
        match value {
            BankTransferData::AchBankTransfer { .. }
            | BankTransferData::SepaBankTransfer { .. }
            | BankTransferData::BacsBankTransfer { .. }
            | BankTransferData::MultibancoBankTransfer { .. }
            | BankTransferData::PermataBankTransfer { .. }
            | BankTransferData::BcaBankTransfer { .. }
            | BankTransferData::BniVaBankTransfer { .. }
            | BankTransferData::BriVaBankTransfer { .. }
            | BankTransferData::CimbVaBankTransfer { .. }
            | BankTransferData::DanamonVaBankTransfer { .. }
            | BankTransferData::MandiriVaBankTransfer { .. }
            | BankTransferData::Pix { .. }
            | BankTransferData::Pse {}
            | BankTransferData::InstantBankTransfer {}
            | BankTransferData::InstantBankTransferFinland {}
            | BankTransferData::InstantBankTransferPoland {}
            | BankTransferData::IndonesianBankTransfer { .. }
            | BankTransferData::LocalBankTransfer { .. } => Err(IntegrationError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Paypal"),
                Default::default(),
            )
            .into()),
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<&VoucherData> for PaypalPaymentsRequest<T>
{
    type Error = Report<IntegrationError>;
    fn try_from(value: &VoucherData) -> Result<Self, Self::Error> {
        match value {
            VoucherData::Boleto(_)
            | VoucherData::Efecty
            | VoucherData::PagoEfectivo
            | VoucherData::RedCompra
            | VoucherData::RedPagos
            | VoucherData::Alfamart(_)
            | VoucherData::Indomaret(_)
            | VoucherData::Oxxo
            | VoucherData::SevenEleven(_)
            | VoucherData::Lawson(_)
            | VoucherData::MiniStop(_)
            | VoucherData::FamilyMart(_)
            | VoucherData::Seicomart(_)
            | VoucherData::PayEasy(_) => Err(IntegrationError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Paypal"),
                Default::default(),
            )
            .into()),
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<&GiftCardData> for PaypalPaymentsRequest<T>
{
    type Error = Report<IntegrationError>;
    fn try_from(value: &GiftCardData) -> Result<Self, Self::Error> {
        match value {
            GiftCardData::Givex(_) | GiftCardData::PaySafeCard {} => {
                Err(error_stack::report!(IntegrationError::NotSupported {
                    message: utils::get_unimplemented_payment_method_error_message("Paypal"),
                    connector: "Paypal",
                    context: Default::default(),
                }))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PaypalAuthUpdateRequest {
    grant_type: String,
    client_id: Secret<String>,
    client_secret: Secret<String>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PaypalRouterData<
            RouterDataV2<
                domain_types::connector_flow::ServerAuthenticationToken,
                MerchantAuthenticationFlowData,
                domain_types::connector_types::ServerAuthenticationTokenRequestData,
                ServerAuthenticationTokenResponseData,
            >,
            T,
        >,
    > for PaypalAuthUpdateRequest
{
    type Error = Report<IntegrationError>;
    fn try_from(
        item: PaypalRouterData<
            RouterDataV2<
                domain_types::connector_flow::ServerAuthenticationToken,
                MerchantAuthenticationFlowData,
                domain_types::connector_types::ServerAuthenticationTokenRequestData,
                ServerAuthenticationTokenResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = PaypalAuthType::try_from(&item.router_data.connector_config)?;
        let credentials = auth.get_credentials()?;
        Ok(Self {
            grant_type: item.router_data.request.grant_type,
            client_id: credentials.get_client_id(),
            client_secret: credentials.get_client_secret(),
        })
    }
}

#[derive(Default, Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct PaypalAuthUpdateResponse {
    pub access_token: Secret<String>,
    pub token_type: String,
    pub expires_in: i64,
}

impl<F, T> TryFrom<ResponseRouterData<PaypalAuthUpdateResponse, Self>>
    for RouterDataV2<F, MerchantAuthenticationFlowData, T, ServerAuthenticationTokenResponseData>
{
    type Error = Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaypalAuthUpdateResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(ServerAuthenticationTokenResponseData {
                access_token: item.response.access_token,
                expires_in: Some(item.response.expires_in),
                token_type: None,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalIncrementalStatus {
    CREATED,
    CAPTURED,
    DENIED,
    PARTIALLYCAPTURED,
    VOIDED,
    PENDING,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaypalNetworkTransactionReference {
    id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaypalIncrementalAuthStatusDetails {
    reason: Option<PaypalStatusPendingReason>,
}

#[derive(Debug, Deserialize, Serialize, strum::Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalStatusPendingReason {
    PENDINGREVIEW,
    DECLINEDBYRISKFRAUDFILTERS,
}

impl From<PaypalIncrementalStatus> for common_enums::AuthorizationStatus {
    fn from(item: PaypalIncrementalStatus) -> Self {
        match item {
            PaypalIncrementalStatus::CREATED
            | PaypalIncrementalStatus::CAPTURED
            | PaypalIncrementalStatus::PARTIALLYCAPTURED => Self::Success,
            PaypalIncrementalStatus::PENDING => Self::Processing,
            PaypalIncrementalStatus::DENIED | PaypalIncrementalStatus::VOIDED => Self::Failure,
        }
    }
}

impl From<PaypalIncrementalStatus> for common_enums::AttemptStatus {
    fn from(item: PaypalIncrementalStatus) -> Self {
        match item {
            PaypalIncrementalStatus::CREATED
            | PaypalIncrementalStatus::CAPTURED
            | PaypalIncrementalStatus::PARTIALLYCAPTURED => Self::Authorized,
            PaypalIncrementalStatus::PENDING => Self::Pending,
            PaypalIncrementalStatus::DENIED | PaypalIncrementalStatus::VOIDED => Self::Failure,
        }
    }
}

#[derive(Debug)]
pub enum PaypalAuthType {
    TemporaryAuth,
    AuthWithDetails(PaypalConnectorCredentials),
}

#[derive(Debug)]
pub enum PaypalConnectorCredentials {
    StandardIntegration(StandardFlowCredentials),
    PartnerIntegration(PartnerFlowCredentials),
}

impl PaypalConnectorCredentials {
    pub fn get_client_id(&self) -> Secret<String> {
        match self {
            Self::StandardIntegration(item) => item.client_id.clone(),
            Self::PartnerIntegration(item) => item.client_id.clone(),
        }
    }

    pub fn get_client_secret(&self) -> Secret<String> {
        match self {
            Self::StandardIntegration(item) => item.client_secret.clone(),
            Self::PartnerIntegration(item) => item.client_secret.clone(),
        }
    }

    pub fn get_payer_id(&self) -> Option<Secret<String>> {
        match self {
            Self::StandardIntegration(_) => None,
            Self::PartnerIntegration(item) => Some(item.payer_id.clone()),
        }
    }

    pub fn generate_authorization_value(&self) -> String {
        let auth_id = format!(
            "{}:{}",
            self.get_client_id().expose(),
            self.get_client_secret().expose(),
        );
        format!("Basic {}", BASE64_ENGINE.encode(auth_id))
    }
}

#[derive(Debug)]
pub struct StandardFlowCredentials {
    pub(super) client_id: Secret<String>,
    pub(super) client_secret: Secret<String>,
}

#[derive(Debug)]
pub struct PartnerFlowCredentials {
    pub(super) client_id: Secret<String>,
    pub(super) client_secret: Secret<String>,
    pub(super) payer_id: Secret<String>,
}

impl PaypalAuthType {
    pub fn get_credentials(&self) -> CustomResult<&PaypalConnectorCredentials, IntegrationError> {
        match self {
            Self::TemporaryAuth => Err(IntegrationError::InvalidConnectorConfig {
                config: "TemporaryAuth found in connector_account_details",
                context: Default::default(),
            }
            .into()),
            Self::AuthWithDetails(credentials) => Ok(credentials),
        }
    }
}

impl TryFrom<&ConnectorSpecificConfig> for PaypalAuthType {
    type Error = Report<IntegrationError>;
    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Paypal {
                client_id,
                client_secret,
                payer_id,
                ..
            } => match payer_id {
                None => Ok(Self::AuthWithDetails(
                    PaypalConnectorCredentials::StandardIntegration(StandardFlowCredentials {
                        client_id: client_id.to_owned(),
                        client_secret: client_secret.to_owned(),
                    }),
                )),
                Some(payer_id) => Ok(Self::AuthWithDetails(
                    PaypalConnectorCredentials::PartnerIntegration(PartnerFlowCredentials {
                        client_id: client_id.to_owned(),
                        client_secret: client_secret.to_owned(),
                        payer_id: payer_id.to_owned(),
                    }),
                )),
            },
            _ => Err(IntegrationError::FailedToObtainAuthType {
                context: Default::default(),
            })?,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalOrderStatus {
    Pending,
    Completed,
    Voided,
    Created,
    Saved,
    PayerActionRequired,
    Approved,
    /// Any value PayPal adds later; mapped non-terminally.
    #[serde(other)]
    Unknown,
}

pub(crate) fn get_order_status(
    item: PaypalOrderStatus,
    intent: PaypalPaymentIntent,
) -> common_enums::AttemptStatus {
    match item {
        PaypalOrderStatus::Completed => {
            if intent == PaypalPaymentIntent::Authorize {
                common_enums::AttemptStatus::Authorized
            } else {
                common_enums::AttemptStatus::Charged
            }
        }
        PaypalOrderStatus::Voided => common_enums::AttemptStatus::Voided,
        PaypalOrderStatus::Created | PaypalOrderStatus::Saved | PaypalOrderStatus::Pending => {
            common_enums::AttemptStatus::Pending
        }
        PaypalOrderStatus::Approved => common_enums::AttemptStatus::AuthenticationSuccessful,
        PaypalOrderStatus::PayerActionRequired => {
            common_enums::AttemptStatus::AuthenticationPending
        }
        // doc: https://developer.paypal.com/docs/api/orders/v2/#orders_get!c=200&path=status
        // An undocumented order status is never treated as terminal.
        PaypalOrderStatus::Unknown => common_enums::AttemptStatus::Pending,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentsCollectionItem {
    amount: OrderAmount,
    expiration_time: Option<String>,
    id: String,
    final_capture: Option<bool>,
    status: PaypalPaymentStatus,
    processor_response: Option<ProcessorResponse>,
    /// Scheme transaction id of this authorization/capture (NTID for later MITs).
    network_transaction_reference: Option<PaypalNetworkTransactionReferenceResponse>,
}

/// `processor_response` of an authorization or capture.
/// Doc: https://developer.paypal.com/docs/api/orders/v2/#definition-processor_response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessorResponse {
    avs_code: Option<String>,
    cvv_code: Option<String>,
    response_code: Option<String>,
    /// Merchant advice code (MAC) for declined card transactions.
    payment_advice_code: Option<String>,
}

/// `network_transaction_reference` of an authorization or capture.
/// Doc: https://developer.paypal.com/docs/api/orders/v2/#definition-network_transaction_reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalNetworkTransactionReferenceResponse {
    id: Secret<String>,
    date: Option<String>,
    network: Option<String>,
}

/// AVS / CVV results of the selected payment item, surfaced as
/// `connector_response.additional_payment_method_data.card.payment_checks`.
/// Returns `None` when PayPal reported neither check.
fn get_paypal_connector_response(
    payment_collection_item: &PaymentsCollectionItem,
) -> Option<ConnectorResponseData> {
    let processor_response = payment_collection_item.processor_response.as_ref()?;
    let mut payment_checks = serde_json::Map::new();
    if let Some(avs_code) = processor_response.avs_code.as_ref() {
        payment_checks.insert("avs_code".to_string(), serde_json::json!(avs_code));
    }
    if let Some(cvv_code) = processor_response.cvv_code.as_ref() {
        payment_checks.insert("cvv_code".to_string(), serde_json::json!(cvv_code));
    }
    (!payment_checks.is_empty()).then(|| {
        ConnectorResponseData::with_additional_payment_method_data(
            AdditionalPaymentMethodConnectorResponse::Card {
                authentication_data: None,
                payment_checks: Some(serde_json::Value::Object(payment_checks)),
                card_network: None,
                domestic_network: None,
                auth_code: None,
            },
        )
    })
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PaymentsCollection {
    authorizations: Option<Vec<PaymentsCollectionItem>>,
    captures: Option<Vec<PaymentsCollectionItem>>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PurchaseUnitItem {
    pub reference_id: Option<String>,
    pub invoice_id: Option<String>,
    pub payments: PaymentsCollection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalThreeDsResponse {
    id: String,
    status: PaypalOrderStatus,
    links: Vec<PaypalLinks>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PaypalPostAuthenticateResponse {
    PaypalLiabilityResponse(PaypalLiabilityResponse),
    PaypalNonLiabilityResponse(PaypalNonLiabilityResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalLiabilityResponse {
    pub payment_source: CardParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalNonLiabilityResponse {
    payment_source: CardsData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardParams {
    pub card: AuthResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub authentication_result: PaypalThreeDsParams,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalThreeDsParams {
    pub liability_shift: LiabilityShift,
    pub three_d_secure: ThreeDsCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreeDsCheck {
    pub enrollment_status: Option<EnrollmentStatus>,
    pub authentication_status: Option<AuthenticationStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LiabilityShift {
    Possible,
    No,
    /// `UNKNOWN`, and any value PayPal adds later; never accepted by the 3DS outcome guard.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnrollmentStatus {
    Null,
    #[serde(rename = "Y")]
    Ready,
    #[serde(rename = "N")]
    NotReady,
    #[serde(rename = "U")]
    Unavailable,
    #[serde(rename = "B")]
    Bypassed,
    /// Any value PayPal adds later; never accepted by the 3DS outcome guard.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticationStatus {
    Null,
    #[serde(rename = "Y")]
    Success,
    #[serde(rename = "N")]
    Failed,
    #[serde(rename = "R")]
    Rejected,
    #[serde(rename = "A")]
    Attempted,
    #[serde(rename = "U")]
    Unable,
    #[serde(rename = "C")]
    ChallengeRequired,
    #[serde(rename = "I")]
    InfoOnly,
    #[serde(rename = "D")]
    Decoupled,
    /// Any value PayPal adds later; never accepted by the 3DS outcome guard.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalOrdersResponse {
    id: String,
    intent: PaypalPaymentIntent,
    // PayPal can omit the top-level order `status` in some Orders v2 responses (observed in PSync
    // for an order whose only capture was `DECLINED`). This field is kept optional so the response
    // still deserializes when it is absent. The attempt status is not derived from this field
    // anyway: for orders it is taken from the capture/authorization status inside `purchase_units`
    // (see `TryFrom<ResponseRouterData<PaypalOrdersResponse, ..>>`).
    status: Option<PaypalOrderStatus>,
    purchase_units: Vec<PurchaseUnitItem>,
    payment_source: Option<PaymentSourceItemResponse>,
    payer: Option<Payer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payer {
    payer_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalLinks {
    href: Option<Url>,
    rel: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RedirectPurchaseUnitItem {
    pub invoice_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalRedirectResponse {
    id: String,
    intent: PaypalPaymentIntent,
    status: PaypalOrderStatus,
    purchase_units: Vec<RedirectPurchaseUnitItem>,
    links: Vec<PaypalLinks>,
    payment_source: Option<PaymentSourceItemResponse>,
    payer: Option<Payer>,
}

// Note: Don't change order of deserialization of variant, priority is in descending order
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PaypalAuthResponse {
    PaypalOrdersResponse(PaypalOrdersResponse),
    PaypalRedirectResponse(PaypalRedirectResponse),
    PaypalThreeDsResponse(PaypalThreeDsResponse),
}

// Note: Don't change order of deserialization of variant, priority is in descending order
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PaypalSyncResponse {
    PaypalOrdersSyncResponse(PaypalOrdersResponse),
    PaypalThreeDsSyncResponse(PaypalThreeDsSyncResponse),
    PaypalRedirectSyncResponse(PaypalRedirectResponse),
    PaypalPaymentsSyncResponse(PaypalPaymentsSyncResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NextActionCall {
    CompleteAuthorize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaypalPaymentsSyncResponse {
    id: String,
    status: PaypalPaymentStatus,
    amount: OrderAmount,
    invoice_id: Option<String>,
    supplementary_data: PaypalSupplementaryData,
    payer: Option<Payer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalThreeDsSyncResponse {
    id: String,
    status: PaypalOrderStatus,
    // provided to separated response of card's 3DS from other
    payment_source: CardsData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardsData {
    card: CardDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardDetails {
    last_digits: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaypalMeta {
    pub authorize_id: Option<String>,
    pub capture_id: Option<String>,
    pub incremental_authorization_id: Option<String>,
    pub psync_flow: PaypalPaymentIntent,
    pub next_action: Option<NextActionCall>,
    pub order_id: Option<String>,
    /// Intent of a PayPal-hosted 3DS order, recorded at create time because the SCA
    /// create-order response does not echo `intent`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_intent: Option<PaypalPaymentIntent>,
}

fn get_id_based_on_intent(
    intent: &PaypalPaymentIntent,
    purchase_unit: &PurchaseUnitItem,
    http_status: u16,
) -> Result<String, Report<ConnectorError>> {
    let id = || -> Option<String> {
        match intent {
            PaypalPaymentIntent::Capture => Some(
                purchase_unit
                    .payments
                    .captures
                    .clone()?
                    .into_iter()
                    .next()?
                    .id,
            ),
            PaypalPaymentIntent::Authorize => Some(
                purchase_unit
                    .payments
                    .authorizations
                    .clone()?
                    .into_iter()
                    .next()?
                    .id,
            ),
            PaypalPaymentIntent::Authenticate => None,
        }
    }();
    id.ok_or_else(|| {
        Report::new(ConnectorError::response_handling_failed_with_context(
            http_status,
            Some("missing capture or authorization id for PayPal order intent".to_string()),
        ))
    })
}

fn extract_incremental_authorization_id(response: &PaypalOrdersResponse) -> Option<String> {
    for unit in &response.purchase_units {
        if let Some(authorizations) = &unit.payments.authorizations {
            if let Some(first_auth) = authorizations.first() {
                return Some(first_auth.id.clone());
            }
        }
    }
    None
}

impl<F, Req> TryFrom<ResponseRouterData<PaypalOrdersResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>
where
    Req: GetRequestIncrementalAuthorization,
{
    type Error = Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<PaypalOrdersResponse, Self>) -> Result<Self, Self::Error> {
        let purchase_units = item.response.purchase_units.first().ok_or_else(|| {
            Report::new(ConnectorError::response_handling_failed_with_context(
                item.http_code,
                Some("missing purchase_units in PayPal order response".to_string()),
            ))
        })?;

        let id = get_id_based_on_intent(&item.response.intent, purchase_units, item.http_code)?;
        let (connector_meta, order_id) = match item.response.intent.clone() {
            PaypalPaymentIntent::Capture => (
                serde_json::json!(PaypalMeta {
                    authorize_id: None,
                    capture_id: Some(id),
                    incremental_authorization_id: None,
                    psync_flow: item.response.intent.clone(),
                    next_action: None,
                    order_id: None,
                    order_intent: None,
                }),
                ResponseId::ConnectorTransactionId(item.response.id.clone()),
            ),

            PaypalPaymentIntent::Authorize => (
                serde_json::json!(PaypalMeta {
                    authorize_id: Some(id),
                    capture_id: None,
                    incremental_authorization_id: extract_incremental_authorization_id(
                        &item.response
                    ),
                    psync_flow: item.response.intent.clone(),
                    next_action: None,
                    order_id: None,
                    order_intent: None,
                }),
                ResponseId::ConnectorTransactionId(item.response.id.clone()),
            ),

            PaypalPaymentIntent::Authenticate => Err(
                crate::utils::response_handling_fail_for_connector(item.http_code, "paypal"),
            )?,
        };
        //payment collection will always have only one element as we only make one transaction per order.
        let payment_collection = &item
            .response
            .purchase_units
            .first()
            .ok_or(crate::utils::response_handling_fail_for_connector(
                item.http_code,
                "paypal",
            ))?
            .payments;
        //payment collection item will either have "authorizations" field or "capture" field, not both at a time.
        let payment_collection_item = match (
            &payment_collection.authorizations,
            &payment_collection.captures,
        ) {
            (Some(authorizations), None) => authorizations.first(),
            (None, Some(captures)) => captures.first(),
            (Some(_), Some(captures)) => captures.first(),
            _ => None,
        }
        .ok_or(crate::utils::response_handling_fail_for_connector(
            item.http_code,
            "paypal",
        ))?;
        // Derive the attempt status from the capture/authorization status rather than the
        // top-level order `status`, which PayPal may omit (e.g. a declined capture). For example a
        // `DECLINED` capture maps to `AttemptStatus::Failure` and is handled by the branch below.
        let status = payment_collection_item.status.clone();
        let status = common_enums::AttemptStatus::from(status);

        match utils::is_payment_failure(status) {
            true => {
                let error_code = payment_collection_item
                    .processor_response
                    .as_ref()
                    .and_then(|response| response.response_code.clone());

                let error_message = error_code
                    .as_deref()
                    .and_then(get_paypal_error_message)
                    .map(|message| message.to_string());
                let advice_code = payment_collection_item
                    .processor_response
                    .as_ref()
                    .and_then(|response| response.payment_advice_code.clone());

                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        connector_response: get_paypal_connector_response(payment_collection_item),
                        ..item.router_data.resource_common_data
                    },
                    response: Err(domain_types::router_data::ErrorResponse {
                        code: error_code
                            .clone()
                            .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                        message: error_message
                            .clone()
                            .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                        reason: error_message,
                        status_code: item.http_code,
                        // A declined/denied/failed/expired item on HTTP 2xx is a terminal
                        // decline; say so instead of leaving the caller to guess.
                        attempt_status: Some(FlowStatus::Payment(
                            common_enums::AttemptStatus::Failure,
                        )),
                        connector_transaction_id: Some(item.response.id.clone()),
                        network_decline_code: error_code,
                        network_advice_code: advice_code,
                        network_error_message: None,
                        typed_connector_response: None,
                        raw_connector_response: None,
                        raw_connector_request: None,
                        typed_connector_request: None,
                    }),
                    ..item.router_data
                })
            }
            false => Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    sender_payment_instrument_id: item
                        .response
                        .payer
                        .as_ref()
                        .and_then(|payer| payer.payer_id.clone()),
                    connector_response: get_paypal_connector_response(payment_collection_item),
                    ..item.router_data.resource_common_data
                },
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: order_id,
                    redirection_data: None,
                    mandate_reference: Some(Box::new(MandateReference {
                        connector_mandate_id: match item.response.payment_source.clone() {
                            Some(paypal_source) => match paypal_source {
                                PaymentSourceItemResponse::Paypal(paypal_source) => {
                                    paypal_source.attributes.and_then(|attr| attr.vault.id)
                                }
                                PaymentSourceItemResponse::Card(card) => {
                                    card.attributes.and_then(|attr| attr.vault.id)
                                }
                                PaymentSourceItemResponse::Eps(_)
                                | PaymentSourceItemResponse::Ideal(_)
                                | PaymentSourceItemResponse::GooglePay(_)
                                | PaymentSourceItemResponse::ApplePay(_) => None,
                            },
                            None => None,
                        },
                        payment_method_id: None,
                        // Surface the PayPal vault customer id (returning-customer flow),
                        // mirroring the reference. Only PayPal sources carry a vault customer;
                        // card/eps/ideal/wallet sources have none here.
                        connector_mandate_request_reference_id: match item
                            .response
                            .payment_source
                            .clone()
                        {
                            Some(PaymentSourceItemResponse::Paypal(paypal_source)) => paypal_source
                                .attributes
                                .and_then(|attr| attr.vault.customer.map(|cus| cus.id)),
                            Some(PaymentSourceItemResponse::Card(_))
                            | Some(PaymentSourceItemResponse::Eps(_))
                            | Some(PaymentSourceItemResponse::Ideal(_))
                            | Some(PaymentSourceItemResponse::GooglePay(_))
                            | Some(PaymentSourceItemResponse::ApplePay(_))
                            | None => None,
                        },
                        mandate_metadata: None,
                    })),
                    status_code: item.http_code,
                    connector_metadata: Some(connector_meta),
                    network_txn_id: payment_collection_item
                        .network_transaction_reference
                        .as_ref()
                        .map(|reference| reference.id.clone().expose()),
                    network_txn_link_id: None,
                    connector_response_reference_id: purchase_units
                        .invoice_id
                        .clone()
                        .or(Some(item.response.id)),
                    incremental_authorization_allowed: item
                        .router_data
                        .request
                        .get_request_incremental_authorization(),
                    splits: None,
                    payment_account_reference: None,
                }),
                ..item.router_data
            }),
        }
    }
}

fn get_redirect_url(link_vec: Vec<PaypalLinks>) -> Result<Option<Url>, Report<ConnectorError>> {
    let mut link: Option<Url> = None;
    for item2 in link_vec.iter() {
        if item2.rel == "payer-action" {
            link.clone_from(&item2.href)
        }
    }
    Ok(link)
}

impl TryFrom<ResponseRouterData<PaypalSyncResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<PaypalSyncResponse, Self>) -> Result<Self, Self::Error> {
        match item.response {
            PaypalSyncResponse::PaypalOrdersSyncResponse(response) => {
                Self::try_from(ResponseRouterData {
                    response,
                    router_data: item.router_data,
                    http_code: item.http_code,
                })
            }
            PaypalSyncResponse::PaypalRedirectSyncResponse(response) => {
                Self::try_from(ResponseRouterData {
                    response,
                    router_data: item.router_data,
                    http_code: item.http_code,
                })
            }
            PaypalSyncResponse::PaypalPaymentsSyncResponse(response) => {
                Self::try_from(ResponseRouterData {
                    response,
                    router_data: item.router_data,
                    http_code: item.http_code,
                })
            }
            PaypalSyncResponse::PaypalThreeDsSyncResponse(response) => {
                Self::try_from(ResponseRouterData {
                    response,
                    router_data: item.router_data,
                    http_code: item.http_code,
                })
            }
        }
    }
}

impl TryFrom<ResponseRouterData<PaypalRedirectResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaypalRedirectResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let payment_experience = item.router_data.request.payment_experience;
        let status = get_order_status(item.response.clone().status, item.response.intent.clone());
        let link = get_redirect_url(item.response.links.clone())?;

        // For Paypal SDK flow, we need to trigger SDK client and then complete authorize
        let next_action =
            if let Some(common_enums::PaymentExperience::InvokeSdkClient) = payment_experience {
                Some(NextActionCall::CompleteAuthorize)
            } else {
                None
            };
        let connector_meta = serde_json::json!(PaypalMeta {
            authorize_id: None,
            capture_id: None,
            incremental_authorization_id: None,
            psync_flow: item.response.intent,
            next_action,
            order_id: None,
            order_intent: None,
        });
        let purchase_units = item.response.purchase_units.first();
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                sender_payment_instrument_id: item
                    .response
                    .payer
                    .as_ref()
                    .and_then(|payer| payer.payer_id.clone()),
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: Some(Box::new(RedirectForm::from((
                    link.ok_or(crate::utils::response_handling_fail_for_connector(
                        item.http_code,
                        "paypal",
                    ))?,
                    Method::Get,
                )))),
                mandate_reference: None,
                connector_metadata: Some(connector_meta),
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: Some(
                    purchase_units.map_or(item.response.id, |item| item.invoice_id.clone()),
                ),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
                splits: None,
                payment_account_reference: None,
            }),
            ..item.router_data
        })
    }
}

impl<F, T> TryFrom<ResponseRouterData<PaypalThreeDsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaypalThreeDsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            // status is hardcoded because this try_from will only be reached in card 3ds before the completion of complete authorize flow.
            // also force sync won't be hit in terminal status thus leaving us with only one status to get here.
            resource_common_data: PaymentFlowData {
                status: common_enums::AttemptStatus::AuthenticationPending,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
                splits: None,
                payment_account_reference: None,
            }),
            ..item.router_data
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<PaypalAuthResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<PaypalAuthResponse, Self>) -> Result<Self, Self::Error> {
        match item.response {
            PaypalAuthResponse::PaypalOrdersResponse(orders_response) => {
                Self::try_from(ResponseRouterData {
                    response: orders_response,
                    router_data: item.router_data,
                    http_code: item.http_code,
                })
            }
            PaypalAuthResponse::PaypalRedirectResponse(redirect_response) => {
                Self::try_from(ResponseRouterData {
                    response: redirect_response,
                    router_data: item.router_data,
                    http_code: item.http_code,
                })
            }
            PaypalAuthResponse::PaypalThreeDsResponse(threeds_response) => {
                Self::try_from(ResponseRouterData {
                    response: threeds_response,
                    router_data: item.router_data,
                    http_code: item.http_code,
                })
            }
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<PaypalThreeDsResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaypalThreeDsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let order_intent = paypal_order_intent(item.router_data.request.is_auto_capture());
        let connector_meta = serde_json::json!(PaypalMeta {
            authorize_id: None,
            capture_id: None,
            incremental_authorization_id: None,
            psync_flow: PaypalPaymentIntent::Authenticate, // when there is no capture or auth id present
            next_action: None,
            // The 3DS completion Authorize addresses orders/{id}/<capture|authorize>.
            order_id: Some(item.response.id.clone()),
            // The intent this SCA order was created with; the 3DS completion must use
            // the matching orders/{id}/<capture|authorize> (ACTION_DOES_NOT_MATCH_INTENT).
            order_intent: Some(order_intent),
        });

        let status = get_order_status(
            item.response.clone().status,
            PaypalPaymentIntent::Authenticate,
        );
        let link = get_redirect_url(item.response.links.clone())?;

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: Some(Box::new(paypal_threeds_link(
                    (
                        link,
                        item.router_data.request.complete_authorize_url.clone(),
                    ),
                    item.http_code,
                )?)),
                mandate_reference: None,
                connector_metadata: Some(connector_meta),
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
                splits: None,
                payment_account_reference: None,
            }),
            ..item.router_data
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<PaypalRedirectResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaypalRedirectResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = get_order_status(item.response.clone().status, item.response.intent.clone());
        let link = get_redirect_url(item.response.links.clone())?;

        let connector_meta = serde_json::json!(PaypalMeta {
            authorize_id: None,
            capture_id: None,
            incremental_authorization_id: None,
            psync_flow: item.response.intent,
            next_action: None,
            order_id: None,
            order_intent: None,
        });
        let purchase_units = item.response.purchase_units.first();
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                sender_payment_instrument_id: item
                    .response
                    .payer
                    .as_ref()
                    .and_then(|payer| payer.payer_id.clone()),
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: link.map(|url| Box::new(RedirectForm::from((url, Method::Get)))),
                mandate_reference: None,
                connector_metadata: Some(connector_meta),
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: Some(
                    purchase_units.map_or(item.response.id, |item| item.invoice_id.clone()),
                ),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
                splits: None,
                payment_account_reference: None,
            }),
            ..item.router_data
        })
    }
}

fn paypal_threeds_link(
    (redirect_url, complete_auth_url): (Option<Url>, Option<String>),
    http_status: u16,
) -> Result<RedirectForm, Report<ConnectorError>> {
    let mut redirect_url = redirect_url.ok_or_else(|| {
        Report::new(ConnectorError::response_handling_failed_with_context(
            http_status,
            Some("missing redirect URL for PayPal 3DS".to_string()),
        ))
    })?;
    let complete_auth_url = complete_auth_url.ok_or_else(|| {
        Report::new(ConnectorError::response_handling_failed_with_context(
            http_status,
            Some("complete_authorize_url missing for PayPal 3DS".to_string()),
        ))
    })?;
    let mut form_fields = std::collections::HashMap::from_iter(
        redirect_url
            .query_pairs()
            .map(|(key, value)| (key.to_string(), value.to_string())),
    );

    // paypal requires return url to be passed as a field along with payer_action_url
    form_fields.insert(String::from("redirect_uri"), complete_auth_url);

    // Do not include query params in the endpoint
    redirect_url.set_query(None);

    Ok(RedirectForm::Form {
        endpoint: redirect_url.to_string(),
        method: Method::Get,
        form_fields,
    })
}

impl<F, T> TryFrom<ResponseRouterData<PaypalPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaypalPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status: common_enums::AttemptStatus::from(item.response.status),
                sender_payment_instrument_id: item
                    .response
                    .payer
                    .as_ref()
                    .and_then(|payer| payer.payer_id.clone()),
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response
                        .supplementary_data
                        .related_ids
                        .order_id
                        .clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: item
                    .response
                    .invoice_id
                    .clone()
                    .or(Some(item.response.supplementary_data.related_ids.order_id)),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
                splits: None,
                payment_account_reference: None,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Serialize)]
pub struct PaypalPaymentsCaptureRequest {
    amount: OrderAmount,
    final_capture: bool,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PaypalRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for PaypalPaymentsCaptureRequest
{
    type Error = Report<IntegrationError>;
    fn try_from(
        item: PaypalRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let value = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.amount_to_capture.amount,
                item.router_data.request.currency,
            )
            .change_context(IntegrationError::AmountConversionFailed {
                context: Default::default(),
            })?;
        let amount = OrderAmount {
            currency_code: item.router_data.request.currency,
            value,
        };
        Ok(Self {
            amount,
            final_capture: true,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalPaymentStatus {
    Created,
    Captured,
    Completed,
    Declined,
    Voided,
    Failed,
    Pending,
    Denied,
    Expired,
    PartiallyCaptured,
    Refunded,
    PartiallyRefunded,
    /// Any value PayPal adds later; mapped non-terminally.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaypalCaptureResponse {
    id: String,
    status: PaypalPaymentStatus,
    amount: Option<OrderAmount>,
    invoice_id: Option<String>,
    final_capture: bool,
    payment_source: Option<PaymentSourceItemResponse>,
    /// Processor decline / advice codes of a DECLINED or FAILED capture.
    /// Doc: https://developer.paypal.com/docs/api/payments/v2/#authorizations_capture!c=201&path=processor_response
    processor_response: Option<ProcessorResponse>,
}

impl From<PaypalPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: PaypalPaymentStatus) -> Self {
        // doc: https://developer.paypal.com/docs/api/payments/v2/#captures_get!c=200&path=status
        // doc: https://developer.paypal.com/docs/api/payments/v2/#authorizations_get!c=200&path=status
        match item {
            PaypalPaymentStatus::Created => Self::Authorized,
            PaypalPaymentStatus::Completed
            | PaypalPaymentStatus::Captured
            | PaypalPaymentStatus::Refunded
            | PaypalPaymentStatus::PartiallyRefunded => Self::Charged,
            PaypalPaymentStatus::Declined => Self::Failure,
            PaypalPaymentStatus::Failed => Self::CaptureFailed,
            PaypalPaymentStatus::Pending => Self::Pending,
            PaypalPaymentStatus::Denied | PaypalPaymentStatus::Expired => Self::Failure,
            PaypalPaymentStatus::PartiallyCaptured => Self::PartialCharged,
            PaypalPaymentStatus::Voided => Self::Voided,
            PaypalPaymentStatus::Unknown => Self::Pending,
        }
    }
}

/// Attempt status of a capture resource returned by
/// `POST /v2/payments/authorizations/{id}/capture`.
///
/// Differs from the shared [`From<PaypalPaymentStatus>`] (which PSync also uses) only in
/// that a `DECLINED` capture of an approved authorization is `CaptureFailed`, not
/// `Failure`: the authorization itself still stands.
/// doc: https://developer.paypal.com/docs/api/payments/v2/#authorizations_capture!c=201&path=status
fn capture_attempt_status(status: PaypalPaymentStatus) -> common_enums::AttemptStatus {
    match status {
        PaypalPaymentStatus::Completed
        | PaypalPaymentStatus::Refunded
        | PaypalPaymentStatus::PartiallyRefunded => common_enums::AttemptStatus::Charged,
        PaypalPaymentStatus::Declined | PaypalPaymentStatus::Failed => {
            common_enums::AttemptStatus::CaptureFailed
        }
        PaypalPaymentStatus::Pending | PaypalPaymentStatus::Unknown => {
            common_enums::AttemptStatus::Pending
        }
        // Not documented capture statuses; keep the shared payment-resource mapping.
        other @ (PaypalPaymentStatus::Created
        | PaypalPaymentStatus::Captured
        | PaypalPaymentStatus::Voided
        | PaypalPaymentStatus::Denied
        | PaypalPaymentStatus::Expired
        | PaypalPaymentStatus::PartiallyCaptured) => common_enums::AttemptStatus::from(other),
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<PaypalCaptureResponse, PaypalRouterData<Self, T>>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaypalCaptureResponse, PaypalRouterData<Self, T>>,
    ) -> Result<Self, Self::Error> {
        let item = ResponseRouterData {
            response: item.response,
            router_data: item.router_data.router_data,
            http_code: item.http_code,
        };
        let status = capture_attempt_status(item.response.status.clone());
        let amount_captured = match status {
            common_enums::AttemptStatus::Pending
            | common_enums::AttemptStatus::Authorized
            | common_enums::AttemptStatus::Failure
            | common_enums::AttemptStatus::RouterDeclined
            | common_enums::AttemptStatus::AuthenticationFailed
            | common_enums::AttemptStatus::CaptureFailed
            | common_enums::AttemptStatus::Started
            | common_enums::AttemptStatus::AuthenticationPending
            | common_enums::AttemptStatus::AuthenticationSuccessful
            | common_enums::AttemptStatus::AuthorizationFailed
            | common_enums::AttemptStatus::Authorizing
            | common_enums::AttemptStatus::VoidInitiated
            | common_enums::AttemptStatus::CodInitiated
            | common_enums::AttemptStatus::CaptureInitiated
            | common_enums::AttemptStatus::VoidFailed
            | common_enums::AttemptStatus::AutoRefunded
            | common_enums::AttemptStatus::Unresolved
            | common_enums::AttemptStatus::Unspecified
            | common_enums::AttemptStatus::PaymentMethodAwaited
            | common_enums::AttemptStatus::ConfirmationAwaited
            | common_enums::AttemptStatus::DeviceDataCollectionPending
            | common_enums::AttemptStatus::Voided
            | common_enums::AttemptStatus::VoidedPostCapture
            | common_enums::AttemptStatus::VoidPostCaptureInitiated
            | common_enums::AttemptStatus::Expired
            | common_enums::AttemptStatus::Unknown
            | common_enums::AttemptStatus::PartiallyAuthorized => {
                Some(common_utils::types::Money {
                    amount: MinorUnit::zero(),
                    currency: item.router_data.request.currency,
                })
            }
            common_enums::AttemptStatus::Charged
            | common_enums::AttemptStatus::PartialCharged
            | common_enums::AttemptStatus::PartialChargedAndChargeable
            | common_enums::AttemptStatus::IntegrityFailure => {
                Some(item.router_data.request.amount_to_capture.clone())
            }
        };
        let connector_payment_id: PaypalMeta = match to_connector_meta(
            item.router_data
                .request
                .connector_feature_data
                .clone()
                .map(|m| m.expose()),
        ) {
            Ok(v) => v,
            Err(_) => {
                return Err(Report::new(
                    ConnectorError::response_handling_failed_with_context(
                        item.http_code,
                        Some(
                            "invalid or missing connector_meta_data on capture response"
                                .to_string(),
                        ),
                    ),
                ));
            }
        };

        // Simplified capture_id logic to use response.id directly
        let capture_id = item.response.id.clone();
        let invoice_id = item.response.invoice_id.clone();

        // A DECLINED/FAILED capture on HTTP 2xx is a terminal capture failure; report it
        // as an error instead of a success-shaped response.
        if utils::is_payment_failure(status) {
            // Same decline mapping as the Authorize decline path (b4-13).
            let error_code = item
                .response
                .processor_response
                .as_ref()
                .and_then(|response| response.response_code.clone());
            let error_message = error_code
                .as_deref()
                .and_then(get_paypal_error_message)
                .map(|message| message.to_string());
            let advice_code = item
                .response
                .processor_response
                .as_ref()
                .and_then(|response| response.payment_advice_code.clone());
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    amount_captured,
                    ..item.router_data.resource_common_data
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: error_code
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: error_message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: Some(match error_message {
                        Some(message) => format!(
                            "PayPal capture {capture_id} status {:?}: {message}",
                            item.response.status
                        ),
                        None => format!(
                            "PayPal capture {capture_id} status {:?}",
                            item.response.status
                        ),
                    }),
                    status_code: item.http_code,
                    attempt_status: Some(FlowStatus::Payment(status)),
                    // The payment's reference on every flow is the order id (TH-16), never
                    // the capture id, so a failed capture cannot overwrite it (b4-13).
                    connector_transaction_id: item
                        .router_data
                        .request
                        .connector_transaction_id
                        .get_connector_transaction_id()
                        .ok(),
                    network_decline_code: error_code,
                    network_advice_code: advice_code,
                    network_error_message: None,
                    typed_connector_response: None,
                    raw_connector_response: None,
                    raw_connector_request: None,
                    typed_connector_request: None,
                }),
                ..item.router_data
            });
        }

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                amount_captured,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: item.router_data.request.connector_transaction_id.clone(),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: Some(serde_json::json!(PaypalMeta {
                    authorize_id: connector_payment_id.authorize_id,
                    capture_id: Some(capture_id.clone()),
                    incremental_authorization_id: None,
                    psync_flow: PaypalPaymentIntent::Capture,
                    next_action: None,
                    order_id: None,
                    order_intent: None,
                })),
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: invoice_id.or(Some(capture_id)),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
                splits: None,
                payment_account_reference: None,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalCancelStatus {
    Voided,
    /// Any value PayPal adds later; mapped non-terminally.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PaypalPaymentsCancelResponse {
    id: String,
    status: PaypalCancelStatus,
    amount: Option<OrderAmount>,
    invoice_id: Option<String>,
}

impl TryFrom<ResponseRouterData<PaypalPaymentsCancelResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaypalPaymentsCancelResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.status {
            PaypalCancelStatus::Voided => common_enums::AttemptStatus::Voided,
            PaypalCancelStatus::Unknown => common_enums::AttemptStatus::Pending,
        };
        // The payment's reference stays the order id the Authorize call returned; the
        // authorization id (`item.response.id`) is only the void endpoint's path key.
        let resource_id = ResponseId::ConnectorTransactionId(
            item.router_data.request.connector_transaction_id.clone(),
        );
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: item
                    .response
                    .invoice_id
                    .or(Some(item.response.id)),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
                splits: None,
                payment_account_reference: None,
            }),
            ..item.router_data
        })
    }
}

impl<F, T> TryFrom<ResponseRouterData<PaypalSetupMandatesResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaypalSetupMandatesResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let info_response = item.response;

        // doc: https://developer.paypal.com/docs/api/payment-tokens/v3/#payment-tokens_create
        // 201 = payment token created, 200 = idempotent replay of the same
        // PayPal-Request-Id (same token). Non-2xx is handled by get_error_response_v2;
        // any other 2xx is undocumented and is not reported as a vaulted mandate.
        if !matches!(item.http_code, 200 | 201) {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::Failure,
                    ..item.router_data.resource_common_data
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: NO_ERROR_CODE.to_string(),
                    message: NO_ERROR_MESSAGE.to_string(),
                    reason: Some(format!(
                        "PayPal payment-token creation returned undocumented HTTP {}",
                        item.http_code
                    )),
                    status_code: item.http_code,
                    attempt_status: Some(FlowStatus::Payment(common_enums::AttemptStatus::Failure)),
                    connector_transaction_id: Some(info_response.id),
                    ..Default::default()
                }),
                ..item.router_data
            });
        }

        let mandate_reference = Some(Box::new(MandateReference {
            connector_mandate_id: Some(info_response.id.clone()),
            payment_method_id: None,
            connector_mandate_request_reference_id: Some(info_response.customer.id.clone()),
            mandate_metadata: None,
        }));
        // PayPal vaulting is not an authorization: a created payment token is reported
        // Charged (Hyperswitch parity), with the vault id as the mandate id.
        let status = common_enums::AttemptStatus::Charged;
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(info_response.id.clone()),
                redirection_data: None,
                mandate_reference,
                connector_metadata: None,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: Some(info_response.id.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
                splits: None,
                payment_account_reference: None,
            }),
            ..item.router_data
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PaypalRouterData<
            RouterDataV2<
                domain_types::connector_flow::SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for PaypalZeroMandateRequest
{
    type Error = Report<IntegrationError>;
    fn try_from(
        item: PaypalRouterData<
            RouterDataV2<
                domain_types::connector_flow::SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let payment_source = match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(ccard) => ZeroMandateSourceItem::Card(CardMandateRequest {
                billing_address: get_address_info(
                    item.router_data.resource_common_data.get_optional_billing(),
                ),
                expiry: Some(ccard.get_expiry_date_as_yyyymm("-")),
                name: item
                    .router_data
                    .resource_common_data
                    .get_optional_billing_full_name(),
                number: Some(
                    ccard
                        .card_number
                        .peek()
                        .parse::<cards::CardNumber>()
                        .map_err(|_| {
                            error_stack::report!(IntegrationError::InvalidDataFormat {
                                field_name: "payment_method_data.card.card_number",
                                context: Default::default(),
                            })
                        })?,
                ),
            }),
            // $0 Auth / Apple Pay PSP-decryption chain: the setup token minted by
            // PaymentMethodService/Tokenize (POST v3/vault/setup-tokens) is converted
            // into the durable vault id here.
            // Doc: https://developer.paypal.com/docs/api/payment-tokens/v3/#payment-tokens_create
            PaymentMethodData::PaymentMethodToken(setup_token) => {
                ZeroMandateSourceItem::Token(PaypalSetupTokenRef {
                    id: setup_token.token,
                    token_type: PaypalVaultTokenType::SetupToken,
                })
            }

            PaymentMethodData::Wallet(_)
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::DecryptedWalletTokenDetailsForNetworkTransactionId(_)
            | PaymentMethodData::CardWithNoCvc(_)
            | PaymentMethodData::MobilePayment(_) => {
                Err(error_stack::report!(IntegrationError::NotSupported {
                    message: utils::get_unimplemented_payment_method_error_message("Paypal"),
                    connector: "Paypal",
                    context: IntegrationErrorContext {
                        suggested_action: Some(
                            "PayPal SetupRecurring vaults a raw card, or a setup token from \
                             PaymentMethodService/Tokenize via PaymentService/TokenSetupRecurring"
                                .to_string(),
                        ),
                        doc_url: Some(
                            "https://developer.paypal.com/docs/api/payment-tokens/v3/#payment-tokens_create"
                                .to_string(),
                        ),
                        additional_context: None,
                    },
                }))?
            }
        };

        Ok(Self { payment_source })
    }
}

/// PostAuthenticate outcome guard over PayPal's 3DS decision table
/// (doc: https://developer.paypal.com/docs/checkout/advanced/customize/3d-secure/response-parameters/).
///
/// Accepts exactly the rows PayPal says to continue with, and every accepted
/// enrollment / authentication status is corroborated by `liability_shift` (Orders v2
/// returns no ECI or CAVV, so liability_shift is the only corroborating signal):
/// - row 1:  enrollment `Y`, authentication `Y` (authenticated)  -> liability `POSSIBLE`
/// - row 4:  enrollment `Y`, authentication `A` (attempted)      -> liability `POSSIBLE`
/// - row 9:  enrollment `N` (not enrolled), no authentication     -> liability `NO`
/// - row 10: enrollment `U` (unavailable), no authentication      -> liability `NO`
/// - row 12: enrollment `B` (bypassed), no authentication         -> liability `NO`
///
/// Everything else -- `N`/`R`/`U`/`C`/`I`/`D` authentication statuses, a `Y`/`A` status
/// without `POSSIBLE`, any `UNKNOWN` liability shift, an authentication status on a
/// non-enrolled card, or an unrecognised value -- is rejected.
fn is_accepted_paypal_3ds_outcome(
    enrollment_status: Option<&EnrollmentStatus>,
    authentication_status: Option<&AuthenticationStatus>,
    liability_shift: &LiabilityShift,
) -> bool {
    match liability_shift {
        LiabilityShift::Possible => matches!(
            (enrollment_status, authentication_status),
            (
                Some(EnrollmentStatus::Ready),
                Some(AuthenticationStatus::Success | AuthenticationStatus::Attempted)
            )
        ),
        LiabilityShift::No => matches!(
            (enrollment_status, authentication_status),
            (
                Some(
                    EnrollmentStatus::NotReady
                        | EnrollmentStatus::Unavailable
                        | EnrollmentStatus::Bypassed
                ),
                None
            )
        ),
        LiabilityShift::Unknown => false,
    }
}

/// The PayPal order a PostAuthenticate reads (`GET v2/checkout/orders/{id}`): the
/// `reference_id` set by the 3DS Authorize, else the caller's `connector_order_reference_id`.
pub fn paypal_post_auth_order_id<T: PaymentMethodDataTypes>(
    router_data: &RouterDataV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    >,
) -> Option<String> {
    router_data
        .resource_common_data
        .reference_id
        .clone()
        .or_else(|| router_data.request.connector_order_reference_id.clone())
}

/// G-ThreeDS-02: a card 3DS completion may move money only when the request carries the
/// outcome PostAuthenticate accepted for this same order (PayPal's sandbox completes an
/// order still in `PAYER_ACTION_REQUIRED`, so the vendor cannot be relied on to refuse).
/// Accepted `trans_status`, each emitted by PostAuthenticate only for its corroborated row:
/// - `Success`                  row 1        (enrollment Y, authentication Y, liability POSSIBLE)
/// - `NotVerified`              row 4        (enrollment Y, authentication A, liability POSSIBLE)
/// - `VerificationNotPerformed` rows 9/10/12 (enrollment N/U/B, no authentication, liability NO)
///
/// Absent data, any other status, or an outcome for a different order is refused.
pub fn paypal_completion_has_accepted_3ds(
    authentication_data: Option<&AuthenticationData>,
    connector_order_id: &str,
) -> bool {
    authentication_data.is_some_and(|auth| {
        auth.transaction_id.as_deref() == Some(connector_order_id)
            && matches!(
                auth.trans_status,
                Some(
                    common_enums::TransactionStatus::Success
                        | common_enums::TransactionStatus::NotVerified
                        | common_enums::TransactionStatus::VerificationNotPerformed
                )
            )
    })
}

/// G-ThreeDS-02 (deny by default): arms whose order completion is gated by a payer
/// approval (on PayPal, in the wallet, or at the bank), not by card 3DS. Every other arm
/// must carry the accepted outcome checked by `paypal_completion_has_accepted_3ds`.
/// Exhaustive on purpose: a new `PaymentMethodData` variant must be classified here.
pub fn paypal_completion_exempt_from_3ds<T: PaymentMethodDataTypes>(
    payment_method_data: &PaymentMethodData<T>,
) -> bool {
    match payment_method_data {
        PaymentMethodData::Wallet(wallet) => matches!(
            wallet,
            WalletData::PaypalRedirect(_)
                | WalletData::PaypalSdk(_)
                | WalletData::ApplePay(_)
                | WalletData::GooglePay(_)
        ),
        PaymentMethodData::BankRedirect(bank) => matches!(
            bank,
            BankRedirectData::Eps { .. }
                | BankRedirectData::Giropay { .. }
                | BankRedirectData::Ideal { .. }
                | BankRedirectData::Sofort { .. }
        ),
        PaymentMethodData::Card(_)
        | PaymentMethodData::CardWithNoCvc(_)
        | PaymentMethodData::CardDetailsForNetworkTransactionId(_)
        | PaymentMethodData::DecryptedWalletTokenDetailsForNetworkTransactionId(_)
        | PaymentMethodData::CardRedirect(_)
        | PaymentMethodData::PayLater(_)
        | PaymentMethodData::BankDebit(_)
        | PaymentMethodData::BankTransfer(_)
        | PaymentMethodData::Crypto(_)
        | PaymentMethodData::MandatePayment
        | PaymentMethodData::Reward
        | PaymentMethodData::RealTimePayment(_)
        | PaymentMethodData::Upi(_)
        | PaymentMethodData::Voucher(_)
        | PaymentMethodData::GiftCard(_)
        | PaymentMethodData::PaymentMethodToken(_)
        | PaymentMethodData::OpenBanking(_)
        | PaymentMethodData::NetworkToken(_)
        | PaymentMethodData::MobilePayment(_) => false,
    }
}

// TryFrom implementation for PostAuthenticate response
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<PaypalPostAuthenticateResponse, Self>>
    for RouterDataV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    >
{
    type Error = Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaypalPostAuthenticateResponse, Self>,
    ) -> Result<Self, Self::Error> {
        // Accepted row -> the 3DS outcome handed to the completion Authorize, which refuses
        // to move money without it (G-ThreeDS-02, `paypal_completion_has_accepted_3ds`).
        let mut accepted_trans_status = None;
        let rejection_reason = match &item.response {
            PaypalPostAuthenticateResponse::PaypalLiabilityResponse(liability_response) => {
                let authentication_result =
                    &liability_response.payment_source.card.authentication_result;
                let enrollment_status = authentication_result
                    .three_d_secure
                    .enrollment_status
                    .as_ref();
                let authentication_status = authentication_result
                    .three_d_secure
                    .authentication_status
                    .as_ref();
                if is_accepted_paypal_3ds_outcome(
                    enrollment_status,
                    authentication_status,
                    &authentication_result.liability_shift,
                ) {
                    accepted_trans_status = match authentication_status {
                        // row 1: Y / Y, corroborated by liability_shift POSSIBLE
                        Some(AuthenticationStatus::Success) => {
                            Some(common_enums::TransactionStatus::Success)
                        }
                        // row 4: Y / A, corroborated by liability_shift POSSIBLE
                        Some(AuthenticationStatus::Attempted) => {
                            Some(common_enums::TransactionStatus::NotVerified)
                        }
                        // rows 9 / 10 / 12: enrollment N / U / B, no authentication,
                        // corroborated by liability_shift NO
                        None => Some(common_enums::TransactionStatus::VerificationNotPerformed),
                        // Not an accepted row; emitting nothing keeps the completion refused.
                        Some(
                            AuthenticationStatus::Null
                            | AuthenticationStatus::Failed
                            | AuthenticationStatus::Rejected
                            | AuthenticationStatus::Unable
                            | AuthenticationStatus::ChallengeRequired
                            | AuthenticationStatus::InfoOnly
                            | AuthenticationStatus::Decoupled
                            | AuthenticationStatus::Unknown,
                        ) => None,
                    };
                    None
                } else {
                    Some(format!(
                        "Cannot continue with Authorization due to failed Liability Shift. Connector Responded with LiabilityShift: {:?}, EnrollmentStatus: {:?}, and AuthenticationStatus: {:?}",
                        authentication_result.liability_shift,
                        enrollment_status.unwrap_or(&EnrollmentStatus::Null),
                        authentication_status.unwrap_or(&AuthenticationStatus::Null),
                    ))
                }
            }
            // No `authentication_result` on the order: the payer never completed (or
            // never started) the 3DS challenge. Never treated as authenticated (B010).
            PaypalPostAuthenticateResponse::PaypalNonLiabilityResponse(_) => Some(
                "Cannot continue with Authorization: PayPal order carries no 3DS \
                 authentication_result (payer has not completed authentication)"
                    .to_string(),
            ),
        };

        let post_auth_order_id = paypal_post_auth_order_id(&item.router_data);
        match rejection_reason {
            None => Ok(Self {
                flow: item.router_data.flow,
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::AuthenticationSuccessful,
                    ..item.router_data.resource_common_data
                },
                response: Ok(PaymentsResponseData::PostAuthenticateResponse {
                    // Bound to the order this leg read, so the completion can check it is
                    // completing the same order (G-ThreeDS-02). Orders v2 returns no ECI/CAVV.
                    authentication_data: accepted_trans_status.map(|trans_status| {
                        AuthenticationData {
                            trans_status: Some(trans_status),
                            transaction_id: post_auth_order_id,
                            eci: None,
                            cavv: None,
                            ucaf_collection_indicator: None,
                            threeds_server_transaction_id: None,
                            message_version: None,
                            ds_trans_id: None,
                            acs_transaction_id: None,
                            network_params: None,
                            exemption_indicator: None,
                            created_at: None,
                            challenge_code: None,
                            challenge_cancel: None,
                            challenge_code_reason: None,
                            message_extension: None,
                            authentication_type: None,
                        }
                    }),
                    connector_response_reference_id: None,
                    status_code: item.http_code,
                }),
                connector_config: item.router_data.connector_config,
                request: item.router_data.request,
            }),
            Some(reason) => Ok(Self {
                flow: item.router_data.flow,
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::AuthenticationFailed,
                    ..item.router_data.resource_common_data
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    attempt_status: Some(FlowStatus::Payment(
                        common_enums::AttemptStatus::AuthenticationFailed,
                    )),
                    code: NO_ERROR_CODE.to_string(),
                    message: NO_ERROR_MESSAGE.to_string(),
                    connector_transaction_id: None,
                    reason: Some(reason),
                    status_code: item.http_code,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                    typed_connector_response: None,
                    raw_connector_response: None,
                    raw_connector_request: None,
                    typed_connector_request: None,
                }),
                connector_config: item.router_data.connector_config,
                request: item.router_data.request,
            }),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum RefundStatus {
    Completed,
    Failed,
    Cancelled,
    Pending,
    /// Any value PayPal adds later; mapped non-terminally.
    #[serde(other)]
    Unknown,
}

impl From<RefundStatus> for common_enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Completed => Self::Success,
            RefundStatus::Failed | RefundStatus::Cancelled => Self::Failure,
            RefundStatus::Pending | RefundStatus::Unknown => Self::Pending,
        }
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OrderErrorDetails {
    pub issue: String,
    pub description: Option<String>,
    pub value: Option<String>,
    pub field: Option<String>,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ErrorDetails {
    pub issue: String,
    pub description: Option<String>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct PaypalSupplementaryData {
    pub related_ids: PaypalRelatedIds,
}
#[derive(Deserialize, Debug, Serialize)]
pub struct PaypalRelatedIds {
    pub order_id: String,
}

/// Maximum `invoice_id` length on a refund request (`refund_request.invoice_id`, 1-127).
/// Doc: https://developer.paypal.com/docs/api/payments/v2/#captures_refund
const PAYPAL_REFUND_INVOICE_ID_MAX_LEN: usize = 127;
/// Maximum `note_to_payer` length on a refund request (`refund_request.note_to_payer`, 1-255).
/// Doc: https://developer.paypal.com/docs/api/payments/v2/#captures_refund
const PAYPAL_REFUND_NOTE_TO_PAYER_MAX_LEN: usize = 255;

#[derive(Default, Debug, Serialize)]
pub struct PaypalRefundRequest {
    pub amount: OrderAmount,
    /// Merchant reference of this refund (the refund id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoice_id: Option<String>,
    /// Refund reason shown to the payer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note_to_payer: Option<String>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PaypalRouterData<
            RouterDataV2<
                domain_types::connector_flow::Refund,
                RefundFlowData,
                RefundsData,
                RefundsResponseData,
            >,
            T,
        >,
    > for PaypalRefundRequest
{
    type Error = Report<IntegrationError>;
    fn try_from(
        item: PaypalRouterData<
            RouterDataV2<
                domain_types::connector_flow::Refund,
                RefundFlowData,
                RefundsData,
                RefundsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let value = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.refund_amount.amount,
                item.router_data.request.currency,
            )
            .change_context(IntegrationError::AmountConversionFailed {
                context: Default::default(),
            })?;
        let request = &item.router_data.request;
        // Both fields are 1..=N characters on the wire: an empty value is omitted
        // rather than sent, a longer one is truncated to the documented maximum.
        let invoice_id = Some(request.refund_id.as_str())
            .filter(|refund_id| !refund_id.is_empty())
            .map(|refund_id| truncate_chars(refund_id, PAYPAL_REFUND_INVOICE_ID_MAX_LEN));
        let note_to_payer = request
            .reason
            .as_deref()
            .filter(|reason| !reason.trim().is_empty())
            .map(|reason| truncate_chars(reason, PAYPAL_REFUND_NOTE_TO_PAYER_MAX_LEN));
        Ok(Self {
            amount: OrderAmount {
                currency_code: request.currency,
                value,
            },
            invoice_id,
            note_to_payer,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefundResponse {
    id: String,
    status: RefundStatus,
    amount: Option<OrderAmount>,
}

impl TryFrom<ResponseRouterData<RefundResponse, Self>>
    for RouterDataV2<
        domain_types::connector_flow::Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    >
{
    type Error = Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<RefundResponse, Self>) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status: common_enums::RefundStatus::from(item.response.status),
                status_code: item.http_code,
                acquirer_reference_number: None,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RefundSyncResponse {
    id: String,
    status: RefundStatus,
}

impl TryFrom<ResponseRouterData<RefundSyncResponse, Self>>
    for RouterDataV2<
        domain_types::connector_flow::RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    >
{
    type Error = Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<RefundSyncResponse, Self>) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status: common_enums::RefundStatus::from(item.response.status),
                status_code: item.http_code,
                acquirer_reference_number: None,
            }),
            ..item.router_data
        })
    }
}

/// Orders v2 stored-credential (MIT) reference used in RepeatPayment error contexts.
const PAYPAL_MIT_DOC_URL: &str =
    "https://developer.paypal.com/docs/api/orders/v2/#definition-card_stored_credential";

/// `stored_credential.payment_type` for a merchant-initiated charge: scheduled
/// categories (recurring, subscription, installment) are `RECURRING`, everything
/// else (unscheduled, resubmission, or no category) is `UNSCHEDULED`.
/// Doc: https://developer.paypal.com/docs/api/orders/v2/#definition-card_stored_credential
fn get_paypal_mit_payment_type(
    mit_category: Option<&common_enums::MitCategory>,
) -> PaypalStoredPaymentType {
    match mit_category {
        Some(common_enums::MitCategory::Recurring)
        | Some(common_enums::MitCategory::Subscription)
        | Some(common_enums::MitCategory::Installment) => PaypalStoredPaymentType::Recurring,
        Some(common_enums::MitCategory::Unscheduled)
        | Some(common_enums::MitCategory::Resubmission)
        | None => PaypalStoredPaymentType::Unscheduled,
    }
}

/// `stored_credential{MERCHANT, <payment_type>, SUBSEQUENT}` for a MIT, optionally
/// chained to the scheme reference of the earlier transaction.
fn get_paypal_mit_stored_credential(
    payment_type: PaypalStoredPaymentType,
    previous_network_transaction_reference: Option<PaypalPreviousNetworkTransactionReference>,
) -> PaypalStoredCredential {
    PaypalStoredCredential {
        payment_initiator: PaypalPaymentInitiator::Merchant,
        payment_type,
        usage: Some(PaypalStoredCredentialUsage::Subsequent),
        previous_network_transaction_reference,
    }
}

/// `payment_source.card` for an NTID MIT: the card itself (no CVC) plus
/// `stored_credential.previous_network_transaction_reference{id, network}`.
///
/// Refuses before any call when the request carries no card (G-RepeatPayment-02) or
/// when the card is Mastercard or Discover (G-RepeatPayment-01): PayPal makes the
/// 4-digit `previous_network_transaction_reference.date` mandatory for those
/// networks and no UCS field carries it.
/// Doc: https://developer.paypal.com/docs/api/orders/v2/#definition-card_stored_credential
fn get_paypal_ntid_card_request<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
>(
    item: &PaypalRouterData<
        RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>,
        T,
    >,
    network_mandate_id: &domain_types::connector_types::NetworkMandateIdRef,
    payment_type: PaypalStoredPaymentType,
) -> Result<CardRequestStruct<T>, Report<IntegrationError>> {
    // (number, expiry YYYY-MM, holder name, PayPal brand)
    let (number, expiry, card_holder_name, network) =
        match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => (
                card.card_number.clone(),
                card.get_expiry_date_as_yyyymm("-"),
                card.card_holder_name.clone(),
                card.card_network
                    .as_ref()
                    .and_then(PaypalCardBrand::from_card_network)
                    .or_else(|| {
                        utils::get_card_issuer(card.card_number.peek())
                            .ok()
                            .as_ref()
                            .and_then(PaypalCardBrand::from_card_issuer)
                    }),
            ),
            PaymentMethodData::CardDetailsForNetworkTransactionId(card) => (
                card.card_number.clone(),
                card.get_expiry_date_as_yyyymm("-"),
                card.card_holder_name.clone(),
                card.card_network
                    .as_ref()
                    .and_then(PaypalCardBrand::from_card_network)
                    .or_else(|| {
                        card.get_card_issuer()
                            .ok()
                            .as_ref()
                            .and_then(PaypalCardBrand::from_card_issuer)
                    }),
            ),
            // G-RepeatPayment-02: an NTID MIT sends the card next to the reference.
            _ => {
                return Err(error_stack::report!(
                    IntegrationError::MissingRequiredField {
                        field_name: "payment_method_data.card",
                        context: IntegrationErrorContext {
                            suggested_action: Some(
                                "Send the card number and expiry with a network-transaction-id \
                             MIT; PayPal charges the card against the previous network reference"
                                    .to_string(),
                            ),
                            doc_url: Some(PAYPAL_MIT_DOC_URL.to_string()),
                            additional_context: None,
                        },
                    }
                ));
            }
        };

    // G-RepeatPayment-01: `date` is mandatory for Mastercard / Discover.
    if matches!(
        network,
        Some(PaypalCardBrand::Mastercard) | Some(PaypalCardBrand::Discover)
    ) {
        return Err(error_stack::report!(
            IntegrationError::MissingRequiredField {
                field_name: "previous_network_transaction_reference.date",
                context: IntegrationErrorContext {
                    suggested_action: Some(
                        "PayPal requires the 4-digit scheme authorization date for Mastercard and \
                     Discover NTID MITs and UCS carries no such field; use a PayPal vault id \
                     (connector_mandate_id) for this card instead"
                            .to_string(),
                    ),
                    doc_url: Some(PAYPAL_MIT_DOC_URL.to_string()),
                    additional_context: None,
                },
            }
        ));
    }

    Ok(CardRequestStruct {
        billing_address: get_address_info(
            item.router_data
                .resource_common_data
                .get_optional_payment_billing(),
        ),
        expiry: Some(expiry),
        name: card_holder_name.or_else(|| {
            item.router_data
                .resource_common_data
                .get_optional_payment_billing_full_name()
        }),
        number: Some(number),
        // A MIT never carries the security code.
        security_code: None,
        attributes: None,
        stored_credential: Some(get_paypal_mit_stored_credential(
            payment_type,
            Some(PaypalPreviousNetworkTransactionReference {
                id: Secret::new(network_mandate_id.network_transaction_id.clone()),
                network,
            }),
        )),
    })
}

// RepeatPayment - TryFrom implementation for MIT payments
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PaypalRouterData<
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for PaypalPaymentsRequest<T>
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: PaypalRouterData<
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // Determine intent based on capture_method
        let intent = if item.router_data.request.is_auto_capture() {
            PaypalPaymentIntent::Capture
        } else {
            PaypalPaymentIntent::Authorize
        };
        let paypal_auth: PaypalAuthType =
            PaypalAuthType::try_from(&item.router_data.connector_config)?;
        let payee = get_payee(&paypal_auth);

        let amount = OrderRequestAmount::try_from(&item)?;
        let connector_request_reference_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let shipping_address = ShippingAddress::from(&item);
        let item_details = vec![ItemDetails::try_from(&item)?];
        let soft_descriptor =
            get_paypal_soft_descriptor(item.router_data.request.billing_descriptor.as_ref());
        let supplementary_data = get_paypal_supplementary_data(
            item.router_data.resource_common_data.l2_l3_data.as_deref(),
            &connector_request_reference_id,
            item.router_data.request.currency,
            item.connector.amount_converter,
        )?;

        let purchase_units = vec![PurchaseUnitRequest {
            reference_id: Some(connector_request_reference_id.clone()),
            custom_id: item.router_data.request.merchant_order_id.clone(),
            invoice_id: Some(connector_request_reference_id),
            amount,
            payee,
            shipping: Some(shipping_address),
            items: item_details,
            soft_descriptor,
            supplementary_data,
        }];

        // Every MIT carries the merchant-initiated stored-credential indicators.
        // Doc: https://developer.paypal.com/docs/api/orders/v2/#definition-card_stored_credential
        let payment_type =
            get_paypal_mit_payment_type(item.router_data.request.mit_category.as_ref());

        let payment_source = match &item.router_data.request.mandate_reference {
            domain_types::connector_types::MandateReferenceId::ConnectorMandateId(data) => {
                let connector_mandate_id = data.get_connector_mandate_id().ok_or(
                    IntegrationError::MissingRequiredField {
                        field_name: "connector_mandate_id",
                        context: IntegrationErrorContext {
                            suggested_action: Some(
                                "Pass the PayPal vault id returned by SetupRecurring as \
                                 connector_recurring_payment_id.connector_mandate_id"
                                    .to_string(),
                            ),
                            doc_url: Some(PAYPAL_MIT_DOC_URL.to_string()),
                            additional_context: None,
                        },
                    },
                )?;
                let payment_method_type = item.router_data.request.payment_method_type.ok_or(
                    IntegrationError::MissingRequiredField {
                        field_name: "payment_method_type",
                        context: IntegrationErrorContext {
                            suggested_action: Some(
                                "Set payment_method_type (card, apple_pay or paypal) for a \
                                 PayPal vault-id MIT"
                                    .to_string(),
                            ),
                            doc_url: Some(PAYPAL_MIT_DOC_URL.to_string()),
                            additional_context: None,
                        },
                    },
                )?;
                match payment_method_type {
                    common_enums::PaymentMethodType::Card => Some(PaymentSourceItem::Card(
                        CardRequest::CardVaultStruct(CardVaultStruct {
                            vault_id: Secret::new(connector_mandate_id),
                            attributes: item
                                .router_data
                                .resource_common_data
                                .customer_id
                                .clone()
                                .map(|customer_id| VaultRequestAttributes {
                                    customer: Some(CustomerRequestData {
                                        merchant_customer_id: Some(customer_id),
                                    }),
                                }),
                            stored_credential: Some(get_paypal_mit_stored_credential(
                                payment_type,
                                None,
                            )),
                        }),
                    )),
                    common_enums::PaymentMethodType::ApplePay => Some(
                        PaymentSourceItem::ApplePayVault(PaypalApplePayVaultRequest {
                            vault_id: Secret::new(connector_mandate_id),
                            // A customer-present charge (off_session == false) is the first use
                            // of a just-vaulted Apple Pay token: CIT, CUSTOMER/FIRST with no
                            // previous reference. Otherwise MIT, MERCHANT/SUBSEQUENT (UD-07).
                            // Doc: https://developer.paypal.com/docs/api/orders/v2/#definition-card_stored_credential
                            stored_credential: if item.router_data.request.off_session
                                == Some(false)
                            {
                                PaypalStoredCredential {
                                    payment_initiator: PaypalPaymentInitiator::Customer,
                                    payment_type,
                                    usage: Some(PaypalStoredCredentialUsage::First),
                                    previous_network_transaction_reference: None,
                                }
                            } else {
                                get_paypal_mit_stored_credential(payment_type, None)
                            },
                        }),
                    ),
                    common_enums::PaymentMethodType::Paypal => Some(PaymentSourceItem::Paypal(
                        PaypalRedirectionRequest::PaypalVaultStruct(PaypalVaultStruct {
                            vault_id: Secret::new(connector_mandate_id),
                            // If PayPal requires buyer re-approval for this wallet MIT, return the
                            // buyer to Hyperswitch's complete-authorize endpoint so the order can be
                            // captured on return. Falls back to router_return_url when unset.
                            experience_context: item
                                .router_data
                                .request
                                .complete_authorize_url
                                .clone()
                                .or_else(|| item.router_data.request.router_return_url.clone())
                                .map(|url| ContextStruct {
                                    return_url: Some(url.clone()),
                                    cancel_url: Some(url),
                                    user_action: Some(UserAction::PayNow),
                                    shipping_preference: ShippingPreference::GetFromFile,
                                }),
                        }),
                    )),
                    _ => {
                        return Err(error_stack::report!(IntegrationError::NotSupported {
                            message: format!(
                                "Payment method type {payment_method_type:?} not supported for PayPal repeat payments"
                            ),
                            connector: "paypal",
                            context: IntegrationErrorContext {
                                suggested_action: Some(
                                    "PayPal vault-id MITs support card, apple_pay and paypal"
                                        .to_string(),
                                ),
                                doc_url: Some(PAYPAL_MIT_DOC_URL.to_string()),
                                additional_context: None,
                            },
                        }));
                    }
                }
            }
            domain_types::connector_types::MandateReferenceId::NetworkMandateId(
                network_mandate_id,
            ) => Some(PaymentSourceItem::Card(CardRequest::CardRequestStruct(
                get_paypal_ntid_card_request(&item, network_mandate_id, payment_type)?,
            ))),
            domain_types::connector_types::MandateReferenceId::NetworkTokenWithNTI(_) => {
                return Err(error_stack::report!(IntegrationError::NotSupported {
                    message: "Network token with NTID not supported for PayPal repeat payments"
                        .to_string(),
                    connector: "paypal",
                    context: IntegrationErrorContext {
                        suggested_action: Some(
                            "Use a PayPal vault id or a raw card with its network transaction id"
                                .to_string(),
                        ),
                        doc_url: Some(PAYPAL_MIT_DOC_URL.to_string()),
                        additional_context: None,
                    },
                }));
            }
        };

        Ok(Self {
            intent,
            purchase_units,
            payment_source,
        })
    }
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct PaypalPaymentErrorResponse {
    pub name: Option<String>,
    pub message: String,
    pub debug_id: Option<String>,
    pub details: Option<Vec<ErrorDetails>>,
}

// ----------------------------------------------------------------------------
// Webhooks (Payments / Refunds / Disputes)
// ----------------------------------------------------------------------------

pub mod webhook_headers {
    // PayPal transmission headers used for signature verification
    pub const PAYPAL_TRANSMISSION_ID: &str = "paypal-transmission-id";
    pub const PAYPAL_TRANSMISSION_TIME: &str = "paypal-transmission-time";
    pub const PAYPAL_CERT_URL: &str = "paypal-cert-url";
    pub const PAYPAL_TRANSMISSION_SIG: &str = "paypal-transmission-sig";
    pub const PAYPAL_AUTH_ALGO: &str = "paypal-auth-algo";
}

/// Envelope of a PayPal webhook notification. `resource` is decoded by
/// [`PaypalWebhooksBody::resource`] into the object the `event_type` documents, rather than by an
/// untagged enum in which the first structurally matching variant wins (a refund body carrying
/// `supplementary_data` used to decode as a capture).
/// doc: https://developer.paypal.com/api/rest/webhooks/event-names/
#[derive(Deserialize, Debug, Serialize)]
pub struct PaypalWebhooksBody {
    pub event_type: PaypalWebhookEventType,
    #[serde(default)]
    pub resource: serde_json::Value,
}

impl PaypalWebhooksBody {
    /// Decode `resource` as the object type the event carries (`resource_type`).
    pub fn resource(&self) -> Result<PaypalResource, serde_json::Error> {
        Ok(match self.event_type.resource_kind() {
            PaypalWebhookResourceKind::Payment => PaypalResource::Payment(Box::new(
                PaypalPaymentWebhookResource::deserialize(&self.resource)?,
            )),
            PaypalWebhookResourceKind::Order => PaypalResource::Order(Box::new(
                PaypalOrderWebhookResource::deserialize(&self.resource)?,
            )),
            PaypalWebhookResourceKind::Refund => PaypalResource::Refund(Box::new(
                PaypalRefundWebhookResource::deserialize(&self.resource)?,
            )),
            PaypalWebhookResourceKind::Dispute => PaypalResource::Dispute(Box::new(
                PaypalDisputeWebhooks::deserialize(&self.resource)?,
            )),
            PaypalWebhookResourceKind::Unsupported => PaypalResource::Unsupported,
        })
    }

    /// The dispute fields event-type mapping and references read. Lenient on purpose: the
    /// deprecated `RISK.DISPUTE.CREATED` payload need not carry the full dispute object.
    pub fn dispute_fields(&self) -> Result<PaypalDisputeEventFields, serde_json::Error> {
        PaypalDisputeEventFields::deserialize(&self.resource)
    }
}

#[derive(Deserialize, Debug, Serialize)]
pub struct PaypalWebooksEventType {
    pub event_type: PaypalWebhookEventType,
}

/// doc: https://developer.paypal.com/api/rest/webhooks/event-names/
#[derive(Clone, Copy, Deserialize, Debug, strum::Display, Serialize)]
pub enum PaypalWebhookEventType {
    #[serde(rename = "PAYMENT.AUTHORIZATION.CREATED")]
    PaymentAuthorizationCreated,
    #[serde(rename = "PAYMENT.AUTHORIZATION.VOIDED")]
    PaymentAuthorizationVoided,

    #[serde(rename = "PAYMENT.CAPTURE.COMPLETED")]
    PaymentCaptureCompleted,
    #[serde(rename = "PAYMENT.CAPTURE.PENDING")]
    PaymentCapturePending,
    #[serde(rename = "PAYMENT.CAPTURE.DECLINED")]
    PaymentCaptureDeclined,
    #[serde(rename = "PAYMENT.CAPTURE.DENIED")]
    PaymentCaptureDenied,
    #[serde(rename = "PAYMENT.CAPTURE.REVERSED")]
    PaymentCaptureReversed,
    #[serde(rename = "PAYMENT.CAPTURE.REFUNDED")]
    PaymentCaptureRefunded,

    #[serde(rename = "PAYMENT.REFUND.COMPLETED")]
    PaymentRefundCompleted,
    #[serde(rename = "PAYMENT.REFUND.PENDING")]
    PaymentRefundPending,
    #[serde(rename = "PAYMENT.REFUND.FAILED")]
    PaymentRefundFailed,

    #[serde(rename = "CHECKOUT.ORDER.COMPLETED")]
    CheckoutOrderCompleted,
    #[serde(rename = "CHECKOUT.ORDER.PROCESSED")]
    CheckoutOrderProcessed,
    #[serde(rename = "CHECKOUT.ORDER.APPROVED")]
    CheckoutOrderApproved,

    #[serde(rename = "CUSTOMER.DISPUTE.CREATED")]
    CustomerDisputeCreated,
    #[serde(rename = "CUSTOMER.DISPUTE.RESOLVED")]
    CustomerDisputeResolved,
    #[serde(rename = "CUSTOMER.DISPUTE.UPDATED")]
    CustomerDisputedUpdated,
    #[serde(rename = "RISK.DISPUTE.CREATED")]
    RiskDisputeCreated,

    #[serde(other)]
    Unknown,
}

/// The `resource_type` an event carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaypalWebhookResourceKind {
    /// `capture` or `authorization`
    Payment,
    /// `checkout-order`
    Order,
    /// `refund`
    Refund,
    /// `dispute`
    Dispute,
    Unsupported,
}

impl PaypalWebhookEventType {
    /// doc: https://developer.paypal.com/api/rest/webhooks/event-names/ (resource per event)
    pub fn resource_kind(self) -> PaypalWebhookResourceKind {
        match self {
            Self::PaymentAuthorizationCreated
            | Self::PaymentAuthorizationVoided
            | Self::PaymentCaptureCompleted
            | Self::PaymentCapturePending
            | Self::PaymentCaptureDeclined
            | Self::PaymentCaptureDenied
            | Self::PaymentCaptureReversed => PaypalWebhookResourceKind::Payment,
            Self::PaymentCaptureRefunded
            | Self::PaymentRefundCompleted
            | Self::PaymentRefundPending
            | Self::PaymentRefundFailed => PaypalWebhookResourceKind::Refund,
            Self::CheckoutOrderCompleted
            | Self::CheckoutOrderProcessed
            | Self::CheckoutOrderApproved => PaypalWebhookResourceKind::Order,
            Self::CustomerDisputeCreated
            | Self::CustomerDisputeResolved
            | Self::CustomerDisputedUpdated
            | Self::RiskDisputeCreated => PaypalWebhookResourceKind::Dispute,
            Self::Unknown => PaypalWebhookResourceKind::Unsupported,
        }
    }
}

#[derive(Debug)]
pub enum PaypalResource {
    Payment(Box<PaypalPaymentWebhookResource>),
    Order(Box<PaypalOrderWebhookResource>),
    Refund(Box<PaypalRefundWebhookResource>),
    Dispute(Box<PaypalDisputeWebhooks>),
    Unsupported,
}

/// `capture` / `authorization` resource of a `PAYMENT.CAPTURE.*` / `PAYMENT.AUTHORIZATION.*` event.
/// doc: https://developer.paypal.com/docs/api/payments/v2/#captures_get
#[derive(Deserialize, Debug, Serialize)]
pub struct PaypalPaymentWebhookResource {
    pub id: Option<String>,
    pub supplementary_data: Option<PaypalWebhookSupplementaryData>,
    pub invoice_id: Option<String>,
    pub links: Option<Vec<PaypalLinks>>,
    pub status_details: Option<PaypalWebhookStatusDetails>,
}

impl PaypalPaymentWebhookResource {
    /// The order id, which is this connector's `connector_transaction_id`:
    /// `supplementary_data.related_ids.order_id`, else the id in the `rel: "up"` link when that
    /// link points at `/v2/checkout/orders/{id}`.
    pub fn order_id(&self) -> Option<String> {
        self.supplementary_data
            .as_ref()
            .and_then(|data| data.related_ids.as_ref())
            .and_then(|ids| ids.order_id.clone())
            .or_else(|| {
                self.links
                    .iter()
                    .flatten()
                    .filter(|link| link.rel == "up")
                    .find_map(|link| {
                        let segments: Vec<&str> = link.href.as_ref()?.path_segments()?.collect();
                        match segments.as_slice() {
                            [.., "checkout", "orders", order_id] if !order_id.is_empty() => {
                                Some((*order_id).to_string())
                            }
                            _ => None,
                        }
                    })
            })
    }
}

#[derive(Deserialize, Debug, Serialize)]
pub struct PaypalWebhookSupplementaryData {
    pub related_ids: Option<PaypalWebhookRelatedIds>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct PaypalWebhookRelatedIds {
    pub order_id: Option<String>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct PaypalWebhookStatusDetails {
    pub reason: Option<String>,
}

/// `checkout-order` resource of a `CHECKOUT.ORDER.*` event; `id` is the order id.
/// doc: https://developer.paypal.com/docs/api/orders/v2/#orders_get
#[derive(Deserialize, Debug, Serialize)]
pub struct PaypalOrderWebhookResource {
    pub id: String,
    pub intent: Option<PaypalPaymentIntent>,
    pub status: Option<PaypalOrderStatus>,
    #[serde(default)]
    pub purchase_units: Vec<PaypalOrderWebhookPurchaseUnit>,
}

/// A purchase unit of a `checkout-order` webhook resource. `payments` is absent until the order
/// is authorized or captured, so it is optional here (unlike the Orders API response).
#[derive(Deserialize, Debug, Serialize)]
pub struct PaypalOrderWebhookPurchaseUnit {
    #[serde(default)]
    pub payments: Option<PaymentsCollection>,
}

impl PaypalOrderWebhookResource {
    /// Payment status of a `COMPLETED` order, read from its payments exactly as PSync reads the
    /// same order: intent `CAPTURE` -> `captures[0].status`, intent `AUTHORIZE` ->
    /// `authorizations[0].status` (the attempt status is then the shared
    /// [`From<PaypalPaymentStatus>`] map). `COMPLETED` alone is never taken as captured: with no
    /// intent or no matching payment the order state is unknown and `None` is returned.
    /// doc: https://developer.paypal.com/docs/api/orders/v2/#orders_get!c=200&path=status
    pub fn completed_payment_status(&self) -> Option<PaypalPaymentStatus> {
        let payments = self.purchase_units.first()?.payments.as_ref()?;
        let item = match self.intent.as_ref()? {
            PaypalPaymentIntent::Capture => payments.captures.as_ref()?.first(),
            PaypalPaymentIntent::Authorize => payments.authorizations.as_ref()?.first(),
            PaypalPaymentIntent::Authenticate => None,
        }?;
        Some(item.status.clone())
    }
}

/// `refund` resource of a `PAYMENT.CAPTURE.REFUNDED` / `PAYMENT.REFUND.*` event. A refund carries
/// no `processor_response`; its failure reason is `status_details.reason`.
/// doc: https://developer.paypal.com/docs/api/payments/v2/#refunds_get
#[derive(Deserialize, Debug, Serialize)]
pub struct PaypalRefundWebhookResource {
    pub id: String,
    pub status_details: Option<PaypalWebhookStatusDetails>,
}

/// doc: https://developer.paypal.com/docs/api/customer-disputes/v1/#disputes_get
#[derive(Deserialize, Debug, Serialize)]
pub struct PaypalDisputeWebhooks {
    pub dispute_id: String,
    pub disputed_transactions: Vec<DisputeTransaction>,
    pub dispute_amount: OrderAmount,
    pub dispute_outcome: Option<DisputeOutcome>,
    pub dispute_life_cycle_stage: DisputeLifeCycleStage,
    pub status: DisputeStatus,
    pub reason: Option<String>,
}

/// The dispute fields the event-type mapping (`status`, nested `dispute_outcome.outcome_code`)
/// and the webhook reference (`dispute_id`, `disputed_transactions[].seller_transaction_id`) read.
#[derive(Deserialize, Debug, Serialize)]
pub struct PaypalDisputeEventFields {
    pub dispute_id: Option<String>,
    pub status: Option<DisputeStatus>,
    pub dispute_outcome: Option<DisputeOutcome>,
    pub disputed_transactions: Option<Vec<DisputeTransaction>>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct DisputeTransaction {
    pub seller_transaction_id: Option<String>,
}

/// The disputed payment's reference: the `seller_transaction_id` shared by every disputed
/// transaction that carries one. This is PayPal's **capture** id, not the order id this
/// connector returns as `connector_transaction_id` on its payment flows; the caller resolves it
/// through the capture id it stored. A multi-transaction dispute is never attributed to its
/// first entry: two or more distinct ids, or none, yield `None`.
/// doc: https://developer.paypal.com/docs/api/customer-disputes/v1/#disputes_get
pub fn paypal_dispute_transaction_id(transactions: &[DisputeTransaction]) -> Option<String> {
    let mut ids = transactions
        .iter()
        .filter_map(|transaction| transaction.seller_transaction_id.as_deref());
    let first = ids.next()?;
    ids.all(|id| id == first).then(|| first.to_string())
}

#[derive(Clone, Deserialize, Debug, strum::Display, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DisputeLifeCycleStage {
    Inquiry,
    Chargeback,
    PreArbitration,
    Arbitration,
}

#[derive(Deserialize, Debug, strum::Display, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DisputeStatus {
    Open,
    WaitingForBuyerResponse,
    WaitingForSellerResponse,
    UnderReview,
    Resolved,
    Other,
    #[serde(other)]
    Unknown,
}

/// `resource.dispute_outcome` (nested in the dispute object, not at the top of the event).
#[derive(Deserialize, Debug, Serialize)]
pub struct DisputeOutcome {
    pub outcome_code: OutcomeCode,
}

#[derive(Deserialize, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutcomeCode {
    ResolvedBuyerFavour,
    ResolvedSellerFavour,
    ResolvedWithPayout,
    CanceledByBuyer,
    ACCEPTED,
    DENIED,
    NONE,
    #[serde(other)]
    Unknown,
}

// ----------------------------------------------------------------------------
// Webhook Source Verification
// ----------------------------------------------------------------------------

/// Body of `POST /v1/notifications/verify-webhook-signature`.
/// doc: https://developer.paypal.com/docs/api/webhooks/v1/#verify-webhook-signature_post
#[derive(Debug, Serialize)]
pub struct PaypalSourceVerificationRequest {
    pub transmission_id: String,
    pub transmission_time: String,
    pub cert_url: String,
    pub transmission_sig: String,
    pub auth_algo: String,
    /// The merchant's Webhook ID (`^[A-Za-z0-9]+$`, at most 50 characters).
    pub webhook_id: Secret<String>,
    /// The notification exactly as received: PayPal verifies the signature over the original
    /// bytes, so the body is never parsed into a `Value` and re-serialised.
    pub webhook_event: Box<serde_json::value::RawValue>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PaypalSourceVerificationResponse {
    pub verification_status: PaypalSourceVerificationStatus,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalSourceVerificationStatus {
    Success,
    Failure,
}

#[derive(Deserialize, Debug)]
pub struct PaypalAccessTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

// Normalize headers to lowercase keys (HTTP header names are case-insensitive per RFC 7230).
fn webhook_headers_lowercase(
    headers: &std::collections::HashMap<String, String>,
) -> std::collections::HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect()
}

/// Maximum length of a PayPal Webhook ID (`webhook_id`, pattern `^[A-Za-z0-9]+$`).
/// doc: https://developer.paypal.com/docs/api/webhooks/v1/#verify-webhook-signature_post
const PAYPAL_WEBHOOK_ID_MAX_LEN: usize = 50;
const PAYPAL_VERIFY_WEBHOOK_DOC_URL: &str =
    "https://developer.paypal.com/docs/api/webhooks/v1/#verify-webhook-signature_post";

/// Validate the configured webhook secret as a PayPal Webhook ID before any postback.
///
/// An empty or malformed secret is refused rather than sent: the gRPC server substitutes a
/// placeholder when the caller configured none, and posting that would only ever earn a
/// `FAILURE`. The value is never echoed into the error.
fn paypal_webhook_id(secret: &[u8]) -> Result<Secret<String>, Report<IntegrationError>> {
    let refuse = |reason: &str| IntegrationError::MissingRequiredField {
        field_name: "webhook_id",
        context: IntegrationErrorContext {
            suggested_action: Some(
                "Configure the PayPal Webhook ID of the subscribed listener as the webhook secret"
                    .to_string(),
            ),
            doc_url: Some(PAYPAL_VERIFY_WEBHOOK_DOC_URL.to_string()),
            additional_context: Some(reason.to_string()),
        },
    };
    let webhook_id =
        std::str::from_utf8(secret).map_err(|_| refuse("webhook secret is not valid UTF-8"))?;
    if webhook_id.is_empty() {
        return Err(refuse("webhook secret is empty").into());
    }
    if webhook_id.len() > PAYPAL_WEBHOOK_ID_MAX_LEN
        || !webhook_id.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(refuse(
            "webhook secret is not a PayPal Webhook ID (^[A-Za-z0-9]+$, at most 50 characters)",
        )
        .into());
    }
    Ok(Secret::new(webhook_id.to_string()))
}

// Transformers for VerifyWebhookSource flow.
//
// Timestamp decision: no tolerance window is enforced. PayPal documents none,
// `paypal-transmission-time` is part of the signed message (it cannot be altered without failing
// verification), and PayPal itself re-delivers the same event for up to 3 days, which a fixed
// window would reject. Replay protection stays with the caller's de-duplication on the event id.
// doc: https://developer.paypal.com/api/rest/webhooks/rest/
impl TryFrom<&VerifyWebhookSourceRequestData> for PaypalSourceVerificationRequest {
    type Error = Report<IntegrationError>;
    fn try_from(req: &VerifyWebhookSourceRequestData) -> Result<Self, Self::Error> {
        let webhook_id = paypal_webhook_id(&req.merchant_secret.secret)?;

        let webhook_event: Box<serde_json::value::RawValue> = serde_json::from_slice(
            &req.webhook_body,
        )
        .change_context(IntegrationError::InvalidDataFormat {
            field_name: "webhook_event",
            context: IntegrationErrorContext {
                suggested_action: Some(
                    "Pass the PayPal notification body unmodified as received".to_string(),
                ),
                doc_url: Some(PAYPAL_VERIFY_WEBHOOK_DOC_URL.to_string()),
                additional_context: Some("webhook body is not valid JSON".to_string()),
            },
        })?;

        let headers = webhook_headers_lowercase(&req.webhook_headers);
        let header = |name: &'static str| -> Result<String, Report<IntegrationError>> {
            headers.get(name).cloned().ok_or_else(|| {
                IntegrationError::MissingRequiredField {
                    field_name: name,
                    context: IntegrationErrorContext {
                        suggested_action: Some(
                            "Forward every paypal-* transmission header received with the notification"
                                .to_string(),
                        ),
                        doc_url: Some(PAYPAL_VERIFY_WEBHOOK_DOC_URL.to_string()),
                        additional_context: None,
                    },
                }
                .into()
            })
        };

        Ok(Self {
            transmission_id: header(webhook_headers::PAYPAL_TRANSMISSION_ID)?,
            transmission_time: header(webhook_headers::PAYPAL_TRANSMISSION_TIME)?,
            cert_url: header(webhook_headers::PAYPAL_CERT_URL)?,
            transmission_sig: header(webhook_headers::PAYPAL_TRANSMISSION_SIG)?,
            auth_algo: header(webhook_headers::PAYPAL_AUTH_ALGO)?,
            webhook_id,
            webhook_event,
        })
    }
}

impl From<PaypalSourceVerificationStatus> for VerifyWebhookStatus {
    fn from(item: PaypalSourceVerificationStatus) -> Self {
        match item {
            PaypalSourceVerificationStatus::Success => Self::SourceVerified,
            PaypalSourceVerificationStatus::Failure => Self::SourceNotVerified,
        }
    }
}

impl TryFrom<ResponseRouterData<PaypalSourceVerificationResponse, Self>>
    for RouterDataV2<
        VerifyWebhookSource,
        VerifyWebhookSourceFlowData,
        VerifyWebhookSourceRequestData,
        VerifyWebhookSourceResponseData,
    >
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<PaypalSourceVerificationResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(VerifyWebhookSourceResponseData {
                verify_webhook_status: VerifyWebhookStatus::from(item.response.verification_status),
            }),
            ..item.router_data
        })
    }
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct PaypalOrderErrorResponse {
    pub name: Option<String>,
    pub message: String,
    pub debug_id: Option<String>,
    pub details: Option<Vec<OrderErrorDetails>>,
}

impl From<OrderErrorDetails> for ErrorCodeAndMessage {
    fn from(error: OrderErrorDetails) -> Self {
        Self {
            error_code: error.issue.to_string(),
            error_message: error.issue,
        }
    }
}

impl From<ErrorDetails> for ErrorCodeAndMessage {
    fn from(error: ErrorDetails) -> Self {
        Self {
            error_code: error.issue.to_string(),
            error_message: error.issue.to_string(),
        }
    }
}

fn get_paypal_error_message(error_code: &str) -> Option<&str> {
    match error_code {
        "00N7" | "RESPONSE_00N7" => Some("CVV2_FAILURE_POSSIBLE_RETRY_WITH_CVV."),
        "0390" | "RESPONSE_0390" => Some("ACCOUNT_NOT_FOUND."),
        "0500" | "RESPONSE_0500" => Some("DO_NOT_HONOR."),
        "0580" | "RESPONSE_0580" => Some("UNAUTHORIZED_TRANSACTION."),
        "0800" | "RESPONSE_0800" => Some("BAD_RESPONSE_REVERSAL_REQUIRED."),
        "0880" | "RESPONSE_0880" => Some("CRYPTOGRAPHIC_FAILURE."),
        "0890" | "RESPONSE_0890" => Some("UNACCEPTABLE_PIN."),
        "0960" | "RESPONSE_0960" => Some("SYSTEM_MALFUNCTION."),
        "0R00" | "RESPONSE_0R00" => Some("CANCELLED_PAYMENT."),
        "1000" | "RESPONSE_1000" => Some("PARTIAL_AUTHORIZATION."),
        "10BR" | "RESPONSE_10BR" => Some("ISSUER_REJECTED."),
        "1300" | "RESPONSE_1300" => Some("INVALID_DATA_FORMAT."),
        "1310" | "RESPONSE_1310" => Some("INVALID_AMOUNT."),
        "1312" | "RESPONSE_1312" => Some("INVALID_TRANSACTION_CARD_ISSUER_ACQUIRER."),
        "1317" | "RESPONSE_1317" => Some("INVALID_CAPTURE_DATE."),
        "1320" | "RESPONSE_1320" => Some("INVALID_CURRENCY_CODE."),
        "1330" | "RESPONSE_1330" => Some("INVALID_ACCOUNT."),
        "1335" | "RESPONSE_1335" => Some("INVALID_ACCOUNT_RECURRING."),
        "1340" | "RESPONSE_1340" => Some("INVALID_TERMINAL."),
        "1350" | "RESPONSE_1350" => Some("INVALID_MERCHANT."),
        "1352" | "RESPONSE_1352" => Some("RESTRICTED_OR_INACTIVE_ACCOUNT."),
        "1360" | "RESPONSE_1360" => Some("BAD_PROCESSING_CODE."),
        "1370" | "RESPONSE_1370" => Some("INVALID_MCC."),
        "1380" | "RESPONSE_1380" => Some("INVALID_EXPIRATION."),
        "1382" | "RESPONSE_1382" => Some("INVALID_CARD_VERIFICATION_VALUE."),
        "1384" | "RESPONSE_1384" => Some("INVALID_LIFE_CYCLE_OF_TRANSACTION."),
        "1390" | "RESPONSE_1390" => Some("INVALID_ORDER."),
        "1393" | "RESPONSE_1393" => Some("TRANSACTION_CANNOT_BE_COMPLETED."),
        "5100" | "RESPONSE_5100" => Some("GENERIC_DECLINE."),
        "5110" | "RESPONSE_5110" => Some("CVV2_FAILURE."),
        "5120" | "RESPONSE_5120" => Some("INSUFFICIENT_FUNDS."),
        "5130" | "RESPONSE_5130" => Some("INVALID_PIN."),
        "5135" | "RESPONSE_5135" => Some("DECLINED_PIN_TRY_EXCEEDED."),
        "5140" | "RESPONSE_5140" => Some("CARD_CLOSED."),
        "5150" | "RESPONSE_5150" => Some(
            "PICKUP_CARD_SPECIAL_CONDITIONS. Try using another card. Do not retry the same card.",
        ),
        "5160" | "RESPONSE_5160" => Some("UNAUTHORIZED_USER."),
        "5170" | "RESPONSE_5170" => Some("AVS_FAILURE."),
        "5180" | "RESPONSE_5180" => {
            Some("INVALID_OR_RESTRICTED_CARD. Try using another card. Do not retry the same card.")
        }
        "5190" | "RESPONSE_5190" => Some("SOFT_AVS."),
        "5200" | "RESPONSE_5200" => Some("DUPLICATE_TRANSACTION."),
        "5210" | "RESPONSE_5210" => Some("INVALID_TRANSACTION."),
        "5400" | "RESPONSE_5400" => Some("EXPIRED_CARD."),
        "5500" | "RESPONSE_5500" => Some("INCORRECT_PIN_REENTER."),
        "5650" | "RESPONSE_5650" => Some("DECLINED_SCA_REQUIRED."),
        "5700" | "RESPONSE_5700" => {
            Some("TRANSACTION_NOT_PERMITTED. Outside of scope of accepted business.")
        }
        "5710" | "RESPONSE_5710" => Some("TX_ATTEMPTS_EXCEED_LIMIT."),
        "5800" | "RESPONSE_5800" => Some("REVERSAL_REJECTED."),
        "5900" | "RESPONSE_5900" => Some("INVALID_ISSUE."),
        "5910" | "RESPONSE_5910" => Some("ISSUER_NOT_AVAILABLE_NOT_RETRIABLE."),
        "5920" | "RESPONSE_5920" => Some("ISSUER_NOT_AVAILABLE_RETRIABLE."),
        "5930" | "RESPONSE_5930" => Some("CARD_NOT_ACTIVATED."),
        "5950" | "RESPONSE_5950" => Some(
            "DECLINED_DUE_TO_UPDATED_ACCOUNT. External decline as an updated card has been issued.",
        ),
        "6300" | "RESPONSE_6300" => Some("ACCOUNT_NOT_ON_FILE."),
        "7700" | "RESPONSE_7700" => Some("ERROR_3DS."),
        "7710" | "RESPONSE_7710" => Some("AUTHENTICATION_FAILED."),
        "7800" | "RESPONSE_7800" => Some("BIN_ERROR."),
        "7900" | "RESPONSE_7900" => Some("PIN_ERROR."),
        "8000" | "RESPONSE_8000" => Some("PROCESSOR_SYSTEM_ERROR."),
        "8010" | "RESPONSE_8010" => Some("HOST_KEY_ERROR."),
        "8020" | "RESPONSE_8020" => Some("CONFIGURATION_ERROR."),
        "8030" | "RESPONSE_8030" => Some("UNSUPPORTED_OPERATION."),
        "8100" | "RESPONSE_8100" => Some("FATAL_COMMUNICATION_ERROR."),
        "8110" | "RESPONSE_8110" => Some("RETRIABLE_COMMUNICATION_ERROR."),
        "8220" | "RESPONSE_8220" => Some("SYSTEM_UNAVAILABLE."),
        "9100" | "RESPONSE_9100" => Some("DECLINED_PLEASE_RETRY. Retry."),
        "9500" | "RESPONSE_9500" => {
            Some("SUSPECTED_FRAUD. Try using another card. Do not retry the same card.")
        }
        "9510" | "RESPONSE_9510" => Some("SECURITY_VIOLATION."),
        "9520" | "RESPONSE_9520" => {
            Some("LOST_OR_STOLEN. Try using another card. Do not retry the same card.")
        }
        "9540" | "RESPONSE_9540" => Some("REFUSED_CARD."),
        "9600" | "RESPONSE_9600" => Some("UNRECOGNIZED_RESPONSE_CODE."),
        "PCNR" | "RESPONSE_PCNR" => Some("CONTINGENCIES_NOT_RESOLVED."),
        "PCVV" | "RESPONSE_PCVV" => Some("CVV_FAILURE."),
        "PP06" | "RESPONSE_PP06" => Some("ACCOUNT_CLOSED. A previously open account is now closed"),
        "PPRN" | "RESPONSE_PPRN" => Some("REATTEMPT_NOT_PERMITTED."),
        "PPAD" | "RESPONSE_PPAD" => Some("BILLING_ADDRESS."),
        "PPAB" | "RESPONSE_PPAB" => Some("ACCOUNT_BLOCKED_BY_ISSUER."),
        "PPAE" | "RESPONSE_PPAE" => Some("AMEX_DISABLED."),
        "PPAG" | "RESPONSE_PPAG" => Some("ADULT_GAMING_UNSUPPORTED."),
        "PPAI" | "RESPONSE_PPAI" => Some("AMOUNT_INCOMPATIBLE."),
        "PPAR" | "RESPONSE_PPAR" => Some("AUTH_RESULT."),
        "PPAU" | "RESPONSE_PPAU" => Some("MCC_CODE."),
        "PPAV" | "RESPONSE_PPAV" => Some("ARC_AVS."),
        "PPAX" | "RESPONSE_PPAX" => Some("AMOUNT_EXCEEDED."),
        "PPBG" | "RESPONSE_PPBG" => Some("BAD_GAMING."),
        "PPC2" | "RESPONSE_PPC2" => Some("ARC_CVV."),
        "PPCE" | "RESPONSE_PPCE" => Some("CE_REGISTRATION_INCOMPLETE."),
        "PPCO" | "RESPONSE_PPCO" => Some("COUNTRY."),
        "PPCR" | "RESPONSE_PPCR" => Some("CREDIT_ERROR."),
        "PPCT" | "RESPONSE_PPCT" => Some("CARD_TYPE_UNSUPPORTED."),
        "PPCU" | "RESPONSE_PPCU" => Some("CURRENCY_USED_INVALID."),
        "PPD3" | "RESPONSE_PPD3" => Some("SECURE_ERROR_3DS."),
        "PPDC" | "RESPONSE_PPDC" => Some("DCC_UNSUPPORTED."),
        "PPDI" | "RESPONSE_PPDI" => Some("DINERS_REJECT."),
        "PPDV" | "RESPONSE_PPDV" => Some("AUTH_MESSAGE."),
        "PPDT" | "RESPONSE_PPDT" => Some("DECLINE_THRESHOLD_BREACH."),
        "PPEF" | "RESPONSE_PPEF" => Some("EXPIRED_FUNDING_INSTRUMENT."),
        "PPEL" | "RESPONSE_PPEL" => Some("EXCEEDS_FREQUENCY_LIMIT."),
        "PPER" | "RESPONSE_PPER" => Some("INTERNAL_SYSTEM_ERROR."),
        "PPEX" | "RESPONSE_PPEX" => Some("EXPIRY_DATE."),
        "PPFE" | "RESPONSE_PPFE" => Some("FUNDING_SOURCE_ALREADY_EXISTS."),
        "PPFI" | "RESPONSE_PPFI" => Some("INVALID_FUNDING_INSTRUMENT."),
        "PPFR" | "RESPONSE_PPFR" => Some("RESTRICTED_FUNDING_INSTRUMENT."),
        "PPFV" | "RESPONSE_PPFV" => Some("FIELD_VALIDATION_FAILED."),
        "PPGR" | "RESPONSE_PPGR" => Some("GAMING_REFUND_ERROR."),
        "PPH1" | "RESPONSE_PPH1" => Some("H1_ERROR."),
        "PPIF" | "RESPONSE_PPIF" => Some("IDEMPOTENCY_FAILURE."),
        "PPII" | "RESPONSE_PPII" => Some("INVALID_INPUT_FAILURE."),
        "PPIM" | "RESPONSE_PPIM" => Some("ID_MISMATCH."),
        "PPIT" | "RESPONSE_PPIT" => Some("INVALID_TRACE_ID."),
        "PPLR" | "RESPONSE_PPLR" => Some("LATE_REVERSAL."),
        "PPLS" | "RESPONSE_PPLS" => Some("LARGE_STATUS_CODE."),
        "PPMB" | "RESPONSE_PPMB" => Some("MISSING_BUSINESS_RULE_OR_DATA."),
        "PPMC" | "RESPONSE_PPMC" => Some("BLOCKED_Mastercard."),
        "PPMD" | "RESPONSE_PPMD" => Some("DEPRECATED The PPMD value has been deprecated."),
        "PPNC" | "RESPONSE_PPNC" => Some("NOT_SUPPORTED_NRC."),
        "PPNL" | "RESPONSE_PPNL" => Some("EXCEEDS_NETWORK_FREQUENCY_LIMIT."),
        "PPNM" | "RESPONSE_PPNM" => Some("NO_MID_FOUND."),
        "PPNT" | "RESPONSE_PPNT" => Some("NETWORK_ERROR."),
        "PPPH" | "RESPONSE_PPPH" => Some("NO_PHONE_FOR_DCC_TRANSACTION."),
        "PPPI" | "RESPONSE_PPPI" => Some("INVALID_PRODUCT."),
        "PPPM" | "RESPONSE_PPPM" => Some("INVALID_PAYMENT_METHOD."),
        "PPQC" | "RESPONSE_PPQC" => Some("QUASI_CASH_UNSUPPORTED."),
        "PPRE" | "RESPONSE_PPRE" => Some("UNSUPPORT_REFUND_ON_PENDING_BC."),
        "PPRF" | "RESPONSE_PPRF" => Some("INVALID_PARENT_TRANSACTION_STATUS."),
        "PPRR" | "RESPONSE_PPRR" => Some("MERCHANT_NOT_REGISTERED."),
        "PPS0" | "RESPONSE_PPS0" => Some("BANKAUTH_ROW_MISMATCH."),
        "PPS1" | "RESPONSE_PPS1" => Some("BANKAUTH_ROW_SETTLED."),
        "PPS2" | "RESPONSE_PPS2" => Some("BANKAUTH_ROW_VOIDED."),
        "PPS3" | "RESPONSE_PPS3" => Some("BANKAUTH_EXPIRED."),
        "PPS4" | "RESPONSE_PPS4" => Some("CURRENCY_MISMATCH."),
        "PPS5" | "RESPONSE_PPS5" => Some("CREDITCARD_MISMATCH."),
        "PPS6" | "RESPONSE_PPS6" => Some("AMOUNT_MISMATCH."),
        "PPSC" | "RESPONSE_PPSC" => Some("ARC_SCORE."),
        "PPSD" | "RESPONSE_PPSD" => Some("STATUS_DESCRIPTION."),
        "PPSE" | "RESPONSE_PPSE" => Some("AMEX_DENIED."),
        "PPTE" | "RESPONSE_PPTE" => Some("VERIFICATION_TOKEN_EXPIRED."),
        "PPTF" | "RESPONSE_PPTF" => Some("INVALID_TRACE_REFERENCE."),
        "PPTI" | "RESPONSE_PPTI" => Some("INVALID_TRANSACTION_ID."),
        "PPTR" | "RESPONSE_PPTR" => Some("VERIFICATION_TOKEN_REVOKED."),
        "PPTT" | "RESPONSE_PPTT" => Some("TRANSACTION_TYPE_UNSUPPORTED."),
        "PPTV" | "RESPONSE_PPTV" => Some("INVALID_VERIFICATION_TOKEN."),
        "PPUA" | "RESPONSE_PPUA" => Some("USER_NOT_AUTHORIZED."),
        "PPUC" | "RESPONSE_PPUC" => Some("CURRENCY_CODE_UNSUPPORTED."),
        "PPUE" | "RESPONSE_PPUE" => Some("UNSUPPORT_ENTITY."),
        "PPUI" | "RESPONSE_PPUI" => Some("UNSUPPORT_INSTALLMENT."),
        "PPUP" | "RESPONSE_PPUP" => Some("UNSUPPORT_POS_FLAG."),
        "PPUR" | "RESPONSE_PPUR" => Some("UNSUPPORTED_REVERSAL."),
        "PPVC" | "RESPONSE_PPVC" => Some("VALIDATE_CURRENCY."),
        "PPVE" | "RESPONSE_PPVE" => Some("VALIDATION_ERROR."),
        "PPVT" | "RESPONSE_PPVT" => Some("VIRTUAL_TERMINAL_UNSUPPORTED."),
        _ => None,
    }
}

#[derive(Deserialize, Debug, Serialize)]
pub struct PaypalAccessTokenErrorResponse {
    pub error: String,
    pub error_description: String,
}

// ---- ClientAuthenticationToken flow types ----

/// PayPal client token request for SDK initialization.
/// PayPal's v1/identity/generate-token endpoint accepts an optional customer_id
/// and returns a client_token for the JS SDK. Passing customer_id scopes the
/// token to the customer and enables vault-related features.
#[derive(Debug, Serialize)]
pub struct PaypalClientAuthTokenRequest {
    /// Optional customer ID to scope the client token to a specific customer.
    /// When provided, enables vault-related features in the PayPal JS SDK.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PaypalRouterData<
            RouterDataV2<
                ClientAuthenticationToken,
                MerchantAuthenticationFlowData,
                ClientAuthenticationTokenRequestData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for PaypalClientAuthTokenRequest
{
    type Error = Report<IntegrationError>;
    fn try_from(
        item: PaypalRouterData<
            RouterDataV2<
                ClientAuthenticationToken,
                MerchantAuthenticationFlowData,
                ClientAuthenticationTokenRequestData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let customer_id = item
            .router_data
            .request
            .customer
            .as_ref()
            .and_then(|c| c.customer_id.as_ref())
            .map(|id| id.get_string_repr().to_string());

        Ok(Self { customer_id })
    }
}

/// PayPal client token response from v1/identity/generate-token.
#[derive(Debug, Deserialize, Serialize)]
pub struct PaypalClientAuthTokenResponse {
    pub client_token: String,
}

impl TryFrom<ResponseRouterData<PaypalClientAuthTokenResponse, Self>>
    for RouterDataV2<
        ClientAuthenticationToken,
        MerchantAuthenticationFlowData,
        ClientAuthenticationTokenRequestData,
        PaymentsResponseData,
    >
{
    type Error = Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaypalClientAuthTokenResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;

        let session_data = ClientAuthenticationTokenData::Paypal(Box::new(
            PaypalClientAuthenticationResponseDomain {
                connector: "paypal".to_string(),
                session_token: response.client_token.clone(),
                sdk_next_action: SdkNextAction {
                    next_action: domain_types::connector_types::NextActionCall::Confirm,
                },
                client_token: Some(response.client_token),
                transaction_info: Some(PaypalTransactionInfoDomain {
                    flow: PaypalFlowDomain::Checkout,
                    currency_code: item.router_data.request.currency,
                    total_price: item.router_data.request.amount.amount,
                }),
            },
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

// ---- PaymentMethodToken flow types (Vault v3 setup token) ----

/// `POST /v3/vault/setup-tokens` request.
/// Doc: https://developer.paypal.com/docs/api/payment-tokens/v3/#setup-tokens_create
#[derive(Debug, Serialize)]
pub struct PaypalSetupTokenRequest<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    payment_source: PaypalSetupTokenSource<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaypalSetupTokenSource<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    Card(PaypalSetupTokenCard<T>),
    ApplePay(PaypalSetupTokenApplePay),
}

/// `payment_source.card` of a setup token: PayPal runs a zero-value verification
/// (where the issuer supports it) according to `verification_method`.
#[derive(Debug, Serialize)]
pub struct PaypalSetupTokenCard<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    number: RawCardNumber<T>,
    expiry: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    billing_address: Option<Address>,
    verification_method: PaypalVerificationMethod,
    experience_context: PaypalSetupTokenExperienceContext,
}

/// `payment_source.card.experience_context` of a setup token. Without it PayPal leaves a
/// card setup token in `CREATED` (no verification) and it cannot be converted into a
/// payment token; with it the token reaches `APPROVED`.
/// Doc: https://developer.paypal.com/docs/api/payment-tokens/v3/#setup-tokens_create
#[derive(Debug, Serialize)]
pub struct PaypalSetupTokenExperienceContext {
    return_url: String,
    cancel_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalVerificationMethod {
    ScaWhenRequired,
}

/// `payment_source.apple_pay` of a setup token: the only PayPal request field that
/// accepts an encrypted (PSP-decrypted) Apple Pay token.
/// Doc: https://developer.paypal.com/docs/api/payment-tokens/v3/#definition-apple_pay_request
#[derive(Debug, Serialize)]
pub struct PaypalSetupTokenApplePay {
    token: Secret<String>,
    card: PaypalSetupTokenApplePayCard,
}

#[derive(Debug, Serialize)]
pub struct PaypalSetupTokenApplePayCard {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    card_type: Option<PaypalCardType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    brand: Option<PaypalCardBrand>,
    #[serde(skip_serializing_if = "Option::is_none")]
    billing_address: Option<Address>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalCardType {
    Credit,
    Debit,
    Prepaid,
}

/// Apple Pay `paymentMethod.type` -> PayPal card type; unknown values are omitted.
fn get_paypal_apple_pay_card_type(pm_type: &str) -> Option<PaypalCardType> {
    match pm_type.to_ascii_lowercase().as_str() {
        "credit" => Some(PaypalCardType::Credit),
        "debit" => Some(PaypalCardType::Debit),
        "prepaid" => Some(PaypalCardType::Prepaid),
        _ => None,
    }
}

/// Apple Pay `paymentMethod.network` -> PayPal card brand; unknown values are omitted.
fn get_paypal_apple_pay_card_brand(network: &str) -> Option<PaypalCardBrand> {
    match network.to_ascii_lowercase().as_str() {
        "visa" => Some(PaypalCardBrand::Visa),
        "mastercard" => Some(PaypalCardBrand::Mastercard),
        "amex" => Some(PaypalCardBrand::Amex),
        "discover" => Some(PaypalCardBrand::Discover),
        _ => None,
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PaypalRouterData<
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
            T,
        >,
    > for PaypalSetupTokenRequest<T>
{
    type Error = Report<IntegrationError>;
    fn try_from(
        item: PaypalRouterData<
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let billing_address = get_address_info(
            router_data
                .resource_common_data
                .get_optional_payment_billing(),
        );
        let payment_source = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => PaypalSetupTokenSource::Card(PaypalSetupTokenCard {
                number: card.card_number.clone(),
                expiry: card.get_expiry_date_as_yyyymm("-"),
                name: card.card_holder_name.clone().or_else(|| {
                    router_data
                        .resource_common_data
                        .get_optional_payment_billing_full_name()
                }),
                billing_address,
                verification_method: PaypalVerificationMethod::ScaWhenRequired,
                experience_context: {
                    let return_url = router_data
                        .resource_common_data
                        .get_return_url()
                        .filter(|url| !url.trim().is_empty())
                        .ok_or(IntegrationError::MissingRequiredField {
                            field_name: "return_url",
                            context: IntegrationErrorContext {
                                suggested_action: Some(
                                    "Provide return_url on the Tokenize request: PayPal only \
                                     approves a card setup token that carries \
                                     experience_context.return_url/cancel_url"
                                        .to_string(),
                                ),
                                doc_url: Some(
                                    "https://developer.paypal.com/docs/api/payment-tokens/v3/"
                                        .to_string(),
                                ),
                                additional_context: None,
                            },
                        })?;
                    PaypalSetupTokenExperienceContext {
                        cancel_url: return_url.clone(),
                        return_url,
                    }
                },
            }),
            PaymentMethodData::Wallet(WalletData::ApplePay(apple_pay_data)) => {
                match &apple_pay_data.payment_data {
                    domain_types::payment_method_data::ApplePayPaymentData::Encrypted(token) => {
                        PaypalSetupTokenSource::ApplePay(PaypalSetupTokenApplePay {
                            token: Secret::new(token.clone()),
                            card: PaypalSetupTokenApplePayCard {
                                card_type: get_paypal_apple_pay_card_type(
                                    &apple_pay_data.payment_method.pm_type,
                                ),
                                brand: get_paypal_apple_pay_card_brand(
                                    &apple_pay_data.payment_method.network,
                                ),
                                billing_address,
                            },
                        })
                    }
                    domain_types::payment_method_data::ApplePayPaymentData::Decrypted(_) => {
                        Err(error_stack::report!(IntegrationError::NotSupported {
                            message: "Decrypted Apple Pay data on PayPal Vault v3 setup token"
                                .to_string(),
                            connector: "Paypal",
                            context: IntegrationErrorContext {
                                suggested_action: Some(
                                    "Send decrypted Apple Pay data to PaymentService/Authorize; \
                                     Vault v3 apple_pay accepts only the encrypted token"
                                        .to_string(),
                                ),
                                doc_url: Some(
                                    "https://developer.paypal.com/docs/api/payment-tokens/v3/"
                                        .to_string(),
                                ),
                                additional_context: None,
                            },
                        }))?
                    }
                }
            }
            PaymentMethodData::Wallet(WalletData::GooglePay(_)) => {
                Err(error_stack::report!(IntegrationError::NotSupported {
                    message: "Google Pay on PayPal Vault v3 setup token: payment_source has no \
                              google_pay field (card, paypal, venmo, apple_pay, token, bank)"
                        .to_string(),
                    connector: "Paypal",
                    context: IntegrationErrorContext {
                        suggested_action: Some(
                            "Send decrypted Google Pay data to PaymentService/Authorize"
                                .to_string(),
                        ),
                        doc_url: Some(
                            "https://developer.paypal.com/docs/api/payment-tokens/v3/".to_string(),
                        ),
                        additional_context: None,
                    },
                }))?
            }
            PaymentMethodData::Wallet(_)
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::PaymentMethodToken(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::DecryptedWalletTokenDetailsForNetworkTransactionId(_)
            | PaymentMethodData::CardWithNoCvc(_)
            | PaymentMethodData::MobilePayment(_) => {
                Err(error_stack::report!(IntegrationError::NotSupported {
                    message: utils::get_unimplemented_payment_method_error_message("Paypal"),
                    connector: "Paypal",
                    context: IntegrationErrorContext {
                        suggested_action: Some(
                            "PayPal Vault v3 setup tokens accept card or encrypted Apple Pay"
                                .to_string(),
                        ),
                        doc_url: Some(
                            "https://developer.paypal.com/docs/api/payment-tokens/v3/".to_string(),
                        ),
                        additional_context: None,
                    },
                }))?
            }
        };
        Ok(Self { payment_source })
    }
}

/// `payment_token_status` of a setup token.
/// Doc: https://developer.paypal.com/docs/api/payment-tokens/v3/#setup-tokens_create!c=201&path=status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalSetupTokenStatus {
    Created,
    PayerActionRequired,
    Approved,
    Vaulted,
    Tokenized,
    /// Any value PayPal adds later; never treated as usable.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalSetupTokenResponse {
    pub id: String,
    pub status: PaypalSetupTokenStatus,
}

impl<T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<PaypalSetupTokenResponse, Self>>
    for RouterDataV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    >
{
    type Error = Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaypalSetupTokenResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        // Only an APPROVED setup token can be converted into a payment token
        // (PaymentService/TokenSetupRecurring). PAYER_ACTION_REQUIRED needs a browser
        // approval this RPC cannot return, so it is surfaced as an error.
        let (attempt_status, message) = match response.status {
            PaypalSetupTokenStatus::Approved => {
                return Ok(Self {
                    response: Ok(PaymentMethodTokenResponse {
                        token: response.id,
                        // A setup token is single-use; the durable vault id is created by
                        // TokenSetupRecurring.
                        connector_payment_method_id: None,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                });
            }
            PaypalSetupTokenStatus::PayerActionRequired => (
                common_enums::AttemptStatus::AuthenticationPending,
                "PayPal setup token requires payer approval (3DS) before it can be vaulted",
            ),
            PaypalSetupTokenStatus::Created
            | PaypalSetupTokenStatus::Vaulted
            | PaypalSetupTokenStatus::Tokenized => (
                common_enums::AttemptStatus::Failure,
                "PayPal setup token is not in APPROVED state",
            ),
            PaypalSetupTokenStatus::Unknown => (
                common_enums::AttemptStatus::Pending,
                "PayPal setup token returned an undocumented status",
            ),
        };
        Ok(Self {
            response: Err(domain_types::router_data::ErrorResponse {
                code: NO_ERROR_CODE.to_string(),
                message: message.to_string(),
                reason: Some(format!(
                    "setup token {} status {:?}",
                    response.id, response.status
                )),
                status_code: item.http_code,
                attempt_status: Some(FlowStatus::Payment(attempt_status)),
                connector_transaction_id: Some(response.id),
                ..Default::default()
            }),
            ..item.router_data
        })
    }
}
