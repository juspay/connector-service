//! AsiaPay (PayDollar) — transformers and wire types.
//!
//! Wire shape: `application/x-www-form-urlencoded` form posts to the hosted
//! payment page (`payForm.jsp`) for Authorize and to the merchant API
//! (`orderApi.jsp`) for the sync/refund units. The payment page itself
//! answers with either an HTTP redirect or an HTML page (the account's hosted
//! channel/its error page), so the Authorize response type below is the shape
//! of the JSON the connector's own `preprocess_response_bytes` synthesizes
//! from that HTML, not a gateway document.
//!
//! Amounts on the wire are decimal major-unit strings (`amount=100.00`,
//! spec Number(12,2)) → `StringMajorUnit`.

use std::fmt::Debug;

use bytes::Bytes;
use common_enums::{AttemptStatus, CaptureMethod, Currency, RefundStatus};
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::CustomResult,
    types::StringMajorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors::{ConnectorError, IntegrationError, IntegrationErrorContext},
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::{ConnectorSpecificConfig, ErrorResponse, FlowStatus},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use super::AsiapayRouterData;

crate::connectors::macros::create_amount_converter_wrapper!(
    connector_name: Asiapay,
    amount_type: StringMajorUnit
);

// ---------------------------------------------------------------------------
// Authentication — credentials travel as form fields (spec:## Authentication)
// ---------------------------------------------------------------------------

pub struct AsiapayAuthType {
    pub merchant_id: Secret<String>,
    pub username: Secret<String>,
    pub password: Secret<String>,
    pub secure_hash_secret: Option<Secret<String>>,
}

impl TryFrom<&ConnectorSpecificConfig> for AsiapayAuthType {
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Asiapay {
                merchant_id,
                username,
                password,
                secure_hash_secret,
                ..
            } => Ok(Self {
                merchant_id: merchant_id.to_owned(),
                username: username.to_owned(),
                password: password.to_owned(),
                secure_hash_secret: secure_hash_secret.to_owned(),
            }),
            _ => Err(error_stack::report!(
                IntegrationError::FailedToObtainAuthType {
                    context: IntegrationErrorContext {
                        suggested_action: Some(
                            "Configure the connector account with AsiaPay credentials".to_string(),
                        ),
                        doc_url: None,
                        additional_context: Some(
                            "ConnectorSpecificConfig variant mismatch: expected Asiapay credentials"
                                .to_string(),
                        ),
                    },
                }
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared status vocabulary (Payment Status Classification, spec:## Status
// Mappings) — 19 documented statuses plus the serde(other) catch-all (INV-09).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsiapayPaymentStatus {
    Accepted,
    #[serde(rename = "Accepted_Adj")]
    AcceptedAdj,
    Authorized,
    #[serde(rename = "Authorized_Adj")]
    AuthorizedAdj,
    Captured,
    Capturing,
    #[serde(rename = "ChargeBack")]
    ChargeBack,
    #[serde(rename = "PartialChargeBack")]
    PartialChargeBack,
    #[serde(rename = "PartialRefunded")]
    PartialRefunded,
    Pending,
    #[serde(rename = "Pending_feedback")]
    PendingFeedback,
    #[serde(rename = "Pending_3D")]
    Pending3D,
    Refunded,
    Rejected,
    #[serde(rename = "RequestPartialRefund")]
    RequestPartialRefund,
    #[serde(rename = "RequestRefund")]
    RequestRefund,
    #[serde(rename = "Reversal-Auth")]
    ReversalAuth,
    Voided,
    Voiding,
    /// Absorbs any status string the vendor adds later (INV-09); maps to the
    /// non-terminal Pending.
    #[serde(other)]
    Unknown,
}

impl From<AsiapayPaymentStatus> for AttemptStatus {
    fn from(status: AsiapayPaymentStatus) -> Self {
        match status {
            AsiapayPaymentStatus::Accepted
            | AsiapayPaymentStatus::AcceptedAdj
            | AsiapayPaymentStatus::Captured
            // A Query on a refunded payment still reports the money that moved;
            // the refund lifecycle is tracked separately (plan §4 PSync).
            | AsiapayPaymentStatus::PartialRefunded
            | AsiapayPaymentStatus::Refunded
            | AsiapayPaymentStatus::RequestPartialRefund
            | AsiapayPaymentStatus::RequestRefund => Self::Charged,
            AsiapayPaymentStatus::Authorized => Self::Authorized,
            AsiapayPaymentStatus::AuthorizedAdj => Self::PartialCharged,
            AsiapayPaymentStatus::Capturing => Self::CaptureInitiated,
            AsiapayPaymentStatus::ChargeBack | AsiapayPaymentStatus::PartialChargeBack => {
                Self::Failure
            }
            AsiapayPaymentStatus::Pending | AsiapayPaymentStatus::PendingFeedback => Self::Pending,
            AsiapayPaymentStatus::Pending3D => Self::AuthenticationPending,
            AsiapayPaymentStatus::Rejected => Self::Failure,
            AsiapayPaymentStatus::ReversalAuth | AsiapayPaymentStatus::Voided => Self::Voided,
            AsiapayPaymentStatus::Voiding => Self::VoidInitiated,
            AsiapayPaymentStatus::Unknown => Self::Pending,
        }
    }
}

impl From<AsiapayPaymentStatus> for RefundStatus {
    fn from(status: AsiapayPaymentStatus) -> Self {
        match status {
            AsiapayPaymentStatus::Refunded
            | AsiapayPaymentStatus::PartialRefunded
            | AsiapayPaymentStatus::AcceptedAdj
            | AsiapayPaymentStatus::Voided => Self::Success,
            AsiapayPaymentStatus::RequestRefund
            | AsiapayPaymentStatus::RequestPartialRefund
            | AsiapayPaymentStatus::Pending
            | AsiapayPaymentStatus::PendingFeedback
            | AsiapayPaymentStatus::Pending3D
            | AsiapayPaymentStatus::Unknown => Self::Pending,
            AsiapayPaymentStatus::Rejected
            | AsiapayPaymentStatus::ChargeBack
            | AsiapayPaymentStatus::PartialChargeBack => Self::Failure,
            AsiapayPaymentStatus::Accepted
            | AsiapayPaymentStatus::Authorized
            | AsiapayPaymentStatus::AuthorizedAdj
            | AsiapayPaymentStatus::Captured
            | AsiapayPaymentStatus::Capturing
            | AsiapayPaymentStatus::ReversalAuth
            | AsiapayPaymentStatus::Voiding => Self::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared error shape — merchant API failures are URL-encoded
// (`resultCode=-1&errMsg=...`); payment-page failures are an HTML page
// (spec:## HTTP Codes and Errors). Parsed leniently: never fails.
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AsiapayError {
    #[serde(rename = "resultCode")]
    pub result_code: Option<String>,
    #[serde(rename = "errMsg")]
    pub err_msg: Option<String>,
    pub prc: Option<String>,
    pub src: Option<String>,
}

/// Lenient URL-encoded `key=value&...` reader for the merchant-API error
/// body. Unknown/absent keys stay `None`; stray segments are ignored.
impl AsiapayError {
    pub fn from_form_encoded(body: &str) -> Self {
        let mut error = Self::default();
        for pair in body.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            match key.trim() {
                "resultCode" => error.result_code = Some(value.trim().to_string()),
                "errMsg" => error.err_msg = Some(value.trim().to_string()),
                "prc" => error.prc = Some(value.trim().to_string()),
                "src" => error.src = Some(value.trim().to_string()),
                _ => {}
            }
        }
        error
    }

    pub fn is_empty(&self) -> bool {
        self.result_code.is_none()
            && self.err_msg.is_none()
            && self.prc.is_none()
            && self.src.is_none()
    }
}

// ---------------------------------------------------------------------------
// Authorize — DPC form post of the card + order fields to payForm.jsp
// (spec:## Complete Endpoint Inventory — Authorize). All fields are required
// for card payments; `secureHash` only when the account's Secure Hash
// function is enabled (production; sandbox runs unsigned, plan UD-02).
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct AsiapayPaymentsRequest<
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
> {
    #[serde(rename = "merchantId")]
    pub merchant_id: Secret<String>,
    #[serde(rename = "orderRef")]
    pub order_ref: String,
    pub amount: StringMajorUnit,
    #[serde(rename = "currCode")]
    pub curr_code: String,
    pub lang: String,
    #[serde(rename = "pMethod", skip_serializing_if = "Option::is_none")]
    pub p_method: Option<String>,
    #[serde(rename = "cardNo")]
    pub card_no: RawCardNumber<T>,
    #[serde(rename = "securityCode")]
    pub security_code: Secret<String>,
    #[serde(rename = "cardHolder")]
    pub card_holder: Secret<String>,
    #[serde(rename = "epMonth")]
    pub ep_month: Secret<String>,
    #[serde(rename = "epYear")]
    pub ep_year: Secret<String>,
    #[serde(rename = "payType")]
    pub pay_type: String,
    #[serde(rename = "successUrl")]
    pub success_url: String,
    #[serde(rename = "failUrl")]
    pub fail_url: String,
    #[serde(rename = "errorUrl")]
    pub error_url: String,
    #[serde(rename = "secureHash", skip_serializing_if = "Option::is_none")]
    pub secure_hash: Option<Secret<String>>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        AsiapayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for AsiapayPaymentsRequest<T>
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        item: AsiapayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = AsiapayAuthType::try_from(&router_data.connector_config)?;

        // G-Authorize-01 — successUrl/failUrl/errorUrl are required wire
        // fields (spec:## Authorize params); fail closed before any request
        // is built.
        let return_url = router_data
            .request
            .router_return_url
            .clone()
            .filter(|url| !url.trim().is_empty())
            .ok_or(IntegrationError::MissingRequiredField {
                field_name: "return_url",
                context: IntegrationErrorContext {
                    suggested_action: Some(
                        "Pass return_url in the payment request; AsiaPay requires \
                         successUrl/failUrl/errorUrl on every payment-page post"
                            .to_string(),
                    ),
                    doc_url: None,
                    additional_context: None,
                },
            })?;

        // G-Authorize-02 — currCode has no proto pass-through; the currency
        // must exist in the documented numeric code list (spec:## Authorize
        // params currCode). Unknown → fail closed, no request is built.
        let curr_code = currency_to_curr_code(router_data.request.currency)?;

        let card_data = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card_data) => card_data,
            other => {
                return Err(IntegrationError::NotImplemented(
                    format!(
                        "AsiaPay cards-only integration: payment method '{}' is not supported",
                        payment_method_name(other)
                    ),
                    IntegrationErrorContext {
                        suggested_action: None,
                        doc_url: None,
                        additional_context: Some(
                            "spec:## Overview — cards only in this integration scope; pMethod \
                             carries card schemes (VISA/Master/Diners/JCB/AMEX)"
                                .to_string(),
                        ),
                    },
                )
                .into())
            }
        };

        let p_method = card_brand_to_p_method(card_data.card_network.as_ref())?;

        let card_holder =
            card_data
                .card_holder_name
                .clone()
                .ok_or(IntegrationError::MissingRequiredField {
                    field_name: "card_holder_name",
                    context: IntegrationErrorContext {
                        suggested_action: None,
                        doc_url: None,
                        additional_context: Some(
                            "asiapay: cardHolder is a required payment-page field".to_string(),
                        ),
                    },
                })?;

        let amount = item
            .connector
            .amount_converter
            .convert(
                router_data.request.amount.amount,
                router_data.request.currency,
            )
            .change_context(IntegrationError::AmountConversionFailed {
                context: IntegrationErrorContext {
                    suggested_action: None,
                    doc_url: None,
                    additional_context: Some(
                        "asiapay: amount does not fit the Number(12,2) major-unit wire format"
                            .to_string(),
                    ),
                },
            })?;

        // payType=N sale (auto-capture) / H authorize-only hold
        // (spec:## Authorize params payType).
        let pay_type = match router_data.request.capture_method {
            Some(CaptureMethod::Manual) | Some(CaptureMethod::ManualMultiple) => "H",
            _ => "N",
        };

        let order_ref = router_data
            .request
            .merchant_order_id
            .clone()
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| {
                router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone()
            });

        // secureHash (spec:## Authentication — Secure Hash): SHA-1 hex over
        // merchantId|orderRef|currCode|amount|payType|secret. Sandbox: omitted
        // (no secret provisioned, plan UD-02).
        let secure_hash = auth.secure_hash_secret.as_ref().map(|secret| {
            let verify_string = format!(
                "{}|{}|{}|{}|{}|{}",
                auth.merchant_id.peek(),
                order_ref,
                curr_code,
                amount.get_amount_as_string(),
                pay_type,
                secret.peek()
            );
            Secret::new(sha1_hex(&verify_string))
        });

        Ok(Self {
            merchant_id: auth.merchant_id,
            order_ref,
            amount,
            curr_code,
            lang: "E".to_string(),
            p_method,
            card_no: card_data.card_number.clone(),
            security_code: card_data.card_cvc.clone(),
            card_holder,
            ep_month: card_data.card_exp_month.clone(),
            ep_year: card_data.card_exp_year.clone(),
            pay_type: pay_type.to_string(),
            success_url: return_url.clone(),
            fail_url: return_url.clone(),
            error_url: return_url,
            secure_hash,
        })
    }
}

// ---------------------------------------------------------------------------
// Authorize response — synthesized by `preprocess_response_bytes` in
// asiapay.rs from the gateway's HTML page (or an empty 3xx body):
// `{ "error_message": ... }` for the parameter-error page,
// `{ "html_body": ... }` for the hosted page body, `{}` otherwise.
// ---------------------------------------------------------------------------

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AsiapayAuthorizeResponse {
    pub error_message: Option<String>,
    pub html_body: Option<String>,
}

impl Debug for AsiapayAuthorizeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsiapayAuthorizeResponse")
            .field("error_message", &self.error_message)
            .field(
                "html_body",
                &self.html_body.as_ref().map(|_| "[REDACTED_HTML]"),
            )
            .finish()
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<crate::types::ResponseRouterData<AsiapayAuthorizeResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: crate::types::ResponseRouterData<AsiapayAuthorizeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Echo of the request side's orderRef derivation — the authorize
        // response carries no gateway reference of its own (the definitive
        // PayRef only arrives via the Data Feed / PSync Query).
        let order_ref = router_data
            .request
            .merchant_order_id
            .clone()
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| {
                router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone()
            });

        // Parameter/system error page (the gateway's errorUrl hop rendered
        // server side) — a 2xx body carrying a failure (INV-11).
        if let Some(error_message) = &response.error_message {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: NO_ERROR_CODE.to_string(),
                    message: error_message.clone(),
                    reason: Some(error_message.clone()),
                    attempt_status: Some(FlowStatus::Payment(AttemptStatus::Failure)),
                    connector_transaction_id: Some(order_ref),
                    ..Default::default()
                }),
                ..router_data.clone()
            });
        }

        // Accepted into the hosted channel: surface the hosted page as
        // redirection data (RedirectForm::Html) in a Pending state — the
        // shopper finishes the payment on AsiaPay's own page; the gateway
        // result then lands via the Data Feed / Query (spec:## Authorize
        // Response, plan UD-01).
        let redirection_data = response
            .html_body
            .clone()
            .map(|html_data| Box::new(RedirectForm::Html { html_data }));

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status: AttemptStatus::Pending,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(order_ref.clone()),
                redirection_data,
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: Some(order_ref),
                incremental_authorization_allowed: None,
                splits: None,
                status_code: item.http_code,
                payment_account_reference: None,
            }),
            ..router_data.clone()
        })
    }
}

// ---------------------------------------------------------------------------
// PSync — Merchant API "Query Payment Status", `actionType=Query`
// (spec:## Payment Status (PSync — Merchant API)). Form-encoded POST to
// `orderApi.jsp`; the answer is an XML `<records><record>…</record></records>`
// document, converted to JSON by `preprocess_response_bytes` in `asiapay.rs`
// before the macro bridge's serde_json parse (plan §4 PSync response_structs).
// Query-by-`payRef` is preferred; `orderRef` is the documented fallback when
// payRef is absent — both are conditional (spec:## PSync params).
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct AsiapayPSyncRequest {
    #[serde(rename = "merchantId")]
    pub merchant_id: Secret<String>,
    #[serde(rename = "loginId")]
    pub login_id: Secret<String>,
    pub password: Secret<String>,
    #[serde(rename = "actionType")]
    pub action_type: &'static str,
    #[serde(rename = "payRef", skip_serializing_if = "Option::is_none")]
    pub pay_ref: Option<String>,
    #[serde(rename = "orderRef", skip_serializing_if = "Option::is_none")]
    pub order_ref: Option<String>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        AsiapayRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for AsiapayPSyncRequest
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        item: AsiapayRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = AsiapayAuthType::try_from(&router_data.connector_config)?;

        // What the caller stored as the connector transaction id is the
        // gateway's payRef for the Query (plan §8 PSync consumes).
        let raw_txn_id = match &router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) | ResponseId::EncodedData(id) => {
                Some(id.trim().to_string()).filter(|id| !id.is_empty())
            }
            ResponseId::NoResponseId => None,
        };
        let reference_id = &router_data
            .resource_common_data
            .connector_request_reference_id;
        let (pay_ref, order_ref) = match raw_txn_id {
            Some(id) if id.chars().all(|c| c.is_ascii_digit()) => (Some(id), None),
            Some(id) => (None, Some(id)),
            None if !reference_id.trim().is_empty() => {
                (None, Some(reference_id.trim().to_string()))
            }
            None => (None, None),
        };

        // G-PSync-01 — Query requires payRef, or orderRef when payRef is
        // absent; fail closed before any request is built.
        if pay_ref.is_none() && order_ref.is_none() {
            return Err(IntegrationError::MissingRequiredField {
                field_name: "connector_transaction_id",
                context: IntegrationErrorContext {
                    suggested_action: Some(
                        "Pass connector_transaction_id (the PayRef from the Data Feed / Authorize), \
                         or provide the original orderRef"
                            .to_string(),
                    ),
                    doc_url: None,
                    additional_context: Some(
                        "spec:## PSync params — payRef required if orderRef not provided and vice \
                         versa (Query keys the transaction on one of the two)"
                            .to_string(),
                    ),
                },
            }
            .into());
        }

        Ok(Self {
            merchant_id: auth.merchant_id,
            login_id: auth.username,
            password: auth.password,
            action_type: "Query",
            pay_ref,
            order_ref,
        })
    }
}

/// PSync response — one Query `<record>`. Dual input: the XML `<record>` is
/// deserialized directly by `quick_xml` in `preprocess_response_bytes`; the
/// macro bridge then re-parses the JSON re-serialisation of this struct, so
/// the field set is a superset of both the XML record fields and the
/// URL-encoded failure shape (`resultCode=-1&errMsg=…`, spec:## HTTP Codes
/// and Errors) that `preprocess_response_bytes` emits for merchant-API
/// auth/parameter failures.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AsiapayQueryResponse {
    #[serde(rename = "orderStatus")]
    pub order_status: Option<AsiapayPaymentStatus>,
    #[serde(rename = "ref")]
    pub order_ref: Option<String>,
    #[serde(rename = "payRef")]
    pub pay_ref: Option<String>,
    pub amt: Option<String>,
    pub cur: Option<String>,
    #[serde(rename = "successcode")]
    pub success_code: Option<String>,
    pub prc: Option<String>,
    pub src: Option<String>,
    #[serde(rename = "errMsg")]
    pub err_msg: Option<String>,
    #[serde(rename = "resultCode")]
    pub result_code: Option<String>,
}

/// `<records>` wrapper — a Query answer carries one record per matched
/// transaction; the documented in-band failure (resultCode=-1) arrives
/// URL-encoded instead (spec:## PSync response).
#[derive(Debug, Deserialize)]
struct AsiapayQueryRecords {
    #[serde(default)]
    record: Vec<AsiapayQueryResponse>,
}

/// Convert a Query XML body to the JSON bytes of its first `<record>` for
/// the macro bridge's serde_json parse. Called by
/// `preprocess_response_bytes` in `asiapay.rs`.
pub(super) fn query_xml_to_json(xml_body: &str) -> CustomResult<Bytes, IntegrationError> {
    let records: AsiapayQueryRecords =
        quick_xml::de::from_str(xml_body).change_context(IntegrationError::InvalidDataFormat {
            field_name: "response_body",
            context: IntegrationErrorContext {
                suggested_action: None,
                doc_url: None,
                additional_context: Some(
                    "asiapay: Query response is not the documented <records><record>… XML \
                     (spec:## Payment Status (PSync — Merchant API))"
                        .to_string(),
                ),
            },
        })?;
    let json_bytes = serde_json::to_vec(&records.record.into_iter().next().unwrap_or_default())
        .change_context(IntegrationError::InvalidDataFormat {
            field_name: "response_body",
            context: IntegrationErrorContext {
                suggested_action: None,
                doc_url: None,
                additional_context: Some(
                    "asiapay: Query record failed JSON re-serialisation in response \
                         preprocessing"
                        .to_string(),
                ),
            },
        })?;
    Ok(Bytes::from(json_bytes))
}

impl TryFrom<crate::types::ResponseRouterData<AsiapayQueryResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: crate::types::ResponseRouterData<AsiapayQueryResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Round-trippable identifier: keep what the caller passed — the XML
        // echo strips leading zeros from payRef
        // (run:test/evidence/baseline/probe_PSync.txt). Fall back to the XML
        // echo's payRef, then the echoed ref.
        let request_transaction_id = match &router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) | ResponseId::EncodedData(id) => {
                Some(id.clone()).filter(|id| !id.trim().is_empty())
            }
            ResponseId::NoResponseId => None,
        };
        let transaction_id = request_transaction_id
            .or_else(|| response.pay_ref.clone().filter(|p| !p.trim().is_empty()))
            .or_else(|| response.order_ref.clone().filter(|r| !r.trim().is_empty()));
        let connector_response_reference_id = response
            .order_ref
            .clone()
            .filter(|r| !r.trim().is_empty())
            .or_else(|| response.pay_ref.clone().filter(|p| !p.trim().is_empty()))
            .or(transaction_id.clone());
        // Identifier carrier chain — re-publish metadata the router threaded
        // into the sync call (psync pattern).
        let connector_metadata = router_data
            .request
            .connector_feature_data
            .clone()
            .map(|meta| meta.expose());

        let error_code = response
            .prc
            .clone()
            .filter(|c| !c.trim().is_empty())
            .or_else(|| {
                response
                    .result_code
                    .clone()
                    .filter(|c| !c.trim().is_empty())
            })
            .unwrap_or_else(|| NO_ERROR_CODE.to_string());
        let error_message = response
            .err_msg
            .clone()
            .filter(|m| !m.trim().is_empty())
            .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string());
        let error_router_data = |attempt_status: AttemptStatus| Self {
            resource_common_data: PaymentFlowData {
                status: attempt_status,
                ..router_data.resource_common_data.clone()
            },
            response: Err(ErrorResponse {
                status_code: item.http_code,
                code: error_code.clone(),
                message: error_message.clone(),
                reason: response.err_msg.clone(),
                attempt_status: Some(FlowStatus::Payment(attempt_status)),
                connector_transaction_id: transaction_id.clone(),
                ..Default::default()
            }),
            ..router_data.clone()
        };

        let Some(order_status) = response.order_status else {
            // Query-level failure with no parseable <orderStatus> (auth /
            // parameter failure, errMsg only; spec:## PSync error table) —
            // say nothing about the attempt: Pending, not Failure (INV-08).
            return Ok(error_router_data(AttemptStatus::Pending));
        };

        let status = AttemptStatus::from(order_status);
        if domain_types::utils::is_payment_failure(status) {
            // A 2xx XML body carrying a declined status (e.g. Rejected) is
            // still a failure (INV-11).
            return Ok(error_router_data(status));
        }

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: transaction_id
                    .map(ResponseId::ConnectorTransactionId)
                    .unwrap_or_default(),
                redirection_data: None,
                connector_metadata,
                mandate_reference: None,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id,
                incremental_authorization_allowed: None,
                splits: None,
                status_code: item.http_code,
                payment_account_reference: None,
            }),
            ..router_data.clone()
        })
    }
}

// ---------------------------------------------------------------------------
// Refund — Merchant API "Request Refund for Accepted Payment",
// `actionType=RequestRefund` (spec:## Refund (Merchant API), plan §4 Refund).
// Form-encoded POST to `orderApi.jsp`. Wire amounts are decimal major units
// (`StringMajorUnit`); amount is omitted for full refund (spec:## Refund params).
// An unsettled sale refund resolves as synchronous void per capabilities.
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct AsiapayRefundRequest {
    #[serde(rename = "merchantId")]
    pub merchant_id: Secret<String>,
    #[serde(rename = "loginId")]
    pub login_id: Secret<String>,
    pub password: Secret<String>,
    #[serde(rename = "actionType")]
    pub action_type: &'static str,
    #[serde(rename = "payRef", skip_serializing_if = "Option::is_none")]
    pub pay_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<StringMajorUnit>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        AsiapayRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for AsiapayRefundRequest
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        item: AsiapayRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = AsiapayAuthType::try_from(&router_data.connector_config)?;

        // G-Refund-01: RequestRefund accepts ONLY the numeric PayRef the gateway
        // returned at payment time (spec:## Refund params — payRef, no orderRef
        // field exists on the refund endpoint). Anything else would be rejected
        // by the gateway (resultCode=-1) after a doomed wire call, so validate
        // locally and fail without making the call.
        let raw_txn_id = router_data.request.connector_transaction_id.trim();
        let pay_ref = if !raw_txn_id.is_empty() && raw_txn_id.chars().all(|c| c.is_ascii_digit()) {
            Some(raw_txn_id.to_string())
        } else {
            None
        };

        if pay_ref.is_none() {
            return Err(IntegrationError::MissingRequiredField {
                field_name: "connector_transaction_id",
                context: IntegrationErrorContext {
                    suggested_action: Some(
                        "Pass the numeric PayRef (connector_transaction_id returned by Authorize/PSync) to refund; order references are not accepted by RequestRefund"
                            .to_string(),
                    ),
                    doc_url: None,
                    additional_context: Some(
                        "spec:## Refund params — payRef is required for RequestRefund; orderRef is not a documented refund param".to_string(),
                    ),
                },
            }
            .into());
        }

        // Amount: omit for full refund (spec:## Refund params, plan §4 amount)
        let amount = if router_data.request.refund_amount.amount
            == router_data.request.payment_amount.amount
        {
            None
        } else {
            Some(AsiapayAmountConvertor::convert(
                router_data.request.refund_amount.amount,
                router_data.request.currency,
            )?)
        };

        Ok(Self {
            merchant_id: auth.merchant_id,
            login_id: auth.username,
            password: auth.password,
            action_type: "RequestRefund",
            pay_ref,
            amount,
        })
    }
}

/// Refund response — Merchant API `RequestRefund` response (URL-encoded body,
/// converted to JSON by `preprocess_response_bytes` in `asiapay.rs`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AsiapayRefundResponse {
    #[serde(rename = "resultCode")]
    pub result_code: Option<String>,
    #[serde(rename = "orderStatus")]
    pub order_status: Option<AsiapayPaymentStatus>,
    #[serde(rename = "payRef")]
    pub pay_ref: Option<String>,
    #[serde(rename = "ref")]
    pub order_ref: Option<String>,
    pub amt: Option<String>,
    pub cur: Option<String>,
    #[serde(rename = "errMsg")]
    pub err_msg: Option<String>,
}

impl TryFrom<crate::types::ResponseRouterData<AsiapayRefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: crate::types::ResponseRouterData<AsiapayRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Echoed payRef is the refund identifier (no distinct refund id exists).
        // Fall back to echoed ref (orderRef), then connector_transaction_id.
        let connector_refund_id = response
            .pay_ref
            .clone()
            .filter(|p| !p.trim().is_empty())
            .or_else(|| response.order_ref.clone().filter(|r| !r.trim().is_empty()))
            .unwrap_or_else(|| router_data.request.connector_transaction_id.clone());

        let error_code = response
            .result_code
            .clone()
            .filter(|c| !c.trim().is_empty())
            .unwrap_or_else(|| NO_ERROR_CODE.to_string());
        let error_message = response
            .err_msg
            .clone()
            .filter(|m| !m.trim().is_empty())
            .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string());

        // 2xx failure predicate: resultCode != "0" (spec:## HTTP Codes and Errors, plan §4 error)
        let is_failed = response
            .result_code
            .as_deref()
            .map(|c| c != "0")
            .unwrap_or(false);

        if is_failed {
            return Ok(Self {
                resource_common_data: RefundFlowData {
                    status: RefundStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: error_code,
                    message: error_message,
                    reason: response.err_msg.clone(),
                    attempt_status: Some(FlowStatus::Refund(RefundStatus::Failure)),
                    connector_transaction_id: Some(connector_refund_id),
                    ..Default::default()
                }),
                ..router_data.clone()
            });
        }

        let refund_status = response
            .order_status
            .map(RefundStatus::from)
            .unwrap_or(RefundStatus::Pending);

        if refund_status == RefundStatus::Failure {
            return Ok(Self {
                resource_common_data: RefundFlowData {
                    status: refund_status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: error_code,
                    message: error_message,
                    reason: response.err_msg.clone(),
                    attempt_status: Some(FlowStatus::Refund(refund_status)),
                    connector_transaction_id: Some(connector_refund_id),
                    ..Default::default()
                }),
                ..router_data.clone()
            });
        }

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: item.http_code,
                acquirer_reference_number: None,
            }),
            ..router_data.clone()
        })
    }
}

// ---------------------------------------------------------------------------
// RSync — Merchant API Query for refund status (spec:## Refund Status (RSync),
// plan §4 RSync).
// AsiaPay documents no dedicated refund-status endpoint; refund lifecycle is
// read by querying the original payment's payRef (actionType=Query).
// ---------------------------------------------------------------------------

pub type AsiapayRSyncResponse = AsiapayQueryResponse;

#[derive(Debug, Serialize)]
pub struct AsiapayRSyncRequest {
    #[serde(rename = "merchantId")]
    pub merchant_id: Secret<String>,
    #[serde(rename = "loginId")]
    pub login_id: Secret<String>,
    pub password: Secret<String>,
    #[serde(rename = "actionType")]
    pub action_type: &'static str,
    #[serde(rename = "payRef", skip_serializing_if = "Option::is_none")]
    pub pay_ref: Option<String>,
    #[serde(rename = "orderRef", skip_serializing_if = "Option::is_none")]
    pub order_ref: Option<String>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        AsiapayRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for AsiapayRSyncRequest
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        item: AsiapayRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = AsiapayAuthType::try_from(&router_data.connector_config)?;

        let refund_id = router_data.request.connector_refund_id.trim();
        let txn_id = router_data.request.connector_transaction_id.trim();
        let reference_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .trim();
        let order_id = router_data
            .request
            .connector_order_id
            .as_deref()
            .unwrap_or("")
            .trim();

        let (pay_ref, order_ref) =
            if !refund_id.is_empty() && refund_id.chars().all(|c| c.is_ascii_digit()) {
                (Some(refund_id.to_string()), None)
            } else if !txn_id.is_empty() && txn_id.chars().all(|c| c.is_ascii_digit()) {
                (Some(txn_id.to_string()), None)
            } else if !txn_id.is_empty() {
                (None, Some(txn_id.to_string()))
            } else if !order_id.is_empty() {
                (None, Some(order_id.to_string()))
            } else if !reference_id.is_empty() {
                (None, Some(reference_id.to_string()))
            } else if !refund_id.is_empty() {
                (None, Some(refund_id.to_string()))
            } else {
                (None, None)
            };

        // G-RSync-01 — Query key required; payRef or orderRef required
        if pay_ref.is_none() && order_ref.is_none() {
            return Err(IntegrationError::MissingRequiredField {
                field_name: "connector_refund_id",
                context: IntegrationErrorContext {
                    suggested_action: Some(
                        "Pass connector_refund_id / connector_transaction_id (the PayRef or orderRef)"
                            .to_string(),
                    ),
                    doc_url: None,
                    additional_context: Some(
                        "spec:## Refund Status (RSync) — AsiaPay has no dedicated refund-enquiry \
                         endpoint; refund status is derived via Query on payRef or orderRef"
                            .to_string(),
                    ),
                },
            }
            .into());
        }

        Ok(Self {
            merchant_id: auth.merchant_id,
            login_id: auth.username,
            password: auth.password,
            action_type: "Query",
            pay_ref,
            order_ref,
        })
    }
}

impl TryFrom<crate::types::ResponseRouterData<AsiapayRSyncResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: crate::types::ResponseRouterData<AsiapayQueryResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        let connector_refund_id = if !router_data.request.connector_refund_id.trim().is_empty()
            && router_data
                .request
                .connector_refund_id
                .trim()
                .chars()
                .all(|c| c.is_ascii_digit())
        {
            router_data.request.connector_refund_id.clone()
        } else if let Some(pay_ref) = response.pay_ref.as_ref().filter(|p| !p.trim().is_empty()) {
            pay_ref.trim().to_string()
        } else if !router_data.request.connector_refund_id.trim().is_empty() {
            router_data.request.connector_refund_id.clone()
        } else if !router_data
            .request
            .connector_transaction_id
            .trim()
            .is_empty()
        {
            router_data.request.connector_transaction_id.clone()
        } else {
            response
                .order_ref
                .clone()
                .filter(|r| !r.trim().is_empty())
                .unwrap_or_default()
        };

        let error_code = response
            .prc
            .clone()
            .filter(|c| !c.trim().is_empty())
            .or_else(|| {
                response
                    .result_code
                    .clone()
                    .filter(|c| !c.trim().is_empty())
            })
            .unwrap_or_else(|| NO_ERROR_CODE.to_string());
        let error_message = response
            .err_msg
            .clone()
            .filter(|m| !m.trim().is_empty())
            .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string());

        let Some(order_status) = response.order_status else {
            // Query failure with no orderStatus returned (e.g. invalid query or auth failure)
            // Keep refund in Pending to avoid terminally failing an in-flight refund.
            return Ok(Self {
                resource_common_data: RefundFlowData {
                    status: RefundStatus::Pending,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: error_code,
                    message: error_message,
                    reason: response.err_msg.clone(),
                    attempt_status: Some(FlowStatus::Refund(RefundStatus::Pending)),
                    connector_transaction_id: Some(connector_refund_id),
                    ..Default::default()
                }),
                ..router_data.clone()
            });
        };

        let refund_status = RefundStatus::from(order_status);

        if refund_status == RefundStatus::Failure {
            return Ok(Self {
                resource_common_data: RefundFlowData {
                    status: refund_status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: error_code,
                    message: error_message,
                    reason: response.err_msg.clone(),
                    attempt_status: Some(FlowStatus::Refund(refund_status)),
                    connector_transaction_id: Some(connector_refund_id),
                    ..Default::default()
                }),
                ..router_data.clone()
            });
        }

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: item.http_code,
                acquirer_reference_number: None,
            }),
            ..router_data.clone()
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// currCode code list (spec:## Authorize params currCode) — the ISO-4217
/// numeric codes AsiaPay documents. Anything else is a client error
/// (G-Authorize-02): it would be rejected by the host anyway.
fn currency_to_curr_code(currency: Currency) -> Result<String, IntegrationError> {
    let code =
        match currency {
            Currency::HKD => "344",
            Currency::USD => "840",
            Currency::SGD => "702",
            Currency::CNY => "156",
            Currency::JPY => "392",
            Currency::TWD => "901",
            Currency::AUD => "036",
            Currency::EUR => "978",
            Currency::GBP => "826",
            Currency::CAD => "124",
            Currency::MOP => "446",
            Currency::PHP => "608",
            Currency::THB => "764",
            Currency::MYR => "458",
            Currency::IDR => "360",
            Currency::KRW => "410",
            Currency::SAR => "682",
            Currency::NZD => "554",
            Currency::AED => "784",
            Currency::BND => "096",
            Currency::VND => "704",
            Currency::INR => "356",
            other => return Err(IntegrationError::CurrencyNotSupported {
                message: format!("unsupported currency: {other}"),
                connector: "asiapay",
                context: IntegrationErrorContext {
                    suggested_action: Some(
                        "Use one of the currencies AsiaPay's currCode list documents \
                         (344 HKD, 840 USD, 702 SGD, …)"
                            .to_string(),
                    ),
                    doc_url: None,
                    additional_context: Some(
                        "spec:## Authorize params currCode code list; this sandbox MID settles \
                         SGD (702) only"
                            .to_string(),
                    ),
                },
            }),
        };
    Ok(code.to_string())
}

/// pMethod carries the card scheme (spec:## Authorize params pMethod). `None`
/// when the network is unknown: pMethod is omitted from the form post and the
/// hosted PayDollar page shows its own scheme chooser (BASELINE:/test: S-1
/// posted without pMethod and got the 200 method-selection page). An explicit
/// but unmappable network is still an error.
fn card_brand_to_p_method(
    card_network: Option<&common_enums::CardNetwork>,
) -> Result<Option<String>, IntegrationError> {
    match card_network {
        None => Ok(None),
        Some(common_enums::CardNetwork::Visa) => Ok(Some("VISA".to_string())),
        Some(common_enums::CardNetwork::Mastercard) => Ok(Some("Master".to_string())),
        Some(common_enums::CardNetwork::DinersClub) => Ok(Some("Diners".to_string())),
        Some(common_enums::CardNetwork::JCB) => Ok(Some("JCB".to_string())),
        Some(common_enums::CardNetwork::AmericanExpress) => Ok(Some("AMEX".to_string())),
        Some(other) => Err(IntegrationError::InvalidDataFormat {
            field_name: "card_network",
            context: IntegrationErrorContext {
                suggested_action: Some(
                    "Use a card of one of the documented schemes (VISA, Master, Diners, JCB, \
                     AMEX), or omit card_network and let the hosted page offer the scheme"
                        .to_string(),
                ),
                doc_url: None,
                additional_context: Some(format!(
                    "asiapay: pMethod is restricted to VISA|Master|Diners|JCB|AMEX; got {other:?}"
                )),
            },
        }),
    }
}

/// Human label of the non-card payment-method arm, for the refusal error.
fn payment_method_name<T: PaymentMethodDataTypes>(
    payment_method_data: &PaymentMethodData<T>,
) -> &'static str {
    match payment_method_data {
        PaymentMethodData::Card(_) => "card",
        PaymentMethodData::CardWithNoCvc(_) => "card_with_no_cvc",
        PaymentMethodData::CardDetailsForNetworkTransactionId(_) => "card_details_for_nti",
        PaymentMethodData::DecryptedWalletTokenDetailsForNetworkTransactionId(_) => {
            "decrypted_wallet_token"
        }
        PaymentMethodData::CardRedirect(_) => "card_redirect",
        PaymentMethodData::Wallet(_) => "wallet",
        PaymentMethodData::PayLater(_) => "pay_later",
        PaymentMethodData::BankRedirect(_) => "bank_redirect",
        PaymentMethodData::BankDebit(_) => "bank_debit",
        PaymentMethodData::BankTransfer(_) => "bank_transfer",
        PaymentMethodData::Crypto(_) => "crypto",
        PaymentMethodData::MandatePayment => "mandate_payment",
        PaymentMethodData::Reward => "reward",
        PaymentMethodData::RealTimePayment(_) => "real_time_payment",
        PaymentMethodData::Upi(_) => "upi",
        PaymentMethodData::Voucher(_) => "voucher",
        PaymentMethodData::GiftCard(_) => "gift_card",
        PaymentMethodData::PaymentMethodToken(_) => "payment_method_token",
        PaymentMethodData::OpenBanking(_) => "open_banking",
        PaymentMethodData::NetworkToken(_) => "network_token",
        PaymentMethodData::MobilePayment(_) => "mobile_payment",
    }
}

/// Lowercase hex SHA-1 of the UTF-8 bytes of `input`.
///
/// SHA-1 is dictated by the AsiaPay wire protocol (spec:## Authentication —
/// Secure Hash); it is not used here as a security primitive of our own
/// choosing.
pub(super) fn sha1_hex(input: &str) -> String {
    hex::encode(ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        input.as_bytes(),
    ))
}
