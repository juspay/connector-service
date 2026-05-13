use std::fmt::Debug;

use common_enums::{AttemptStatus, CaptureMethod, RefundStatus};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors::IntegrationError,
    payment_method_data::{Card, PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::Report;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use super::{
    requests::{
        TsysXmlAuthorizeBody, TsysXmlAuthorizeRequest, TsysXmlCaptureRequest,
        TsysXmlCardDataSource, TsysXmlReturnRequest, TsysXmlTransactionInquiryRequest,
        TsysXmlVoidRequest,
    },
    responses::{
        TsysXmlAuthorizeResponse, TsysXmlCaptureResponse, TsysXmlReturnResponse, TsysXmlStatus,
        TsysXmlTransactionInquiryResponse, TsysXmlTransactionState, TsysXmlVoidResponse,
    },
    TsysXmlRouterData,
};
use crate::types::ResponseRouterData;
use domain_types::errors::ConnectorError;

/// Auth bundle for TsysXml (TransIT) — flattened into the XML request body.
///
/// TransIT does not use HTTP auth headers; instead each request carries the
/// `deviceID`, `transactionKey`, and `developerID` inline in the XML payload.
#[derive(Debug, Clone)]
pub struct TsysXmlAuthType {
    pub device_id: Secret<String>,
    pub transaction_key: Secret<String>,
    pub developer_id: Secret<String>,
}

impl TryFrom<&ConnectorSpecificConfig> for TsysXmlAuthType {
    type Error = Report<IntegrationError>;

    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::TsysXml {
                device_id,
                transaction_key,
                developer_id,
                ..
            } => Ok(Self {
                device_id: device_id.to_owned(),
                transaction_key: transaction_key.to_owned(),
                developer_id: developer_id.to_owned(),
            }),
            _ => Err(IntegrationError::FailedToObtainAuthType {
                context: Default::default(),
            }
            .into()),
        }
    }
}

/// Minimal error envelope for TsysXml.
///
/// TransIT signals failure with `<status>FAIL</status>` and supplies a
/// `<responseCode>` / `<responseMessage>` pair. The exact element layout will be
/// hardened further per-flow; this scaffold provides only what
/// `build_error_response` needs.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TsysXmlErrorResponse {
    #[serde(rename = "status", default, alias = "Status")]
    pub status: Option<String>,
    #[serde(rename = "responseCode", default, alias = "ResponseCode")]
    pub response_code: Option<String>,
    #[serde(rename = "responseMessage", default, alias = "ResponseMessage")]
    pub response_message: Option<String>,
}

// =============================================================================
// AUTHORIZE — request transformer
// =============================================================================

fn format_expiration_date(card: &Card<impl PaymentMethodDataTypes>) -> Secret<String> {
    // TransIT documents `MM/YY` (tech spec § Sale/Auth Field Reference). Normalize
    // 4-digit years down to 2 digits.
    let month = card.card_exp_month.peek().clone();
    let year_full = card.card_exp_year.peek().clone();
    let year_short = if year_full.len() == 4 {
        year_full[2..].to_string()
    } else {
        year_full
    };
    Secret::new(format!("{}/{}", month, year_short))
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TsysXmlRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for TsysXmlAuthorizeRequest<T>
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: TsysXmlRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = TsysXmlAuthType::try_from(&router_data.connector_config)?;

        let card = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => {
                return Err(IntegrationError::NotSupported {
                    message: "Selected payment method".to_string(),
                    connector: "tsys_xml",
                    context: Default::default(),
                }
                .into());
            }
        };

        let transaction_amount = super::TsysXmlAmountConvertor::convert(
            router_data.request.minor_amount,
            router_data.request.currency,
        )?;

        // Billing address fields used by AVS (addressLine1 + zip).
        let billing = router_data
            .resource_common_data
            .address
            .get_payment_billing()
            .and_then(|b| b.address.as_ref());
        let address_line1 = billing.and_then(|a| a.line1.clone());
        let zip = billing.and_then(|a| a.zip.clone());

        // TODO(tsys_xml): derive cardDataSource from upstream channel hints
        // (browser_info presence vs PHONE/MOTO). Default to INTERNET — matches
        // cert script Sheet 3 (eCommerce) which is the most common UCS scenario.
        let card_data_source = TsysXmlCardDataSource::Internet;

        let body = TsysXmlAuthorizeBody {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            developer_id: auth.developer_id,
            card_data_source,
            transaction_amount,
            card_number: Secret::new(card.card_number.peek().to_string()),
            expiration_date: format_expiration_date(card),
            cvv2: Some(card.card_cvc.clone()),
            address_line1,
            zip,
            external_reference_id: Some(
                router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
            _marker: std::marker::PhantomData,
        };

        let is_manual_capture = matches!(
            router_data.request.capture_method,
            Some(CaptureMethod::Manual) | Some(CaptureMethod::ManualMultiple)
        );

        Ok(if is_manual_capture {
            Self::Auth(body)
        } else {
            Self::Sale(body)
        })
    }
}

// =============================================================================
// AUTHORIZE — response transformer
// =============================================================================

/// Successful response codes per tech spec § Status Mappings.
///
/// `A0000` = full approval, `A0002` = partial approval. Anything else combined
/// with `status=PASS` is treated as an unexpected success surface (fail closed)
/// to surface upstream.
fn map_authorize_status(
    response: &TsysXmlAuthorizeResponse,
) -> AttemptStatus {
    let body = response.body();
    match (
        body.status.as_ref(),
        body.response_code.as_deref(),
        response,
    ) {
        (Some(TsysXmlStatus::Pass), Some("A0000"), TsysXmlAuthorizeResponse::SaleResponse(_)) => {
            AttemptStatus::Charged
        }
        (Some(TsysXmlStatus::Pass), Some("A0000"), TsysXmlAuthorizeResponse::AuthResponse(_)) => {
            AttemptStatus::Authorized
        }
        (Some(TsysXmlStatus::Pass), Some("A0002"), _) => AttemptStatus::PartialCharged,
        (Some(TsysXmlStatus::Fail), _, _) => AttemptStatus::Failure,
        // Unknown / missing — fail closed.
        _ => AttemptStatus::Failure,
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<TsysXmlAuthorizeResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TsysXmlAuthorizeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let response = &item.response;
        let body = response.body();

        let status = map_authorize_status(response);

        // Failure surface: surface code/message but keep transactionID if TransIT
        // gave us one (tech spec § Error Codes — decline envelopes still carry
        // <transactionID>).
        if matches!(status, AttemptStatus::Failure) {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: body
                        .response_code
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_CODE.to_string()),
                    message: body
                        .response_message
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    reason: body.response_message.clone(),
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: body.transaction_id.clone(),
                    network_decline_code: body.host_response_code.clone(),
                    network_advice_code: None,
                    network_error_message: body.response_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success path requires a transactionID — without one we cannot drive
        // subsequent Capture/Void/Refund flows, so reject as a deserialization
        // problem.
        let transaction_id = body.transaction_id.clone().ok_or_else(|| {
            crate::utils::response_deserialization_fail(
                item.http_code,
                "tsys_xml: success response missing <transactionID>; confirm API contract.",
            )
        })?;

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(transaction_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: body.auth_code.clone(),
            connector_response_reference_id: Some(transaction_id),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// PSYNC — request transformer
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TsysXmlRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for TsysXmlTransactionInquiryRequest
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: TsysXmlRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = TsysXmlAuthType::try_from(&router_data.connector_config)?;

        let transaction_id = router_data.request.get_connector_transaction_id()?;

        Ok(Self {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            developer_id: auth.developer_id,
            transaction_id,
        })
    }
}

// =============================================================================
// PSYNC — response transformer
// =============================================================================

/// Map TransIT PSync (`<status>` + `<transactionState>`) to `AttemptStatus`
/// per tech spec § Status Mappings.
fn map_sync_status(response: &TsysXmlTransactionInquiryResponse) -> AttemptStatus {
    match (response.status.as_ref(), response.transaction_state.as_ref()) {
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Authorized)) => {
            AttemptStatus::Authorized
        }
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Captured)) => {
            AttemptStatus::Charged
        }
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Settled)) => {
            AttemptStatus::Charged
        }
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Voided)) => {
            AttemptStatus::Voided
        }
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Returned)) => {
            AttemptStatus::AutoRefunded
        }
        (Some(TsysXmlStatus::Fail), _) => AttemptStatus::Failure,
        // Unknown / missing transactionState — keep Pending and log a warning
        // rather than panicking. UCS callers will retry the sync.
        _ => {
            tracing::warn!(
                "tsys_xml: PSync response missing or unrecognized transactionState; defaulting to Pending"
            );
            AttemptStatus::Pending
        }
    }
}

impl TryFrom<ResponseRouterData<TsysXmlTransactionInquiryResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TsysXmlTransactionInquiryResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let response = &item.response;

        let status = map_sync_status(response);

        if matches!(status, AttemptStatus::Failure) {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: response
                        .response_code
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .response_message
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    reason: response.response_message.clone(),
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: response.response_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // For success / pending: prefer the response's transactionID when
        // present; otherwise fall back to what we asked about so the caller
        // never loses the reference.
        let connector_txn_id = match response.transaction_id.clone() {
            Some(id) => id,
            None => router_data.request.get_connector_transaction_id().map_err(
                |_| {
                    crate::utils::response_deserialization_fail(
                        item.http_code,
                        "tsys_xml: PSync response and request both missing transactionID.",
                    )
                },
            )?,
        };

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_txn_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(connector_txn_id),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// CAPTURE — request transformer
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TsysXmlRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for TsysXmlCaptureRequest
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: TsysXmlRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = TsysXmlAuthType::try_from(&router_data.connector_config)?;

        // The auth's <transactionID> drives the capture — it is required.
        let transaction_id = router_data.request.get_connector_transaction_id()?;

        let transaction_amount = super::TsysXmlAmountConvertor::convert(
            router_data.request.minor_amount_to_capture,
            router_data.request.currency,
        )?;

        // TODO(tsys_xml): wire seq_number / payment_count for multi-clearing
        // (split-shipment) via add-connector-flow. PR-1 ships single-capture only.
        Ok(Self {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            developer_id: auth.developer_id,
            transaction_id,
            transaction_amount,
            seq_number: None,
            payment_count: None,
        })
    }
}

// =============================================================================
// CAPTURE — response transformer
// =============================================================================

/// Map TransIT Capture (`<status>` + `<responseCode>`) to `AttemptStatus` per
/// tech spec § Status Mappings.
///
/// - `PASS` + `A0000` → `Charged`
/// - `PASS` + `A0002` → `PartialCharged`
/// - `FAIL` (any code) → `CaptureFailed`
/// - Anything else → `CaptureFailed` (fail closed)
fn map_capture_status(response: &TsysXmlCaptureResponse) -> AttemptStatus {
    match (response.status.as_ref(), response.response_code.as_deref()) {
        (Some(TsysXmlStatus::Pass), Some("A0000")) => AttemptStatus::Charged,
        (Some(TsysXmlStatus::Pass), Some("A0002")) => AttemptStatus::PartialCharged,
        (Some(TsysXmlStatus::Fail), _) => AttemptStatus::CaptureFailed,
        _ => AttemptStatus::CaptureFailed,
    }
}

impl TryFrom<ResponseRouterData<TsysXmlCaptureResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TsysXmlCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let response = &item.response;

        let status = map_capture_status(response);

        if matches!(status, AttemptStatus::CaptureFailed) {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: response
                        .response_code
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .response_message
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    reason: response.response_message.clone(),
                    attempt_status: Some(AttemptStatus::CaptureFailed),
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: response.response_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success path: prefer response's transactionID; fall back to the auth
        // txn id we sent (TransIT's capture echoes the same id).
        let connector_txn_id = match response.transaction_id.clone() {
            Some(id) => id,
            None => router_data.request.get_connector_transaction_id().map_err(
                |_| {
                    crate::utils::response_deserialization_fail(
                        item.http_code,
                        "tsys_xml: Capture response missing <transactionID> and request had none.",
                    )
                },
            )?,
        };

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_txn_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(connector_txn_id),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// REFUND — request transformer
// =============================================================================
//
// TransIT Return supports three modes from the same `<Return>` element shape:
//
//   1. Referenced full    — `transactionID` only (no `transactionAmount`).
//   2. Referenced partial — `transactionID` + `transactionAmount`.
//   3. Unreferenced       — NO `transactionID`; raw card data + `transactionAmount`.
//
// Mode selection happens here based on `RefundsData`:
//   * non-empty `connector_transaction_id` → referenced (we always emit
//     `transactionAmount` in PR-1; "omit for full" is a TODO follow-up so the
//     gateway recognises the partial vs. full distinction without us guessing
//     the original amount).
//   * empty `connector_transaction_id` → unreferenced; raw card data is
//     required. `RefundsData` does not surface `payment_method_data` today, so
//     this path returns `MissingRequiredField` until upstream wires card data
//     through for refunds.
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TsysXmlRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for TsysXmlReturnRequest
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: TsysXmlRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = TsysXmlAuthType::try_from(&router_data.connector_config)?;

        let transaction_amount = super::TsysXmlAmountConvertor::convert(
            router_data.request.minor_refund_amount,
            router_data.request.currency,
        )?;

        let connector_transaction_id = router_data.request.connector_transaction_id.clone();

        if !connector_transaction_id.is_empty() {
            // Referenced mode (full or partial). PR-1 always emits
            // `transactionAmount` so the gateway sees the explicit value; a
            // follow-up TODO will compare `refund_amount` to the original
            // captured amount and omit `transactionAmount` for full refunds.
            Ok(Self {
                device_id: auth.device_id,
                transaction_key: auth.transaction_key,
                developer_id: auth.developer_id,
                transaction_id: Some(connector_transaction_id),
                card_data_source: None,
                card_number: None,
                expiration_date: None,
                cvv2: None,
                transaction_amount: Some(transaction_amount),
            })
        } else {
            // Unreferenced mode: full card data must be supplied. `RefundsData`
            // does not carry `payment_method_data` today, so PR-1 surfaces this
            // as a missing-field error rather than silently producing an
            // invalid request.
            Err(IntegrationError::MissingRequiredField {
                field_name: "payment_method_data for unreferenced refund",
                context: Default::default(),
            }
            .into())
        }
    }
}

// =============================================================================
// REFUND — response transformer
// =============================================================================

/// Map TransIT Return (`<status>` + `<responseCode>`) to `RefundStatus` per
/// tech spec § Status Mappings.
///
/// - `PASS` + `A0000` → `Success`
/// - `FAIL` (any code) → `Failure`
/// - Anything else → `Failure` (fail closed)
fn map_refund_status(response: &TsysXmlReturnResponse) -> RefundStatus {
    match (response.status.as_ref(), response.response_code.as_deref()) {
        (Some(TsysXmlStatus::Pass), Some("A0000")) => RefundStatus::Success,
        (Some(TsysXmlStatus::Fail), _) => RefundStatus::Failure,
        _ => RefundStatus::Failure,
    }
}

impl TryFrom<ResponseRouterData<TsysXmlReturnResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TsysXmlReturnResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let response = &item.response;

        let refund_status = map_refund_status(response);

        if matches!(refund_status, RefundStatus::Failure) {
            return Ok(Self {
                resource_common_data: RefundFlowData {
                    status: refund_status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: response
                        .response_code
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .response_message
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    reason: response.response_message.clone(),
                    attempt_status: None,
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: response.response_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success path: TransIT echoes the original capture's transactionID for
        // referenced returns; we treat that as the refund identifier for PR-1.
        // RSync will refine this once we know the on-wire id semantics.
        let connector_refund_id = response.transaction_id.clone().ok_or_else(|| {
            crate::utils::response_deserialization_fail(
                item.http_code,
                "tsys_xml: Return response missing <transactionID>; confirm API contract.",
            )
        })?;

        let refunds_response_data = RefundsResponseData {
            connector_refund_id,
            refund_status,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(refunds_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// RSYNC — request transformer (REUSES TsysXmlTransactionInquiryRequest)
// =============================================================================
//
// TransIT refunds are sync-final on `<ReturnResponse>`; there is no dedicated
// refund-status-poll endpoint. HS still dispatches RSync though, so we
// re-issue a `<TransactionInquiry>` against the original refund's
// `transactionID` (echoed back by TransIT as `connector_refund_id` in our
// Return response transformer). If upstream lacks a refund id we fall back to
// the original payment transactionID — both are valid keys for TransIT's
// inquiry endpoint.
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TsysXmlRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for TsysXmlTransactionInquiryRequest
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: TsysXmlRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = TsysXmlAuthType::try_from(&router_data.connector_config)?;

        // Prefer `connector_refund_id` (TransIT's echoed `<transactionID>` from
        // the original `<ReturnResponse>`); fall back to the original payment's
        // `connector_transaction_id` if the refund id wasn't recorded.
        let transaction_id = if !router_data.request.connector_refund_id.is_empty() {
            router_data.request.connector_refund_id.clone()
        } else if !router_data.request.connector_transaction_id.is_empty() {
            router_data.request.connector_transaction_id.clone()
        } else {
            return Err(IntegrationError::MissingRequiredField {
                field_name: "connector_refund_id or connector_transaction_id",
                context: Default::default(),
            }
            .into());
        };

        Ok(Self {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            developer_id: auth.developer_id,
            transaction_id,
        })
    }
}

// =============================================================================
// RSYNC — response transformer (REUSES TsysXmlTransactionInquiryResponse)
// =============================================================================

/// Map TransIT TransactionInquiry (`<status>` + `<transactionState>`) to
/// `RefundStatus` per tech spec § Status Mappings.
///
/// - `PASS` + `RETURNED` → `Success` (refund applied, awaiting batch settle)
/// - `PASS` + `SETTLED`  → `Success` (refund batch settled — terminal success)
/// - `PASS` + `VOIDED`   → `Failure` (the return itself was reversed; refund
///   didn't actually go through).
///   TODO(tsys_xml): VOIDED-on-RSync semantics depend on whether TransIT
///   distinguishes "return reversed before settle" vs "original auth voided";
///   confirm with TSYS whether `Failure` is the correct terminal mapping.
/// - `FAIL`              → `Failure`
/// - Unknown / missing   → `Pending` (do NOT fail; let HS poll again).
fn map_rsync_status(response: &TsysXmlTransactionInquiryResponse) -> RefundStatus {
    match (response.status.as_ref(), response.transaction_state.as_ref()) {
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Returned)) => {
            RefundStatus::Success
        }
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Settled)) => {
            RefundStatus::Success
        }
        // TODO(tsys_xml): confirm VOIDED semantics with TSYS — currently treated
        // as terminal Failure because a voided return means the refund didn't
        // settle to the cardholder.
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Voided)) => {
            RefundStatus::Failure
        }
        (Some(TsysXmlStatus::Fail), _) => RefundStatus::Failure,
        // Unknown / missing transactionState (including Authorized/Captured
        // pre-return states) — stay Pending so HS keeps polling.
        _ => {
            tracing::warn!(
                "tsys_xml: RSync response missing or unrecognized transactionState; defaulting to Pending"
            );
            RefundStatus::Pending
        }
    }
}

impl TryFrom<ResponseRouterData<TsysXmlTransactionInquiryResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TsysXmlTransactionInquiryResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let response = &item.response;

        let refund_status = map_rsync_status(response);

        if matches!(refund_status, RefundStatus::Failure) {
            return Ok(Self {
                resource_common_data: RefundFlowData {
                    status: refund_status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: response
                        .response_code
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .response_message
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    reason: response.response_message.clone(),
                    attempt_status: None,
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: response.response_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success / Pending: prefer the response's transactionID; fall back to
        // whichever id we sent so the caller never loses the reference.
        let connector_refund_id = match response.transaction_id.clone() {
            Some(id) => id,
            None => {
                if !router_data.request.connector_refund_id.is_empty() {
                    router_data.request.connector_refund_id.clone()
                } else if !router_data.request.connector_transaction_id.is_empty() {
                    router_data.request.connector_transaction_id.clone()
                } else {
                    return Err(crate::utils::response_deserialization_fail(
                        item.http_code,
                        "tsys_xml: RSync response and request both missing transactionID.",
                    )
                    .into());
                }
            }
        };

        let refunds_response_data = RefundsResponseData {
            connector_refund_id,
            refund_status,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(refunds_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// VOID — request transformer
// =============================================================================
//
// TransIT `<Void>` accepts an optional `<transactionAmount>`:
//   * Omitted   → full void of the prior auth.
//   * Provided  → partial void (cert script Step 7) — the prior auth is reduced
//     by that amount.
//
// `PaymentVoidData` carries an `Option<MinorUnit>` `amount` field. When set
// alongside `currency`, we convert via the StringMajorUnit converter and emit
// it; otherwise we omit `<transactionAmount>` so TransIT treats this as a full
// void.
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TsysXmlRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for TsysXmlVoidRequest
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: TsysXmlRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = TsysXmlAuthType::try_from(&router_data.connector_config)?;

        let transaction_id = router_data.request.connector_transaction_id.clone();

        // Partial-void support: if both `amount` and `currency` are present on
        // PaymentVoidData, convert to a major-unit string and emit
        // `<transactionAmount>`; otherwise omit so TransIT performs a full
        // void.
        let transaction_amount = match (
            router_data.request.amount,
            router_data.request.currency,
        ) {
            (Some(amount), Some(currency)) => {
                Some(super::TsysXmlAmountConvertor::convert(amount, currency)?)
            }
            _ => None,
        };

        Ok(Self {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            developer_id: auth.developer_id,
            transaction_id,
            transaction_amount,
        })
    }
}

// =============================================================================
// VOID — response transformer
// =============================================================================

/// Map TransIT Void (`<status>` + `<responseCode>`) to `AttemptStatus` per
/// tech spec § Status Mappings.
///
/// - `PASS` + `A0000` → `Voided` (full void)
/// - `PASS` + `A0002` → `Voided` (partial void — the auth is reduced; at the
///   auth lifecycle level the state is still "voided" from UCS's perspective)
/// - `FAIL` (any code) → `VoidFailed`
/// - Anything else → `VoidFailed` (fail closed)
fn map_void_status(response: &TsysXmlVoidResponse) -> AttemptStatus {
    match (response.status.as_ref(), response.response_code.as_deref()) {
        (Some(TsysXmlStatus::Pass), Some("A0000")) => AttemptStatus::Voided,
        (Some(TsysXmlStatus::Pass), Some("A0002")) => AttemptStatus::Voided,
        (Some(TsysXmlStatus::Fail), _) => AttemptStatus::VoidFailed,
        _ => AttemptStatus::VoidFailed,
    }
}

impl TryFrom<ResponseRouterData<TsysXmlVoidResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TsysXmlVoidResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let response = &item.response;

        let status = map_void_status(response);

        if matches!(status, AttemptStatus::VoidFailed) {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: response
                        .response_code
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .response_message
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    reason: response.response_message.clone(),
                    attempt_status: Some(AttemptStatus::VoidFailed),
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: response.response_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success path: prefer response's transactionID; fall back to the auth
        // txn id we sent (TransIT echoes the same id).
        let connector_txn_id = match response.transaction_id.clone() {
            Some(id) => id,
            None => {
                let id = router_data.request.connector_transaction_id.clone();
                if id.is_empty() {
                    return Err(crate::utils::response_deserialization_fail(
                        item.http_code,
                        "tsys_xml: Void response missing <transactionID> and request had none.",
                    )
                    .into());
                }
                id
            }
        };

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_txn_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(connector_txn_id),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}
