use common_enums::AttemptStatus;
use common_utils::types::{MinorUnit, StringMinorUnit};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

use super::{TsysAmountConvertor, TsysRouterData};

// ============================================================================
// Authentication Type
// ============================================================================

#[derive(Debug, Clone)]
pub struct TsysAuthType {
    pub device_id: Secret<String>,
    pub transaction_key: Secret<String>,
    pub developer_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for TsysAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                device_id: api_key.to_owned(),
                transaction_key: key1.to_owned(),
                developer_id: api_secret.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// ============================================================================
// AUTHORIZE FLOW - Request/Response
// ============================================================================

#[derive(Debug, Serialize)]
pub enum TsysPaymentsRequest<T: PaymentMethodDataTypes> {
    Auth(TsysPaymentAuthSaleRequest<T>),
    Sale(TsysPaymentAuthSaleRequest<T>),
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TsysPaymentAuthSaleRequest<T: PaymentMethodDataTypes> {
    #[serde(rename = "deviceID")]
    device_id: Secret<String>,
    transaction_key: Secret<String>,
    card_data_source: String,
    transaction_amount: StringMinorUnit,
    currency_code: common_enums::enums::Currency,
    card_number: RawCardNumber<T>,
    expiration_date: Secret<String>,
    cvv2: Secret<String>,
    order_number: String,
    terminal_capability: String,
    terminal_operating_environment: String,
    cardholder_authentication_method: String,
    #[serde(rename = "developerID")]
    developer_id: Secret<String>,
}

// TryFrom for macro compatibility - owned TsysRouterData
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        TsysRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for TsysPaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item_data: TsysRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &item_data.router_data;

        match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                let auth: TsysAuthType = TsysAuthType::try_from(&item.connector_auth_type)?;

                let auth_data = TsysPaymentAuthSaleRequest {
                    device_id: auth.device_id,
                    transaction_key: auth.transaction_key,
                    card_data_source: "INTERNET".to_string(),
                    transaction_amount: TsysAmountConvertor::convert(
                        item.request.minor_amount,
                        item.request.currency,
                    )
                    .change_context(errors::ConnectorError::RequestEncodingFailed)?,
                    currency_code: item.request.currency,
                    card_number: card_data.card_number.clone(),
                    expiration_date: card_data
                        .get_card_expiry_month_year_2_digit_with_delimiter("/".to_owned())?,
                    cvv2: card_data.card_cvc.clone(),
                    order_number: item
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                    terminal_capability: "ICC_CHIP_READ_ONLY".to_string(),
                    terminal_operating_environment: "ON_MERCHANT_PREMISES_ATTENDED".to_string(),
                    cardholder_authentication_method: "NOT_AUTHENTICATED".to_string(),
                    developer_id: auth.developer_id,
                };

                // Check if auto-capture or manual capture
                if item.request.is_auto_capture()? {
                    Ok(Self::Sale(auth_data))
                } else {
                    Ok(Self::Auth(auth_data))
                }
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported".to_string(),
            ))?,
        }
    }
}

// Response types for Authorize
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TsysPaymentStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TsysTransactionStatus {
    Approved,
    Declined,
    Void,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TsysResponse {
    pub status: TsysPaymentStatus,
    pub response_code: String,
    pub response_message: String,
    #[serde(rename = "transactionID")]
    pub transaction_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TsysErrorResponse {
    pub status: TsysPaymentStatus,
    pub response_code: String,
    pub response_message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TsysResponseTypes {
    SuccessResponse(TsysResponse),
    ErrorResponse(TsysErrorResponse),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(clippy::enum_variant_names)]
pub enum TsysPaymentsResponse {
    AuthResponse(TsysResponseTypes),
    SaleResponse(TsysResponseTypes),
    CaptureResponse(TsysResponseTypes),
    VoidResponse(TsysResponseTypes),
}

// Separate wrapper types for each flow to avoid macro conflicts
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct TsysAuthorizeResponse(pub TsysPaymentsResponse);

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct TsysCaptureResponse(pub TsysPaymentsResponse);

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct TsysVoidResponse(pub TsysPaymentsResponse);

fn get_payments_response(connector_response: TsysResponse, http_code: u16) -> PaymentsResponseData {
    PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(connector_response.transaction_id.clone()),
        redirection_data: None,
        mandate_reference: None,
        connector_metadata: None,
        network_txn_id: None,
        connector_response_reference_id: Some(connector_response.transaction_id),
        incremental_authorization_allowed: None,
        status_code: http_code,
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            TsysAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            TsysAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let (response, status) = match item.response.0 {
            TsysPaymentsResponse::AuthResponse(resp) => match resp {
                TsysResponseTypes::SuccessResponse(auth_response) => (
                    Ok(get_payments_response(auth_response, item.http_code)),
                    AttemptStatus::Authorized,
                ),
                TsysResponseTypes::ErrorResponse(error_response) => (
                    Err(get_error_response(&error_response, item.http_code)),
                    AttemptStatus::AuthorizationFailed,
                ),
            },
            TsysPaymentsResponse::SaleResponse(resp) => match resp {
                TsysResponseTypes::SuccessResponse(sale_response) => (
                    Ok(get_payments_response(sale_response, item.http_code)),
                    AttemptStatus::Charged,
                ),
                TsysResponseTypes::ErrorResponse(error_response) => (
                    Err(get_error_response(&error_response, item.http_code)),
                    AttemptStatus::Failure,
                ),
            },
            _ => {
                let generic_error = TsysErrorResponse {
                    status: TsysPaymentStatus::Fail,
                    response_code: item.http_code.to_string(),
                    response_message: item.http_code.to_string(),
                };
                (
                    Err(get_error_response(&generic_error, item.http_code)),
                    AttemptStatus::Failure,
                )
            },
        };

        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// TryFrom for Capture flow
impl
    TryFrom<
        ResponseRouterData<
            TsysCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            TsysCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let (response, status) = match item.response.0 {
            TsysPaymentsResponse::CaptureResponse(resp) => match resp {
                TsysResponseTypes::SuccessResponse(capture_response) => (
                    Ok(get_payments_response(capture_response, item.http_code)),
                    AttemptStatus::Charged,
                ),
                TsysResponseTypes::ErrorResponse(error_response) => (
                    Err(get_error_response(&error_response, item.http_code)),
                    AttemptStatus::CaptureFailed,
                ),
            },
            _ => {
                let generic_error = TsysErrorResponse {
                    status: TsysPaymentStatus::Fail,
                    response_code: item.http_code.to_string(),
                    response_message: item.http_code.to_string(),
                };
                (
                    Err(get_error_response(&generic_error, item.http_code)),
                    AttemptStatus::CaptureFailed,
                )
            },
        };

        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// TryFrom for Void flow
impl
    TryFrom<
        ResponseRouterData<
            TsysVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            TsysVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let (response, status) = match item.response.0 {
            TsysPaymentsResponse::VoidResponse(resp) => match resp {
                TsysResponseTypes::SuccessResponse(void_response) => (
                    Ok(get_payments_response(void_response, item.http_code)),
                    AttemptStatus::Voided,
                ),
                TsysResponseTypes::ErrorResponse(error_response) => (
                    Err(get_error_response(&error_response, item.http_code)),
                    AttemptStatus::VoidFailed,
                ),
            },
            _ => {
                let generic_error = TsysErrorResponse {
                    status: TsysPaymentStatus::Fail,
                    response_code: item.http_code.to_string(),
                    response_message: item.http_code.to_string(),
                };
                (
                    Err(get_error_response(&generic_error, item.http_code)),
                    AttemptStatus::VoidFailed,
                )
            },
        };

        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ============================================================================
// PSYNC FLOW - Request/Response
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TsysSearchTransactionRequest {
    #[serde(rename = "deviceID")]
    device_id: Secret<String>,
    transaction_key: Secret<String>,
    #[serde(rename = "transactionID")]
    transaction_id: String,
    #[serde(rename = "developerID")]
    developer_id: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TsysSyncRequest {
    search_transaction: TsysSearchTransactionRequest,
}

// Wrapper struct for PSync to avoid macro conflicts
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct TsysPSyncRequest(TsysSyncRequest);

#[derive(Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct TsysPSyncResponse(TsysSyncResponse);

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        TsysRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for TsysPSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item_data: TsysRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &item_data.router_data;
        let auth: TsysAuthType = TsysAuthType::try_from(&item.connector_auth_type)?;

        let search_transaction = TsysSearchTransactionRequest {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            transaction_id: item
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?,
            developer_id: auth.developer_id,
        };

        Ok(Self(TsysSyncRequest { search_transaction }))
    }
}

// PSync Response
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TsysTransactionDetails {
    #[serde(rename = "transactionID")]
    transaction_id: String,
    transaction_type: String,
    transaction_status: TsysTransactionStatus,
}

impl From<TsysTransactionDetails> for AttemptStatus {
    fn from(item: TsysTransactionDetails) -> Self {
        match item.transaction_status {
            TsysTransactionStatus::Approved => {
                if item.transaction_type.contains("Auth-Only") {
                    Self::Authorized
                } else {
                    Self::Charged
                }
            }
            TsysTransactionStatus::Void => Self::Voided,
            TsysTransactionStatus::Declined => Self::Failure,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TsysPaymentsSyncResponse {
    pub status: TsysPaymentStatus,
    pub response_code: String,
    pub response_message: String,
    pub transaction_details: TsysTransactionDetails,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SearchResponseTypes {
    SuccessResponse(TsysPaymentsSyncResponse),
    ErrorResponse(TsysErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TsysSyncResponse {
    search_transaction_response: SearchResponseTypes,
}

fn get_payments_sync_response(
    connector_response: &TsysPaymentsSyncResponse,
    http_code: u16,
) -> PaymentsResponseData {
    PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(
            connector_response
                .transaction_details
                .transaction_id
                .clone(),
        ),
        redirection_data: None,
        mandate_reference: None,
        connector_metadata: None,
        network_txn_id: None,
        connector_response_reference_id: Some(
            connector_response
                .transaction_details
                .transaction_id
                .clone(),
        ),
        incremental_authorization_allowed: None,
        status_code: http_code,
    }
}

impl
    TryFrom<
        ResponseRouterData<
            TsysPSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            TsysPSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let (response, status) = match item.response.0.search_transaction_response {
            SearchResponseTypes::SuccessResponse(search_response) => (
                Ok(get_payments_sync_response(&search_response, item.http_code)),
                AttemptStatus::from(search_response.transaction_details),
            ),
            SearchResponseTypes::ErrorResponse(error_response) => (
                Err(get_error_response(&error_response, item.http_code)),
                item.router_data.resource_common_data.status,
            ),
        };

        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ============================================================================
// CAPTURE FLOW - Request/Response
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TsysCaptureRequest {
    #[serde(rename = "deviceID")]
    device_id: Secret<String>,
    transaction_key: Secret<String>,
    transaction_amount: StringMinorUnit,
    #[serde(rename = "transactionID")]
    transaction_id: String,
    #[serde(rename = "developerID")]
    developer_id: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TsysPaymentsCaptureRequest {
    capture: TsysCaptureRequest,
}

// TryFrom for macro compatibility - owned TsysRouterData
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        TsysRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for TsysPaymentsCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item_data: TsysRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &item_data.router_data;
        let auth: TsysAuthType = TsysAuthType::try_from(&item.connector_auth_type)?;

        let capture = TsysCaptureRequest {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            transaction_id: item
                .request
                .connector_transaction_id
                .clone()
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?,
            developer_id: auth.developer_id,
            transaction_amount: TsysAmountConvertor::convert(
                item.request.minor_amount_to_capture,
                item.request.currency,
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?,
        };

        Ok(Self { capture })
    }
}

// ============================================================================
// VOID FLOW - Request/Response
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TsysCancelRequest {
    #[serde(rename = "deviceID")]
    device_id: Secret<String>,
    transaction_key: Secret<String>,
    #[serde(rename = "transactionID")]
    transaction_id: String,
    #[serde(rename = "developerID")]
    developer_id: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TsysPaymentsCancelRequest {
    void: TsysCancelRequest,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        TsysRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for TsysPaymentsCancelRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item_data: TsysRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &item_data.router_data;
        let auth: TsysAuthType = TsysAuthType::try_from(&item.connector_auth_type)?;

        let void = TsysCancelRequest {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            transaction_id: item.request.connector_transaction_id.clone(),
            developer_id: auth.developer_id,
        };

        Ok(Self { void })
    }
}

// ============================================================================
// REFUND FLOW - Request/Response
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TsysReturnRequest {
    #[serde(rename = "deviceID")]
    device_id: Secret<String>,
    transaction_key: Secret<String>,
    transaction_amount: StringMinorUnit,
    #[serde(rename = "transactionID")]
    transaction_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TsysRefundRequest {
    #[serde(rename = "Return")]
    return_request: TsysReturnRequest,
}

// TryFrom for macro compatibility - owned TsysRouterData
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        TsysRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for TsysRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item_data: TsysRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &item_data.router_data;
        let auth: TsysAuthType = TsysAuthType::try_from(&item.connector_auth_type)?;

        let return_request = TsysReturnRequest {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            transaction_amount: TsysAmountConvertor::convert(
                MinorUnit(item.request.refund_amount),
                item.request.currency,
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?,
            transaction_id: item.request.connector_transaction_id.clone(),
        };

        Ok(Self { return_request })
    }
}

// Refund Response
impl From<TsysPaymentStatus> for common_enums::enums::RefundStatus {
    fn from(item: TsysPaymentStatus) -> Self {
        match item {
            TsysPaymentStatus::Pass => Self::Success,
            TsysPaymentStatus::Fail => Self::Failure,
        }
    }
}

impl From<TsysTransactionDetails> for common_enums::enums::RefundStatus {
    fn from(item: TsysTransactionDetails) -> Self {
        match item.transaction_status {
            TsysTransactionStatus::Approved => Self::Pending,
            TsysTransactionStatus::Void => Self::Success, // TSYS marks successful refunds as VOID
            TsysTransactionStatus::Declined => Self::Failure,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RefundResponse {
    return_response: TsysResponseTypes,
}

impl
    TryFrom<
        ResponseRouterData<
            RefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = match item.response.return_response {
            TsysResponseTypes::SuccessResponse(return_response) => Ok(RefundsResponseData {
                connector_refund_id: return_response.transaction_id,
                refund_status: common_enums::enums::RefundStatus::from(return_response.status),
                status_code: item.http_code,
            }),
            TsysResponseTypes::ErrorResponse(error_response) => Err(get_error_response(&error_response, item.http_code)),
        };

        Ok(Self {
            response,
            ..item.router_data
        })
    }
}

// ============================================================================
// RSYNC FLOW - Request/Response
// ============================================================================

// Wrapper struct for RSync to avoid macro conflicts
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct TsysRSyncRequest(TsysSyncRequest);

#[derive(Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct TsysRSyncResponse(TsysSyncResponse);

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        TsysRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>,
    > for TsysRSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item_data: TsysRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &item_data.router_data;
        let auth: TsysAuthType = TsysAuthType::try_from(&item.connector_auth_type)?;

        let search_transaction = TsysSearchTransactionRequest {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            transaction_id: item.request.connector_refund_id.clone(),
            developer_id: auth.developer_id,
        };

        Ok(Self(TsysSyncRequest { search_transaction }))
    }
}

impl
    TryFrom<
        ResponseRouterData<
            TsysRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            TsysRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = match item.response.0.search_transaction_response {
            SearchResponseTypes::SuccessResponse(search_response) => Ok(RefundsResponseData {
                connector_refund_id: search_response.transaction_details.transaction_id.clone(),
                refund_status: common_enums::enums::RefundStatus::from(
                    search_response.transaction_details,
                ),
                status_code: item.http_code,
            }),
            SearchResponseTypes::ErrorResponse(error_response) => {
                Err(get_error_response(&error_response, item.http_code))
            },
        };

        Ok(Self {
            response,
            ..item.router_data
        })
    }
}

// ============================================================================
// ERROR RESPONSE HELPER
// ============================================================================

fn get_error_response(
    connector_response: &TsysErrorResponse,
    status_code: u16,
) -> domain_types::router_data::ErrorResponse {
    domain_types::router_data::ErrorResponse {
        code: connector_response.response_code.clone(),
        message: connector_response.response_message.clone(),
        reason: Some(connector_response.response_message.clone()),
        status_code,
        attempt_status: None,
        connector_transaction_id: None,
        network_decline_code: None,
        network_advice_code: None,
        network_error_message: None,
    }
}
