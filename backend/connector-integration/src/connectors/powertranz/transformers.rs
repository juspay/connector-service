use common_enums::enums;
use domain_types::{
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::powertranz::PowertranzRouterData, types::ResponseRouterData};

// ============================================================================
// Auth Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowertranzAuthType {
    pub power_tranz_id: Secret<String>,
    pub power_tranz_password: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PowertranzAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                power_tranz_id: key1.clone(),
                power_tranz_password: api_key.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// ============================================================================
// Payment Request Types
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PowertranzPaymentsRequest {
    pub transaction_identifier: String,
    pub total_amount: f64,
    pub currency_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub three_d_secure: Option<bool>,
    pub source: PowertranzSource,
    pub order_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_data: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PowertranzSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cardholder_name: Option<Secret<String>>,
    pub card_pan: Secret<String>,
    pub card_cvv: Secret<String>,
    pub card_expiration: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PowertranzCaptureRequest {
    pub transaction_identifier: String,
    pub total_amount: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PowertranzVoidRequest {
    pub transaction_identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PowertranzRefundRequest {
    pub transaction_identifier: String,
    pub total_amount: Option<f64>,
    pub refund: bool,
}

// ============================================================================
// Payment Response Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PowertranzPaymentsResponse {
    pub transaction_type: u8,
    pub approved: bool,
    pub transaction_identifier: String,
    #[serde(rename = "IsoResponseCode")]
    pub iso_response_code: String,
    pub response_message: String,
    pub errors: Option<Vec<PowertranzError>>,
}

pub type PowertranzPaymentsSyncResponse = PowertranzPaymentsResponse;
pub type PowertranzCaptureResponse = PowertranzPaymentsResponse;
pub type PowertranzVoidResponse = PowertranzPaymentsResponse;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PowertranzRefundResponse {
    pub transaction_type: u8,
    pub approved: bool,
    pub transaction_identifier: String,
    #[serde(rename = "IsoResponseCode")]
    pub iso_response_code: String,
    pub response_message: String,
    pub errors: Option<Vec<PowertranzError>>,
}

pub type PowertranzRSyncResponse = PowertranzRefundResponse;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PowertranzError {
    pub code: String,
    pub message: String,
}

// ============================================================================
// Error Response Types
// ============================================================================

/// PowerTranz ISO response codes that indicate success
/// Reference: Hyperswitch powertranz implementation
const ISO_SUCCESS_CODES: [&str; 7] = [
    "00",  // Approved or completed successfully
    "3D0", // 3D Secure authentication successful
    "3D1", // 3D Secure authentication attempted
    "HP0", // HostedPay success
    "TK0", // Token success
    "SP4", // Split payment success
    "FC0", // Fraud check success
];

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PowertranzErrorResponse {
    pub errors: Vec<PowertranzError>,
}

/// Build error response from PowerTranz response
///
/// Error handling precedence:
/// 1. If `errors` object exists - use first error's code and message
/// 2. If ISO response code is not in success codes - use ISO code and response message
/// 3. Otherwise - return None (successful response)
pub fn build_powertranz_error_response(
    errors: &Option<Vec<PowertranzError>>,
    iso_response_code: &str,
    response_message: &str,
    status_code: u16,
) -> Option<domain_types::router_data::ErrorResponse> {
    use common_utils::consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE};

    if let Some(errors) = errors {
        if !errors.is_empty() {
            let first_error = errors.first();
            return Some(domain_types::router_data::ErrorResponse {
                status_code,
                code: first_error
                    .map(|e| e.code.clone())
                    .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                message: first_error
                    .map(|e| e.message.clone())
                    .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                reason: Some(
                    errors
                        .iter()
                        .map(|error| format!("{} : {}", error.code, error.message))
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                attempt_status: None,
                connector_transaction_id: None,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            });
        }
    }

    // Check ISO response code if no errors object
    if !ISO_SUCCESS_CODES.contains(&iso_response_code) {
        return Some(domain_types::router_data::ErrorResponse {
            status_code,
            code: iso_response_code.to_string(),
            message: response_message.to_string(),
            reason: Some(response_message.to_string()),
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        });
    }

    None
}

// ============================================================================
// Request Transformers
// ============================================================================

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        PowertranzRouterData<
            RouterDataV2<
                domain_types::connector_flow::Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for PowertranzPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PowertranzRouterData<
            RouterDataV2<
                domain_types::connector_flow::Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let request_data = &item.router_data.request;
        let amount = request_data.amount.get_amount_as_i64() as f64 / 100.0;
        // Use ISO 4217 numeric code (e.g., "840" for USD)
        let currency_code = request_data.currency.iso_4217().to_string();

        match &request_data.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Card(card_data) => {
                // Format: YYMM (e.g., "3012" for December 2030 = year 30, month 12)
                let year = card_data.card_exp_year.peek();
                let year_suffix = if year.len() >= 2 {
                    &year[year.len() - 2..]
                } else {
                    year
                };
                let card_expiration =
                    format!("{}{}", year_suffix, &card_data.card_exp_month.peek());

                Ok(Self {
                    transaction_identifier: uuid::Uuid::new_v4().to_string(),
                    total_amount: amount,
                    currency_code,
                    three_d_secure: Some(false),
                    source: PowertranzSource {
                        cardholder_name: card_data.card_holder_name.clone(),
                        card_pan: Secret::new(card_data.card_number.peek().to_string()),
                        card_cvv: card_data.card_cvc.clone(),
                        card_expiration: Secret::new(card_expiration),
                    },
                    order_identifier: item
                        .router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                    extended_data: None,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported".to_string(),
            )
            .into()),
        }
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        PowertranzRouterData<
            RouterDataV2<
                domain_types::connector_flow::Capture,
                PaymentFlowData,
                PaymentsCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for PowertranzCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PowertranzRouterData<
            RouterDataV2<
                domain_types::connector_flow::Capture,
                PaymentFlowData,
                PaymentsCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = item.router_data.request.amount_to_capture as f64 / 100.0;

        Ok(Self {
            transaction_identifier: item
                .router_data
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?,
            total_amount: amount,
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        PowertranzRouterData<
            RouterDataV2<
                domain_types::connector_flow::Void,
                PaymentFlowData,
                PaymentVoidData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for PowertranzVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PowertranzRouterData<
            RouterDataV2<
                domain_types::connector_flow::Void,
                PaymentFlowData,
                PaymentVoidData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_identifier: item.router_data.request.connector_transaction_id.clone(),
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        PowertranzRouterData<
            RouterDataV2<
                domain_types::connector_flow::Refund,
                RefundFlowData,
                RefundsData,
                RefundsResponseData,
            >,
            T,
        >,
    > for PowertranzRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PowertranzRouterData<
            RouterDataV2<
                domain_types::connector_flow::Refund,
                RefundFlowData,
                RefundsData,
                RefundsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = item.router_data.request.refund_amount as f64 / 100.0;

        Ok(Self {
            transaction_identifier: item.router_data.request.connector_transaction_id.clone(),
            total_amount: Some(amount),
            refund: true,
        })
    }
}

// ============================================================================
// Response Transformers
// ============================================================================

impl<T: PaymentMethodDataTypes, F> TryFrom<ResponseRouterData<PowertranzPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<PowertranzPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transaction_identifier),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<PowertranzPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<PowertranzPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transaction_identifier),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<PowertranzCaptureResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<PowertranzCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transaction_identifier),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<PowertranzVoidResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<PowertranzVoidResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transaction_identifier),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<PowertranzRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<PowertranzRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let refund_status = if response.approved {
            enums::RefundStatus::Success
        } else {
            enums::RefundStatus::Failure
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: response.transaction_identifier.clone(),
                refund_status,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<PowertranzRSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<PowertranzRSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let refund_status = if response.approved {
            enums::RefundStatus::Success
        } else {
            enums::RefundStatus::Failure
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: response.transaction_identifier.clone(),
                refund_status,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}
