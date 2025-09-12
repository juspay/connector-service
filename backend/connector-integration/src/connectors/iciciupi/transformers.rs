use common_utils::types::StringMinorUnit;
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,

};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::iciciupi::IciciUpiRouterData, types::ResponseRouterData};

// Request structures based on Haskell types
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiPaymentsRequest {
    pub payer_va: String,
    pub amount: StringMinorUnit,
    pub note: Option<String>,
    pub collect_by_date: String,
    pub merchant_id: String,
    pub merchant_name: String,
    pub sub_merchant_id: Option<String>,
    pub sub_merchant_name: Option<String>,
    pub terminal_id: Option<String>,
    pub merchant_tran_id: String,
    pub bill_number: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiPaymentsSyncRequest {
    pub merchant_id: String,
    pub sub_merchant_id: Option<String>,
    pub terminal_id: Option<String>,
    pub transaction_type: Option<String>,
    pub merchant_tran_id: String,
}

// Response structures based on Haskell types
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiPaymentsResponse {
    pub act_code: Option<String>,
    pub merchant_id: Option<String>,
    pub sub_merchant_id: Option<String>,
    pub terminal_id: Option<String>,
    pub amount: Option<String>,
    pub success: bool,
    pub message: String,
    pub merchant_tran_id: Option<String>,
    pub bank_rrn: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiPaymentsSyncResponse {
    pub act_code: Option<String>,
    pub merchant_id: Option<String>,
    pub sub_merchant_id: Option<String>,
    pub terminal_id: Option<String>,
    pub amount: Option<String>,
    pub success: bool,
    pub message: String,
    pub merchant_tran_id: Option<String>,
    pub bank_rrn: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiErrorResponse {
    pub error_code: String,
    pub error_message: String,
}

// Auth structure
#[derive(Debug, Deserialize)]
pub struct IciciUpiAuth {
    pub api_key: Secret<String>,
    pub merchant_id: String,
}

impl TryFrom<&ConnectorAuthType> for IciciUpiAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => {
                // For ICICI UPI, we'll use a default merchant ID for now
                // In production, this should be configured per merchant
                Ok(Self {
                    api_key: api_key.clone(),
                    merchant_id: "default_merchant".to_string(),
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Payment status mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IciciUpiPaymentStatus {
    Success,
    Pending,
    Failure,
    #[serde(other)]
    Unknown,
}

impl From<IciciUpiPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: IciciUpiPaymentStatus) -> Self {
        match item {
            IciciUpiPaymentStatus::Success => Self::Charged,
            IciciUpiPaymentStatus::Pending => Self::AuthenticationPending,
            IciciUpiPaymentStatus::Failure => Self::Failure,
            IciciUpiPaymentStatus::Unknown => Self::Pending,
        }
    }
}

// Request conversion for Authorize flow
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<IciciUpiRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for IciciUpiPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: IciciUpiRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = IciciUpiAuth::try_from(&item.router_data.connector_auth_type)?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Extract UPI payment details from payment method data
        let (payer_va, note) = match &item.router_data.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => {
                match upi_data {
                    domain_types::payment_method_data::UpiData::UpiCollect(collect_data) => {
                        (collect_data.vpa_id.as_ref().map(|v| v.clone().expose().to_string()).unwrap_or_default(), None)
                    }
                    domain_types::payment_method_data::UpiData::UpiIntent(_) => {
                        return Err(errors::ConnectorError::NotImplemented("UPI Intent flow not supported".to_string()).into());
                    }
                }
            }
            _ => return Err(errors::ConnectorError::NotImplemented("UPI payment method required".to_string()).into()),
        };

        Ok(Self {
            payer_va,
            amount,
            note,
            collect_by_date: item.router_data.request.get_router_return_url()
                .unwrap_or_else(|_| "".to_string()),
            merchant_id: auth.merchant_id,
            merchant_name: item.router_data.resource_common_data.get_optional_billing_full_name()
                .unwrap_or_else(|| Secret::new("".to_string()))
                .expose(),
            sub_merchant_id: None,
            sub_merchant_name: None,
            terminal_id: None,
            merchant_tran_id: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            bill_number: None,
        })
    }
}

// Request conversion for PSync flow
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<IciciUpiRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for IciciUpiPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: IciciUpiRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = IciciUpiAuth::try_from(&item.router_data.connector_auth_type)?;
        let connector_transaction_id = item.router_data.request.get_connector_transaction_id()?;

        Ok(Self {
            merchant_id: auth.merchant_id,
            sub_merchant_id: None,
            terminal_id: None,
            transaction_type: None,
            merchant_tran_id: connector_transaction_id,
        })
    }
}

// Response conversion for Authorize flow
impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<IciciUpiPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<IciciUpiPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response_data) = if response.success {
            (
                common_enums::AttemptStatus::AuthenticationPending,
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        response.merchant_tran_id.unwrap_or_default(),
                    ),
                    redirection_data: None, // UPI doesn't typically require redirection
                    connector_metadata: None,
                    mandate_reference: None,
                    network_txn_id: response.bank_rrn,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: http_code,
                }),
            )
        } else {
            (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: response.act_code.unwrap_or_else(|| "UNKNOWN".to_string()),
                    message: response.message.clone(),
                    reason: Some(response.message),
                    attempt_status: None,
                    connector_transaction_id: response.merchant_tran_id,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            )
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: response_data,
            ..router_data
        })
    }
}

// Response conversion for PSync flow
impl<F> TryFrom<ResponseRouterData<IciciUpiPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<IciciUpiPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = if response.success {
            common_enums::AttemptStatus::Charged
        } else {
            common_enums::AttemptStatus::Failure
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.merchant_tran_id.unwrap_or_default(),
                ),
                redirection_data: None,
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: response.bank_rrn,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}