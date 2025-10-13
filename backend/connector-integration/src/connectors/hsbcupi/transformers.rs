use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    request::Method,
    types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::hsbcupi::HsbcUpiRouterData, types::ResponseRouterData};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HsbcUpiPaymentsRequest {
    pub pg_merchant_id: String,
    pub me_ref_no: String,
    pub payer_vpa: String,
    pub trans_amount: StringMinorUnit,
    pub trans_remarks: String,
    pub exp_value: String,
    pub add_info1: Option<String>,
    pub add_info2: Option<String>,
    pub add_info3: Option<String>,
    pub add_info4: Option<String>,
    pub add_info5: Option<String>,
    pub add_info6: Option<String>,
    pub add_info7: Option<String>,
    pub add_info8: Option<String>,
    pub add_info9: Option<String>,
    pub add_info10: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HsbcUpiPaymentsSyncRequest {
    pub pg_merchant_id: String,
    pub me_ref_no: String,
    pub trans_rrn: Option<String>,
    pub me_order_no: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HsbcUpiIntentRequest {
    pub pg_merchant_id: String,
    pub order_no: String,
    pub txn_id: String,
    pub expiry_time: String,
    pub circle_code: String,
    pub mobile_no: String,
    pub amount: StringMinorUnit,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HsbcUpiAuth {
    pub pg_merchant_id: Secret<String>,
    pub api_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for HsbcUpiAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => Ok(Self {
                pg_merchant_id: api_key.clone(),
                api_key: Some(api_key.clone()),
            }),
            ConnectorAuthType::Key { api_key, .. } => Ok(Self {
                pg_merchant_id: api_key.clone(),
                api_key: Some(api_key.clone()),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

fn get_merchant_id(
    connector_auth_type: &ConnectorAuthType,
) -> Result<Secret<String>, errors::ConnectorError> {
    match HsbcUpiAuth::try_from(connector_auth_type) {
        Ok(auth) => Ok(auth.pg_merchant_id),
        Err(_) => Err(errors::ConnectorError::FailedToObtainAuthType),
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<HsbcUpiRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for HsbcUpiPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: HsbcUpiRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let merchant_id = get_merchant_id(&item.router_data.connector_auth_type)?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Extract UPI VPA from payment method data
        let payer_vpa = item
            .router_data
            .request
            .payment_method_data
            .as_ref()
            .and_then(|pm| pm.get_upi_vpa())
            .unwrap_or_else(|| "".to_string());

        let me_ref_no = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        Ok(Self {
            pg_merchant_id: merchant_id.expose().clone(),
            me_ref_no,
            payer_vpa,
            trans_amount: amount,
            trans_remarks: "UPI Payment".to_string(),
            exp_value: "30".to_string(), // 30 minutes expiry
            add_info1: None,
            add_info2: None,
            add_info3: None,
            add_info4: None,
            add_info5: None,
            add_info6: None,
            add_info7: None,
            add_info8: None,
            add_info9: None,
            add_info10: None,
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<HsbcUpiRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for HsbcUpiPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: HsbcUpiRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let merchant_id = get_merchant_id(&item.router_data.connector_auth_type)?;
        let me_ref_no = item
            .router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let me_order_no = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        Ok(Self {
            pg_merchant_id: merchant_id.expose().clone(),
            me_ref_no,
            trans_rrn: None, // Will be populated if available
            me_order_no,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HsbcUpiPaymentsResponse {
    pub me_ref_no: String,
    pub trans_id: Option<String>,
    pub trans_rrn: Option<String>,
    pub trans_amount: String,
    pub trans_auth_date_time: Option<String>,
    pub status_code: String,
    pub status_desc: String,
    pub payer_vpa: String,
    pub payee_vpa: String,
    pub pg_merchant_id: String,
    pub add_info1: String,
    pub add_info2: String,
    pub add_info3: String,
    pub add_info4: String,
    pub add_info5: String,
    pub add_info6: String,
    pub add_info7: String,
    pub add_info8: String,
    pub add_info9: String,
    pub add_info10: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HsbcUpiPaymentsSyncResponse {
    pub me_ref_no: String,
    pub me_order_no: String,
    pub trans_id: Option<String>,
    pub trans_rrn: Option<String>,
    pub trans_amount: String,
    pub trans_auth_date_time: Option<String>,
    pub status_code: String,
    pub status_desc: Option<String>,
    pub trans_message: Option<String>,
    pub resp_code: String,
    pub trans_appr_no: Option<String>,
    pub payer_vpa: String,
    pub payee_vpa: String,
    pub pg_merchant_id: String,
    pub payer_acc_no: Option<String>,
    pub payer_ifsc: Option<String>,
    pub add_info1: Option<String>,
    pub add_info2: Option<String>,
    pub add_info3: Option<String>,
    pub add_info4: Option<String>,
    pub add_info5: Option<String>,
    pub add_info6: Option<String>,
    pub add_info7: Option<String>,
    pub add_info8: Option<String>,
    pub add_info9: Option<String>,
    pub add_info10: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HsbcUpiIntentResponse {
    pub order_no: Option<String>,
    pub status: String,
    pub status_desc: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HsbcUpiErrorResponse {
    pub status_code: String,
    pub status_desc: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum HsbcUpiResponseEnum {
    Success(HsbcUpiPaymentsResponse),
    Error(HsbcUpiErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum HsbcUpiSyncResponseEnum {
    Success(HsbcUpiPaymentsSyncResponse),
    Error(HsbcUpiErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum HsbcUpiIntentResponseEnum {
    Success(HsbcUpiIntentResponse),
    Error(HsbcUpiErrorResponse),
}

impl From<String> for common_enums::AttemptStatus {
    fn from(status_code: String) -> Self {
        match status_code.as_str() {
            "00" | "0" => Self::Charged,
            "01" | "1" => Self::AuthenticationPending,
            "02" | "2" => Self::Pending,
            "03" | "3" => Self::Failure,
            "04" | "4" => Self::AuthorizationFailed,
            "05" | "5" => Self::Voided,
            _ => Self::Pending,
        }
    }
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<HsbcUpiResponseEnum, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<HsbcUpiResponseEnum, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            HsbcUpiResponseEnum::Success(response_data) => {
                let status = common_enums::AttemptStatus::from(response_data.status_code.clone());
                
                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            response_data.trans_id.unwrap_or_else(|| {
                                router_data
                                    .resource_common_data
                                    .connector_request_reference_id
                                    .clone()
                            }),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: response_data.trans_rrn,
                        connector_response_reference_id: Some(response_data.me_ref_no),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            HsbcUpiResponseEnum::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: error_data.status_code,
                    message: error_data.status_desc.clone(),
                    reason: error_data.status_desc,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: error_data.error_message,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<HsbcUpiSyncResponseEnum, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<HsbcUpiSyncResponseEnum, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            HsbcUpiSyncResponseEnum::Success(response_data) => {
                let status = common_enums::AttemptStatus::from(response_data.status_code.clone());
                
                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            response_data.trans_id.unwrap_or_else(|| {
                                router_data
                                    .resource_common_data
                                    .connector_request_reference_id
                                    .clone()
                            }),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: response_data.trans_rrn,
                        connector_response_reference_id: Some(response_data.me_ref_no),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            HsbcUpiSyncResponseEnum::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: error_data.status_code,
                    message: error_data.status_desc.clone(),
                    reason: error_data.status_desc,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: error_data.error_message,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}

// Extension trait for PaymentMethodData to get UPI VPA
pub trait UpiVpaExtractor {
    fn get_upi_vpa(&self) -> Option<String>;
}

impl<T: PaymentMethodDataTypes> UpiVpaExtractor for PaymentMethodData<T> {
    fn get_upi_vpa(&self) -> Option<String> {
        match self {
            PaymentMethodData::Upi(upi_data) => {
                // Extract VPA from UPI data - this depends on the actual structure
                // For now, return a placeholder that should be implemented based on actual UPI data structure
                Some("placeholder_vpa@upi".to_string())
            }
            _ => None,
        }
    }
}