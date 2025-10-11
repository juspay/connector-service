use std::collections::HashMap;

use common_utils::{
    ext_traits::ValueExt,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{connectors::hdfcupi::HdfcUpiRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfcUpiPaymentsRequest {
    pub V: String,
    pub requestMsg: String,
    pub pgMerchantId: Secret<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfcUpiPaymentsSyncRequest {
    pub V: String,
    pub requestMsg: String,
    pub pgMerchantId: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum HdfcUpiPaymentsResponse {
    HdfcUpiError(HdfcUpiErrorResponse),
    HdfcUpiData(HdfcUpiCollectResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfcUpiCollectResponse {
    pub orderNo: String,
    pub upiTxnId: String,
    pub amount: String,
    pub status: String,
    pub statusDesc: String,
    pub payerVA: Option<String>,
    pub payeeVA: String,
    pub additionalField1: Option<String>,
    pub additionalField2: Option<String>,
    pub additionalField3: Option<String>,
    pub additionalField4: Option<String>,
    pub additionalField5: Option<String>,
    pub additionalField6: Option<String>,
    pub additionalField7: Option<String>,
    pub additionalField8: Option<String>,
    pub additionalField9: Option<String>,
    pub additionalField10: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfcUpiPaymentsSyncResponse {
    pub upiTxnId: String,
    pub orderNo: String,
    pub amount: String,
    pub txnAuthDate: String,
    pub status: String,
    pub statusDesc: String,
    pub responseCode: String,
    pub approvalNumber: Option<String>,
    pub payerVA: Option<String>,
    pub customerReferenceNo: String,
    pub referenceId: Option<String>,
    pub additionalField1: Option<String>,
    pub additionalField2: Option<String>,
    pub additionalField3: Option<String>,
    pub additionalField4: Option<String>,
    pub additionalField5: Option<String>,
    pub additionalField6: Option<String>,
    pub additionalField7: Option<String>,
    pub additionalField8: Option<String>,
    pub additionalField9: Option<String>,
    pub additionalField10: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfcUpiTxnRefundResponse {
    pub upiTxnId: String,
    pub merchantTxnRef: String,
    pub amount: String,
    pub txnAuthDate: String,
    pub status: String,
    pub statusDesc: String,
    pub responseCode: String,
    pub approvalNumber: Option<String>,
    pub payerVA: Option<String>,
    pub customerReferenceNo: String,
    pub referenceId: Option<String>,
    pub additionalField1: Option<String>,
    pub additionalField2: Option<String>,
    pub additionalField3: Option<String>,
    pub additionalField4: Option<String>,
    pub additionalField5: Option<String>,
    pub additionalField6: Option<String>,
    pub additionalField7: Option<String>,
    pub additionalField8: Option<String>,
    pub additionalField9: Option<String>,
    pub additionalField10: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfcUpiCallback {
    pub meRes: String,
    pub pgMerchantId: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfcUpiMandateCallback {
    pub payload: String,
    pub pgMerchantId: String,
    pub ivToken: String,
    pub keyId: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfcMandateWebhook {
    pub requestInfo: RInfo,
    pub mandateDtls: Vec<MandateDetails>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RInfo {
    pub pgMerchantId: String,
    pub pspRefNo: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MandateDetails {
    // Empty struct as per original Haskell implementation
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PSPHdfcGatewayResponse {
    HdfcUpiCallbackRes(HdfcUpiCallback),
    HdfcUpiMandateCallbackres(HdfcUpiMandateCallback),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfcUpiMetaData {
    #[serde(rename = "__HDFC_UPI_58_remarks")]
    pub __hdfc_upi_58_remarks: Option<String>,
    #[serde(rename = "__HDFC_UPI_58_expiry")]
    pub __hdfc_upi_58_expiry: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetHdfcUpiResponse {
    pub code: i32,
    pub status: String,
    pub response: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TranStatusRes {
    // Empty struct as per original Haskell implementation
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfcUpiErrorResponse {
    pub code: i32,
    pub status: String,
    pub response: String,
}

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct HdfcUpiVoidRequest;
#[derive(Debug, Clone)]
pub struct HdfcUpiVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct HdfcUpiCaptureRequest;
#[derive(Debug, Clone)]
pub struct HdfcUpiCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct HdfcUpiRefundRequest;
#[derive(Debug, Clone)]
pub struct HdfcUpiRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct HdfcUpiRefundSyncRequest;
#[derive(Debug, Clone)]
pub struct HdfcUpiRefundSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct HdfcUpiCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct HdfcUpiCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct HdfcUpiSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct HdfcUpiSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct HdfcUpiSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct HdfcUpiSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct HdfcUpiRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct HdfcUpiRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct HdfcUpiAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct HdfcUpiAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct HdfcUpiDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct HdfcUpiDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct HdfcUpiSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct HdfcUpiSubmitEvidenceResponse;

#[derive(Default, Debug, Deserialize)]
pub struct HdfcUpiAuthType {
    pub auths: HashMap<common_enums::Currency, HdfcUpiAuth>,
}

#[derive(Default, Debug, Deserialize)]
pub struct HdfcUpiAuth {
    pub api_key: Secret<String>,
    pub merchant_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for HdfcUpiAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::CurrencyAuthKey { auth_key_map } => {
                let transformed_auths = auth_key_map
                    .iter()
                    .map(|(currency, identity_auth_key)| {
                        let hdfc_upi_auth = identity_auth_key
                            .to_owned()
                            .parse_value::<HdfcUpiAuth>("HdfcUpiAuth")
                            .change_context(errors::ConnectorError::InvalidDataFormat {
                                field_name: "auth_key_map",
                            })?;

                        Ok((currency.to_owned(), hdfc_upi_auth))
                    })
                    .collect::<Result<_, Self::Error>>()?;

                Ok(Self {
                    auths: transformed_auths,
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl TryFrom<&ConnectorAuthType> for HdfcUpiAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::CurrencyAuthKey { auth_key_map } => {
                if let Some(identity_auth_key) = auth_key_map.get(&common_enums::Currency::INR) {
                    let hdfc_upi_auth: Self = identity_auth_key
                        .to_owned()
                        .parse_value("HdfcUpiAuth")
                        .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                    Ok(hdfc_upi_auth)
                } else {
                    Err(errors::ConnectorError::CurrencyNotSupported {
                        message: "INR".to_string(),
                        connector: "HdfcUpi",
                    }
                    .into())
                }
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HdfcUpiPaymentStatus {
    Success,
    Pending,
    Failure,
    #[default]
    Unknown,
}

impl From<HdfcUpiPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: HdfcUpiPaymentStatus) -> Self {
        match item {
            HdfcUpiPaymentStatus::Success => Self::Charged,
            HdfcUpiPaymentStatus::Pending => Self::AuthenticationPending,
            HdfcUpiPaymentStatus::Failure => Self::Failure,
            HdfcUpiPaymentStatus::Unknown => Self::Pending,
        }
    }
}

fn get_payment_status(status: &str) -> HdfcUpiPaymentStatus {
    match status.to_lowercase().as_str() {
        "success" | "completed" => HdfcUpiPaymentStatus::Success,
        "pending" | "processing" => HdfcUpiPaymentStatus::Pending,
        "failure" | "failed" => HdfcUpiPaymentStatus::Failure,
        _ => HdfcUpiPaymentStatus::Unknown,
    }
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
    HdfcUpiRouterData<
        RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        T,
    >,
> for HdfcUpiPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: HdfcUpiRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth_type = HdfcUpiAuth::try_from(&item.router_data.connector_auth_type)?;
        
        // Extract amount using proper amount converter
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Get customer ID
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        
        // Get transaction reference
        let transaction_id = item.router_data.resource_common_data.connector_request_reference_id;

        // Build request message based on HDFC UPI format
        let request_msg = serde_json::json!({
            "txnId": transaction_id,
            "amount": amount,
            "payerVA": item.router_data.request.payment_method_data.as_ref()
                .and_then(|pm| pm.get_upi_data())
                .and_then(|upi| upi.vpa.clone()),
            "payeeVA": auth_type.merchant_id.peek(),
            "custRefNo": customer_id.get_string_repr(),
            "remarks": item.router_data.request.description.clone().unwrap_or_default()
        }).to_string();

        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => Ok(Self {
                V: "1.0".to_string(),
                requestMsg: request_msg,
                pgMerchantId: auth_type.merchant_id,
            }),
            _ => Err(errors::ConnectorError::NotImplemented(
                "Only UPI payment method is supported".to_string(),
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
        + Serialize,
>
TryFrom<
    HdfcUpiRouterData<
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        T,
    >,
> for HdfcUpiPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: HdfcUpiRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth_type = HdfcUpiAuth::try_from(&item.router_data.connector_auth_type)?;
        
        // Get transaction ID from the request
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        // Build request message for status query
        let request_msg = serde_json::json!({
            "upiTxnId": transaction_id
        }).to_string();

        Ok(Self {
            V: "1.0".to_string(),
            requestMsg: request_msg,
            pgMerchantId: auth_type.merchant_id,
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
        + Serialize
        + Serialize,
> TryFrom<ResponseRouterData<HdfcUpiPaymentsResponse, Self>>
for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<HdfcUpiPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let (status, response) = match response {
            HdfcUpiPaymentsResponse::HdfcUpiError(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.code.to_string(),
                    status_code: item.http_code,
                    message: error_data.response.clone(),
                    reason: Some(error_data.response),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            HdfcUpiPaymentsResponse::HdfcUpiData(response_data) => {
                let payment_status = get_payment_status(&response_data.status);
                
                (
                    payment_status.into(),
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            response_data.upiTxnId.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: Some(serde_json::json!({
                            "orderNo": response_data.orderNo,
                            "payerVA": response_data.payerVA,
                            "payeeVA": response_data.payeeVA,
                            "statusDesc": response_data.statusDesc
                        })),
                        network_txn_id: Some(response_data.upiTxnId),
                        connector_response_reference_id: Some(response_data.orderNo),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
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
        + Serialize
        + Serialize,
> TryFrom<ResponseRouterData<HdfcUpiPaymentsSyncResponse, Self>>
for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<HdfcUpiPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let payment_status = get_payment_status(&response.status);
        
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status: payment_status.into(),
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.upiTxnId.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: Some(serde_json::json!({
                    "orderNo": response.orderNo,
                    "txnAuthDate": response.txnAuthDate,
                    "statusDesc": response.statusDesc,
                    "responseCode": response.responseCode,
                    "approvalNumber": response.approvalNumber,
                    "payerVA": response.payerVA,
                    "customerReferenceNo": response.customerReferenceNo,
                    "referenceId": response.referenceId
                })),
                network_txn_id: Some(response.upiTxnId),
                connector_response_reference_id: Some(response.orderNo),
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}