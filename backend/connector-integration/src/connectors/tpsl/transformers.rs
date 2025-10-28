use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    request::Method,
    types::{StringMinorUnit, MinorUnit},
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{connectors::tpsl::TpslRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsRequest {
    pub getTransactionToken: TpslTransactionRequest,
}

#[derive(Default, Debug, Serialize)]
pub struct TpslTransactionRequest {
    pub msg: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TpslPaymentsResponse {
    TpslError(TpslErrorResponse),
    TpslData(TpslTransactionResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslTransactionResponse {
    #[serde(rename = "return")]
    pub return_value: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslPaymentsSyncRequest {
    pub merchant: TpslMerchantDataType,
    pub payment: TpslPaymentUPISyncType,
    pub transaction: TpslTransactionUPITxnType,
    pub consumer: TpslConsumerDataType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslPaymentsSyncResponse {
    pub merchantCode: String,
    pub merchantTransactionIdentifier: String,
    pub merchantTransactionRequestType: String,
    pub responseType: String,
    pub transactionState: Option<String>,
    pub paymentMethod: TpslUPIPaymentPayload,
    pub error: Option<serde_json::Value>,
    pub merchantResponseString: Option<serde_json::Value>,
    pub statusCode: Option<String>,
    pub statusMessage: Option<String>,
    pub identifier: Option<String>,
    pub bankReferenceIdentifier: Option<String>,
    pub merchantAdditionalDetails: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslMerchantDataType {
    pub identifier: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslPaymentUPISyncType {
    pub instruction: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslTransactionUPITxnType {
    pub deviceIdentifier: String,
    #[serde(rename = "type")]
    pub transaction_type: Option<String>,
    pub subType: Option<String>,
    pub amount: String,
    pub currency: String,
    pub dateTime: String,
    pub requestType: String,
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslConsumerDataType {
    pub identifier: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslUPIPaymentPayload {
    pub token: Option<String>,
    pub instrumentAliasName: String,
    pub instrumentToken: String,
    pub bankSelectionCode: String,
    pub aCS: TpslAcsPayload,
    pub oTP: Option<serde_json::Value>,
    pub paymentTransaction: TpslPaymentTxnPayload,
    pub authentication: Option<serde_json::Value>,
    pub error: TpslPaymentMethodErrorPayload,
    pub paymentMode: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslAcsPayload {
    pub bankAcsFormName: String,
    pub bankAcsHttpMethod: serde_json::Value,
    pub bankAcsParams: Option<serde_json::Value>,
    pub bankAcsUrl: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslPaymentTxnPayload {
    pub amount: String,
    pub balanceAmount: Option<String>,
    pub bankReferenceIdentifier: Option<String>,
    pub dateTime: Option<String>,
    pub errorMessage: Option<String>,
    pub identifier: Option<String>,
    pub refundIdentifier: String,
    pub statusCode: String,
    pub statusMessage: String,
    pub instruction: Option<serde_json::Value>,
    pub reference: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslPaymentMethodErrorPayload {
    pub code: String,
    pub desc: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslErrorResponse {
    pub error_code: String,
    pub error_message: String,
}

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct TpslVoidRequest;

#[derive(Debug, Clone)]
pub struct TpslVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslCaptureRequest;

#[derive(Debug, Clone)]
pub struct TpslCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslRefundRequest;

#[derive(Debug, Clone)]
pub struct TpslRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslRefundSyncRequest;

#[derive(Debug, Clone)]
pub struct TpslRefundSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslCreateOrderRequest;

#[derive(Debug, Clone)]
pub struct TpslCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslSessionTokenRequest;

#[derive(Debug, Clone)]
pub struct TpslSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslMandateRequest;

#[derive(Debug, Clone)]
pub struct TpslMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslRepeatPaymentRequest;

#[derive(Debug, Clone)]
pub struct TpslRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslAcceptDisputeRequest;

#[derive(Debug, Clone)]
pub struct TpslAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslDefendDisputeRequest;

#[derive(Debug, Clone)]
pub struct TpslDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslSubmitEvidenceRequest;

#[derive(Debug, Clone)]
pub struct TpslSubmitEvidenceResponse;

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslAuth {
    pub merchant_id: Secret<String>,
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for TpslAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => Ok(Self {
                merchant_id: api_key.clone(),
                api_key: api_key.clone(),
            }),
            ConnectorAuthType::Key { api_key, .. } => Ok(Self {
                merchant_id: api_key.clone(),
                api_key: api_key.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
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
        TpslRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for TpslPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: TpslRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Create transaction message based on UPI payment method
        let transaction_message = match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => {
                format!(
                    r#"{{
                        "merchant": {{
                            "identifier": "{}"
                        }},
                        "cart": {{
                            "item": [{{
                                "amount": "{}",
                                "comAmt": "0",
                                "sKU": "UPI",
                                "reference": "{}",
                                "identifier": "UPI_001"
                            }}],
                            "description": "UPI Payment"
                        }},
                        "payment": {{
                            "method": {{
                                "token": "UPI",
                                "type": "UPI",
                                "code": "UPI"
                            }},
                            "instrument": {{
                                "expiry": null
                            }},
                            "instruction": null
                        }},
                        "transaction": {{
                            "deviceIdentifier": "WEB",
                            "smsSending": "N",
                            "amount": "{}",
                            "forced3DSCall": "N",
                            "type": "SALE",
                            "description": "UPI Payment",
                            "currency": "{}",
                            "isRegistration": "N",
                            "identifier": "{}",
                            "dateTime": "{}",
                            "token": "",
                            "securityToken": "",
                            "subType": "INTENT",
                            "requestType": "TXN",
                            "reference": "{}",
                            "merchantInitiated": "N",
                            "tenureId": ""
                        }},
                        "consumer": {{
                            "mobileNumber": "{}",
                            "emailID": "{}",
                            "identifier": "{}",
                            "accountNo": "",
                            "accountType": "",
                            "accountHolderName": "",
                            "vpa": "",
                            "aadharNo": ""
                        }},
                        "merchantInputFlags": {{
                            "accountNo": false,
                            "mobileNumber": true,
                            "emailID": true,
                            "cardDetails": false,
                            "mandateDetails": false
                        }}
                    }}"#,
                    customer_id.get_string_repr(),
                    amount,
                    item.router_data.resource_common_data.connector_request_reference_id,
                    amount,
                    item.router_data.request.currency,
                    item.router_data.resource_common_data.connector_request_reference_id,
                    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
                    item.router_data.resource_common_data.connector_request_reference_id,
                    item.router_data.request.get_router_return_url()?.as_str(),
                    item.router_data.request.email.as_ref().map(|e| e.to_string()).unwrap_or_default(),
                    customer_id.get_string_repr()
                )
            }
            _ => return Err(errors::ConnectorError::NotImplemented("Payment method".to_string()).into()),
        };

        Ok(Self {
            getTransactionToken: TpslTransactionRequest {
                msg: transaction_message,
            },
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
> TryFrom<ResponseRouterData<TpslPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<TpslPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = match response {
            TpslPaymentsResponse::TpslError(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error_code.to_string(),
                    status_code: item.http_code,
                    message: error_data.error_message.clone(),
                    reason: Some(error_data.error_message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            TpslPaymentsResponse::TpslData(response_data) => {
                // For UPI payments, we typically get a token that needs to be used for redirection
                let redirection_data = RedirectForm::Form {
                    endpoint: response_data.return_value.clone(),
                    method: Method::Post,
                    form_fields: Default::default(),
                };
                
                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: Some(Box::new(redirection_data)),
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
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
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>
    TryFrom<
        TpslRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for TpslPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: TpslRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            merchant: TpslMerchantDataType {
                identifier: customer_id.get_string_repr(),
            },
            payment: TpslPaymentUPISyncType {
                instruction: serde_json::Value::Null,
            },
            transaction: TpslTransactionUPITxnType {
                deviceIdentifier: "WEB".to_string(),
                transaction_type: Some("SALE".to_string()),
                subType: Some("INTENT".to_string()),
                amount,
                currency: item.router_data.request.currency.to_string(),
                dateTime: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                requestType: "TXN".to_string(),
                token: item.router_data.request.connector_transaction_id.get_connector_transaction_id()
                    .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            },
            consumer: TpslConsumerDataType {
                identifier: customer_id.get_string_repr(),
            },
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
> TryFrom<ResponseRouterData<TpslPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<TpslPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let status = match response.transactionState.as_deref() {
            Some("SUCCESS") | Some("SUCCESSFUL") => common_enums::AttemptStatus::Charged,
            Some("PENDING") | Some("PROCESSING") => common_enums::AttemptStatus::Pending,
            Some("FAILED") | Some("FAILURE") => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        let amount_received = response.paymentMethod.paymentTransaction.amount.parse::<i64>()
            .ok()
            .map(|amt| common_utils::types::MinorUnit::from_major_unit_as_i64(amt as f64));

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.merchantTransactionIdentifier,
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.bankReferenceIdentifier,
                connector_response_reference_id: response.identifier,
                incremental_authorization_allowed: None,
                status_code: http_code,
                amount_received,
                ..Default::default()
            }),
            ..router_data
        })
    }
}