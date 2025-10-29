use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    request::Method,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

// Type alias for router data
pub type TpslRouterData<R, T> = ResponseRouterData<R, T>;

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsRequest {
    #[serde(rename = "getTransactionToken")]
    pub get_transaction_token: TpslTransactionMessage,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionMessage {
    pub msg: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncRequest {
    #[serde(rename = "getTransactionToken")]
    pub get_transaction_token: TpslSyncMessage,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslSyncMessage {
    pub msg: String,
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
#[serde(rename_all = "camelCase")]
pub struct TpslAuth {
    pub merchant_code: Secret<String>,
    pub merchant_key: Secret<String>,
    pub merchant_salt: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for TpslAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => {
                let merchant_code = api_key.clone();
                let merchant_key = key1.clone();
                let merchant_salt = Secret::new("default_salt".to_string()); // Default salt, should be configurable

                Ok(Self {
                    merchant_code,
                    merchant_key,
                    merchant_salt,
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

pub fn get_tpsl_auth_headers(
    auth_type: &TpslAuth,
) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
    Ok(vec![
        ("merchantCode".to_string(), hyperswitch_masking::Maskable::from(auth_type.merchant_code.expose())),
        ("merchantKey".to_string(), hyperswitch_masking::Maskable::from(auth_type.merchant_key.expose())),
    ])
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionResponse {
    #[serde(rename = "getTransactionTokenResponse")]
    pub get_transaction_token_response: TpslTokenResponse,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTokenResponse {
    #[serde(rename = "getTransactionTokenReturn")]
    pub get_transaction_token_return: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsResponse {
    #[serde(rename = "__soapenv:Envelope")]
    pub envelope: TpslEnvelope,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslEnvelope {
    #[serde(rename = "__soapenv:Body")]
    pub body: TpslBody,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslBody {
    #[serde(rename = "getTransactionTokenResponse")]
    pub get_transaction_token_response: TpslTokenResponse,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncResponse {
    #[serde(rename = "__soapenv:Envelope")]
    pub envelope: TpslSyncEnvelope,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslSyncEnvelope {
    #[serde(rename = "__soapenv:Body")]
    pub body: TpslSyncBody,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslSyncBody {
    pub response: TpslSyncData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslSyncData {
    #[serde(rename = "txn_status")]
    pub txn_status: String,
    #[serde(rename = "txn_msg")]
    pub txn_msg: Option<String>,
    #[serde(rename = "txn_err_msg")]
    pub txn_err_msg: String,
    #[serde(rename = "clnt_txn_ref")]
    pub clnt_txn_ref: String,
    #[serde(rename = "tpsl_txn_id")]
    pub tpsl_txn_id: Option<String>,
    #[serde(rename = "txn_amt")]
    pub txn_amt: Option<String>,
    #[serde(rename = "tpsl_txn_time")]
    pub tpsl_txn_time: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslErrorResponse {
    #[serde(rename = "_ErrorCode")]
    pub error_code: String,
    #[serde(rename = "_ErrorMessage")]
    pub error_message: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TpslPaymentStatus {
    #[default]
    Pending,
    Success,
    Failure,
}

impl From<TpslPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: TpslPaymentStatus) -> Self {
        match item {
            TpslPaymentStatus::Success => Self::Charged,
            TpslPaymentStatus::Pending => Self::AuthenticationPending,
            TpslPaymentStatus::Failure => Self::Failure,
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
        let transaction_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        
        let amount = item
            .router_data
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Create transaction message based on UPI payment method
        let transaction_msg = match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => {
                format!(
                    r#"{{
                        "merchant": {{
                            "identifier": "{}"
                        }},
                        "cart": {{
                            "item": [{{
                                "amount": "{}",
                                "identifier": "UPI_ITEM_1",
                                "reference": "{}"
                            }}]
                        }},
                        "payment": {{
                            "method": {{
                                "code": "UPI",
                                "type": "COLLECT"
                            }},
                            "instrument": {{
                                "type": "UPI",
                                "identifier": "{}"
                            }}
                        }},
                        "transaction": {{
                            "amount": "{}",
                            "currency": "{}",
                            "identifier": "{}",
                            "requestType": "TXN"
                        }},
                        "consumer": {{
                            "identifier": "{}",
                            "emailID": "{}",
                            "mobileNumber": "{}"
                        }}
                    }}"#,
                    "MERCHANT_ID", // Will be extracted from auth
                    amount,
                    transaction_id,
                    "UPI_INSTRUMENT_ID", // Will be extracted from payment method data
                    amount,
                    item.router_data.request.currency,
                    transaction_id,
                    customer_id,
                    item.router_data.request.email.as_ref().map(|e| e.to_string()).unwrap_or_default(),
                    item.router_data.request.phone_number.as_ref().map(|p| p.to_string()).unwrap_or_default()
                )
            }
            _ => return Err(errors::ConnectorError::NotImplemented("Payment method".to_string()).into()),
        };

        Ok(Self {
            get_transaction_token: TpslTransactionMessage {
                msg: transaction_msg,
            },
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
        let transaction_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id;

        let sync_msg = format!(
            r#"{{
                "merchant": {{
                    "identifier": "MERCHANT_ID"
                }},
                "transaction": {{
                    "identifier": "{}",
                    "requestType": "STATUS"
                }}
            }}"#,
            transaction_id
        );

        Ok(Self {
            get_transaction_token: TpslSyncMessage { msg: sync_msg },
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

        let token_response = response.envelope.body.get_transaction_token_response;
        let connector_request_reference_id = router_data.resource_common_data.connector_request_reference_id.clone();
        
        // For UPI payments, TPSL typically returns a redirect URL or payment instruction
        let redirection_data = Some(Box::new(RedirectForm::Form {
            endpoint: token_response.get_transaction_token_return,
            method: Method::Post,
            form_fields: HashMap::new(),
        }));

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status: common_enums::AttemptStatus::AuthenticationPending,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    connector_request_reference_id,
                ),
                redirection_data,
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

impl<F> TryFrom<ResponseRouterData<TpslPaymentsSyncResponse, Self>>
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

        let sync_data = response.envelope.body.response;
        
        let status = match sync_data.txn_status.as_str() {
            "SUCCESS" | "SUCCESSFUL" => common_enums::AttemptStatus::Charged,
            "PENDING" => common_enums::AttemptStatus::AuthenticationPending,
            "FAILURE" | "FAILED" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::AuthenticationPending,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    sync_data.clnt_txn_ref,
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: sync_data.tpsl_txn_id,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}