use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    request::Method,
    types::StringMinorUnit,
};
use domain_types::{
    connector_types::{PaymentsResponseData, ResponseId},
    errors::{self, ConnectorError},
    router_data::ConnectorAuthType,
    router_response_types::RedirectForm,
    utils,
};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    msg: String,
    paydata: Option<String>,
    ipaddress: String,
    useragent: String,
}

#[derive(Default, Debug, Serialize)]
pub struct BilldeskPaymentsSyncRequest {
    msg: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BilldeskPaymentsResponse {
    BilldeskError(BilldeskErrorResponse),
    BilldeskData(BilldeskPaymentsResponseData),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsResponseData {
    pub msg: Option<String>,
    pub rdata: Option<BilldeskRdata>,
    pub txnrefno: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRdata {
    pub parameters: HashMap<String, String>,
    pub url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncResponse {
    pub _MerchantID: String,
    pub _CustomerID: String,
    pub _TxnReferenceNo: String,
    pub _BankReferenceNo: String,
    pub _TxnAmount: String,
    pub _BankID: String,
    pub _TxnType: Option<String>,
    pub _CurrencyType: String,
    pub _ItemCode: String,
    pub _TxnDate: Option<String>,
    pub _AuthStatus: String,
    pub _AdditionalInfo1: Option<String>,
    pub _AdditionalInfo2: Option<String>,
    pub _AdditionalInfo3: Option<String>,
    pub _AdditionalInfo4: Option<String>,
    pub _AdditionalInfo5: Option<String>,
    pub _AdditionalInfo6: Option<String>,
    pub _AdditionalInfo7: Option<String>,
    pub _ErrorStatus: String,
    pub _ErrorDescription: String,
    pub _Checksum: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskErrorResponse {
    pub error: serde_json::Value,
    pub error_description: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskAuth {
    pub merchant_id: Secret<String>,
    pub checksum_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => {
                Ok(Self {
                    merchant_id: api_key.clone(),
                    checksum_key: key1.clone(),
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BilldeskPaymentStatus {
    #[default]
    Pending,
    Success,
    Failure,
}

impl From<BilldeskPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: BilldeskPaymentStatus) -> Self {
        match item {
            BilldeskPaymentStatus::Success => Self::Charged,
            BilldeskPaymentStatus::Pending => Self::AuthenticationPending,
            BilldeskPaymentStatus::Failure => Self::Failure,
        }
    }
}

// Simplified request conversion - will be implemented with proper types later
impl TryFrom<()> for BilldeskPaymentsRequest {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(_item: ()) -> Result<Self, Self::Error> {
        Ok(Self {
            msg: "test_message".to_string(),
            paydata: None,
            ipaddress: "127.0.0.1".to_string(),
            useragent: "Mozilla/5.0".to_string(),
        })
    }
}

// Simplified sync request conversion - will be implemented with proper types later
impl TryFrom<()> for BilldeskPaymentsSyncRequest {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(_item: ()) -> Result<Self, Self::Error> {
        Ok(Self {
            msg: "sync_message".to_string(),
        })
    }
}

fn get_merchant_id(connector_auth_type: &ConnectorAuthType) -> Result<String, errors::ConnectorError> {
    match BilldeskAuth::try_from(connector_auth_type) {
        Ok(billdesk_auth) => Ok(billdesk_auth.merchant_id.peek().to_string()),
        Err(_) => Err(errors::ConnectorError::FailedToObtainAuthType),
    }
}

fn get_redirect_form_data(
    payment_method_type: common_enums::PaymentMethodType,
    response_data: BilldeskPaymentsResponseData,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    match payment_method_type {
        common_enums::PaymentMethodType::Upi => {
            if let Some(rdata) = response_data.rdata {
                let url = rdata.url.unwrap_or_default();
                Ok(RedirectForm::Form {
                    endpoint: url,
                    method: Method::Post,
                    form_fields: rdata
                        .parameters
                        .into_iter()
                        .map(|(k, v)| (k, v.into_masked()))
                        .collect(),
                })
            } else {
                Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "rdata",
                }
                .into())
            }
        }
        _ => Err(errors::ConnectorError::NotImplemented(
            utils::get_unimplemented_payment_method_error_message("Billdesk"),
        ).into()),
    }
}

// Simplified response conversion - will be implemented with proper types later
impl TryFrom<BilldeskPaymentsResponse> for PaymentsResponseData {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: BilldeskPaymentsResponse) -> Result<Self, Self::Error> {
        match response {
            BilldeskPaymentsResponse::BilldeskError(error_data) => {
                Err(errors::ConnectorError::RequestEncodingFailed.into())
            }
            BilldeskPaymentsResponse::BilldeskData(_) => {
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId("txn_id".to_string()),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: 200,
                })
            }
        }
    }
}

impl TryFrom<BilldeskPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: BilldeskPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let status = match response._AuthStatus.as_str() {
            "0300" | "0399" => common_enums::AttemptStatus::Charged,
            "0396" => common_enums::AttemptStatus::AuthorizationPending,
            "0397" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Failure,
        };

        let amount = response._TxnAmount.parse::<i64>()
            .map(|amt| common_utils::types::MinorUnit::from_i64(amt))
            .ok();

        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response._TxnReferenceNo),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: Some(response._BankReferenceNo),
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: 200,
        })
    }
}

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct BilldeskVoidRequest;
#[derive(Debug, Clone)]
pub struct BilldeskVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskCaptureRequest;
#[derive(Debug, Clone)]
pub struct BilldeskCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskRefundRequest;
#[derive(Debug, Clone)]
pub struct BilldeskRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskRefundSyncRequest;
#[derive(Debug, Clone)]
pub struct BilldeskRefundSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct BilldeskCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct BilldeskSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct BilldeskSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct BilldeskRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct BilldeskAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct BilldeskDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct BilldeskSubmitEvidenceResponse;