use common_utils::{
    ext_traits::ValueExt,
    types::StringMinorUnit,
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
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::mobikwik::MobikwikRouterData, types::ResponseRouterData};

// Request/Response Types based on Haskell implementation

#[derive(Debug, Serialize)]
pub struct CheckExistingUserRequest {
    pub cell: String,
    pub merchantname: String,
    pub mid: String,
    pub action: String,
    pub msgcode: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize)]
pub struct ExistingUserResponseType {
    pub messagecode: String,
    pub status: String,
    pub statuscode: String,
    pub statusdescription: String,
    pub emailaddress: Option<String>,
    pub range: Option<String>,
    pub nonzeroflag: Option<String>,
    pub checksum: String,
}

#[derive(Debug, Serialize)]
pub struct OtpGenerationRequest {
    pub cell: String,
    pub amount: String,
    pub merchantname: String,
    pub mid: String,
    pub msgcode: String,
    pub tokentype: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize)]
pub struct OtpResponseType {
    pub messagecode: String,
    pub status: String,
    pub statuscode: String,
    pub statusdescription: String,
    pub checksum: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenGenerateRequest {
    pub cell: String,
    pub merchantname: String,
    pub mid: String,
    pub otp: String,
    pub amount: String,
    pub msgcode: String,
    pub tokentype: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponseType {
    pub messagecode: String,
    pub status: String,
    pub statuscode: String,
    pub statusdescription: String,
    pub token: Option<String>,
    pub checksum: String,
}

#[derive(Debug, Serialize)]
pub struct TokenRegenerationRequest {
    pub cell: String,
    pub merchantname: String,
    pub mid: String,
    pub token: String,
    pub msgcode: String,
    pub tokentype: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenRegenResponseType {
    pub messagecode: String,
    pub status: String,
    pub statuscode: String,
    pub statusdescription: String,
    pub token: Option<String>,
    pub checksum: String,
}

#[derive(Debug, Serialize)]
pub struct CreateUserRequest {
    pub cell: String,
    pub merchantname: String,
    pub mid: String,
    pub otp: String,
    pub msgcode: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserResponseType {
    pub messagecode: String,
    pub status: String,
    pub statuscode: String,
    pub statusdescription: String,
    pub checksum: String,
}

#[derive(Debug, Serialize)]
pub struct CheckMobiKwikBalanceRequest {
    pub cell: String,
    pub merchantname: String,
    pub mid: String,
    pub token: String,
    pub msgcode: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize)]
pub struct BalanceResponseType {
    pub messagecode: String,
    pub status: String,
    pub statuscode: String,
    pub statusdescription: String,
    pub balanceamount: Option<String>,
    pub checksum: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AddMoneyDebitRequest {
    pub amount: String,
    pub cell: String,
    pub orderid: String,
    pub merchantname: String,
    pub mid: String,
    pub token: String,
    pub redirecturl: String,
    pub checksum: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct AddMoneyDebitResponse {
    pub statuscode: String,
    pub amount: String,
    pub orderid: String,
    pub statusmessage: String,
    pub checksum: String,
    pub mid: String,
    pub refid: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RedirectDebitRequest {
    pub email: Option<String>,
    pub amount: String,
    pub cell: Option<String>,
    pub orderid: String,
    pub mid: String,
    pub merchantname: String,
    pub redirecturl: String,
    pub showmobile: Option<String>,
    pub version: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize)]
pub struct RedirectDebitResponse {
    pub statuscode: String,
    pub orderid: String,
    pub amount: String,
    pub statusmessage: String,
    pub checksum: String,
    pub mid: String,
    pub refid: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DebitMobiKwikBalanceRequest {
    pub cell: String,
    pub merchantname: String,
    pub mid: String,
    pub token: String,
    pub orderid: String,
    pub txntype: String,
    pub msgcode: String,
    pub amount: String,
    pub comment: String,
    pub checksum: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct DebitResponseType {
    pub messagecode: String,
    pub status: String,
    pub statuscode: String,
    pub statusdescription: String,
    pub debitedamount: Option<String>,
    pub balanceamount: Option<String>,
    pub orderid: Option<String>,
    pub refid: Option<String>,
    pub checksum: String,
}

#[derive(Debug, Serialize)]
pub struct CheckStatusRequest {
    pub mid: String,
    pub orderid: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize)]
pub struct CheckStatusWalletType {
    pub statuscode: String,
    pub orderid: String,
    pub refid: Option<String>,
    pub amount: Option<String>,
    pub statusmessage: String,
    pub ordertype: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize)]
pub struct MobiSyncResponse {
    pub code: i32,
    pub status: String,
    pub response: StatusResp,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum StatusResp {
    ValidMobiSyncResponse(CheckStatusWalletType),
    StatusInvalidResponse(EulerErrorResponse),
    ErrorResponse(ValidationErrorResponse),
}

#[derive(Debug, Deserialize)]
pub struct ValidationErrorResponse {
    pub message: String,
    pub error_code: String,
    pub response: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct MobRefundRequest {
    pub mid: String,
    pub txid: String,
    pub refundid: String,
    pub amount: String,
    pub checksum: String,
    pub refund_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RefundWalletType {
    pub status: String,
    pub statuscode: String,
    pub statusmessage: Option<String>,
    pub txid: String,
    pub refid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MobikwikRefundResponse {
    pub code: i32,
    pub status: String,
    pub response: RefundResp,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RefundResp {
    ValidMobRefundResponse(RefundWalletType),
    RefundErrorResponse(EulerErrorResponse),
}

#[derive(Debug, Deserialize)]
pub struct EulerErrorResponse {
    pub error: bool,
    pub error_message: String,
    pub user_message: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum MobikwikTxnResp {
    DirectDebit(DebitResponseType),
    AddMoneyRedirectFlow(AddMoneyDebitResponse),
    RedirectFlow(RedirectDebitResponse),
    VerifyFailResponse(MobikwikVerifyFailResponse),
}

#[derive(Debug, Deserialize)]
pub struct MobikwikVerifyFailResponse {
    pub error_code: String,
    pub error_message: String,
    pub failure_response: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct MobiRefundSyncRequest {
    pub mid: String,
    pub orderid: String,
    pub refundid: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize)]
pub struct MobiRefundSyncResponse {
    pub code: i32,
    pub status: String,
    pub response: RefundStatusResp,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RefundStatusResp {
    ValidRefundSyncResponse(MobikwikRefundSyncType),
    RefundStatusInvalidResponse(EulerErrorResponse),
    RefundSyncErrorResponse(ValidationErrorResponse),
}

#[derive(Debug, Deserialize)]
pub struct MobikwikRefundSyncType {
    pub status: String,
    pub statuscode: String,
    pub orderid: Option<String>,
    pub txnamount: Option<String>,
    pub refundamount: Option<String>,
    pub refid: Option<String>,
    pub refundid: Option<String>,
    pub partialrefunds: Option<MobikwikPartialRefundType>,
    pub checksum: Option<String>,
    pub statusmessage: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MobikwikPartialRefundType {
    pub status: String,
    pub refid: Option<String>,
    pub refundid: String,
    pub refundamount: String,
    pub timestamp: String,
    pub statuscode: String,
}

// Main request/response types for UPI flows
#[derive(Debug, Serialize)]
pub struct MobikwikPaymentsRequest {
    pub cell: String,
    pub amount: String,
    pub merchantname: String,
    pub mid: String,
    pub orderid: String,
    pub token: Option<String>,
    pub redirecturl: String,
    pub checksum: String,
    pub version: String,
    pub msgcode: String,
    pub txntype: String,
    pub comment: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum MobikwikPaymentsResponse {
    Success(MobikwikSuccessResponse),
    Error(MobikwikErrorResponse),
}

#[derive(Debug, Deserialize)]
pub struct MobikwikSuccessResponse {
    pub statuscode: String,
    pub orderid: String,
    pub amount: String,
    pub statusmessage: String,
    pub checksum: String,
    pub mid: String,
    pub refid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MobikwikErrorResponse {
    pub error: bool,
    pub error_message: String,
    pub user_message: String,
}

#[derive(Debug, Deserialize)]
pub struct MobikwikPaymentsSyncResponse {
    pub statuscode: String,
    pub orderid: String,
    pub refid: Option<String>,
    pub amount: Option<String>,
    pub statusmessage: String,
    pub ordertype: String,
    pub checksum: String,
}

// Auth types
#[derive(Debug, Deserialize)]
pub struct MobikwikAuthType {
    pub merchant_id: Secret<String>,
    pub secret_key: Secret<String>,
    pub merchant_name: String,
}

impl TryFrom<&ConnectorAuthType> for MobikwikAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => {
                let auth: MobikwikAuthType = api_key
                    .to_owned()
                    .parse_str("MobikwikAuthType")
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(auth)
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Helper functions
fn get_auth_data(connector_auth_type: &ConnectorAuthType) -> Result<MobikwikAuthType, error_stack::Report<ConnectorError>> {
    MobikwikAuthType::try_from(connector_auth_type)
}

fn generate_checksum(params: &[(&str, &str)], secret_key: &str) -> String {
    let mut sorted_params: Vec<_> = params.iter().collect();
    sorted_params.sort_by_key(|&(k, _)| *k);
    
    let query_string: String = sorted_params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");
    
    let string_to_hash = format!("{}{}", query_string, secret_key);
    
    // Simple SHA256 hash for now - in production, use proper crypto
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(string_to_hash.as_bytes());
    let result = hasher.finalize();
    
    hex::encode(result)
}

// Implement TryFrom for payment request
impl TryFrom<
    MobikwikRouterData<
        RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<domain_types::payment_method_data::UpiData>,
            PaymentsResponseData,
        >,
        domain_types::payment_method_data::UpiData,
    >,
> for MobikwikPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: MobikwikRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<domain_types::payment_method_data::UpiData>,
                PaymentsResponseData,
            >,
            domain_types::payment_method_data::UpiData,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_data(&item.router_data.connector_auth_type)?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;
        
        let return_url = item.router_data.request.get_router_return_url()?;
        let order_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        
        // Extract phone number from payment method data
        let phone_number = item.router_data.request.payment_method_data
            .as_ref()
            .map(|pm| pm.vpa.clone())
            .unwrap_or_else(|| "".to_string());
        
        let email = item.router_data.request.email.as_ref().map(|e| e.peek().to_string());
        
        // Prepare checksum parameters
        let checksum_params = vec![
            ("amount", &amount.to_string()),
            ("cell", &phone_number),
            ("merchantname", &auth.merchant_name),
            ("mid", &auth.merchant_id.peek()),
            ("orderid", &order_id),
            ("redirecturl", &return_url),
            ("version", "2.0"),
            ("msgcode", "309"), // DEBIT_BALANCE
            ("txntype", "debit"),
        ];
        
        let checksum = generate_checksum(&checksum_params, &auth.secret_key.peek());
        
        Ok(Self {
            cell: phone_number,
            amount: amount.to_string(),
            merchantname: auth.merchant_name,
            mid: auth.merchant_id.peek().to_string(),
            orderid: order_id,
            token: None, // Will be set if user has existing token
            redirecturl: return_url,
            checksum,
            version: "2.0".to_string(),
            msgcode: "309".to_string(), // DEBIT_BALANCE
            txntype: "debit".to_string(),
            comment: Some("UPI Payment".to_string()),
            email,
        })
    }
}

// Implement TryFrom for sync request
impl TryFrom<
    MobikwikRouterData<
        RouterDataV2<
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
        >,
        domain_types::payment_method_data::UpiData,
    >,
> for CheckStatusRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: MobikwikRouterData<
            RouterDataV2<
                PSync,
                PaymentFlowData,
                PaymentsSyncData,
                PaymentsResponseData,
            >,
            domain_types::payment_method_data::UpiData,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_data(&item.router_data.connector_auth_type)?;
        let order_id = item.router_data.request.connector_transaction_id.get_connector_transaction_id()
            .map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?;
        
        // Prepare checksum parameters
        let checksum_params = vec![
            ("mid", &auth.merchant_id.peek()),
            ("orderid", &order_id),
        ];
        
        let checksum = generate_checksum(&checksum_params, &auth.secret_key.peek());
        
        Ok(Self {
            mid: auth.merchant_id.peek().to_string(),
            orderid: order_id,
            checksum,
        })
    }
}

// Response transformations
impl<
    F,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<ResponseRouterData<MobikwikPaymentsResponse, Self>>
for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<MobikwikPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = match response {
            MobikwikPaymentsResponse::Success(success_data) => {
                let status = map_status_code_to_attempt_status(&success_data.statuscode);
                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            success_data.orderid.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: success_data.refid.clone(),
                        connector_response_reference_id: success_data.refid.clone(),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            MobikwikPaymentsResponse::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "MOBIKWIK_ERROR".to_string(),
                    status_code: http_code,
                    message: error_data.user_message.clone(),
                    reason: Some(error_data.error_message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
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
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<ResponseRouterData<MobiSyncResponse, Self>>
for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<MobiSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = match response.response {
            StatusResp::ValidMobiSyncResponse(sync_data) => {
                let status = map_status_code_to_attempt_status(&sync_data.statuscode);
                let amount_received = sync_data.amount
                    .as_ref()
                    .and_then(|amt| amt.parse::<i64>().ok())
                    .map(common_utils::types::MinorUnit);
                
                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            sync_data.orderid.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: sync_data.refid.clone(),
                        connector_response_reference_id: sync_data.refid.clone(),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            StatusResp::StatusInvalidResponse(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "MOBIKWIK_ERROR".to_string(),
                    status_code: http_code,
                    message: error_data.user_message.clone(),
                    reason: Some(error_data.error_message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            StatusResp::ErrorResponse(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error_code,
                    status_code: http_code,
                    message: error_data.message,
                    reason: None,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
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

fn map_status_code_to_attempt_status(status_code: &str) -> common_enums::AttemptStatus {
    match status_code {
        "0" => common_enums::AttemptStatus::Charged,
        "1" => common_enums::AttemptStatus::Pending,
        "2" => common_enums::AttemptStatus::Failure,
        "3" => common_enums::AttemptStatus::AuthenticationPending,
        _ => common_enums::AttemptStatus::Pending,
    }
}