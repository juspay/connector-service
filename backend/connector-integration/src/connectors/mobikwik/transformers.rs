
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::mobikwik::MobikwikRouterData, types::ResponseRouterData};

// Simplified request/response types for UPI flows
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MobikwikPaymentsResponse {
    Success(MobikwikSuccessResponse),
    Error(MobikwikErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MobikwikSuccessResponse {
    pub statuscode: String,
    pub orderid: String,
    pub amount: String,
    pub statusmessage: String,
    pub checksum: String,
    pub mid: String,
    pub refid: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MobikwikErrorResponse {
    pub error: bool,
    pub error_message: String,
    pub user_message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MobikwikPaymentsSyncResponse {
    pub statuscode: String,
    pub orderid: String,
    pub refid: Option<String>,
    pub amount: Option<String>,
    pub statusmessage: String,
    pub ordertype: String,
    pub checksum: String,
}

#[derive(Debug, Serialize)]
pub struct CheckStatusRequest {
    pub mid: String,
    pub orderid: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MobiSyncResponse {
    pub code: i32,
    pub status: String,
    pub response: CheckStatusWalletType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CheckStatusWalletType {
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
    
    // Simple SHA256 hash
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(string_to_hash.as_bytes());
    let result = hasher.finalize();
    
    hex::encode(result)
}

// Simplified TryFrom implementations using generic T
impl<T> TryFrom<
    MobikwikRouterData<
        RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        T,
    >,
> for MobikwikPaymentsRequest
where
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: MobikwikRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
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
        
        let return_url = item.router_data.request.get_router_return_url()
            .change_context(ConnectorError::MissingRequiredField { field_name: "return_url" })?;
        let order_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        
        // Extract phone number - simplified
        let phone_number = item.router_data.request.payment_method_data
            .as_ref()
            .and_then(|pm| pm.get_phone_number())
            .unwrap_or_else(|| "9999999999".to_string());
        
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
            token: None,
            redirecturl: return_url,
            checksum,
            version: "2.0".to_string(),
            msgcode: "309".to_string(),
            txntype: "debit".to_string(),
            comment: Some("UPI Payment".to_string()),
            email,
        })
    }
}

impl<T> TryFrom<
    MobikwikRouterData<
        RouterDataV2<
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
        >,
        T,
    >,
> for CheckStatusRequest
where
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
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
            T,
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
impl<T> TryFrom<ResponseRouterData<MobikwikPaymentsResponse, Self>>
for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
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
                let status = match success_data.statuscode.as_str() {
                    "0" => common_enums::AttemptStatus::Charged,
                    "1" => common_enums::AttemptStatus::Pending,
                    _ => common_enums::AttemptStatus::Failure,
                };
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

impl<T> TryFrom<ResponseRouterData<MobiSyncResponse, Self>>
for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
where
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
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
        
        let sync_data = response.response;
        let status = match sync_data.statuscode.as_str() {
            "0" => common_enums::AttemptStatus::Charged,
            "1" => common_enums::AttemptStatus::Pending,
            _ => common_enums::AttemptStatus::Failure,
        };
        
        let response_data = Ok(PaymentsResponseData::TransactionResponse {
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
        });
        
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