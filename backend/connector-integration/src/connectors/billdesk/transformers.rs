use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    request::Method,
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};

use hyperswitch_masking::{ExposeInterface, Maskable, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    paydata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    txtBankID: Option<String>,
    ipaddress: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    useragent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mobile: Option<String>,
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
#[serde(untagged)]
pub enum BilldeskPaymentsSyncResponse {
    BilldeskError(BilldeskErrorResponse),
    BilldeskData(BilldeskStatusResponseMsg),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsResponseData {
    #[serde(skip_serializing_if = "Option::is_none")]
    msg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rdata: Option<BilldeskRdataResp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    txnrefno: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRdataResp {
    parameters: HashMap<String, String>,
    url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskStatusResponseMsg {
    #[serde(rename = "RequestType")]
    pub request_type: Option<String>,
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "CustomerID")]
    pub customer_id: String,
    #[serde(rename = "TxnReferenceNo")]
    pub txn_reference_no: String,
    #[serde(rename = "BankReferenceNo")]
    pub bank_reference_no: String,
    #[serde(rename = "TxnAmount")]
    pub txn_amount: String,
    #[serde(rename = "BankID")]
    pub bank_id: String,
    #[serde(rename = "Filler1")]
    pub filler1: Option<String>,
    #[serde(rename = "TxnType")]
    pub txn_type: Option<String>,
    #[serde(rename = "CurrencyType")]
    pub currency_type: String,
    #[serde(rename = "ItemCode")]
    pub item_code: String,
    #[serde(rename = "Filler2")]
    pub filler2: Option<String>,
    #[serde(rename = "Filler3")]
    pub filler3: Option<String>,
    #[serde(rename = "Filler4")]
    pub filler4: Option<String>,
    #[serde(rename = "TxnDate")]
    pub txn_date: Option<String>,
    #[serde(rename = "AuthStatus")]
    pub auth_status: String,
    #[serde(rename = "Filler5")]
    pub filler5: Option<String>,
    #[serde(rename = "AdditionalInfo1")]
    pub additional_info1: Option<String>,
    #[serde(rename = "AdditionalInfo2")]
    pub additional_info2: Option<String>,
    #[serde(rename = "AdditionalInfo3")]
    pub additional_info3: Option<String>,
    #[serde(rename = "AdditionalInfo4")]
    pub additional_info4: Option<String>,
    #[serde(rename = "AdditionalInfo5")]
    pub additional_info5: Option<String>,
    #[serde(rename = "AdditionalInfo6")]
    pub additional_info6: Option<String>,
    #[serde(rename = "AdditionalInfo7")]
    pub additional_info7: Option<String>,
    #[serde(rename = "ErrorStatus")]
    pub error_status: String,
    #[serde(rename = "ErrorDescription")]
    pub error_description: String,
    #[serde(rename = "Filler6")]
    pub filler6: Option<String>,
    #[serde(rename = "RefundStatus")]
    pub refund_status: String,
    #[serde(rename = "TotalRefundAmount")]
    pub total_refund_amount: String,
    #[serde(rename = "LastRefundDate")]
    pub last_refund_date: Option<String>,
    #[serde(rename = "LastRefundRefNo")]
    pub last_refund_ref_no: Option<String>,
    #[serde(rename = "QueryStatus")]
    pub query_status: String,
    #[serde(rename = "Checksum")]
    pub checksum: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskAuthType {
    pub merchant_id: Secret<String>,
    pub checksum_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => {
                let merchant_id = api_key.clone();
                let checksum_key = key1.clone();
                
                Ok(Self {
                    merchant_id,
                    checksum_key,
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

pub fn get_billdesk_auth_headers(
    _connector_auth_type: &ConnectorAuthType,
) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
    // Billdesk typically uses custom headers for authentication
    // The actual authentication is done via checksum in the request body
    Ok(vec![])
}

fn create_billdesk_message(
    merchant_id: &str,
    customer_id: &str,
    txn_reference_no: &str,
    amount: &str,
    currency: &str,
    additional_params: &HashMap<String, String>,
) -> String {
    let mut msg_parts = vec![
        format!("MerchantID={}", merchant_id),
        format!("CustomerID={}", customer_id),
        format!("TxnReferenceNo={}", txn_reference_no),
        format!("TxnAmount={}", amount),
        format!("CurrencyType={}", currency),
        format!("ItemCode=DIRECT"),
    ];

    // Add additional parameters
    for (key, value) in additional_params {
        msg_parts.push(format!("{}={}", key, value));
    }

    msg_parts.join("|")
}

impl<T>
    TryFrom<BilldeskRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for BilldeskPaymentsRequest
where
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: BilldeskRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let transaction_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        
        // CRITICAL: Use proper amount framework - get amount as string from converter
        let amount = item.connector.amount_converter.convert(
            item.router_data.request.minor_amount,
            item.router_data.request.currency,
        ).map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;
        let amount_str = amount.to_string();

        let auth = BilldeskAuthType::try_from(&item.router_data.connector_auth_type)?;
        let merchant_id = auth.merchant_id.peek();

        // CRITICAL: Use proper IP address extraction
        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        // CRITICAL: Use proper user agent extraction
        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        match item.router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::UpiCollect) => {
                let mut additional_params = HashMap::new();
                additional_params.insert("BankID".to_string(), "UPI".to_string());
                additional_params.insert("TxnType".to_string(), "PURCHASE".to_string());
                
                let msg = create_billdesk_message(
                    merchant_id,
                    &customer_id.get_string_repr(),
                    &transaction_id,
                    &amount,
                    &item.router_data.request.currency.to_string(),
                    &additional_params,
                );

                Ok(Self {
                    msg,
                    paydata: None, // Will be populated with UPI specific data
                    txtBankID: None,
                    ipaddress: ip_address,
                    useragent: Some(user_agent),
                    mobile: None,
                })
            }
            Some(common_enums::PaymentMethodType::UpiIntent) => {
                let mut additional_params = HashMap::new();
                additional_params.insert("BankID".to_string(), "UPI".to_string());
                additional_params.insert("TxnType".to_string(), "PURCHASE".to_string());
                
                let msg = create_billdesk_message(
                    merchant_id,
                    &customer_id.get_string_repr(),
                    &transaction_id,
                    &amount,
                    &item.router_data.request.currency.to_string(),
                    &additional_params,
                );

                Ok(Self {
                    msg,
                    paydata: None, // Will be populated with UPI specific data
                    txtBankID: None,
                    ipaddress: ip_address,
                    useragent: Some(user_agent),
                    mobile: None,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported".to_string(),
            )
            .into()),
        }
    }
}

impl<T>
    TryFrom<BilldeskRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for BilldeskPaymentsSyncRequest
where
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: BilldeskRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let transaction_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let auth = BilldeskAuthType::try_from(&item.router_data.connector_auth_type)?;
        let merchant_id = auth.merchant_id.peek();

        let additional_params = HashMap::new();
        let msg = create_billdesk_message(
            merchant_id,
            &customer_id.get_string_repr(),
            &transaction_id,
            "0", // Amount not needed for status check
            &item.router_data.request.currency.to_string(),
            &additional_params,
        );

        Ok(Self { msg })
    }
}

fn get_redirect_form_data(
    payment_method_type: common_enums::PaymentMethodType,
    response_data: BilldeskPaymentsResponseData,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    match payment_method_type {
        common_enums::PaymentMethodType::UpiCollect => {
            if let Some(rdata) = response_data.rdata {
                let url = rdata.url.unwrap_or_else(|| "https://api.billdesk.com".to_string());
                Ok(RedirectForm::Form {
                    endpoint: url,
                    method: Method::Post,
                    form_fields: rdata
                        .parameters
                        .into_iter()
                        .map(|(k, v)| (k, v.into()))
                        .collect(),
                })
            } else {
                Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "rdata",
                }
                .into())
            }
        }
        common_enums::PaymentMethodType::UpiIntent => {
            if let Some(rdata) = response_data.rdata {
                let url = rdata.url.unwrap_or_else(|| "https://api.billdesk.com".to_string());
                Ok(RedirectForm::Form {
                    endpoint: url,
                    method: Method::Post,
                    form_fields: rdata
                        .parameters
                        .into_iter()
                        .map(|(k, v)| (k, v.into()))
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
            "Payment method not supported".to_string(),
        ))?,
    }
}

impl<T>
    TryFrom<ResponseRouterData<BilldeskPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = match response {
            BilldeskPaymentsResponse::BilldeskError(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error.to_string(),
                    status_code: http_code,
                    message: error_data.error_description.clone().unwrap_or_default(),
                    reason: error_data.error_description,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            BilldeskPaymentsResponse::BilldeskData(response_data) => {
                let payment_method_type = router_data
                    .request
                    .payment_method_type
                    .ok_or(errors::ConnectorError::MissingPaymentMethodType)?;
                
                let redirection_data = get_redirect_form_data(payment_method_type, response_data)?;
                
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

impl TryFrom<ResponseRouterData<BilldeskPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = match response {
            BilldeskPaymentsSyncResponse::BilldeskError(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error.to_string(),
                    status_code: http_code,
                    message: error_data.error_description.clone().unwrap_or_default(),
                    reason: error_data.error_description,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            BilldeskPaymentsSyncResponse::BilldeskData(response_data) => {
                // Map Billdesk status to our status
                let status = match response_data.auth_status.as_str() {
                    "0300" => common_enums::AttemptStatus::Charged,
                    "0396" => common_enums::AttemptStatus::AuthenticationPending,
                    "0399" => common_enums::AttemptStatus::Pending,
                    _ => common_enums::AttemptStatus::Failure,
                };

                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            response_data.txn_reference_no.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: Some(response_data.bank_reference_no.clone()),
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