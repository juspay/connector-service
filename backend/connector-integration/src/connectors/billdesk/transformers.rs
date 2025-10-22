use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    request::Method,
    types::StringMinorUnit,
};
use hyperswitch_masking::{ExposeInterface, PeekInterface};
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

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    msg: String,
    useragent: Option<String>,
    ipaddress: Option<String>,
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
pub struct BilldeskPaymentsSyncResponse {
    pub msg: Option<String>,
    pub txnrefno: Option<String>,
    pub merchant_id: Option<String>,
    pub customer_id: Option<String>,
    pub bank_reference_no: Option<String>,
    pub txn_amount: Option<String>,
    pub bank_id: Option<String>,
    pub txn_type: Option<String>,
    pub currency_type: Option<String>,
    pub item_code: Option<String>,
    pub txn_date: Option<String>,
    pub auth_status: Option<String>,
    pub additional_info1: Option<String>,
    pub additional_info2: Option<String>,
    pub additional_info3: Option<String>,
    pub additional_info4: Option<String>,
    pub additional_info5: Option<String>,
    pub additional_info6: Option<String>,
    pub additional_info7: Option<String>,
    pub error_status: Option<String>,
    pub error_description: Option<String>,
    pub checksum: Option<String>,
    pub refund_status: Option<String>,
    pub total_refund_amount: Option<String>,
    pub last_refund_date: Option<String>,
    pub last_refund_ref_no: Option<String>,
    pub query_status: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
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
pub struct BilldeskSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct BilldeskSubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct BilldeskDefendDisputeResponse;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskAuthType {
    pub merchant_id: Option<Secret<String>>,
    pub checksum_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::MultiAuthKey { .. } => {
                // Parse the auth type to extract merchant_id and checksum_key
                // This would need to be adapted based on the actual auth structure
                Ok(Self {
                    merchant_id: None, // TODO: Extract from auth_type
                    checksum_key: None, // TODO: Extract from auth_type
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

fn get_merchant_id(
    connector_auth_type: &ConnectorAuthType,
) -> Result<Secret<String>, errors::ConnectorError> {
    match BilldeskAuthType::try_from(connector_auth_type) {
        Ok(billdesk_auth) => Ok(billdesk_auth
            .merchant_id
            .ok_or(errors::ConnectorError::FailedToObtainAuthType)?),
        Err(_) => Err(errors::ConnectorError::FailedToObtainAuthType)?,
    }
}

fn create_billdesk_message(
    merchant_id: &str,
    customer_id: &str,
    txn_reference_no: &str,
    txn_amount: &str,
    currency: &str,
    additional_info: &HashMap<String, String>,
) -> String {
    // Create the message string in the format expected by Billdesk
    // This is based on the Haskell implementation patterns
    let mut message_parts = vec![
        format!("MerchantID={}", merchant_id),
        format!("CustomerID={}", customer_id),
        format!("TxnReferenceNo={}", txn_reference_no),
        format!("TxnAmount={}", txn_amount),
        format!("CurrencyType={}", currency),
    ];

    // Add additional info fields
    for (key, value) in additional_info {
        message_parts.push(format!("{}={}", key, value));
    }

    message_parts.join("|")
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
        BilldeskRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for BilldeskPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: BilldeskRouterData<
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
        let merchant_id = get_merchant_id(&item.router_data.connector_auth_type)?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Extract IP address and user agent
        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        // Get transaction reference ID
        let txn_reference_no = item.router_data.resource_common_data.connector_request_reference_id.clone();

        // Create additional info map
        let mut additional_info = HashMap::new();
        additional_info.insert("ItemCode".to_string(), "DIRECT".to_string());
        additional_info.insert("TxnType".to_string(), "UPI".to_string());

        // Create the message
        let msg = create_billdesk_message(
            &merchant_id.peek(),
            &customer_id.get_string_repr(),
            &txn_reference_no,
            &amount.to_string(),
            &item.router_data.request.currency.to_string(),
            &additional_info,
        );

        match item.router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::UpiCollect) => Ok(Self {
                msg,
                useragent: Some(user_agent),
                ipaddress: Some(ip_address),
            }),
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Billdesk"),
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
        BilldeskRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for BilldeskPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let merchant_id = get_merchant_id(&item.router_data.connector_auth_type)?;
        let txn_reference_no = item.router_data.resource_common_data.connector_request_reference_id.clone();

        // Create message for status check
        let additional_info = HashMap::new();
        let msg = create_billdesk_message(
            &merchant_id.peek(),
            "", // Customer ID may not be needed for status check
            &txn_reference_no,
            "", // Amount may not be needed for status check
            "", // Currency may not be needed for status check
            &additional_info,
        );

        Ok(Self { msg })
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

fn get_redirect_form_data(
    response_data: BilldeskRdata,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    match response_data.url {
        Some(url) => Ok(RedirectForm::Form {
            endpoint: url,
            method: Method::Post,
            form_fields: response_data
                .parameters
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }),
        None => Err(errors::ConnectorError::MissingRequiredField {
            field_name: "redirect_url",
        }
        .into()),
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
> TryFrom<ResponseRouterData<BilldeskPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsResponse, Self>,
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
                    status_code: item.http_code,
                    message: error_data.error_description.clone().unwrap_or_default(),
                    reason: error_data.error_description.clone(),
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
                
                match response_data.rdata {
                    Some(rdata) => {
                        let redirection_data = get_redirect_form_data(rdata)?;
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
                                network_txn_id: response_data.txnrefno,
                                connector_response_reference_id: None,
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    }
                    None => (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: "NO_REDIRECT_DATA".to_string(),
                            status_code: item.http_code,
                            message: "No redirect data received from Billdesk".to_string(),
                            reason: Some("Missing redirect URL and parameters".to_string()),
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    ),
                }
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
> TryFrom<ResponseRouterData<BilldeskPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        // Determine status from auth_status field
        let status = match response.auth_status.as_deref() {
            Some("0300") | Some("0000") => common_enums::AttemptStatus::Charged,
            Some("0399") | Some("0398") => common_enums::AttemptStatus::Failure,
            Some("0301") => common_enums::AttemptStatus::AuthenticationPending,
            _ => common_enums::AttemptStatus::Pending,
        };

        // Extract amount if available
        let amount_received = response.txn_amount.as_ref().and_then(|amt_str| {
            amt_str.parse::<f64>().ok().map(|amt| {
                common_utils::types::MinorUnit::new((amt * 100.0) as i64)
            })
        });

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.merchant_id.unwrap_or_default(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.bank_reference_no,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}