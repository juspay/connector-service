use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    request::Method,
    types::{StringMinorUnit, StringMajorUnit},
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync, Refund, RSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundsData, RefundsResponseData, RefundSyncData, ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
    connector_flow::{PreAuthenticate, Authenticate, PostAuthenticate, VoidPC, CreateOrder, SubmitEvidence, DefendDispute, Accept, SetupMandate, RepeatPayment, CreateSessionToken, CreateAccessToken, CreateConnectorCustomer, PaymentMethodToken},
    connector_types::{PaymentsPreAuthenticateData, PaymentsAuthenticateData, PaymentsPostAuthenticateData, PaymentsCancelPostCaptureData, PaymentCreateOrderData, PaymentCreateOrderResponse, SessionTokenRequestData, SessionTokenResponseData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData, ConnectorCustomerResponse, PaymentMethodTokenizationData, PaymentMethodTokenResponse, DisputeFlowData, AcceptDisputeData, SubmitEvidenceData, DisputeDefendData, DisputeResponseData},
};
use error_stack::ResultExt;
use hyperswitch_masking::{Secret, PeekInterface, ExposeInterface};
use serde::{Deserialize, Serialize};

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};

use super::constants::*;

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    pub msg: String,
    pub ipaddress: Option<String>,
    pub useragent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paydata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txtbankid: Option<String>,
}

#[derive(Default, Debug, Serialize)]
pub struct BilldeskPaymentsSyncRequest {
    pub msg: String,
}

#[derive(Default, Debug, Serialize)]
pub struct BilldeskRefundRequest {
    pub msg: String,
}

#[derive(Default, Debug, Serialize)]
pub struct BilldeskRefundStatusRequest {
    pub msg: String,
}

// Stub types for unsupported flows
#[derive(Default, Debug, Serialize)]
pub struct BilldeskVoidRequest;

#[derive(Default, Debug, Clone)]
pub struct BilldeskVoidResponse;

#[derive(Default, Debug, Serialize)]
pub struct BilldeskCaptureRequest;

#[derive(Default, Debug, Clone)]
pub struct BilldeskCaptureResponse;

#[derive(Default, Debug, Serialize)]
pub struct BilldeskCreateOrderRequest;

#[derive(Default, Debug, Clone)]
pub struct BilldeskCreateOrderResponse;

#[derive(Default, Debug, Serialize)]
pub struct BilldeskSessionTokenRequest;

#[derive(Default, Debug, Clone)]
pub struct BilldeskSessionTokenResponse;

#[derive(Default, Debug, Serialize)]
pub struct BilldeskSetupMandateRequest;

#[derive(Default, Debug, Clone)]
pub struct BilldeskSetupMandateResponse;

#[derive(Default, Debug, Serialize)]
pub struct BilldeskRepeatPaymentRequest;

#[derive(Default, Debug, Clone)]
pub struct BilldeskRepeatPaymentResponse;

#[derive(Default, Debug, Serialize)]
pub struct BilldeskAcceptDisputeRequest;

#[derive(Default, Debug, Clone)]
pub struct BilldeskAcceptDisputeResponse;

#[derive(Default, Debug, Serialize)]
pub struct BilldeskDefendDisputeRequest;

#[derive(Default, Debug, Clone)]
pub struct BilldeskDefendDisputeResponse;

#[derive(Default, Debug, Serialize)]
pub struct BilldeskSubmitEvidenceRequest;

#[derive(Default, Debug, Clone)]
pub struct BilldeskSubmitEvidenceResponse;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskAuth {
    pub merchant_id: Option<Secret<String>>,
    pub checksum_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret: _,
            } => Ok(Self {
                merchant_id: Some(Secret::new(api_key.peek().clone())),
                checksum_key: Some(Secret::new(key1.peek().clone())),
            }),
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                merchant_id: Some(Secret::new(api_key.peek().clone())),
                checksum_key: None,
            }),
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                merchant_id: Some(Secret::new(api_key.peek().clone())),
                checksum_key: Some(Secret::new(key1.peek().clone())),
            }),
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

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct BilldeskErrors {
    pub error: String,
    pub error_description: String,
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
    pub msg: Option<String>,
    pub txn_reference_no: String,
    pub auth_status: String,
    pub txn_amount: String,
    pub currency: String,
    pub error_status: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRefundResponse {
    pub msg: Option<String>,
    pub refund_id: Option<String>,
    pub refund_status: Option<String>,
    pub error_status: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRefundStatusResponse {
    pub msg: Option<String>,
    pub refund_id: String,
    pub refund_status: String,
    pub refund_amount: String,
    pub error_status: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskErrorResponse {
    pub error: String,
    pub error_description: String,
    pub errors: Option<Vec<BilldeskErrors>>,
}

fn create_billdesk_message(
    merchant_id: &str,
    customer_id: &str,
    txn_reference_no: &str,
    amount: &str,
    currency: &str,
    additional_info: &HashMap<String, String>,
) -> String {
    let mut msg_parts = vec![
        format!("MerchantID={}", merchant_id),
        format!("CustomerID={}", customer_id),
        format!("TxnReferenceNo={}", txn_reference_no),
        format!("TxnAmount={}", amount),
        format!("Currency={}", currency),
    ];

    // Add additional info fields
    for (key, value) in additional_info {
        msg_parts.push(format!("{}={}", key, value));
    }

    msg_parts.join("|")
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
        let transaction_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let auth = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
        let merchant_id = auth
            .merchant_id
            .ok_or(ConnectorError::FailedToObtainAuthType)?
            .peek()
            .clone();

        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        let mut additional_info = HashMap::new();
        additional_info.insert("TxnType".to_string(), BILLDESK_DIRECT_TXN_TYPE.to_string());
        additional_info.insert("ItemCode".to_string(), BILLDESK_DIRECT_ITEM_CODE.to_string());
        
        // Add return URL if available
        if let Ok(return_url) = item.router_data.request.get_router_return_url() {
            additional_info.insert("ReturnURL".to_string(), return_url);
        }

        let msg = create_billdesk_message(
            &merchant_id,
            &customer_id.get_string_repr(),
            &transaction_id,
            amount.to_string().as_str(),
            &item.router_data.request.currency.to_string(),
            &additional_info,
        );

        match item.router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::UpiCollect) | Some(common_enums::PaymentMethodType::UpiIntent) => {
                // For UPI, we might need additional paydata
                Ok(Self {
                    msg,
                    ipaddress: Some(ip_address),
                    useragent: Some(user_agent),
                    paydata: None, // Will be populated based on UPI specific data
                    txtbankid: None,
                })
            }
            Some(common_enums::PaymentMethodType::OnlineBankingFpx) | Some(common_enums::PaymentMethodType::OnlineBankingPoland) | 
            Some(common_enums::PaymentMethodType::OnlineBankingCzechRepublic) | Some(common_enums::PaymentMethodType::OnlineBankingFinland) |
            Some(common_enums::PaymentMethodType::OnlineBankingSlovakia) | Some(common_enums::PaymentMethodType::OnlineBankingThailand) => {
                // For Net Banking, we need bank ID
                Ok(Self {
                    msg,
                    ipaddress: Some(ip_address),
                    useragent: Some(user_agent),
                    paydata: None,
                    txtbankid: Some(BILLDESK_DEFAULT_BANK_ID.to_string()), // Default bank ID
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported".to_string(),
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
        let auth = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
        let merchant_id = auth
            .merchant_id
            .ok_or(ConnectorError::FailedToObtainAuthType)?
            .peek()
            .clone();

        let transaction_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id;

        let additional_info = HashMap::new();
        let msg = create_billdesk_message(
            &merchant_id,
            "", // Customer ID not needed for status check
            &transaction_id,
            "", // Amount not needed for status check
            "", // Currency not needed for status check
            &additional_info,
        );

        Ok(Self { msg })
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
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for BilldeskRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
        let merchant_id = auth
            .merchant_id
            .ok_or(ConnectorError::FailedToObtainAuthType)?
            .peek()
            .clone();

        let transaction_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id;

        let amount = item
            .connector
            .amount_converter
            .convert(
                common_utils::types::MinorUnit::new(item.router_data.request.refund_amount),
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let mut additional_info = HashMap::new();
        additional_info.insert("RefAmount".to_string(), amount.to_string());
        additional_info.insert("Currency".to_string(), item.router_data.request.currency.to_string());
        
        additional_info.insert("RefundId".to_string(), item.router_data.request.refund_id.clone());

        let msg = create_billdesk_message(
            &merchant_id,
            "", // Customer ID not needed for refund
            &transaction_id,
            &amount,
            &item.router_data.request.currency.to_string(),
            &additional_info,
        );

        Ok(Self { msg })
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
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for BilldeskRefundStatusRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
        let merchant_id = auth
            .merchant_id
            .ok_or(ConnectorError::FailedToObtainAuthType)?
            .peek()
            .clone();

        let refund_id = item
            .router_data
            .request
            .refund_id
            .clone()
            .ok_or(ConnectorError::MissingRequiredField {
                field_name: "refund_id",
            })?;

        let mut additional_info = HashMap::new();
        additional_info.insert("RefundId".to_string(), refund_id.clone());

        let msg = create_billdesk_message(
            &merchant_id,
            "", // Customer ID not needed for refund status
            "", // Transaction ID not needed for refund status
            "", // Amount not needed for refund status
            "", // Currency not needed for refund status
            &additional_info,
        );

        Ok(Self { msg })
    }
}

fn get_redirect_form_data(
    payment_method_type: common_enums::PaymentMethodType,
    response_data: BilldeskRdata,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    match payment_method_type {
        common_enums::PaymentMethodType::UpiCollect | common_enums::PaymentMethodType::UpiIntent => {
            if let Some(url) = response_data.url {
                Ok(RedirectForm::Form {
                    endpoint: url,
                    method: Method::Post,
                    form_fields: response_data
                        .parameters
                        .into_iter()
                        .map(|(k, v)| (k, v.into()))
                        .collect(),
                })
            } else {
                Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "redirect_url",
                }
                .into())
            }
        }
        common_enums::PaymentMethodType::OnlineBankingFpx | common_enums::PaymentMethodType::OnlineBankingPoland | 
        common_enums::PaymentMethodType::OnlineBankingCzechRepublic | common_enums::PaymentMethodType::OnlineBankingFinland |
        common_enums::PaymentMethodType::OnlineBankingSlovakia | common_enums::PaymentMethodType::OnlineBankingThailand => {
            if let Some(url) = response_data.url {
                Ok(RedirectForm::Form {
                    endpoint: url,
                    method: Method::Get,
                    form_fields: Default::default(),
                })
            } else {
                Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "redirect_url",
                }
                .into())
            }
        }
        _ => Err(errors::ConnectorError::NotImplemented(
            utils::get_unimplemented_payment_method_error_message("Billdesk"),
        ))?,
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
                    message: error_data.error_description.clone(),
                    reason: Some(error_data.error_description),
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
                
                if let Some(rdata) = response_data.rdata {
                    let redirection_data = get_redirect_form_data(payment_method_type, rdata)?;
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
                            network_txn_id: response_data.txnrefno.clone(),
                            connector_response_reference_id: response_data.txnrefno,
                            incremental_authorization_allowed: None,
                            status_code: http_code,
                        }),
                    )
                } else {
                    (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: "NO_REDIRECT_DATA".to_string(),
                            status_code: item.http_code,
                            message: "No redirect data received from Billdesk".to_string(),
                            reason: Some("Missing redirect URL or parameters".to_string()),
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    )
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

impl<F> TryFrom<ResponseRouterData<BilldeskPaymentsSyncResponse, Self>>
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

        let status = match response.auth_status.as_str() {
            BILLDESK_SUCCESS_CODE | BILLDESK_PARTIAL_SUCCESS_CODE => common_enums::AttemptStatus::Charged, // Success
            BILLDESK_FAILURE_CODE => common_enums::AttemptStatus::Failure, // Failure
            BILLDESK_PENDING_CODE_1 | BILLDESK_PENDING_CODE_2 => common_enums::AttemptStatus::AuthenticationPending, // Pending
            _ => common_enums::AttemptStatus::AuthenticationPending, // Default to pending
        };

        let amount_received = common_utils::types::StringMajorUnit::new(response.txn_amount.clone())
            .to_minor_unit_as_i64(common_enums::Currency::INR) // Default to INR, should be extracted from response
            .ok();

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.txn_reference_no),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: Some(response.txn_reference_no),
                connector_response_reference_id: Some(response.txn_reference_no),
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<BilldeskRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<BilldeskRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let refund_status = match response.refund_status.as_deref() {
            Some("SUCCESS") => common_enums::RefundStatus::Success,
            Some("FAILURE") => common_enums::RefundStatus::Failure,
            Some("PENDING") => common_enums::RefundStatus::Pending,
            _ => common_enums::RefundStatus::Pending,
        };

        let connector_refund_id = response.refund_id.unwrap_or_else(|| "unknown".to_string());

        Ok(Self {
            resource_common_data: domain_types::connector_types::RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data
            },
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<BilldeskRefundStatusResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<BilldeskRefundStatusResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let refund_status = match response.refund_status.as_str() {
            "SUCCESS" => common_enums::RefundStatus::Success,
            "FAILURE" => common_enums::RefundStatus::Failure,
            "PENDING" => common_enums::RefundStatus::Pending,
            _ => common_enums::RefundStatus::Pending,
        };

        let amount_received = common_utils::types::StringMajorUnit::new(response.refund_amount.clone())
            .to_minor_unit_as_i64(common_enums::Currency::INR) // Default to INR, should be extracted from response
            .ok();

        Ok(Self {
            resource_common_data: domain_types::connector_types::RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data
            },
            response: Ok(RefundsResponseData {
                connector_refund_id: response.refund_id,
                refund_status,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskIncomingWebhook {
    pub txn_reference_no: String,
    pub auth_status: String,
    pub txn_amount: String,
    pub currency: String,
    pub error_status: Option<String>,
    pub error_description: Option<String>,
}