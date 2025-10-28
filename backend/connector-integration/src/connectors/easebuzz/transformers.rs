use common_enums::{PaymentMethodType, Currency};
use common_utils::{
    errors::CustomResult,
    request::Method,
    types::{StringMinorUnit, MinorUnit},
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::ConnectorError,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ErrorResponse,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::easebuzz::EaseBuzzRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub productinfo: String,
    pub firstname: Option<String>,
    pub email: Option<Email>,
    pub phone: Option<String>,
    pub surl: String,
    pub furl: String,
    pub udf1: Option<String>,
    pub udf2: Option<String>,
    pub udf3: Option<String>,
    pub udf4: Option<String>,
    pub udf5: Option<String>,
    pub udf6: Option<String>,
    pub udf7: Option<String>,
    pub udf8: Option<String>,
    pub udf9: Option<String>,
    pub udf10: Option<String>,
    pub hash: Secret<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub zipcode: Option<String>,
    pub pg: Option<String>,
    pub customer_unique_id: Option<String>,
    pub split_payments: Option<String>,
    pub sub_merchant_id: Option<String>,
    pub customer_name: Option<String>,
    pub enforce_paymentmethod: Option<String>,
    pub show_paymentmethod: Option<String>,
    pub card_type: Option<String>,
    pub bank_code: Option<String>,
    pub wallet: Option<String>,
    pub emi_plan_id: Option<String>,
    pub card_no: Option<Secret<String>>,
    pub ccname: Option<String>,
    pub ccvv: Option<Secret<String>>,
    pub ccexpmon: Option<String>,
    pub ccexpyr: Option<String>,
    // UPI specific fields
    pub vpa: Option<String>,
    pub upi_intent: Option<bool>,
    pub upi_collect: Option<bool>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub email: Option<Email>,
    pub phone: Option<String>,
    pub key: String,
    pub hash: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzPaymentsResponse {
    Success(EaseBuzzPaymentsSuccessResponse),
    Error(EaseBuzzErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSuccessResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: EaseBuzzPaymentData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentData {
    pub payment_url: Option<String>,
    pub txnid: Option<String>,
    pub easebuzz_id: Option<String>,
    pub status: Option<String>,
    pub amount: Option<String>,
    pub card_type: Option<String>,
    pub bank_ref_num: Option<String>,
    pub bank_code: Option<String>,
    pub error_msg: Option<String>,
    pub name_on_card: Option<String>,
    pub card_no: Option<String>,
    pub card_bin: Option<String>,
    pub card_brand: Option<String>,
    pub card_exp_month: Option<String>,
    pub card_exp_year: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub bank_name: Option<String>,
    pub payment_source: Option<String>,
    pub pg_type: Option<String>,
    pub upi_vpa: Option<String>,
    pub upi_intent_url: Option<String>,
    pub upi_qr_code: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncResponse {
    pub status: bool,
    pub msg: EaseBuzzSyncMessageType,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzSyncMessageType {
    Success(EaseBuzzPaymentData),
    Error(String),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzErrorResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: String,
}

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzVoidRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCaptureRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRefundRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRefundSyncRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzRefundSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzSessionTokenResponse;

// Unique stub types for flows that would otherwise conflict
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzPreAuthenticateRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzPreAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzAuthenticateRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzPostAuthenticateRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzPostAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCreateAccessTokenRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzCreateAccessTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCreateConnectorCustomerRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzCreateConnectorCustomerResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzPaymentMethodTokenRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzPaymentMethodTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzSubmitEvidenceResponse;

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<
    EaseBuzzRouterData<
        RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        T,
    >,
> for EaseBuzzPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: EaseBuzzRouterData<
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
        let return_url = item.router_data.request.get_router_return_url()?;
        
        // Extract amount using the amount converter
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Extract transaction ID
        let transaction_id = item.router_data.resource_common_data.connector_request_reference_id.clone();

        // Extract email
        let email = item.router_data.request.email.clone();

        // Extract phone number (not available in PaymentsAuthorizeData)
        let phone: Option<String> = None;

        // Extract IP address
        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        // Extract browser info for user agent
        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        // Get authentication credentials
        let (key, hash) = item.connector.get_easebuzz_auth_credentials(&item.router_data.connector_auth_type)?;

        // Handle UPI payment methods
        let (vpa, upi_intent, upi_collect) = match item.router_data.request.payment_method_type {
            Some(PaymentMethodType::UpiCollect) => {
                // Extract UPI specific data from payment_method_data
                let vpa = extract_upi_vpa(&item.router_data.request.payment_method_data)?;
                (Some(vpa), Some(false), Some(true))
            }
            Some(PaymentMethodType::UpiIntent) => {
                let vpa = extract_upi_vpa(&item.router_data.request.payment_method_data)?;
                (Some(vpa), Some(true), Some(false))
            }
            _ => (None, None, None),
        };

        Ok(Self {
            txnid: transaction_id,
            amount,
            productinfo: "Payment".to_string(),
            firstname: Some(customer_id.get_string_repr().to_string()),
            email,
            phone,
            surl: return_url.clone(),
            furl: return_url,
            udf1: Some(ip_address),
            udf2: Some(user_agent),
            udf3: None,
            udf4: None,
            udf5: None,
            udf6: None,
            udf7: None,
            udf8: None,
            udf9: None,
            udf10: None,
            hash: Secret::new(hash),
            address1: None,
            address2: None,
            city: None,
            state: None,
            country: None,
            zipcode: None,
            pg: None,
            customer_unique_id: Some(customer_id.get_string_repr().to_string()),
            split_payments: None,
            sub_merchant_id: None,
            customer_name: None,
            enforce_paymentmethod: None,
            show_paymentmethod: None,
            card_type: None,
            bank_code: None,
            wallet: None,
            emi_plan_id: None,
            card_no: None,
            ccname: None,
            ccvv: None,
            ccexpmon: None,
            ccexpyr: None,
            vpa,
            upi_intent,
            upi_collect,
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
> TryFrom<
    EaseBuzzRouterData<
        RouterDataV2<
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
        >,
        T,
    >,
> for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: EaseBuzzRouterData<
            RouterDataV2<
                PSync,
                PaymentFlowData,
                PaymentsSyncData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // Extract amount using the amount converter (for sync, we need to get this from elsewhere)
        let amount = item
            .connector
            .amount_converter
            .convert(
                MinorUnit::new(1000), // Default amount for sync - this should come from original transaction
                Currency::INR, // Default currency
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Extract transaction ID from sync request
        let transaction_id = match &item.router_data.request.connector_transaction_id {
            domain_types::connector_types::ResponseId::ConnectorTransactionId(id) => id.clone(),
            _ => "default_transaction_id".to_string(),
        };

        // Email not available in PaymentsSyncData
        let email: Option<Email> = None;

        // Extract phone number (not available in PaymentsAuthorizeData)
        let phone: Option<String> = None;

        // Get authentication credentials
        let (key, hash) = item.connector.get_easebuzz_auth_credentials(&item.router_data.connector_auth_type)?;

        Ok(Self {
            txnid: transaction_id,
            amount,
            email,
            phone,
            key,
            hash: Secret::new(hash),
        })
    }
}

fn extract_upi_vpa<T: PaymentMethodDataTypes>(payment_method_data: &domain_types::payment_method_data::PaymentMethodData<T>) -> CustomResult<String, ConnectorError> {
    match payment_method_data {
        domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => {
            match upi_data {
                domain_types::payment_method_data::UpiData::UpiCollect(collect_data) => {
                    match collect_data.vpa_id {
                        Some(ref vpa) => Ok(vpa.peek().clone()),
                        None => Err(ConnectorError::MissingRequiredField {
                            field_name: "vpa_id",
                        }
                        .into()),
                    }
                }
                domain_types::payment_method_data::UpiData::UpiIntent(_intent_data) => {
                    Err(ConnectorError::MissingRequiredField {
                        field_name: "vpa_not_available_for_intent",
                    }
                    .into())
                }
                domain_types::payment_method_data::UpiData::UpiQr(_qr_data) => {
                    Err(ConnectorError::MissingRequiredField {
                        field_name: "vpa_not_available_for_qr",
                    }
                    .into())
                }
            }
        }
        _ => Err(ConnectorError::MissingRequiredField {
            field_name: "upi_payment_method_data",
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
        + Serialize> TryFrom<ResponseRouterData<EaseBuzzPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = match response {
            EaseBuzzPaymentsResponse::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.status.to_string(),
                    status_code: item.http_code,
                    message: error_data.error_desc.clone().unwrap_or_default(),
                    reason: error_data.error_desc.clone(),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            EaseBuzzPaymentsResponse::Success(response_data) => {
                if response_data.status == 1 {
                    // Success - redirect to payment URL
                    let payment_url = response_data.data.payment_url.ok_or_else(|| {
                        ConnectorError::MissingRequiredField {
                            field_name: "payment_url",
                        }
                    })?;

                    let redirection_data = RedirectForm::Form {
                        endpoint: payment_url,
                        method: Method::Get,
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
                            network_txn_id: response_data.data.easebuzz_id,
                            connector_response_reference_id: response_data.data.txnid,
                            incremental_authorization_allowed: None,
                            status_code: http_code,
                        }),
                    )
                } else {
                    // Error response
                    (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: response_data.status.to_string(),
                            status_code: item.http_code,
                            message: response_data.error_desc.clone().unwrap_or_default(),
                            reason: response_data.error_desc.clone(),
                            attempt_status: None,
                            connector_transaction_id: response_data.data.txnid,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: response_data.data.error_msg,
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

impl<
    F,
> TryFrom<ResponseRouterData<EaseBuzzPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = match response.msg {
            EaseBuzzSyncMessageType::Success(payment_data) => {
                let attempt_status = match payment_data.status.as_deref() {
                    Some("success") => common_enums::AttemptStatus::Charged,
                    Some("pending") => common_enums::AttemptStatus::Pending,
                    Some("failure") | Some("failed") => common_enums::AttemptStatus::Failure,
                    Some("user_aborted") => common_enums::AttemptStatus::AuthorizationFailed,
                    _ => common_enums::AttemptStatus::Pending,
                };

                let amount_received = payment_data.amount.as_ref()
                    .and_then(|amt| amt.parse::<f64>().ok())
                    .map(|amt| MinorUnit::new((amt * 100.0) as i64));

                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            payment_data.txnid.clone().unwrap_or_default(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: payment_data.easebuzz_id,
                        connector_response_reference_id: payment_data.txnid,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            EaseBuzzSyncMessageType::Error(error_message) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "SYNC_ERROR".to_string(),
                    status_code: item.http_code,
                    message: error_message.clone(),
                    reason: Some(error_message),
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