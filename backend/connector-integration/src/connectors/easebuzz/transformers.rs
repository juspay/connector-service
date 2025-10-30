use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, request::Method, types::StringMinorUnit,
    Email,
};
use hyperswitch_masking::PeekInterface;
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

use crate::{connectors::easebuzz::EaseBuzzRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub currency: String,
    pub email: Option<Email>,
    pub phone: Option<String>,
    pub firstname: Option<String>,
    pub lastname: Option<String>,
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
    pub productinfo: String,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub zipcode: Option<String>,
    pub pg: Option<String>,
    pub customer_unique_id: Option<String>,
    pub split_payments: Option<String>,
    pub show_payment_mode: Option<String>,
    pub card_bin: Option<String>,
    pub merchant_name: Option<String>,
    pub merchant_logo: Option<String>,
    pub merchant_trn_id: Option<String>,
    pub enforce_paymethod: Option<String>,
    pub surcharge: Option<String>,
    pub device: Option<EaseBuzzDevice>,
    pub payment_method: Option<EaseBuzzPaymentMethod>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzDevice {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub accept_header: Option<String>,
    pub language: Option<String>,
    pub java_enabled: Option<String>,
    pub javascript_enabled: Option<String>,
    pub screen_height: Option<String>,
    pub screen_width: Option<String>,
    pub color_depth: Option<String>,
    pub timezone: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentMethod {
    pub upi: Option<EaseBuzzUpiMethod>,
    pub card: Option<EaseBuzzCardMethod>,
    pub netbanking: Option<EaseBuzzNetbankingMethod>,
    pub wallet: Option<EaseBuzzWalletMethod>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzUpiMethod {
    pub vpa: Option<String>,
    pub intent_flow: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzCardMethod {
    pub number: Option<Secret<String>>,
    pub expiry_month: Option<String>,
    pub expiry_year: Option<String>,
    pub cvv: Option<Secret<String>>,
    pub name_on_card: Option<String>,
    pub save_card: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzNetbankingMethod {
    pub bank_code: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzWalletMethod {
    pub wallet_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzPaymentsSyncRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub email: String,
    pub phone: String,
    pub key: String,
    pub hash: String,
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
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Extract payment method details
        let payment_method = extract_payment_method(&item.router_data.request.payment_method_data)?;

        Ok(Self {
            txnid: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount,
            currency: item.router_data.request.currency.to_string(),
            email: item.router_data.request.email.clone(),
            phone: item.router_data.request.phone_number.as_ref().map(|p| p.to_string()),
            firstname: item.router_data.request.customer_name.clone(),
            lastname: None,
            surl: return_url.clone(),
            furl: return_url,
            productinfo: "Payment".to_string(),
            payment_method: Some(payment_method),
            device: extract_device_info(&item.router_data.request),
            // Default values for optional fields
            udf1: None,
            udf2: None,
            udf3: None,
            udf4: None,
            udf5: None,
            udf6: None,
            udf7: None,
            udf8: None,
            udf9: None,
            udf10: None,
            address1: None,
            address2: None,
            city: None,
            state: None,
            country: None,
            zipcode: None,
            pg: None,
            customer_unique_id: Some(customer_id.get_string_repr().to_string()),
            split_payments: None,
            show_payment_mode: None,
            card_bin: None,
            merchant_name: None,
            merchant_logo: None,
            merchant_trn_id: None,
            enforce_paymethod: None,
            surcharge: None,
        })
    }
}

impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Extract API key from auth type
        let (key, hash) = extract_auth_credentials(&item.connector_auth_type)?;

        Ok(Self {
            txnid: item.resource_common_data.connector_request_reference_id.clone(),
            amount: "0".into(), // Placeholder - will be populated from actual sync data
            email: "".to_string(), // Placeholder - will be populated from actual sync data
            phone: "".to_string(), // Placeholder - will be populated from actual sync data
            key,
            hash,
        })
    }
}

fn extract_payment_method(
    payment_method_data: &domain_types::payment_method_data::PaymentMethodData,
) -> Result<EaseBuzzPaymentMethod, ConnectorError> {
    match payment_method_data {
        domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => {
            Ok(EaseBuzzPaymentMethod {
                upi: Some(EaseBuzzUpiMethod {
                    vpa: None, // UPI data structure needs to be checked
                    intent_flow: Some(true),
                }),
                card: None,
                netbanking: None,
                wallet: None,
            })
        }
        domain_types::payment_method_data::PaymentMethodData::Card(card_data) => {
            Ok(EaseBuzzPaymentMethod {
                upi: None,
                card: Some(EaseBuzzCardMethod {
                    number: card_data.card_number.clone().map(Secret::new),
                    expiry_month: card_data.expiry_month.as_ref().map(|m| m.to_string()),
                    expiry_year: card_data.expiry_year.as_ref().map(|y| format!("20{}", y)),
                    cvv: card_data.cvv.clone().map(Secret::new),
                    name_on_card: card_data.card_holder_name.as_ref().map(|s| s.expose().clone()),
                    save_card: Some(false),
                }),
                netbanking: None,
                wallet: None,
            })
        }
        _ => Ok(EaseBuzzPaymentMethod {
            upi: None,
            card: None,
            netbanking: None,
            wallet: None,
        }),
    }
}

fn extract_device_info(
    request_data: &PaymentsAuthorizeData<impl PaymentMethodDataTypes>,
) -> Option<EaseBuzzDevice> {
    request_data.browser_info.as_ref().map(|browser_info| EaseBuzzDevice {
        ip: request_data.get_ip_address_as_optional().map(|ip| ip.expose()),
        user_agent: browser_info.user_agent.clone(),
        accept_header: browser_info.accept_header.clone(),
        language: browser_info.language.clone(),
        java_enabled: browser_info.java_enabled.map(|j| j.to_string()),
        javascript_enabled: browser_info.javascript_enabled.map(|j| j.to_string()),
        screen_height: browser_info.screen_height.map(|h| h.to_string()),
        screen_width: browser_info.screen_width.map(|w| w.to_string()),
        color_depth: browser_info.color_depth.map(|d| d.to_string()),
        timezone: browser_info.timezone.clone(),
    })
}

fn extract_auth_credentials(
    connector_auth_type: &ConnectorAuthType,
) -> Result<(String, String), ConnectorError> {
    match connector_auth_type {
        ConnectorAuthType::SignatureKey { api_key, api_secret, .. } => {
            let key = api_key.peek().to_string();
            let hash = api_secret.peek().to_string();
            Ok((key, hash))
        }
        _ => Err(errors::ConnectorError::FailedToObtainAuthType),
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzPaymentsResponse {
    Success(EaseBuzzPaymentsResponseData),
    Error(EaseBuzzErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsResponseData {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: EaseBuzzPaymentData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzPaymentData {
    RedirectUrl(String),
    TransactionDetails(EaseBuzzTransactionDetails),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzTransactionDetails {
    pub txnid: String,
    pub amount: String,
    pub status: String,
    pub payment_source: String,
    pub card_no: Option<String>,
    pub bank_ref_num: Option<String>,
    pub bank_code: Option<String>,
    pub error_message: Option<String>,
    pub name_on_card: Option<String>,
    pg_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EaseBuzzPaymentsSyncResponse {
    pub txnid: String,
    pub status: bool,
    pub msg: EaseBuzzSyncMessage,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzSyncMessage {
    Success(EaseBuzzTransactionDetails),
    Error(String),
}

#[derive(Debug, Deserialize, Serialize)]
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
pub struct EaseBuzzSubmitEvidenceRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzSubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzDefendDisputeRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzDefendDisputeResponse;

impl<
    F,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize
        + Serialize,
> TryFrom<ResponseRouterData<EaseBuzzPaymentsResponse, Self>>
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
                    message: error_data.error_desc.clone(),
                    reason: error_data.error_desc,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            EaseBuzzPaymentsResponse::Success(response_data) => {
                match response_data.data {
                    EaseBuzzPaymentData::RedirectUrl(redirect_url) => {
                        let redirection_data = RedirectForm::Form {
                            endpoint: redirect_url,
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
                                network_txn_id: None,
                                connector_response_reference_id: None,
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    }
                    EaseBuzzPaymentData::TransactionDetails(txn_details) => {
                        let status = if txn_details.status == "success" {
                            common_enums::AttemptStatus::Charged
                        } else {
                            common_enums::AttemptStatus::Failure
                        };

                        (
                            status,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(txn_details.txnid),
                                redirection_data: None,
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: txn_details.bank_ref_num,
                                connector_response_reference_id: None,
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    }
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

impl TryFrom<ResponseRouterData<EaseBuzzPaymentsSyncResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
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

        let (status, response) = if response.status {
            match response.msg {
                EaseBuzzSyncMessage::Success(txn_details) => {
                    let status = if txn_details.status == "success" {
                        common_enums::AttemptStatus::Charged
                    } else {
                        common_enums::AttemptStatus::Failure
                    };

                    (
                        status,
                        Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(txn_details.txnid),
                            redirection_data: None,
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: txn_details.bank_ref_num,
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            status_code: http_code,
                        }),
                    )
                }
                EaseBuzzSyncMessage::Error(error_msg) => (
                    common_enums::AttemptStatus::Failure,
                    Err(ErrorResponse {
                        code: "SYNC_ERROR".to_string(),
                        status_code: item.http_code,
                        message: error_msg.clone(),
                        reason: Some(error_msg),
                        attempt_status: None,
                        connector_transaction_id: None,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    }),
                ),
            }
        } else {
            (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "SYNC_FAILED".to_string(),
                    status_code: item.http_code,
                    message: "Transaction sync failed".to_string(),
                    reason: Some("Transaction sync failed".to_string()),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            )
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