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

use crate::{connectors::easebuzz::EaseBuzzRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    txnid: String,
    amount: StringMinorUnit,
    productinfo: String,
    firstname: Option<String>,
    email: Option<Email>,
    phone: Option<String>,
    surl: String,
    furl: String,
    udf1: Option<String>,
    udf2: Option<String>,
    udf3: Option<String>,
    udf4: Option<String>,
    udf5: Option<String>,
    udf6: Option<String>,
    udf7: Option<String>,
    udf8: Option<String>,
    udf9: Option<String>,
    udf10: Option<String>,
    hash: Secret<String>,
    address1: Option<String>,
    address2: Option<String>,
    city: Option<String>,
    state: Option<String>,
    country: Option<String>,
    zipcode: Option<String>,
    pg: Option<String>,
    customer_unique_id: Option<String>,
    split_payments: Option<String>,
    sub_merchant_id: Option<String>,
    customer_name: Option<String>,
    enforce_paymentmethod: Option<String>,
    show_paymentmethod: Option<String>,
    card_type: Option<String>,
    bank_code: Option<String>,
    wallet: Option<String>,
    emi_plan_id: Option<String>,
    card_no: Option<Secret<String>>,
    ccname: Option<String>,
    ccvv: Option<Secret<String>>,
    ccexpmon: Option<String>,
    ccexpyr: Option<String>,
    // UPI specific fields
    vpa: Option<String>,
    upi_intent: Option<bool>,
    upi_collect: Option<bool>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncRequest {
    txnid: String,
    amount: StringMinorUnit,
    email: Option<Email>,
    phone: Option<String>,
    key: String,
    hash: Secret<String>,
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
    status: i32,
    error_desc: Option<String>,
    data: EaseBuzzPaymentData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentData {
    payment_url: Option<String>,
    txnid: Option<String>,
    easebuzz_id: Option<String>,
    status: Option<String>,
    amount: Option<String>,
    card_type: Option<String>,
    bank_ref_num: Option<String>,
    bank_code: Option<String>,
    error_msg: Option<String>,
    name_on_card: Option<String>,
    card_no: Option<String>,
    card_bin: Option<String>,
    card_brand: Option<String>,
    card_exp_month: Option<String>,
    card_exp_year: Option<String>,
    name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    bank_name: Option<String>,
    payment_source: Option<String>,
    pg_type: Option<String>,
    upi_vpa: Option<String>,
    upi_intent_url: Option<String>,
    upi_qr_code: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncResponse {
    status: bool,
    msg: EaseBuzzSyncMessageType,
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
    status: i32,
    error_desc: Option<String>,
    data: String,
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

        // Extract phone number
        let phone = item.router_data.request.get_phone_number()?;

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
        let (key, hash) = get_easebuzz_auth_credentials(&item.router_data.connector_auth_type)?;

        // Handle UPI payment methods
        let (vpa, upi_intent, upi_collect) = match item.router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::Upi) => {
                // Extract UPI specific data from payment_method_data
                let vpa = extract_upi_vpa(&item.router_data.request.payment_method_data)?;
                (Some(vpa), Some(true), Some(false))
            }
            Some(common_enums::PaymentMethodType::UpiCollect) => {
                let vpa = extract_upi_vpa(&item.router_data.request.payment_method_data)?;
                (Some(vpa), Some(false), Some(true))
            }
            Some(common_enums::PaymentMethodType::UpiIntent) => {
                let vpa = extract_upi_vpa(&item.router_data.request.payment_method_data)?;
                (Some(vpa), Some(true), Some(false))
            }
            _ => (None, None, None),
        };

        Ok(Self {
            txnid: transaction_id,
            amount,
            productinfo: "Payment".to_string(),
            firstname: Some(customer_id.get_string_repr()),
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
            customer_unique_id: Some(customer_id.get_string_repr()),
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
>
    TryFrom<
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
        // Extract amount using the amount converter
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Extract transaction ID from connector request reference
        let transaction_id = item.router_data.resource_common_data.connector_request_reference_id.clone();

        // Extract email
        let email = item.router_data.request.email.clone();

        // Extract phone number
        let phone = item.router_data.request.get_phone_number()?;

        // Get authentication credentials
        let (key, hash) = get_easebuzz_auth_credentials(&item.router_data.connector_auth_type)?;

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

fn extract_upi_vpa(payment_method_data: &Option<serde_json::Value>) -> CustomResult<String, ConnectorError> {
    match payment_method_data {
        Some(data) => {
            data.get_str("upi_vpa")
                .or_else(|| data.get_str("vpa"))
                .or_else(|| data.get_str("virtual_payment_address"))
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    ConnectorError::MissingRequiredField {
                        field_name: "upi_vpa",
                    }
                    .into()
                })
        }
        None => Err(ConnectorError::MissingRequiredField {
            field_name: "payment_method_data",
        }
        .into()),
    }
}

fn get_easebuzz_auth_credentials(
    connector_auth_type: &ConnectorAuthType,
) -> CustomResult<(String, String), ConnectorError> {
    match connector_auth_type {
        ConnectorAuthType::SignatureKey { api_key, key, .. } => {
            let key_str = key.peek().clone();
            let api_key_str = api_key.peek().clone();
            Ok((key_str, api_key_str))
        }
        ConnectorAuthType::Key { api_key, .. } => {
            let api_key_str = api_key.peek().clone();
            Ok((api_key_str.clone(), api_key_str))
        }
        _ => Err(ConnectorError::FailedToObtainAuthType.into()),
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
                            message: response_data.error_desc.clone(),
                            reason: response_data.error_desc,
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
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize
        + Serialize,
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
                    .map(|amt| common_utils::types::MinorUnit::from_major_unit_as_i64(amt));

                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            payment_data.txnid.unwrap_or_default(),
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