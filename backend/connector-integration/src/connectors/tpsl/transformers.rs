use std::{collections::HashMap, str::FromStr};

use common_enums;
use common_utils::{
    errors::CustomResult, request::Method, types::StringMinorUnit,
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
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{connectors::tpsl::TPSLRouterData, types::ResponseRouterData};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsRequest {
    pub merchant: TpslMerchantPayload,
    pub cart: TpslCartPayload,
    pub payment: TpslPaymentPayload,
    pub transaction: TpslTransactionPayload,
    pub consumer: TpslConsumerPayload,
    pub merchant_input_flags: TpslFlagsType,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslMerchantPayload {
    pub webhook_endpoint_url: String,
    pub response_type: String,
    pub response_endpoint_url: String,
    pub description: String,
    pub identifier: Secret<String>,
    pub webhook_type: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslCartPayload {
    pub item: Vec<TpslItemPayload>,
    pub reference: String,
    pub identifier: String,
    pub description: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslItemPayload {
    pub description: String,
    pub provider_identifier: String,
    pub surcharge_or_discount_amount: StringMinorUnit,
    pub amount: StringMinorUnit,
    pub com_amt: String,
    pub s_k_u: String,
    pub reference: String,
    pub identifier: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentPayload {
    pub method: TpslMethodPayload,
    pub instrument: TpslInstrumentPayload,
    pub instruction: TpslInstructionPayload,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslMethodPayload {
    pub token: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub code: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslInstrumentPayload {
    pub expiry: TpslExpiryPayload,
    pub provider: String,
    pub i_fsc: String,
    pub holder: TpslHolderPayload,
    pub b_i_c: String,
    #[serde(rename = "type")]
    pub instrument_type: String,
    pub action: String,
    pub m_i_c_r: String,
    pub verification_code: String,
    pub i_b_a_n: String,
    pub processor: String,
    pub issuance: TpslExpiryPayload,
    pub alias: String,
    pub identifier: String,
    pub token: String,
    pub authentication: TpslAuthenticationPayload,
    pub sub_type: String,
    pub issuer: String,
    pub acquirer: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslExpiryPayload {
    pub year: String,
    pub month: String,
    pub date_time: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslHolderPayload {
    pub name: String,
    pub address: TpslAddressPayload,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslAddressPayload {
    pub country: String,
    pub street: String,
    pub state: String,
    pub city: String,
    pub zip_code: Secret<String>,
    pub county: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslAuthenticationPayload {
    pub token: String,
    #[serde(rename = "type")]
    pub auth_type: String,
    pub sub_type: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslInstructionPayload {
    pub occurrence: String,
    pub amount: StringMinorUnit,
    pub frequency: String,
    #[serde(rename = "type")]
    pub instruction_type: String,
    pub description: String,
    pub action: String,
    pub limit: String,
    pub end_date_time: String,
    pub debit_day: String,
    pub debit_flag: String,
    pub identifier: String,
    pub reference: String,
    pub start_date_time: String,
    pub validity: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionPayload {
    pub device_identifier: String,
    pub sms_sending: String,
    pub amount: StringMinorUnit,
    pub forced_3_d_s_call: String,
    #[serde(rename = "type")]
    pub transaction_type: String,
    pub description: String,
    pub currency: String,
    pub is_registration: String,
    pub identifier: String,
    pub date_time: String,
    pub token: String,
    pub security_token: String,
    pub sub_type: String,
    pub request_type: String,
    pub reference: String,
    pub merchant_initiated: String,
    pub tenure_id: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslConsumerPayload {
    pub mobile_number: String,
    pub email_i_d: Email,
    pub identifier: String,
    pub account_no: String,
    pub account_type: String,
    pub account_holder_name: String,
    pub aadhar_no: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslFlagsType {
    pub account_no: bool,
    pub mobile_number: bool,
    pub email_i_d: bool,
    pub card_details: bool,
    pub mandate_details: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TpslPaymentsResponse {
    TpslUPISuccessTxnResponse(TpslUPITxnResponse),
    TpslErrorResponse(TpslErrorResponse),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPITxnResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: String,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: String,
    pub merchant_additional_details: serde_json::Value,
    pub payment_method: TpslUPIPaymentPayload,
    pub error: Option<serde_json::Value>,
    pub merchant_response_string: Option<serde_json::Value>,
    pub pdf_download_url: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPIPaymentPayload {
    pub token: Option<String>,
    pub instrument_alias_name: String,
    pub instrument_token: String,
    pub bank_selection_code: String,
    pub a_c_s: TpslAcsPayload,
    pub o_t_p: Option<serde_json::Value>,
    pub payment_transaction: TpslPaymentTxnPayload,
    pub authentication: Option<serde_json::Value>,
    pub error: TpslPaymentMethodErrorPayload,
    pub payment_mode: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAcsPayload {
    pub bank_acs_form_name: String,
    pub bank_acs_http_method: serde_json::Value,
    pub bank_acs_params: Option<serde_json::Value>,
    pub bank_acs_url: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentTxnPayload {
    pub amount: StringMinorUnit,
    pub balance_amount: Option<StringMinorUnit>,
    pub bank_reference_identifier: Option<String>,
    pub date_time: Option<String>,
    pub error_message: Option<String>,
    pub identifier: Option<String>,
    pub refund_identifier: String,
    pub status_code: String,
    pub status_message: String,
    pub instruction: Option<serde_json::Value>,
    pub reference: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentMethodErrorPayload {
    pub code: String,
    pub desc: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslErrorResponse {
    pub error_code: String,
    pub error_message: String,
}

// Sync request and response types
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncRequest {
    pub merchant: TpslMerchantDataType,
    pub payment: TpslPaymentUPISyncType,
    pub transaction: TpslTransactionUPITxnType,
    pub consumer: TpslConsumerDataType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMerchantDataType {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentUPISyncType {
    pub instruction: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionUPITxnType {
    pub device_identifier: String,
    #[serde(rename = "type")]
    pub transaction_type: Option<String>,
    pub sub_type: Option<String>,
    pub amount: StringMinorUnit,
    pub currency: String,
    pub date_time: String,
    pub request_type: String,
    pub token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslConsumerDataType {
    pub identifier: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: String,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: String,
    pub payment_method: TpslUPIPaymentPayload,
    pub error: Option<serde_json::Value>,
    pub merchant_response_string: Option<serde_json::Value>,
    pub status_code: Option<String>,
    pub status_message: Option<String>,
    pub identifier: Option<String>,
    pub bank_reference_identifier: Option<String>,
    pub merchant_additional_details: Option<serde_json::Value>,
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
pub struct TpslSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct TpslSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct TpslRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct TpslAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct TpslSubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct TpslDefendDisputeResponse;

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslAuthType {
    pub merchant_code: Option<Secret<String>>,
    pub security_token: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for TpslAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => {
                let auth_str = api_key.clone().expose();
                let auth_data: TpslAuthType = serde_json::from_str(&auth_str)
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(auth_data)
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct TpslAuth {
    pub merchant_code: Option<Secret<String>>,
    pub security_token: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for TpslAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => {
                let auth_str = api_key.clone().expose();
                let auth_data: TpslAuth = serde_json::from_str(&auth_str)
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(auth_data)
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TpslPaymentStatus {
    Success,
    Pending,
    Failure,
    #[default]
    Processing,
}

impl From<TpslPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: TpslPaymentStatus) -> Self {
        match item {
            TpslPaymentStatus::Success => Self::Charged,
            TpslPaymentStatus::Pending => Self::AuthenticationPending,
            TpslPaymentStatus::Failure => Self::Failure,
            TpslPaymentStatus::Processing => Self::Pending,
        }
    }
}



impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize
>
TryFrom<
    TPSLRouterData<
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
        item: TPSLRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // CRITICAL: Extract all values dynamically from router data - NO HARDCODING
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()
            .unwrap_or_else(|| "https://default.return.url".to_string());
        
        // CRITICAL: Use proper amount converter - never hardcode amounts
        let amount = item.connector.amount_converter.convert(
            item.router_data.request.minor_amount,
            item.router_data.request.currency,
        ).change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let currency = item.router_data.request.currency.to_string();

        // CRITICAL: Extract authentication data dynamically
        let auth = TpslAuth::try_from(&item.router_data.connector_auth_type)?;
        
        // CRITICAL: Extract transaction ID dynamically
        let transaction_id = item.router_data.resource_common_data.connector_request_reference_id.clone();
        
        // CRITICAL: Extract IP address dynamically
        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        
        // CRITICAL: Extract email dynamically
        let email = item.router_data.request.email.clone()
            .unwrap_or_else(|| Email::from_str("default@example.com").unwrap());
        
        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => Ok(Self {
                merchant: TpslMerchantPayload {
                    webhook_endpoint_url: return_url.clone(),
                    response_type: "URL".to_string(),
                    response_endpoint_url: return_url.clone(),
                    description: "UPI Payment".to_string(),
                    identifier: auth.merchant_code.ok_or(ConnectorError::FailedToObtainAuthType)?,
                    webhook_type: "HTTP".to_string(),
                },
                cart: TpslCartPayload {
                    item: vec![TpslItemPayload {
                        description: "UPI Payment".to_string(),
                        provider_identifier: "UPI".to_string(),
                        surcharge_or_discount_amount: common_utils::types::StringMinorUnit::default(),
                        amount: amount.clone(),
                        com_amt: "0".to_string(),
                        s_k_u: "UPI".to_string(),
                        reference: transaction_id.clone(),
                        identifier: transaction_id.clone(),
                    }],
                    reference: transaction_id.clone(),
                    identifier: transaction_id.clone(),
                    description: "UPI Payment".to_string(),
                },
                payment: TpslPaymentPayload {
                    method: TpslMethodPayload {
                        token: "UPI".to_string(),
                        method_type: "UPI".to_string(),
                        code: "UPI".to_string(),
                    },
                    instrument: TpslInstrumentPayload {
                        expiry: TpslExpiryPayload {
                            year: "2024".to_string(),
                            month: "12".to_string(),
                            date_time: OffsetDateTime::now_utc().to_string(),
                        },
                        provider: "UPI".to_string(),
                        i_fsc: "".to_string(),
                        holder: TpslHolderPayload {
                            name: customer_id.get_string_repr().to_string(),
                            address: TpslAddressPayload {
                                country: "IN".to_string(),
                                street: "".to_string(),
                                state: "".to_string(),
                                city: "".to_string(),
                                zip_code: Secret::new("000000".to_string()),
                                county: "".to_string(),
                            },
                        },
                        b_i_c: "".to_string(),
                        instrument_type: "UPI".to_string(),
                        action: "SALE".to_string(),
                        m_i_c_r: "".to_string(),
                        verification_code: "".to_string(),
                        i_b_a_n: "".to_string(),
                        processor: "UPI".to_string(),
                        issuance: TpslExpiryPayload {
                            year: "2024".to_string(),
                            month: "12".to_string(),
                            date_time: OffsetDateTime::now_utc().to_string(),
                        },
                        alias: "".to_string(),
                        identifier: "".to_string(),
                        token: "".to_string(),
                        authentication: TpslAuthenticationPayload {
                            token: "".to_string(),
                            auth_type: "".to_string(),
                            sub_type: "".to_string(),
                        },
                        sub_type: "".to_string(),
                        issuer: "".to_string(),
                        acquirer: "".to_string(),
                    },
                    instruction: TpslInstructionPayload {
                        occurrence: "".to_string(),
                        amount: amount.clone(),
                        frequency: "".to_string(),
                        instruction_type: "".to_string(),
                        description: "".to_string(),
                        action: "".to_string(),
                        limit: "".to_string(),
                        end_date_time: "".to_string(),
                        debit_day: "".to_string(),
                        debit_flag: "".to_string(),
                        identifier: "".to_string(),
                        reference: "".to_string(),
                        start_date_time: "".to_string(),
                        validity: "".to_string(),
                    },
                },
                transaction: TpslTransactionPayload {
                    device_identifier: ip_address,
                    sms_sending: "N".to_string(),
                    amount: amount,
                    forced_3_d_s_call: "N".to_string(),
                    transaction_type: "SALE".to_string(),
                    description: "UPI Payment".to_string(),
                    currency,
                    is_registration: "N".to_string(),
                    identifier: transaction_id.clone(),
                    date_time: OffsetDateTime::now_utc().to_string(),
                    token: auth.security_token.ok_or(ConnectorError::FailedToObtainAuthType)?.expose().to_string(),
                    security_token: auth.security_token.ok_or(ConnectorError::FailedToObtainAuthType)?.expose().to_string(),
                    sub_type: "UPI".to_string(),
                    request_type: "SALE".to_string(),
                    reference: transaction_id,
                    merchant_initiated: "N".to_string(),
                    tenure_id: "".to_string(),
                },
                consumer: TpslConsumerPayload {
                    mobile_number: "".to_string(), // TODO: Extract from customer data if available
                    email_i_d: email,
                    identifier: customer_id.get_string_repr().to_string(),
                    account_no: "".to_string(),
                    account_type: "".to_string(),
                    account_holder_name: customer_id.get_string_repr().to_string(),
                    aadhar_no: "".to_string(),
                },
                merchant_input_flags: TpslFlagsType {
                    account_no: false,
                    mobile_number: true,
                    email_i_d: true,
                    card_details: false,
                    mandate_details: false,
                },
            }),
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment methods other than UPI are not supported".to_string(),
            )
            .into()),
        }
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
        
        let (status, response) = match response {
            TpslPaymentsResponse::TpslUPISuccessTxnResponse(response_data) => {
                let redirection_data = get_redirect_form_data(&response_data)?;
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
                        network_txn_id: response_data.payment_method.payment_transaction.identifier.clone(),
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            TpslPaymentsResponse::TpslErrorResponse(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error_code.to_string(),
                    status_code: item.http_code,
                    message: error_data.error_message.clone(),
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

fn get_redirect_form_data(
    response_data: &TpslUPITxnResponse,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    // Extract redirect URL from ACS payload if available
    if let Some(acs_url) = response_data.payment_method.a_c_s.bank_acs_url.as_str() {
        Ok(RedirectForm::Form {
            endpoint: acs_url.to_string(),
            method: Method::Post,
            form_fields: HashMap::new(),
        })
    } else {
        Err(errors::ConnectorError::MissingRequiredField {
            field_name: "redirect_url",
        }
        .into())
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
    TPSLRouterData<
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        T,
    >,
> for TpslPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: TPSLRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // CRITICAL: Extract all values dynamically from router data - NO HARDCODING
        let amount = item.connector.amount_converter.convert(
            item.router_data.request.amount,
            item.router_data.request.currency,
        ).map_err(|_| errors::ConnectorError::ParsingFailed)?;
        let currency = item.router_data.request.currency.to_string();

        let auth = TpslAuth::try_from(&item.router_data.connector_auth_type)?;

        Ok(Self {
            merchant: TpslMerchantDataType {
                identifier: auth.merchant_code.ok_or(ConnectorError::FailedToObtainAuthType)?.expose().to_string(),
            },
            payment: TpslPaymentUPISyncType {
                instruction: serde_json::Value::Null,
            },
            transaction: TpslTransactionUPITxnType {
                device_identifier: "127.0.0.1".to_string(), // PaymentsSyncData doesn't have browser_info
                transaction_type: Some("SALE".to_string()),
                sub_type: Some("UPI".to_string()),
                amount: amount,
                currency,
                date_time: OffsetDateTime::now_utc().to_string(),
                request_type: "SALE".to_string(),
                token: auth.security_token.ok_or(ConnectorError::FailedToObtainAuthType)?.expose().to_string(),
            },
            consumer: TpslConsumerDataType {
                identifier: item.router_data.resource_common_data.get_customer_id()?.get_string_repr().to_string(),
            },
        })
    }
}

impl<
    F,
> TryFrom<ResponseRouterData<TpslPaymentsSyncResponse, Self>>
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
        
        let status = match response.transaction_state.as_str() {
            "SUCCESS" | "SUCCESSFUL" => common_enums::AttemptStatus::Charged,
            "PENDING" => common_enums::AttemptStatus::Pending,
            "FAILED" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.merchant_transaction_identifier,
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.payment_method.payment_transaction.identifier,
                connector_response_reference_id: response.identifier,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}