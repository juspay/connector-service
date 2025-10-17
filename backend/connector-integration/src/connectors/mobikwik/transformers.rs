use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    request::Method,
    types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::mobikwik::MobikwikRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobikwikPaymentsRequest {
    pub cell: String,
    pub amount: StringMinorUnit,
    pub orderid: String,
    pub merchantname: String,
    pub mid: String,
    pub token: Option<String>,
    pub redirecturl: String,
    pub checksum: String,
    pub version: String,
    pub email: Option<Email>,
    pub txntype: Option<String>,
    pub comment: Option<String>,
    pub showmobile: Option<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobikwikPaymentsSyncRequest {
    pub mid: String,
    pub orderid: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MobikwikPaymentsResponse {
    DebitResponse(DebitResponseType),
    AddMoneyResponse(AddMoneyDebitResponse),
    RedirectResponse(RedirectDebitResponse),
    ErrorResponse(MobikwikErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobikwikPaymentsSyncResponse {
    pub statuscode: String,
    pub orderid: String,
    pub refid: Option<String>,
    pub amount: Option<String>,
    pub statusmessage: String,
    pub ordertype: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddMoneyDebitResponse {
    pub statuscode: String,
    pub amount: String,
    pub orderid: String,
    pub statusmessage: String,
    pub checksum: String,
    pub mid: String,
    pub refid: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectDebitResponse {
    pub statuscode: String,
    pub orderid: String,
    pub amount: String,
    pub statusmessage: String,
    pub checksum: String,
    pub mid: String,
    pub refid: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobikwikErrorResponse {
    pub statuscode: String,
    pub statusmessage: String,
    pub error: Option<String>,
    pub errordescription: Option<String>,
}

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct MobikwikVoidRequest;
#[derive(Debug, Clone)]
pub struct MobikwikVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikCaptureRequest;
#[derive(Debug, Clone)]
pub struct MobikwikCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikRefundRequest;
#[derive(Debug, Clone)]
pub struct MobikwikRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikRefundSyncRequest;
#[derive(Debug, Clone)]
pub struct MobikwikRefundSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct MobikwikCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct MobikwikSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct MobikwikSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct MobikwikRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct MobikwikAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct MobikwikDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct MobikwikSubmitEvidenceResponse;

#[derive(Default, Debug, Deserialize)]
pub struct MobikwikAuthType {
    pub auths: HashMap<common_enums::Currency, MobikwikAuth>,
}

#[derive(Default, Debug, Deserialize)]
pub struct MobikwikAuth {
    pub merchant_id: Option<Secret<String>>,
    pub checksum_secret: Option<Secret<String>>,
    pub api_key: Option<Secret<String>>,
    pub salt: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for MobikwikAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::CurrencyAuthKey { auth_key_map } => {
                let transformed_auths = auth_key_map
                    .iter()
                    .map(|(currency, identity_auth_key)| {
                        let mobikwik_auth = identity_auth_key
                            .to_owned()
                            .parse_value::<MobikwikAuth>("MobikwikAuth")
                            .change_context(errors::ConnectorError::InvalidDataFormat {
                                field_name: "auth_key_map",
                            })?;

                        Ok((currency.to_owned(), mobikwik_auth))
                    })
                    .collect::<Result<_, Self::Error>>()?;

                Ok(Self {
                    auths: transformed_auths,
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl TryFrom<&ConnectorAuthType> for MobikwikAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(value: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match value {
            ConnectorAuthType::CurrencyAuthKey { auth_key_map } => {
                // For simplicity, use the first available currency auth
                // In production, you might want to handle multiple currencies
                if let Some((_, identity_auth_key)) = auth_key_map.iter().next() {
                    let mobikwik_auth: Self = identity_auth_key
                        .to_owned()
                        .parse_value("MobikwikAuth")
                        .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                    Ok(mobikwik_auth)
                } else {
                    Err(errors::ConnectorError::FailedToObtainAuthType.into())
                }
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MobikwikPaymentStatus {
    #[default]
    Pending,
    Success,
    Failure,
    Processing,
}

impl From<MobikwikPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: MobikwikPaymentStatus) -> Self {
        match item {
            MobikwikPaymentStatus::Success => Self::Charged,
            MobikwikPaymentStatus::Failure => Self::Failure,
            MobikwikPaymentStatus::Pending => Self::Pending,
            MobikwikPaymentStatus::Processing => Self::AuthenticationPending,
        }
    }
}

fn get_merchant_id(
    connector_auth_type: &ConnectorAuthType,
    _currency: common_enums::Currency,
) -> Result<Secret<String>, errors::ConnectorError> {
    match MobikwikAuth::try_from(connector_auth_type) {
        Ok(mobikwik_auth) => {
            mobikwik_auth.merchant_id.ok_or(errors::ConnectorError::FailedToObtainAuthType)
        }
        Err(_) => Err(errors::ConnectorError::FailedToObtainAuthType)?,
    }
}

fn generate_checksum(
    params: &HashMap<String, String>,
    salt: &str,
) -> Result<String, errors::ConnectorError> {
    // This is a simplified checksum generation
    // In production, implement the actual checksum algorithm as per Mobikwik's documentation
    let mut sorted_params: Vec<_> = params.iter().collect();
    sorted_params.sort_by_key(|&(k, _)| k);
    
    let param_string = sorted_params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");
    
    let string_to_hash = format!("{}{}", param_string, salt);
    
    // Use SHA256 for checksum (adjust based on actual Mobikwik requirements)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(string_to_hash.as_bytes());
    let result = hasher.finalize();
    
    Ok(hex::encode(result))
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
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        let merchant_id = get_merchant_id(
            &item.router_data.connector_auth_type,
            item.router_data.request.currency,
        )?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Extract phone number from payment method data
        let phone_number = match &item.router_data.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => {
                match upi_data {
                    domain_types::payment_method_data::UpiData::UpiCollect(collect_data) => {
                        collect_data.vpa_id.as_ref()
                            .map(|vpa| vpa.peek().clone())
                            .unwrap_or_else(|| customer_id.get_string_repr().to_string())
                    }
                    _ => customer_id.get_string_repr().to_string(),
                }
            }
            _ => customer_id.get_string_repr().to_string(),
        };

        // Build parameters for checksum generation
        let mut params = HashMap::new();
        params.insert("cell".to_string(), phone_number.clone());
        params.insert("amount".to_string(), amount.to_string());
        params.insert("orderid".to_string(), item.router_data.resource_common_data.connector_request_reference_id.clone());
        params.insert("merchantname".to_string(), "Hyperswitch".to_string());
        params.insert("mid".to_string(), merchant_id.peek().clone());
        params.insert("version".to_string(), "2.0".to_string());

        // Generate checksum (simplified - use actual salt in production)
        let checksum = generate_checksum(&params, "salt_placeholder")?;

        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => Ok(Self {
                cell: phone_number,
                amount,
                orderid: item.router_data.resource_common_data.connector_request_reference_id,
                merchantname: "Hyperswitch".to_string(),
                mid: merchant_id.peek().clone(),
                token: None, // Token will be set after OTP verification
                redirecturl: return_url.to_string(),
                checksum,
                version: "2.0".to_string(),
                email: item.router_data.request.email.clone(),
                txntype: Some("debit".to_string()),
                comment: Some("Payment via Hyperswitch".to_string()),
                showmobile: Some("true".to_string()),
            }),
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment methods".to_string(),
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
        MobikwikRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for MobikwikPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: MobikwikRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let merchant_id = get_merchant_id(
            &item.router_data.connector_auth_type,
            item.router_data.request.currency,
        )?;

        // Build parameters for checksum generation
        let mut params = HashMap::new();
        params.insert("mid".to_string(), merchant_id.peek().clone());
        params.insert("orderid".to_string(), item.router_data.resource_common_data.connector_request_reference_id.clone());

        // Generate checksum
        let checksum = generate_checksum(&params, "salt_placeholder")?;

        Ok(Self {
            mid: merchant_id.peek().clone(),
            orderid: item.router_data.resource_common_data.connector_request_reference_id,
            checksum,
        })
    }
}

fn get_redirect_form_data(
    payment_method_type: common_enums::PaymentMethodType,
    response_data: &MobikwikPaymentsResponse,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    match payment_method_type {
        common_enums::PaymentMethodType::UpiIntent => {
            // For Mobikwik, typically redirect to their payment page
            let redirect_url = match response_data {
                MobikwikPaymentsResponse::RedirectResponse(resp) => {
                    Some(format!("https://walletapi.mobikwik.com/redirect?orderid={}", resp.orderid))
                }
                MobikwikPaymentsResponse::AddMoneyResponse(resp) => {
                    Some(format!("https://walletapi.mobikwik.com/addmoney?orderid={}", resp.orderid))
                }
                _ => None,
            };

            if let Some(url) = redirect_url {
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
            utils::get_unimplemented_payment_method_error_message("Mobikwik"),
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
            MobikwikPaymentsResponse::ErrorResponse(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.statuscode.to_string(),
                    status_code: item.http_code,
                    message: error_data.statusmessage.clone(),
                    reason: Some(error_data.statusmessage),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            MobikwikPaymentsResponse::DebitResponse(response_data) => {
                let attempt_status = if response_data.status == "success" {
                    common_enums::AttemptStatus::Charged
                } else {
                    common_enums::AttemptStatus::Failure
                };

                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: response_data.refid.clone(),
                        connector_response_reference_id: response_data.refid,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            MobikwikPaymentsResponse::AddMoneyResponse(response_data) => {
                let payment_method_type = router_data
                    .request
                    .payment_method_type
                    .ok_or(errors::ConnectorError::MissingPaymentMethodType)?;
                
                let redirection_data = get_redirect_form_data(payment_method_type, &MobikwikPaymentsResponse::AddMoneyResponse(response_data.clone()))?;

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
                        network_txn_id: response_data.refid.clone(),
                        connector_response_reference_id: response_data.refid,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            MobikwikPaymentsResponse::RedirectResponse(response_data) => {
                let payment_method_type = router_data
                    .request
                    .payment_method_type
                    .ok_or(errors::ConnectorError::MissingPaymentMethodType)?;
                
                let redirection_data = get_redirect_form_data(payment_method_type, &MobikwikPaymentsResponse::RedirectResponse(response_data.clone()))?;

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
                        network_txn_id: response_data.refid.clone(),
                        connector_response_reference_id: response_data.refid,
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

impl TryFrom<MobikwikPaymentsSyncResponse> for PaymentsResponseData
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: MobikwikPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let attempt_status = match response.statuscode.as_str() {
            "0" | "200" => common_enums::AttemptStatus::Charged,
            "1" | "400" => common_enums::AttemptStatus::Failure,
            "2" | "300" => common_enums::AttemptStatus::Pending,
            _ => common_enums::AttemptStatus::AuthenticationPending,
        };

        Ok(Self::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.orderid),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: response.refid,
            connector_response_reference_id: response.refid,
            incremental_authorization_allowed: None,
            status_code: 200,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MobikwikIncomingWebhook {
    pub statuscode: String,
    pub orderid: String,
    pub refid: Option<String>,
    pub amount: Option<String>,
    pub statusmessage: String,
    pub ordertype: String,
    pub checksum: String,
}