use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, request::Method, types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData},
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

use crate::{connectors::easebuzz::EasebuzzRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzPaymentsRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub currency: String,
    pub email: Option<Email>,
    pub phone: Option<String>,
    pub firstname: Option<String>,
    pub lastname: Option<String>,
    pub surl: String,
    pub furl: String,
    pub productinfo: String,
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
    pub key: Secret<String>,
    pub payment_source: Option<String>,
    pub sub_merchant_id: Option<String>,
    pub customer_unique_id: Option<String>,
    pub split_info: Option<String>,
    pub custom_notes: Option<String>,
    pub device_info: Option<EasebuzzDeviceInfo>,
    pub card_details: Option<EasebuzzCardDetails>,
    pub upi: Option<EasebuzzUpiDetails>,
    pub bankcode: Option<String>,
    pub auth: Option<EasebuzzAuthData>,
    pub enforce_paymentmethod: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzDeviceInfo {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub accept_header: Option<String>,
    pub language: Option<String>,
    pub timezone: Option<String>,
    pub screen_width: Option<i32>,
    pub screen_height: Option<i32>,
    pub color_depth: Option<i32>,
    pub java_enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzCardDetails {
    pub card_number: Secret<String>,
    pub card_holder_name: String,
    pub card_exp_month: String,
    pub card_exp_year: String,
    pub card_cvv: Secret<String>,
    pub card_brand: Option<String>,
    pub card_type: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzUpiDetails {
    pub vpa: Option<String>,
    pub upi_intent: Option<bool>,
    pub upi_collect: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzAuthData {
    pub three_ds_server_trans_id: Option<String>,
    pub ds_trans_id: Option<String>,
    pub three_ds_method_data: Option<String>,
    pub notification_url: Option<String>,
    pub challenge_request: Option<String>,
    pub challenge_response: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EasebuzzPaymentsSyncRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub email: String,
    pub phone: String,
    pub key: Secret<String>,
    pub hash: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzPaymentsResponse {
    pub status: bool,
    pub message: Option<String>,
    pub easebuzz_id: Option<String>,
    pub txnid: Option<String>,
    pub amount: Option<String>,
    pub currency: Option<String>,
    pub payment_source: Option<String>,
    pub card_no: Option<String>,
    pub card_type: Option<String>,
    pub name_on_card: Option<String>,
    pub bank_ref_num: Option<String>,
    pub bankcode: Option<String>,
    pub error_desc: Option<String>,
    pub error_code: Option<String>,
    pub data: Option<EasebuzzResponseData>,
    pub redirect_url: Option<String>,
    pub payment_mode: Option<String>,
    pub card_token: Option<String>,
    pub card_brand: Option<String>,
    pub card_issuer: Option<String>,
    pub card_issuer_country: Option<String>,
    pub card_category: Option<String>,
    pub card_sub_type: Option<String>,
    pub card_level: Option<String>,
    pub card_isin: Option<String>,
    pub card_number_length: Option<i32>,
    pub card_bin: Option<String>,
    pub card_last_four_digits: Option<String>,
    pub card_expiry_month: Option<String>,
    pub card_expiry_year: Option<String>,
    pub card_holder_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzResponseData {
    pub payment_url: Option<String>,
    pub qr_link: Option<String>,
    pub vpa: Option<String>,
    pub upi_intent: Option<bool>,
    pub upi_collect: Option<bool>,
    pub payment_mode: Option<String>,
    pub card_token: Option<String>,
    pub card_brand: Option<String>,
    pub card_issuer: Option<String>,
    pub card_issuer_country: Option<String>,
    pub card_category: Option<String>,
    pub card_sub_type: Option<String>,
    pub card_level: Option<String>,
    pub card_isin: Option<String>,
    pub card_number_length: Option<i32>,
    pub card_bin: Option<String>,
    pub card_last_four_digits: Option<String>,
    pub card_expiry_month: Option<String>,
    pub card_expiry_year: Option<String>,
    pub card_holder_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzPaymentsSyncResponse {
    pub status: bool,
    pub message: Option<String>,
    pub easebuzz_id: Option<String>,
    pub txnid: Option<String>,
    pub amount: Option<String>,
    pub currency: Option<String>,
    pub payment_source: Option<String>,
    pub card_no: Option<String>,
    pub card_type: Option<String>,
    pub name_on_card: Option<String>,
    pub bank_ref_num: Option<String>,
    pub bankcode: Option<String>,
    pub error_desc: Option<String>,
    pub error_code: Option<String>,
    pub data: Option<EasebuzzResponseData>,
    pub redirect_url: Option<String>,
    pub payment_mode: Option<String>,
    pub card_token: Option<String>,
    pub card_brand: Option<String>,
    pub card_issuer: Option<String>,
    pub card_issuer_country: Option<String>,
    pub card_category: Option<String>,
    pub card_sub_type: Option<String>,
    pub card_level: Option<String>,
    pub card_isin: Option<String>,
    pub card_number_length: Option<i32>,
    pub card_bin: Option<String>,
    pub card_last_four_digits: Option<String>,
    pub card_expiry_month: Option<String>,
    pub card_expiry_year: Option<String>,
    pub card_holder_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzErrorResponse {
    pub status: bool,
    pub message: String,
    pub error_code: Option<String>,
    pub error_desc: Option<String>,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzAuthType {
    pub auths: HashMap<common_enums::Currency, EasebuzzAuth>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzAuth {
    pub key: Secret<String>,
    pub salt: Secret<String>,
    pub merchant_id: Option<Secret<String>>,
    pub sub_merchant_id: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for EasebuzzAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::CurrencyAuthKey { auth_key_map } => {
                let transformed_auths = auth_key_map
                    .iter()
                    .map(|(currency, identity_auth_key)| {
                        let easebuzz_auth = identity_auth_key
                            .to_owned()
                            .parse_value::<EasebuzzAuth>("EasebuzzAuth")
                            .change_context(errors::ConnectorError::InvalidDataFormat {
                                field_name: "auth_key_map",
                            })?;

                        Ok((currency.to_owned(), easebuzz_auth))
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

impl TryFrom<(&ConnectorAuthType, &common_enums::Currency)> for EasebuzzAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(value: (&ConnectorAuthType, &common_enums::Currency)) -> Result<Self, Self::Error> {
        let (auth_type, currency) = value;

        if let ConnectorAuthType::CurrencyAuthKey { auth_key_map } = auth_type {
            if let Some(identity_auth_key) = auth_key_map.get(currency) {
                let easebuzz_auth: Self = identity_auth_key
                    .to_owned()
                    .parse_value("EasebuzzAuth")
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(easebuzz_auth)
            } else {
                Err(errors::ConnectorError::CurrencyNotSupported {
                    message: currency.to_string(),
                    connector: "EaseBuzz",
                }
                .into())
            }
        } else {
            Err(errors::ConnectorError::FailedToObtainAuthType.into())
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EasebuzzPaymentStatus {
    Success,
    Pending,
    Failure,
    #[default]
    Unknown,
}

impl From<EasebuzzPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: EasebuzzPaymentStatus) -> Self {
        match item {
            EasebuzzPaymentStatus::Success => Self::Charged,
            EasebuzzPaymentStatus::Pending => Self::AuthenticationPending,
            EasebuzzPaymentStatus::Failure => Self::Failure,
            EasebuzzPaymentStatus::Unknown => Self::Pending,
        }
    }
}

fn get_auth_credentials(
    connector_auth_type: &ConnectorAuthType,
    currency: common_enums::Currency,
) -> Result<EasebuzzAuth, errors::ConnectorError> {
    EasebuzzAuth::try_from((connector_auth_type, &currency))
        .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)
}

fn get_redirect_form_data(
    payment_method_type: common_enums::PaymentMethodType,
    response_data: EasebuzzResponseData,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    match payment_method_type {
        common_enums::PaymentMethodType::UpiCollect => {
            if let Some(payment_url) = response_data.payment_url {
                Ok(RedirectForm::Form {
                    endpoint: payment_url,
                    method: Method::Get,
                    form_fields: Default::default(),
                })
            } else if let Some(qr_link) = response_data.qr_link {
                Ok(RedirectForm::Form {
                    endpoint: qr_link,
                    method: Method::Get,
                    form_fields: Default::default(),
                })
            } else {
                Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "payment_url or qr_link",
                }
                .into())
            }
        }
        _ => Err(errors::ConnectorError::NotImplemented(
            utils::get_unimplemented_payment_method_error_message("EaseBuzz"),
        ))?,
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
        EasebuzzRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for EasebuzzPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: EasebuzzRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        let auth = get_auth_credentials(
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

        // Extract browser info for device info
        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        let device_info = Some(EasebuzzDeviceInfo {
            ip_address: Some(ip_address),
            user_agent: Some(user_agent),
            accept_header: Some("application/json".to_string()),
            language: Some("en-US".to_string()),
            timezone: Some("UTC".to_string()),
            screen_width: None,
            screen_height: None,
            color_depth: None,
            java_enabled: None,
        });

        // Handle UPI payment method
        let upi_details = match item.router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::UpiCollect) => {
                Some(EasebuzzUpiDetails {
                    vpa: None, // Will be extracted from payment_method_data if available
                    upi_intent: Some(true),
                    upi_collect: Some(false),
                })
            }
            _ => None,
        };

        Ok(Self {
            txnid: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount,
            currency: item.router_data.request.currency.to_string(),
            email: item.router_data.request.email.clone(),
            phone: None, // Extract from payment_method_data if available
            firstname: None, // Extract from customer data if available
            lastname: None, // Extract from customer data if available
            surl: return_url.clone(),
            furl: return_url,
            productinfo: "Payment".to_string(),
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
            hash: auth.salt, // In real implementation, this would be a proper hash
            key: auth.key,
            payment_source: Some("upi".to_string()),
            sub_merchant_id: auth.sub_merchant_id.map(|s| s.expose()),
            customer_unique_id: Some(customer_id.get_string_repr().to_string()),
            split_info: None,
            custom_notes: None,
            device_info,
            card_details: None,
            upi: upi_details,
            bankcode: None,
            auth: None,
            enforce_paymentmethod: Some(true),
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
        EasebuzzRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for EasebuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: EasebuzzRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(
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

        Ok(Self {
            txnid: item.router_data.request.connector_transaction_id
                .get_connector_transaction_id()
                .map_err(|_| errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_transaction_id",
                })?,
            amount,
            email: item.router_data.request.email.clone()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "email",
                })?
                .to_string(),
            phone: "1234567890".to_string(), // Default phone number
            key: auth.key,
            hash: auth.salt, // In real implementation, this would be a proper hash
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
    > TryFrom<ResponseRouterData<EasebuzzPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<EasebuzzPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = if response.status {
            let payment_method_type = router_data
                .request
                .payment_method_type
                .ok_or(errors::ConnectorError::MissingPaymentMethodType)?;
            
            if let Some(response_data) = response.data {
                let redirection_data = get_redirect_form_data(payment_method_type, response_data)?;
                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: Some(Box::new(redirection_data)),
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: response.easebuzz_id,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            } else {
                (
                    common_enums::AttemptStatus::Charged,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: response.easebuzz_id,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
        } else {
            (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: response.error_code.unwrap_or_else(|| "UNKNOWN".to_string()),
                    status_code: http_code,
                    message: response.message.clone().unwrap_or_else(|| "Unknown error".to_string()),
                    reason: response.message,
                    attempt_status: None,
                    connector_transaction_id: response.txnid,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: response.error_desc.clone(),
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

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<EasebuzzPaymentsSyncResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<EasebuzzPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let status = if response.status {
            common_enums::AttemptStatus::Charged
        } else {
            common_enums::AttemptStatus::Failure
        };

        let response_data = PaymentsResponseData::TransactionResponse {
            resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
                response.txnid.unwrap_or_else(|| "unknown".to_string()),
            ),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: response.easebuzz_id,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(response_data),
            ..router_data
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzIncomingWebhook {
    pub easebuzz_id: Option<String>,
    pub txnid: Option<String>,
    pub amount: Option<String>,
    pub currency: Option<String>,
    pub status: Option<bool>,
    pub message: Option<String>,
    pub payment_source: Option<String>,
    pub card_no: Option<String>,
    pub card_type: Option<String>,
    pub name_on_card: Option<String>,
    pub bank_ref_num: Option<String>,
    pub bankcode: Option<String>,
    pub error_desc: Option<String>,
    pub error_code: Option<String>,
    pub data: Option<EasebuzzResponseData>,
    pub redirect_url: Option<String>,
    pub payment_mode: Option<String>,
    pub card_token: Option<String>,
    pub card_brand: Option<String>,
    pub card_issuer: Option<String>,
    pub card_issuer_country: Option<String>,
    pub card_category: Option<String>,
    pub card_sub_type: Option<String>,
    pub card_level: Option<String>,
    pub card_isin: Option<String>,
    pub card_number_length: Option<i32>,
    pub card_bin: Option<String>,
    pub card_last_four_digits: Option<String>,
    pub card_expiry_month: Option<String>,
    pub card_expiry_year: Option<String>,
    pub card_holder_name: Option<String>,
}