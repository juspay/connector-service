use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, id_type, request::Method, types::FloatMajorUnit,
    Email,
};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors::{self, ConnectorError},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{connectors::cashtocode::CashtocodeRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CashtocodePaymentsRequest {
    amount: FloatMajorUnit,
    transaction_id: String,
    user_id: Secret<id_type::CustomerId>,
    currency: common_enums::Currency,
    first_name: Option<Secret<String>>,
    last_name: Option<Secret<String>>,
    user_alias: Secret<id_type::CustomerId>,
    requested_url: String,
    cancel_url: String,
    email: Option<Email>,
    mid: Secret<String>,
}

fn get_mid(
    connector_auth_type: &ConnectorAuthType,
    payment_method_type: Option<common_enums::PaymentMethodType>,
    currency: common_enums::Currency,
) -> Result<Secret<String>, errors::ConnectorError> {
    match CashtocodeAuth::try_from((connector_auth_type, &currency)) {
        Ok(cashtocode_auth) => match payment_method_type {
            Some(common_enums::PaymentMethodType::ClassicReward) => Ok(cashtocode_auth
                .merchant_id_classic
                .ok_or(errors::ConnectorError::FailedToObtainAuthType)?),
            Some(common_enums::PaymentMethodType::Evoucher) => Ok(cashtocode_auth
                .merchant_id_evoucher
                .ok_or(errors::ConnectorError::FailedToObtainAuthType)?),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType),
        },
        Err(_) => Err(errors::ConnectorError::FailedToObtainAuthType)?,
    }
}

impl
    TryFrom<
        CashtocodeRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for CashtocodePaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: CashtocodeRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let url = item.router_data.request.get_router_return_url()?;
        let mid = get_mid(
            &item.router_data.connector_auth_type,
            item.router_data.request.payment_method_type,
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
        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Reward => Ok(Self {
                amount,
                transaction_id: item
                    .router_data
                    .resource_common_data
                    .connector_request_reference_id,
                currency: item.router_data.request.currency,
                user_id: Secret::new(customer_id.to_owned()),
                first_name: None,
                last_name: None,
                user_alias: Secret::new(customer_id),
                requested_url: url.to_owned(),
                cancel_url: url,
                email: item.router_data.request.email.clone(),
                mid,
            }),
            _ => Err(errors::ConnectorError::NotImplemented("Payment methods".to_string()).into()),
        }
    }
}

#[derive(Default, Debug, Deserialize)]
pub struct CashtocodeAuthType {
    pub auths: HashMap<common_enums::Currency, CashtocodeAuth>,
}

#[derive(Default, Debug, Deserialize)]
pub struct CashtocodeAuth {
    pub password_classic: Option<Secret<String>>,
    pub password_evoucher: Option<Secret<String>>,
    pub username_classic: Option<Secret<String>>,
    pub username_evoucher: Option<Secret<String>>,
    pub merchant_id_classic: Option<Secret<String>>,
    pub merchant_id_evoucher: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for CashtocodeAuthType {
    type Error = error_stack::Report<errors::ConnectorError>; // Assuming ErrorStack is the appropriate error type

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::CurrencyAuthKey { auth_key_map } => {
                let transformed_auths = auth_key_map
                    .iter()
                    .map(|(currency, identity_auth_key)| {
                        let cashtocode_auth = identity_auth_key
                            .to_owned()
                            .parse_value::<CashtocodeAuth>("CashtocodeAuth")
                            .change_context(errors::ConnectorError::InvalidDataFormat {
                                field_name: "auth_key_map",
                            })?;

                        Ok((currency.to_owned(), cashtocode_auth))
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

impl TryFrom<(&ConnectorAuthType, &common_enums::Currency)> for CashtocodeAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(value: (&ConnectorAuthType, &common_enums::Currency)) -> Result<Self, Self::Error> {
        let (auth_type, currency) = value;

        if let ConnectorAuthType::CurrencyAuthKey { auth_key_map } = auth_type {
            if let Some(identity_auth_key) = auth_key_map.get(currency) {
                let cashtocode_auth: Self = identity_auth_key
                    .to_owned()
                    .parse_value("CashtocodeAuth")
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(cashtocode_auth)
            } else {
                Err(errors::ConnectorError::CurrencyNotSupported {
                    message: currency.to_string(),
                    connector: "CashToCode",
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
pub enum CashtocodePaymentStatus {
    Succeeded,
    #[default]
    Processing,
}

impl From<CashtocodePaymentStatus> for common_enums::AttemptStatus {
    fn from(item: CashtocodePaymentStatus) -> Self {
        match item {
            CashtocodePaymentStatus::Succeeded => Self::Charged,
            CashtocodePaymentStatus::Processing => Self::AuthenticationPending,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct CashtocodeErrors {
    pub message: String,
    pub path: String,
    #[serde(rename = "type")]
    pub event_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CashtocodePaymentsResponse {
    CashtoCodeError(CashtocodeErrorResponse),
    CashtoCodeData(CashtocodePaymentsResponseData),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CashtocodePaymentsResponseData {
    pub pay_url: url::Url,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CashtocodePaymentsSyncResponse {
    pub transaction_id: String,
    pub amount: FloatMajorUnit,
}

fn get_redirect_form_data(
    payment_method_type: common_enums::PaymentMethodType,
    response_data: CashtocodePaymentsResponseData,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    match payment_method_type {
        common_enums::PaymentMethodType::ClassicReward => Ok(RedirectForm::Form {
            //redirect form is manually constructed because the connector for this pm type expects query params in the url
            endpoint: response_data.pay_url.to_string(),
            method: Method::Post,
            form_fields: Default::default(),
        }),
        common_enums::PaymentMethodType::Evoucher => Ok(RedirectForm::Form {
            //here the pay url gets parsed, and query params are sent as formfields as the connector expects
            endpoint: response_data.pay_url.to_string(),
            method: Method::Get,
            form_fields: Default::default(),
        }),
        _ => Err(errors::ConnectorError::NotImplemented(
            utils::get_unimplemented_payment_method_error_message("CashToCode"),
        ))?,
    }
}

impl<F> TryFrom<ResponseRouterData<CashtocodePaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<CashtocodePaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let (status, response) = match response {
            CashtocodePaymentsResponse::CashtoCodeError(error_data) => (
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
                    raw_connector_response: None,
                }),
            ),
            CashtocodePaymentsResponse::CashtoCodeData(response_data) => {
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
                        raw_connector_response: None,
                        status_code: Some(http_code),
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

#[derive(Debug, Deserialize, Serialize)]
pub struct CashtocodeErrorResponse {
    pub error: serde_json::Value,
    pub error_description: String,
    pub errors: Option<Vec<CashtocodeErrors>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CashtocodeIncomingWebhook {
    pub amount: FloatMajorUnit,
    pub currency: String,
    pub foreign_transaction_id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub transaction_id: String,
}
