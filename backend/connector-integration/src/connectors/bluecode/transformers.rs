use common_enums::{self, enums, AttemptStatus};
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    pii,
    request::Method,
    types::FloatMajorUnit,
};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId,
    },
    errors::{self},
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, WalletData},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::{report, ResultExt};
# use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::types::ResponseRouterData;

// Auth
pub struct BluecodeAuthType {
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BluecodeAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Requests
#[derive(Debug, Serialize)]
pub struct BluecodePaymentsRequest {
    pub amount: FloatMajorUnit,
    pub currency: enums::Currency,
    pub payment_provider: String,
    pub shop_name: String,
    pub reference: String,
    pub ip_address: Option<Secret<String, pii::IpAddress>>,
    pub first_name: Secret<String>,
    pub last_name: Secret<String>,
    pub billing_address_country_code_iso: enums::CountryAlpha2,
    pub billing_address_city: String,
    pub billing_address_line1: Secret<String>,
    pub billing_address_postal_code: Option<Secret<String>>,
    pub webhook_url: url::Url,
    pub success_url: url::Url,
    pub failure_url: url::Url,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BluecodeWebhookResponse {
    pub id: Option<i64>,
    pub order_id: String,
    pub user_id: Option<i64>,
    pub customer_id: Option<String>,
    pub customer_email: Option<common_utils::Email>,
    pub customer_phone: Option<String>,
    pub status: BluecodePaymentStatus,
    pub payment_provider: Option<String>,
    pub payment_connector: Option<String>,
    pub payment_method: Option<String>,
    pub payment_method_type: Option<String>,
    pub shop_name: Option<String>,
    pub sender_name: Option<String>,
    pub sender_email: Option<String>,
    pub description: Option<String>,
    pub amount: FloatMajorUnit,
    pub currency: enums::Currency,
    pub charged_amount: Option<FloatMajorUnit>,
    pub charged_amount_currency: Option<String>,
    pub charged_fx_amount: Option<FloatMajorUnit>,
    pub charged_fx_amount_currency: Option<enums::Currency>,
    pub is_underpaid: Option<bool>,
    pub billing_amount: Option<FloatMajorUnit>,
    pub billing_currency: Option<String>,
    pub language: Option<String>,
    pub ip_address: Option<Secret<String, common_utils::pii::IpAddress>>,
    pub first_name: Option<Secret<String>>,
    pub last_name: Option<Secret<String>>,
    pub billing_address_line1: Option<Secret<String>>,
    pub billing_address_city: Option<Secret<String>>,
    pub billing_address_postal_code: Option<Secret<String>>,
    pub billing_address_country: Option<String>,
    pub billing_address_country_code_iso: Option<enums::CountryAlpha2>,
    pub shipping_address_country_code_iso: Option<enums::CountryAlpha2>,
    pub success_url: Option<url::Url>,
    pub failure_url: Option<url::Url>,
    pub source: Option<String>,
    pub bonus_code: Option<String>,
    pub dob: Option<String>,
    pub fees_amount: Option<f64>,
    pub fx_margin_amount: Option<f64>,
    pub fx_margin_percent: Option<f64>,
    pub fees_percent: Option<f64>,
    pub reseller_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BluecodeCaptureRequest;

#[derive(Debug, Serialize)]
pub struct BluecodeVoidRequest;

#[derive(Debug, Serialize)]
pub struct BluecodeRefundRequest {
    pub amount: FloatMajorUnit,
}

impl TryFrom<&pii::SecretSerdeValue> for BluecodeMetadataObject {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(secret_value: &pii::SecretSerdeValue) -> Result<Self, Self::Error> {
        let secret_value_str = match secret_value.peek() {
            serde_json::Value::String(s) => s.clone(),
            _ => {
                return Err(report!(errors::ConnectorError::InvalidConnectorConfig {
                    config: "BluecodeMetadataObject in connector_meta_data was not a JSON string",
                }));
            }
        };

        serde_json::from_str(&secret_value_str).change_context(
            errors::ConnectorError::InvalidConnectorConfig {
                config: "Deserializing BluecodeMetadataObject from connector_meta_data string",
            },
        )
    }
}

// Request TryFrom implementations
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::BluecodeRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for BluecodePaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: super::BluecodeRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        if item.router_data.request.capture_method == Some(enums::CaptureMethod::Manual) {
            return Err(errors::ConnectorError::CaptureMethodNotSupported.into());
        }
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Wallet(WalletData::BluecodeRedirect {}) => {
                let amount = item
                    .connector
                    .amount_converter
                    .convert(
                        item.router_data.request.minor_amount,
                        item.router_data.request.currency,
                    )
                    .change_context(errors::ConnectorError::RequestEncodingFailed)?;
                let bluecode_mca_metadata = BluecodeMetadataObject::try_from(
                    &item.router_data.resource_common_data.get_connector_meta()?,
                )?;

                Ok(Self {
                    amount,
                    currency: item.router_data.request.currency,
                    payment_provider: "bluecode_payment".to_string(),
                    shop_name: bluecode_mca_metadata.shop_name.clone(),
                    reference: item
                        .router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                    ip_address: item.router_data.request.get_ip_address_as_optional(),
                    first_name: item
                        .router_data
                        .resource_common_data
                        .get_billing_first_name()?,
                    last_name: item
                        .router_data
                        .resource_common_data
                        .get_billing_last_name()?,
                    billing_address_country_code_iso: item
                        .router_data
                        .resource_common_data
                        .get_billing_country()?,
                    billing_address_city: item
                        .router_data
                        .resource_common_data
                        .get_billing_city()?,
                    billing_address_line1: item
                        .router_data
                        .resource_common_data
                        .get_billing_line1()?,
                    billing_address_postal_code: item
                        .router_data
                        .resource_common_data
                        .get_optional_billing_zip(),
                    webhook_url: url::Url::parse(&item.router_data.request.get_webhook_url()?)
                        .change_context(errors::ConnectorError::ParsingFailed)?,
                    success_url: url::Url::parse(
                        &item.router_data.request.get_router_return_url()?,
                    )
                    .change_context(errors::ConnectorError::ParsingFailed)?,
                    failure_url: url::Url::parse(
                        &item.router_data.request.get_router_return_url()?,
                    )
                    .change_context(errors::ConnectorError::ParsingFailed)?,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented("Payment method".to_string()).into()),
        }
    }
}

// Responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluecodePaymentsResponse {
    pub id: i64,
    pub order_id: String,
    pub amount: FloatMajorUnit,
    pub currency: enums::Currency,
    pub charged_amount: FloatMajorUnit,
    pub charged_currency: enums::Currency,
    pub status: BluecodePaymentStatus,
    pub payment_link: url::Url,
    pub etoken: Secret<String>,
    pub payment_request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluecodeSyncResponse {
    pub id: Option<i64>,
    pub order_id: String,
    pub status: BluecodePaymentStatus,
    pub amount: FloatMajorUnit,
    pub currency: enums::Currency,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BluecodePaymentStatus {
    Pending,
    PaymentInitiated,
    ManualProcessing,
    Failed,
    Completed,
}

impl From<BluecodePaymentStatus> for AttemptStatus {
    fn from(item: BluecodePaymentStatus) -> Self {
        match item {
            BluecodePaymentStatus::ManualProcessing => Self::Pending,
            BluecodePaymentStatus::Pending | BluecodePaymentStatus::PaymentInitiated => {
                Self::AuthenticationPending
            }
            BluecodePaymentStatus::Failed => Self::Failure,
            BluecodePaymentStatus::Completed => Self::Charged,
        }
    }
}

// Response TryFrom implementations
impl<F, T>
    TryFrom<
        ResponseRouterData<
            BluecodePaymentsResponse,
            RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
where
    T: Clone,
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            BluecodePaymentsResponse,
            RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let redirection_data = Some(domain_types::router_response_types::RedirectForm::Form {
            endpoint: item.response.payment_link.to_string(),
            method: Method::Get,
            form_fields: Default::default(),
        });
        let response = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(item.response.order_id),
            redirection_data: redirection_data.map(Box::new),
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(item.response.payment_request_id),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        });

        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status: AttemptStatus::from(item.response.status),
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<BluecodeSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: ResponseRouterData<BluecodeSyncResponse, Self>) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let status = AttemptStatus::from(response.status);
        let response = if status == common_enums::AttemptStatus::Failure {
            Err(ErrorResponse {
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: Some(NO_ERROR_MESSAGE.to_string()),
                attempt_status: Some(status),
                connector_transaction_id: Some(response.order_id.clone()),
                status_code: http_code,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.order_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            })
        };
        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

// Error
#[derive(Debug, Serialize, Deserialize)]
pub struct BluecodeErrorResponse {
    pub message: String,
    pub context_data: std::collections::HashMap<String, Value>,
}

// Webhooks, metadata etc.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BluecodeMetadataObject {
    pub shop_name: String,
}

pub fn sort_and_minify_json(value: &Value) -> Result<String, errors::ConnectorError> {
    fn sort_value(val: &Value) -> Value {
        match val {
            Value::Object(map) => {
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_by_key(|(k, _)| k.to_owned());

                let sorted_map: Map<String, Value> = entries
                    .into_iter()
                    .map(|(k, v)| (k.clone(), sort_value(v)))
                    .collect();

                Value::Object(sorted_map)
            }
            Value::Array(arr) => Value::Array(arr.iter().map(sort_value).collect()),
            _ => val.clone(),
        }
    }

    let sorted_value = sort_value(value);
    serde_json::to_string(&sorted_value)
        .map_err(|_| errors::ConnectorError::WebhookBodyDecodingFailed)
}
