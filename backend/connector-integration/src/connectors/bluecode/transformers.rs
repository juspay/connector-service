use super::BluecodeRouterData;
use crate::types::ResponseRouterData;
use common_enums::{self, enums, AttemptStatus};
use common_utils::{
    pii,
    request::Method,
    types::{AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector},
};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors::{self},
    payment_method_data::{PaymentMethodData, WalletData},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::report;
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

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
    pub webhook_url: String,
    pub success_url: String,
    pub failure_url: String,
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
impl
    TryFrom<
        BluecodeRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for BluecodePaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: BluecodeRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Wallet(WalletData::BluecodeRedirect {}) => {
                let amount = FloatMajorUnitForConnector
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
                    webhook_url: item.router_data.request.get_webhook_url()?,
                    success_url: item.router_data.request.get_router_return_url()?,
                    failure_url: item.router_data.request.get_router_return_url()?,
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

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct BluecodeRefundResponse {
//     id: String,
//     status: BluecodeRefundStatus,
// }

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

// #[derive(Debug, Copy, Serialize, Deserialize, Clone)]
// #[serde(rename_all = "PascalCase")]
// pub enum BluecodeRefundStatus {
//     Succeeded,
//     Failed,
//     Processing,
// }

// impl From<BluecodeRefundStatus> for enums::RefundStatus {
//     fn from(item: BluecodeRefundStatus) -> Self {
//         match item {
//             BluecodeRefundStatus::Succeeded => Self::Success,
//             BluecodeRefundStatus::Failed => Self::Failure,
//             BluecodeRefundStatus::Processing => Self::Pending,
//         }
//     }
// }

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
        let redirection_data = Some(RedirectForm::from((
            item.response.payment_link.clone(),
            Method::Get,
        )));
        let response = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(item.response.order_id),
            redirection_data: redirection_data.map(Box::new),
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(item.response.payment_request_id),
            incremental_authorization_allowed: None,
            raw_connector_response: None,
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

impl<F, T>
    TryFrom<
        ResponseRouterData<
            BluecodeSyncResponse,
            RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
where
    T: Clone,
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            BluecodeSyncResponse,
            RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // let response = Ok(PaymentsResponseData::TransactionResponse {
        //     resource_id: ResponseId::ConnectorTransactionId(item.response.order_id),
        //     redirection_data: None,
        //     mandate_reference: None,
        //     connector_metadata: None,
        //     network_txn_id: None,
        //     connector_response_reference_id: None,
        //     incremental_authorization_allowed: None,
        //     raw_connector_response: None,
        //     status_code: item.http_code,
        // });
        Ok(Self {
            // response,
            resource_common_data: PaymentFlowData {
                status: AttemptStatus::from(item.response.status),
                ..item.router_data.resource_common_data
            },
            ..item.router_data
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

// impl TryFrom<&Option<SecretSerdeValue>> for BluecodeMetadataObject {
//     type Error = error_stack::Report<errors::ConnectorError>;
//     fn try_from(meta_data: &Option<SecretSerdeValue>) -> Result<Self, Self::Error> {
//         let metadata_value = meta_data
//             .as_ref()
//             .ok_or(errors::ConnectorError::InvalidConnectorConfig { config: "metadata" })?
//             .peek();
//         serde_json::from_value(metadata_value.clone())
//             .change_context(errors::ConnectorError::InvalidConnectorConfig { config: "metadata" })
//     }
// }

// pub(crate) fn get_bluecode_webhook_event(
//     status: BluecodePaymentStatus,
// ) -> api_models_webhooks::IncomingWebhookEvent {
//     match status {
//         BluecodePaymentStatus::Completed => {
//             api_models_webhooks::IncomingWebhookEvent::PaymentIntentSuccess
//         }
//         BluecodePaymentStatus::PaymentInitiated
//         | BluecodePaymentStatus::ManualProcessing
//         | BluecodePaymentStatus::Pending => {
//             api_models_webhooks::IncomingWebhookEvent::PaymentIntentProcessing
//         }
//         BluecodePaymentStatus::Failed => {
//             api_models_webhooks::IncomingWebhookEvent::PaymentIntentFailure
//         }
//     }
// }

// pub(crate) fn get_webhook_object_from_body(
//     body: &[u8],
// ) -> CustomResult<BluecodeSyncResponse, common_utils::errors::ParsingError> {
//     let webhook: BluecodeSyncResponse = body.parse_struct("BluecodeIncomingWebhook")?;
//     Ok(webhook)
// }

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
