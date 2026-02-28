use common_enums;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use super::PproRouterData;
use crate::types::ResponseRouterData;
use domain_types::{
    connector_flow::{Capture, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, RefundFlowData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ErrorResponse,
    router_data_v2::RouterDataV2,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PproPaymentsRequest {
    pub payment_method: String,
    pub payment_descriptor: Option<String>,
    pub amount: Amount,
    pub consumer: Option<PproConsumer>,
    pub authentication_settings: Option<Vec<PproAuthenticationSettings>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PproAuthenticationSettings {
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<PproAuthSettingsDetails>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PproAuthSettingsDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile_intent_uri: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PproConsumer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<common_utils::pii::Email>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Amount {
    pub currency: String,
    pub value: i64,
}

impl<F, T>
    TryFrom<
        PproRouterData<
            RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for PproPaymentsRequest
where
    T: Clone + PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: PproRouterData<
            RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let payment_method = match router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::WeChatPay) => "WECHATPAY".to_string(),
            Some(common_enums::PaymentMethodType::BancontactCard) => "BANCONTACT".to_string(),
            Some(ref pm) => pm.to_string().to_uppercase(),
            None => "".to_string(),
        };

        let amount = Amount {
            currency: router_data.request.currency.to_string(),
            value: router_data.request.amount.get_amount_as_i64(),
        };

        let mut authentication_settings = vec![];
        if let Some(return_url) = &router_data.request.router_return_url {
            authentication_settings.push(PproAuthenticationSettings {
                r#type: "REDIRECT".to_string(),
                settings: Some(PproAuthSettingsDetails {
                    return_url: Some(return_url.to_string()),
                    scan_by: None,
                    mobile_intent_uri: None,
                }),
            });
        }

        authentication_settings.extend(vec![
            PproAuthenticationSettings {
                r#type: "SCAN_CODE".to_string(),
                settings: Some(PproAuthSettingsDetails {
                    return_url: None,
                    scan_by: None,
                    mobile_intent_uri: None,
                }),
            },
            PproAuthenticationSettings {
                r#type: "MULTI_FACTOR".to_string(),
                settings: None,
            },
            PproAuthenticationSettings {
                r#type: "APP_NOTIFICATION".to_string(),
                settings: None,
            },
            PproAuthenticationSettings {
                r#type: "APP_INTENT".to_string(),
                settings: Some(PproAuthSettingsDetails {
                    return_url: None,
                    scan_by: None,
                    mobile_intent_uri: Some("hyperswitch://paymentresponse".to_string()),
                }),
            },
        ]);

        let consumer = router_data
            .resource_common_data
            .get_billing_address()
            .ok()
            .map(|billing| {
                let mut name_parts = Vec::new();
                if let Some(first_name) = billing.first_name.as_ref() {
                    name_parts.push(first_name.clone().expose());
                }
                if let Some(last_name) = billing.last_name.as_ref() {
                    name_parts.push(last_name.clone().expose());
                }

                let name = if !name_parts.is_empty() {
                    Some(Secret::new(name_parts.join(" ")))
                } else {
                    None
                };

                PproConsumer {
                    name,
                    email: router_data.resource_common_data.get_billing_email().ok(),
                    country: billing.country.map(|c| c.to_string()),
                }
            });

        Ok(Self {
            payment_method,
            payment_descriptor: None,
            amount,
            consumer,
            authentication_settings: if authentication_settings.is_empty() {
                None
            } else {
                Some(authentication_settings)
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PproPaymentsResponse {
    pub id: String,
    pub status: String,
    pub amount: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_methods: Option<Vec<PproAuthenticationResponse>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<PproFailure>,
}

pub type PproPSyncResponse = PproPaymentsResponse;
pub type PproRSyncResponse = PproPaymentsResponse;
pub type PproAuthorizeResponse = PproPaymentsResponse;
pub type PproCaptureResponse = PproPaymentsResponse;
pub type PproVoidResponse = PproPaymentsResponse;
pub type PproRefundResponse = PproPaymentsResponse;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PproAuthenticationResponse {
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<PproAuthDetailsResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PproAuthDetailsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_document: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile_intent_uri: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PproCaptureRequest {
    pub amount: Amount,
}

impl<T>
    TryFrom<
        PproRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for PproCaptureRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: PproRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: Amount {
                currency: item.router_data.request.currency.to_string(),
                value: item.router_data.request.amount_to_capture,
            },
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PproVoidRequest {}

impl<T>
    TryFrom<
        PproRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for PproVoidRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        _item: PproRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PproRefundRequest {
    pub amount: Amount,
}

impl<T>
    TryFrom<
        PproRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for PproRefundRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: PproRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: Amount {
                currency: item.router_data.request.currency.to_string(),
                value: item.router_data.request.refund_amount,
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PproFailure {
    pub failure_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub failure_message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PproErrorResponse {
    pub status: u16,
    pub failure_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PproWebhookEvent {
    pub specversion: String,
    pub r#type: String,
    pub source: String,
    pub id: String,
    pub time: String,
    pub data: PproWebhookData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PproWebhookData {
    pub id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<PproFailure>,
}

impl<F, Req> TryFrom<ResponseRouterData<PproPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: ResponseRouterData<PproPaymentsResponse, Self>) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_str() {
            "AUTHORIZATION_PROCESSING" | "CAPTURE_PROCESSING" => {
                common_enums::AttemptStatus::Pending
            }
            "AUTHENTICATION_PENDING" => common_enums::AttemptStatus::AuthenticationPending,
            "AUTHORIZATION_ASYNC" | "CAPTURE_PENDING" => common_enums::AttemptStatus::Authorized,
            "CAPTURED" => common_enums::AttemptStatus::Charged,
            "FAILED" | "DISCARDED" => common_enums::AttemptStatus::Failure,
            "VOIDED" => common_enums::AttemptStatus::Voided,
            _ => common_enums::AttemptStatus::Pending,
        };

        let mut error_response = None;
        if status == common_enums::AttemptStatus::Failure {
            if let Some(failure) = &item.response.failure {
                let fallback_msg = failure
                    .failure_code
                    .clone()
                    .unwrap_or_else(|| "UNKNOWN".to_string());
                let message = if failure.failure_message.is_empty() {
                    fallback_msg.clone()
                } else {
                    failure.failure_message.clone()
                };

                error_response = Some(ErrorResponse {
                    status_code: item.http_code,
                    code: failure
                        .failure_code
                        .clone()
                        .unwrap_or_else(|| "UNKNOWN".to_string()),
                    message,
                    reason: Some(format!("{}: {}", failure.failure_type, fallback_msg)),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                });
            }
        }

        let mut redirection_data: Option<domain_types::router_response_types::RedirectForm> = None;
        if status == common_enums::AttemptStatus::AuthenticationPending {
            if let Some(auth_methods) = item.response.authentication_methods.as_ref() {
                let methods_array: &Vec<PproAuthenticationResponse> = auth_methods;
                let mut is_sdk_flow = false;
                if let Some(meta_data) = item
                    .router_data
                    .resource_common_data
                    .connector_meta_data
                    .clone()
                {
                    let meta_val = meta_data.expose();
                    if let Some(sdk_params) = meta_val.get("sdk_params").and_then(|v| v.as_bool()) {
                        is_sdk_flow = sdk_params;
                    }
                }

                let priorities = if is_sdk_flow {
                    vec![
                        "APP_INTENT",
                        "SCAN_CODE",
                        "APP_NOTIFICATION",
                        "REDIRECT",
                        "MULTI_FACTOR",
                    ]
                } else {
                    vec![
                        "REDIRECT",
                        "APP_NOTIFICATION",
                        "MULTI_FACTOR",
                        "SCAN_CODE",
                        "APP_INTENT",
                    ]
                };
                for priority in priorities {
                    if let Some(matched) = methods_array.iter().find(|m| m.r#type == priority) {
                        if let Some(details) = &matched.details {
                            match priority {
                                "SCAN_CODE" => {
                                    if let Some(payload) = &details.code_payload {
                                        redirection_data = Some(domain_types::router_response_types::RedirectForm::Uri {
                                              uri: payload.to_string(),
                                          });
                                        break;
                                    }
                                }
                                "APP_INTENT" => {
                                    if let Some(intent_uri) = &details.mobile_intent_uri {
                                        redirection_data = Some(domain_types::router_response_types::RedirectForm::Uri {
                                              uri: intent_uri.to_string(),
                                          });
                                        break;
                                    }
                                }
                                "REDIRECT" => {
                                    if let Some(url) = &details.request_url {
                                        let method = match details.request_method.as_deref() {
                                            Some("POST") => common_utils::request::Method::Post,
                                            _ => common_utils::request::Method::Get,
                                        };
                                        redirection_data = Some(domain_types::router_response_types::RedirectForm::Form {
                                              endpoint: url.to_string(),
                                              method,
                                              form_fields: std::collections::HashMap::new(),
                                          });
                                        break;
                                    }
                                }
                                "APP_NOTIFICATION" | "MULTI_FACTOR" => {
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        let response = if let Some(err) = error_response {
            Err(err)
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: redirection_data.map(Box::new),
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response,
            ..item.router_data
        })
    }
}

impl<F, Req, T> TryFrom<ResponseRouterData<PproPaymentsResponse, Self>>
    for RouterDataV2<F, Req, T, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: ResponseRouterData<PproPaymentsResponse, Self>) -> Result<Self, Self::Error> {
        let refund_status = match item.response.status.as_str() {
            "CAPTURED" | "REFUND_SETTLED" | "SUCCESS" | "REFUNDED" => {
                common_enums::RefundStatus::Success
            }
            "FAILED" | "REJECTED" | "DECLINED" => common_enums::RefundStatus::Failure,
            _ => common_enums::RefundStatus::Pending,
        };

        let response = if refund_status == common_enums::RefundStatus::Failure {
            let failure_code = item
                .response
                .failure
                .as_ref()
                .and_then(|f| f.failure_code.clone());
            let failure_message = item
                .response
                .failure
                .as_ref()
                .map_or("".to_string(), |f| f.failure_message.clone());
            let failure_type = item
                .response
                .failure
                .as_ref()
                .map_or("".to_string(), |f| f.failure_type.clone());

            let fallback_msg = get_error_message(failure_code.as_deref());
            let message = if failure_message.is_empty() {
                fallback_msg.clone()
            } else {
                failure_message
            };

            Err(ErrorResponse {
                code: failure_code.unwrap_or_else(|| "UNKNOWN".to_string()),
                message,
                reason: Some(format!("{}: {}", failure_type, fallback_msg)),
                status_code: item.http_code,
                attempt_status: None,
                connector_transaction_id: Some(item.response.id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            Ok(RefundsResponseData {
                connector_refund_id: item.response.id.clone(),
                refund_status,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            response,
            ..item.router_data
        })
    }
}

pub fn get_error_message(failure_code: Option<&str>) -> String {
    match failure_code {
        Some("ACCOUNT_NOT_SUPPORTED") => {
            "The consumer's account or card not supported.".to_string()
        }
        Some("AMOUNT_NOT_SUPPORTED") => {
            "Amount value is invalid or outside supported range.".to_string()
        }
        Some("AUTHENTICATION_FAILED") => "The consumer failed authentication.".to_string(),
        Some("CANCELED_BY_CONSUMER") => {
            "The consumer intentionally abandoned the authentication flow.".to_string()
        }
        Some("COUNTRY_NOT_SUPPORTED") => {
            "The country value is not supported by the provider.".to_string()
        }
        Some("DUPLICATE_DETECTED") => {
            "Provider detected a very similar request recently with the same details and amount."
                .to_string()
        }
        Some("EXPIRED_CARD") => "The card has expired.".to_string(),
        Some("INCORRECT_BILLING_ADDRESS") => "The billing address entered was wrong.".to_string(),
        Some("INCORRECT_CVV") => "The CVC/CVV was wrong.".to_string(),
        Some("INCORRECT_HOLDER_NAME") => {
            "The card or account holderName could not be validated by the issuer.".to_string()
        }
        Some("INCORRECT_ISSUER") => {
            "The card number/issuer is not within a card number range supported by the provider."
                .to_string()
        }
        Some("INCORRECT_NUMBER") => {
            "The card or account number cannot be validated by the issuer.".to_string()
        }
        Some("INSUFFICIENT_FUNDS") => "Insufficient funds in the account.".to_string(),
        Some("IS_EXCEEDING_ACCOUNT_LIMIT") => {
            "The amount value exceeds the limit on the consumer's account.".to_string()
        }
        Some("IS_GENERIC_DECLINE") => "Generic decline by the issuer.".to_string(),
        Some("IS_HIGH_VELOCITY") => {
            "The consumer has exceeded the number of attempts allowed by the issuer.".to_string()
        }
        Some("IS_NOT_PERMITTED") => "Not permitted by the issuer.".to_string(),
        Some("SUS_FRAUD") => {
            "The payment was declined because the issuer or provider suspects it was fraudulent."
                .to_string()
        }
        Some("SUS_LOST") => {
            "The payment was declined because the consumer's card was reported lost.".to_string()
        }
        Some("SUS_STOLEN") => {
            "The payment was declined because the consumer's card was reported stolen.".to_string()
        }
        Some("AGREEMENT_INACTIVE") => {
            "Payment Agreement not yet active or failed during setup.".to_string()
        }
        Some("AGREEMENT_REVOKED") => {
            "Payment Agreement revoked by the consumer or merchant.".to_string()
        }
        Some("BLOCKED_ACCOUNT") => {
            "Account or card blocked by PPRO due to suspected fraud or abuse.".to_string()
        }
        Some("BLOCKED_BIN") => {
            "BIN (first 6–8 digits) blocked by PPRO due to high risk or chargebacks.".to_string()
        }
        Some("BLOCKED_EMAIL") => {
            "Consumer email blocked by PPRO due to suspected fraud or abuse.".to_string()
        }
        Some("BLOCKED_IP") => {
            "Consumer IP blocked by PPRO due to suspected fraud or abuse.".to_string()
        }
        Some("EXCEEDS_AUTHORIZED_AMOUNT") => {
            "Capture or void amount exceeds the remaining authorized amount.".to_string()
        }
        Some("EXCEEDS_CAPTURED_AMOUNT") => "Refund amount exceeds the captured funds.".to_string(),
        Some("EXCEEDS_REFUND_LIMIT") => {
            "Refund would reduce the account balance below minimum.".to_string()
        }
        Some("EXCEEDS_REFUNDABLE_AMOUNT") => {
            "Refund attempted before capture or after full refund.".to_string()
        }
        Some("HIGH_ACCOUNT_VELOCITY") => {
            "Too many attempts from the same account or card.".to_string()
        }
        Some("HIGH_BIN_VELOCITY") => "Too many attempts from the same BIN range.".to_string(),
        Some("HIGH_EMAIL_VELOCITY") => {
            "Too many attempts using the same email address.".to_string()
        }
        Some("HIGH_IP_VELOCITY") => "Too many attempts from the same IP address.".to_string(),
        Some("INSTRUMENT_NOT_FOUND") => "Specified `instrumentId` not found.".to_string(),
        Some("INVALID_ACCOUNT") => "Account or card format not supported.".to_string(),
        Some("INVALID_AUTHENTICATION_SETTINGS") => {
            "Invalid or missing `authenticationSettings` for the payment method.".to_string()
        }
        Some("INVALID_COUNTRY") => {
            "Unsupported or invalid country for this payment method.".to_string()
        }
        Some("INVALID_CURRENCY") => {
            "Unsupported or invalid currency for this payment method.".to_string()
        }
        Some("INVALID_IP") => "Consumer IP invalid or not supported by the provider.".to_string(),
        Some("INVALID_PAYMENT_METHOD") => "Unrecognized `paymentMethod` value.".to_string(),
        Some("INVALID_TAX_ID") => {
            "Invalid `consumer.taxIdentification` for this payment method".to_string()
        }
        Some("NO_AUTHORIZED_AMOUNT") => {
            "No successful Authorization found; capture/void not possible.".to_string()
        }
        Some("PAYMENT_METHOD_TIMEOUT") => {
            "Authorization not completed within timeout limit set by PPRO.".to_string()
        }
        Some("UNRESPONSIVE_ISSUER") => "The issuer cannot be contacted/is unavailable.".to_string(),
        Some("UNRESPONSIVE_PROVIDER") => {
            "The provider cannot be contacted/is unavailable.".to_string()
        }
        Some("PROVIDER_PROCESSING_ERROR") => {
            "The provider could not process the request we sent to them.".to_string()
        }
        Some("INTERNAL_SERVICE_UNAVAILABLE") => {
            "A PPRO internal service is temporarily down during request processing.".to_string()
        }
        Some("INTERNAL_PROCESSING_ERROR") => {
            "A PPRO internal service encountered an unexpected error while handling the request."
                .to_string()
        }
        Some(code) => format!("Unknown error code: {}", code),
        None => "Unknown error".to_string(),
    }
}
