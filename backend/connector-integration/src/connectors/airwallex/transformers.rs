use common_enums::enums;
use common_utils::{errors::ParsingError, pii::IpAddress, request::Method, consts};
use error_stack::{ResultExt, report};
use hyperswitch_domain_models::{
    payment_method_data::{self, PaymentMethodData, Card, WalletData, MandatePaymentDetails, PaymentMethodDataExt},
    router_data::{AccessToken, ConnectorAuthType, RouterData, RouterDataExt},
    router_flow_types::{
        access_token_auth::AccessTokenAuth,
        payments::{Authorize, Capture, PSync, PaymentMethodToken, Session, SetupMandate, Void},
        refunds::{Execute, RSync},
    },
    router_request_types::{self as router_req_types, PaymentsSyncData, ResponseId, SetupMandateRequestData, PaymentsPreProcessingData, PaymentMethodTokenizationData, CompleteAuthorizeData},
    router_response_types::{self as router_res_types, PaymentsResponseData, RedirectForm, RefundsResponseData, MandateReference, NextAction},
    types as domain_types,
};
use hyperswitch_interfaces::{api, errors};
use masking::{ExposeInterface, PeekInterface, Secret, Maskable};
use serde::{Deserialize, Serialize};
use time::PrimitiveDateTime;
use url::Url;
use uuid::Uuid;

use crate::utils::{self, BrowserInformationData, CardData as _, PaymentsAuthorizeRequestData, to_currency_base_unit_as_string, get_unimplemented_payment_method_error_message};
use domain_types::{
    connector_flow::{self},
    connector_types::{self as app_connector_types, PaymentFlowData, PaymentsAuthorizeData as AppPaymentsAuthorizeData, PaymentsResponseData as AppPaymentsResponseData},
    types::MinorUnit
};
use hyperswitch_domain_models::router_data_v2::RouterDataV2;

// ========= AUTH TYPES =========
pub struct AirwallexAuthType {
    pub x_api_key: Secret<String>,
    pub x_client_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for AirwallexAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::BodyKey { api_key, key1 } = auth_type {
            Ok(Self {
                x_api_key: api_key.clone(),
                x_client_id: key1.clone(),
            })
        } else {
            Err(errors::ConnectorError::FailedToObtainAuthType)?
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AirwallexAuthUpdateRequest {
    #[serde(rename = "client_id")]
    pub client_id: String,
    #[serde(rename = "apiKey")]
    pub api_key: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AirwallexAuthUpdateResponse {
    pub token: Secret<String>,
    pub expires_in: i64,
}

// ========= REQUEST COMMON =========
#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct ReferrerData {
    #[serde(rename = "type")]
    r_type: String,
    version: String,
}

// Generic struct for Airwallex Router Data to include amount and currency unit handling
#[derive(Debug, Serialize)]
pub struct AirwallexRouterData<'a, T, Request> { // Added Request generic
    pub amount: String, // Amount in string format for Airwallex
    pub router_data: &'a RouterDataV2<T, PaymentFlowData, Request, AppPaymentsResponseData>, // Changed to use AppPaymentsResponseData
    pub currency: enums::Currency,
}

impl<'a, T, Request> TryFrom<(&'a api::CurrencyUnit, enums::Currency, i64, &'a RouterDataV2<T, PaymentFlowData, Request, AppPaymentsResponseData>)> for AirwallexRouterData<'a, T, Request> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (currency_unit, currency, amount, router_data): (
            &'a api::CurrencyUnit,
            enums::Currency,
            i64,
            &'a RouterDataV2<T, PaymentFlowData, Request, AppPaymentsResponseData>,
        ),
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: to_currency_base_unit_as_string(amount, currency)?,
            router_data,
            currency,
        })
    }
}

// ========= PAYMENTS REQUEST =========
#[derive(Debug, Serialize)]
pub struct AirwallexPaymentsRequest {
    pub request_id: String,
    pub amount: String,
    pub currency: enums::Currency,
    pub merchant_order_id: String,
    pub payment_method: AirwallexPaymentMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_data: Option<AirwallexDeviceData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    // Based on Hyperswitch, some additional fields for card payments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_method: Option<String>, // "automatic" or "manual"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method_options: Option<AirwallexPaymentMethodOptions>,
}

#[derive(Debug, Serialize)]
pub struct AirwallexPaymentMethod {
    #[serde(rename = "type")]
    pub payment_type: String, // e.g., "card"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<AirwallexCard>,
    // other payment methods like 'googlepay', 'applepay' can be added here
}

#[derive(Debug, Serialize)]
pub struct AirwallexCard {
    pub number: Secret<String, common_utils::pii::CardNumberStrategy>,
    pub expiry_month: Secret<String>,
    pub expiry_year: Secret<String>,
    pub cvc: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing: Option<AirwallexBilling>,
    // name_on_card is often part of billing address in Airwallex
}

#[derive(Debug, Serialize)]
pub struct AirwallexBilling {
    pub first_name: Option<Secret<String>>,
    pub last_name: Option<Secret<String>>,
    pub phone_number: Option<Secret<String>>,
    pub email: Option<Secret<String, common_utils::pii::EmailStrategy>>,
    pub address: AirwallexAddress,
}

#[derive(Debug, Serialize)]
pub struct AirwallexAddress {
    pub country_code: String, // ISO 3166 alpha-2 country code
    pub state: Option<String>,
    pub city: Option<String>,
    pub street: Option<String>, // Line 1 + Line 2 + Line 3
    pub postcode: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AirwallexDeviceData {
    pub device_id: Option<String>,      // unique ID for the device
    pub ip_address: Option<IpAddress>,  // customer's IP address
    pub user_agent: Option<String>,     // customer's browser user agent
    pub accept_language: Option<String>, // customer's browser accept language
}

#[derive(Debug, Serialize)]
pub struct AirwallexPaymentMethodOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<AirwallexCardOptions>,
}

#[derive(Debug, Serialize)]
pub struct AirwallexCardOptions {
    pub auto_capture: bool, // Corresponds to capture_method. true for automatic, false for manual.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub three_ds: Option<AirwallexThreeDS>,
}

#[derive(Debug, Serialize)]
pub struct AirwallexThreeDS {
    // Fields for 3DS, e.g. enrollment status, etc.
    // For now, let's assume it might involve a redirect or a specific request from Airwallex
    // If we are just indicating preference, it might be simpler.
    // Hyperswitch code indicates return_url is important here.
    pub return_url: Option<String>, // return_url for 3DS completion
    // other 3ds fields like platform, version based on requirements
}

impl TryFrom<&AirwallexRouterData<'_, connector_flow::Authorize, AppPaymentsAuthorizeData>> for AirwallexPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &AirwallexRouterData<'_, connector_flow::Authorize, AppPaymentsAuthorizeData>) -> Result<Self, Self::Error> {
        let request_data = &item.router_data.request;
        let customer_id = item.router_data.customer_id.clone();

        let payment_method_data = request_data.payment_method_data.clone();

        let (airwallex_card, payment_type_str) = match payment_method_data {
            PaymentMethodData::Card(card_data) => {
                let card_number = card_data.card_number;
                let expiry_month = card_data.card_exp_month;
                let expiry_year = card_data.card_exp_year;
                let cvc = card_data.card_cvc;

                let billing_address = item.router_data.address.billing.as_ref();
                let airwallex_billing = billing_address.map(|billing| {
                    let hyperswitch_address = billing.address.as_ref();
                    AirwallexBilling {
                        first_name: hyperswitch_address.and_then(|a| a.first_name.clone()),
                        last_name: hyperswitch_address.and_then(|a| a.last_name.clone()),
                        phone_number: billing.phone.as_ref().and_then(|p| p.number.clone()),
                        email: billing.email.clone().map(|e| e.into()),
                        address: AirwallexAddress {
                            country_code: hyperswitch_address.and_then(|a| a.country).map(|c| c.to_string()).ok_or(
                                errors::ConnectorError::MissingRequiredField { field_name: "billing.address.country_code" }
                            )?,
                            state: hyperswitch_address.and_then(|a| a.state.clone().map(|s| s.peek().clone())),
                            city: hyperswitch_address.and_then(|a| a.city.clone()),
                            street: hyperswitch_address.map(|a| {
                                format!("{}{}{}\", \n                                    a.line1.as_ref().map_or(\"\", |l1| l1.peek()),\n                                    a.line2.as_ref().map_or(\"\", |l2| l2.peek()),\n                                    a.line3.as_ref().map_or(\"\", |l3| l3.peek()),\n                                )\n                            }),
                            postcode: hyperswitch_address.and_then(|a| a.zip.clone().map(|z| z.peek().clone())),
                        },
                    }
                }).transpose()?.ok_or_else(|| errors::ConnectorError::MissingRequiredField { field_name: "billing address" })?; // Ensure billing is present for card if needed by Airwallex
                
                (Some(AirwallexCard {
                    number: card_number,
                    expiry_month,
                    expiry_year,
                    cvc,
                    billing: Some(airwallex_billing),
                }), "card".to_string())
            }
            _ => return Err(report!(errors::ConnectorError::NotImplemented(
                get_unimplemented_payment_method_error_message("Airwallex")
            ))),
        };

        let payment_method = AirwallexPaymentMethod {
            payment_type: payment_type_str,
            card: airwallex_card,
        };

        let device_data = request_data.browser_info.as_ref().map(|bi| AirwallexDeviceData {
            device_id: None, // Not directly available, could be generated/passed if needed
            ip_address: bi.ip_address.clone(),
            user_agent: bi.user_agent.clone(),
            accept_language: bi.language.clone(),
        });

        let auto_capture = match request_data.capture_method {
            Some(enums::CaptureMethod::Automatic) => true,
            Some(enums::CaptureMethod::Manual) => false,
            None => true, // Default to automatic if not specified, as per Airwallex common practice
            Some(enums::CaptureMethod::Scheduled) => return Err(errors::ConnectorError::FlowNotSupported {
                flow: "Scheduled Capture".to_string(),
                connector: "Airwallex".to_string(),
            }.into()),
        };

        let payment_method_options = Some(AirwallexPaymentMethodOptions {
            card: Some(AirwallexCardOptions {
                auto_capture,
                three_ds: if request_data.enrolled_for_3ds {
                    Some(AirwallexThreeDS {
                        return_url: request_data.router_return_url.clone(),
                    })
                } else {
                    None
                },
            }),
        });

        Ok(Self {
            request_id: Uuid::new_v4().to_string(),
            amount: item.amount.clone(),
            currency: request_data.currency,
            merchant_order_id: item.router_data.connector_request_reference_id.clone(),
            payment_method,
            return_url: request_data.router_return_url.clone(),
            device_data,
            customer_id,
            capture_method: None, // This is handled in payment_method_options.card.auto_capture
            payment_method_options,
        })
    }
}

// ========= PAYMENTS RESPONSE =========
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct AirwallexPaymentsResponse {
    pub id: String, // PaymentIntent ID or PaymentAttempt ID
    pub request_id: String,
    pub amount: f64, // Airwallex returns amount as float
    pub currency: String,
    pub merchant_order_id: String,
    pub status: String, // e.g., SUCCEEDED, FAILED, PENDING_AUTHENTICATION etc.
    pub next_action: Option<AirwallexNextAction>,
    #[serde(default)]
    pub authentication_data: Option<serde_json::Value>, // For 3DS or other auth challenges
    #[serde(default)]
    pub captured_amount: Option<f64>,
    #[serde(default)]
    pub created_at: String, // Timestamp
    #[serde(default)]
    pub client_secret: Option<Secret<String>>,
    // Other fields as needed, e.g. error codes if status is FAILED
    pub code: Option<String>, // Error code if payment failed
    pub message: Option<String>, // Error message if payment failed
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct AirwallexNextAction {
    #[serde(rename = "type")]
    pub action_type: String, // e.g., "redirect"
    pub method: Option<String>, // e.g., "GET"
    pub url: Option<String>,    // URL for redirection
    pub data: Option<serde_json::Value>, // Additional data for next action, e.g. for SDK
}

// This is a simplified mapping, actual status mapping needs to be robust.
impl TryFrom<&AirwallexPaymentsResponse> for enums::AttemptStatus { // Changed to take a reference
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &AirwallexPaymentsResponse) -> Result<Self, Self::Error> { // Changed to take a reference
        match item.status.to_uppercase().as_str() {
            "SUCCEEDED" | "AUTHORIZED" => Ok(enums::AttemptStatus::Authorized), // Or Charged if auto-capture
            "CAPTURED" => Ok(enums::AttemptStatus::Charged),
            "PENDING_AUTHENTICATION" | "PENDING_DEVICE_DATA_COLLECTION" => Ok(enums::AttemptStatus::AuthenticationPending),
            "REQUIRES_PAYMENT_METHOD" | "REQUIRES_CAPTURE" | "PENDING_PAYMENT" => Ok(enums::AttemptStatus::Pending),
            "FAILED" | "CANCELLED" => Ok(enums::AttemptStatus::Failure),
            "REQUIRES_CUSTOMER_ACTION" => Ok(enums::AttemptStatus::Unresolved), // or specific status like 'PendingConfirmation'
            _ => Err(report!(errors::ConnectorError::UnexpectedResponseError(item.status.as_bytes().to_vec()))), // Use as_bytes().to_vec() for Vec<u8>
        }
    }
}

// ========= ERROR RESPONSE =========
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AirwallexErrorResponse {
    pub code: String,
    pub message: String,
    pub source: Option<String>,
    // Potentially other fields like 'param' or detailed errors array
} 