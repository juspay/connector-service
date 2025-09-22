use common_utils::{ext_traits::OptionExt, request::Method, types::MinorUnit};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::{
        PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
        WalletData as WalletDataPaymentMethod,
    },
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack;
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::Deserialize;
use serde::Serialize;
use std::fmt::Debug;

use super::RapydRouterData;
use crate::types::ResponseRouterData;

// Custom serializer for amount to ensure it's a string
fn serialize_amount_as_string<S>(amount: &MinorUnit, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    // Convert amount to string without decimal points for minor units
    serializer.serialize_str(&amount.to_string())
}

// Response type conversions
// Capture Response - should set status to CHARGED when successful
impl<F>
    TryFrom<
        ResponseRouterData<
            RapydPaymentsResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            RapydPaymentsResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let (status, response) = match &item.response.data {
            Some(data) => {
                let attempt_status =
                    get_status(data.status.to_owned(), data.next_action.to_owned());
                match attempt_status {
                    common_enums::AttemptStatus::Failure => (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: data
                                .failure_code
                                .to_owned()
                                .unwrap_or(item.response.status.error_code.clone()),
                            status_code: item.http_code,
                            message: item.response.status.status.clone().unwrap_or_default(),
                            reason: data.failure_message.to_owned(),
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    ),
                    _ => {
                        // For capture, if status is Closed or Active with NotApplicable, treat as Charged
                        let final_status =
                            match (data.status.to_owned(), data.next_action.to_owned()) {
                                (RapydPaymentStatus::Closed, _) => {
                                    common_enums::AttemptStatus::Charged
                                }
                                (RapydPaymentStatus::Active, NextAction::NotApplicable) => {
                                    common_enums::AttemptStatus::Charged
                                }
                                _ => attempt_status,
                            };
                        (
                            final_status,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(data.id.to_owned()),
                                redirection_data: None,
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: None,
                                connector_response_reference_id: data
                                    .merchant_reference_id
                                    .to_owned(),
                                incremental_authorization_allowed: None,
                                status_code: item.http_code,
                            }),
                        )
                    }
                }
            }
            None => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: item.response.status.error_code.clone(),
                    status_code: item.http_code,
                    message: item.response.status.status.clone().unwrap_or_default(),
                    reason: item.response.status.message.clone(),
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
                ..item.router_data.resource_common_data
            },
            response,
            ..item.router_data
        })
    }
}

// Void Response - should set status to VOIDED when successful
impl<F>
    TryFrom<
        ResponseRouterData<
            RapydPaymentsResponse,
            RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            RapydPaymentsResponse,
            RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        println!("Rapyd Void Response Debug:");
        println!("  HTTP Code: {}", item.http_code);
        println!("  Response Status: {:?}", item.response.status);
        println!("  Response Data: {:?}", item.response.data);

        let (status, response) = match &item.response.data {
            Some(data) => {
                let attempt_status =
                    get_status(data.status.to_owned(), data.next_action.to_owned());
                match attempt_status {
                    common_enums::AttemptStatus::Failure => (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: data
                                .failure_code
                                .to_owned()
                                .unwrap_or(item.response.status.error_code.clone()),
                            status_code: item.http_code,
                            message: item.response.status.status.clone().unwrap_or_default(),
                            reason: data.failure_message.to_owned(),
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    ),
                    _ => {
                        // For void, set status to Voided regardless of Rapyd status if operation was successful
                        let final_status = common_enums::AttemptStatus::Voided;
                        (
                            final_status,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(data.id.to_owned()),
                                redirection_data: None,
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: None,
                                connector_response_reference_id: data
                                    .merchant_reference_id
                                    .to_owned(),
                                incremental_authorization_allowed: None,
                                status_code: item.http_code,
                            }),
                        )
                    }
                }
            }
            None => {
                // For void operations, if HTTP status indicates success, treat as voided
                // Rapyd DELETE operations might not return data field but still be successful
                if item.http_code >= 200 && item.http_code < 300 {
                    println!("  Void operation successful based on HTTP status");
                    (
                        common_enums::AttemptStatus::Voided,
                        Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                item.router_data.request.connector_transaction_id.clone(),
                            ),
                            redirection_data: None,
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            status_code: item.http_code,
                        }),
                    )
                } else {
                    println!("  Void operation failed based on HTTP status");
                    (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: item.response.status.error_code.clone(),
                            status_code: item.http_code,
                            message: item.response.status.status.clone().unwrap_or_default(),
                            reason: item.response.status.message.clone(),
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    )
                }
            }
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

#[derive(Debug, Serialize)]
pub struct EmptyRequest;

// RapydRouterData is now generated by the macro in rapyd.rs

#[derive(Debug, Serialize)]
pub struct RapydAuthType {
    pub(super) access_key: Secret<String>,
    pub(super) secret_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for RapydAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                access_key: api_key.to_owned(),
                secret_key: key1.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType)?,
        }
    }
}

#[derive(Default, Debug, Serialize)]
pub struct RapydPaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    #[serde(serialize_with = "serialize_amount_as_string")]
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
    pub payment_method: PaymentMethod<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method_options: Option<PaymentMethodOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_reference_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complete_payment_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_payment_url: Option<String>,
}

#[derive(Default, Debug, Serialize)]
pub struct PaymentMethodOptions {
    #[serde(rename = "3d_required")]
    pub three_ds: bool,
}

#[derive(Default, Debug, Serialize)]
pub struct PaymentMethod<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    #[serde(rename = "type")]
    pub pm_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<PaymentFields<T>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digital_wallet: Option<RapydWallet>,
}

#[derive(Default, Debug, Serialize)]
pub struct PaymentFields<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub number: RawCardNumber<T>,
    pub expiration_month: Secret<String>,
    pub expiration_year: Secret<String>,
    pub name: Secret<String>,
    pub cvv: Secret<String>,
}

#[derive(Default, Debug, Serialize)]
pub struct Address {
    name: Secret<String>,
    line_1: Secret<String>,
    line_2: Option<Secret<String>>,
    line_3: Option<Secret<String>>,
    city: Option<String>,
    state: Option<Secret<String>>,
    country: Option<String>,
    zip: Option<Secret<String>>,
    phone_number: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RapydWallet {
    #[serde(rename = "type")]
    payment_type: String,
    #[serde(rename = "details")]
    token: Option<Secret<String>>,
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
        RapydRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for RapydPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: RapydRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let (capture, payment_method_options) =
            match item.router_data.resource_common_data.payment_method {
                common_enums::PaymentMethod::Card => {
                    let three_ds_enabled = matches!(
                        item.router_data.resource_common_data.auth_type,
                        common_enums::AuthenticationType::ThreeDs
                    );
                    let payment_method_options = PaymentMethodOptions {
                        three_ds: three_ds_enabled,
                    };
                    (
                        Some(matches!(
                            item.router_data.request.capture_method,
                            Some(common_enums::CaptureMethod::Automatic)
                                | Some(common_enums::CaptureMethod::SequentialAutomatic)
                                | None
                        )),
                        Some(payment_method_options),
                    )
                }
                _ => (None, None),
            };

        let payment_method = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(ref ccard) => {
                Some(PaymentMethod {
                    pm_type: "in_amex_card".to_owned(), // Use Amex card type as per hyperswitch implementation
                    fields: Some(PaymentFields {
                        number: ccard.card_number.to_owned(),
                        expiration_month: ccard.card_exp_month.to_owned(),
                        expiration_year: ccard.card_exp_year.to_owned(),
                        name: item
                            .router_data
                            .resource_common_data
                            .get_optional_billing_full_name()
                            .unwrap_or(Secret::new("Test User".to_string())),
                        cvv: ccard.card_cvc.to_owned(),
                    }),
                    address: None,
                    digital_wallet: None,
                })
            }
            PaymentMethodData::Wallet(ref wallet_data) => {
                let digital_wallet = match wallet_data {
                    WalletDataPaymentMethod::GooglePay(data) => Some(RapydWallet {
                        payment_type: "google_pay".to_string(),
                        token: Some(Secret::new(
                            data.tokenization_data
                                .get_encrypted_google_pay_token()
                                .change_context(errors::ConnectorError::MissingRequiredField {
                                    field_name: "gpay wallet_token",
                                })?
                                .to_owned(),
                        )),
                    }),
                    WalletDataPaymentMethod::ApplePay(data) => {
                        let apple_pay_encrypted_data = data
                            .payment_data
                            .get_encrypted_apple_pay_payment_data_mandatory()
                            .change_context(errors::ConnectorError::MissingRequiredField {
                                field_name: "Apple pay encrypted data",
                            })?;
                        Some(RapydWallet {
                            payment_type: "apple_pay".to_string(),
                            token: Some(Secret::new(apple_pay_encrypted_data.to_string())),
                        })
                    }
                    _ => None,
                };
                Some(PaymentMethod {
                    pm_type: "by_visa_card".to_string(),
                    fields: None,
                    address: None,
                    digital_wallet,
                })
            }
            _ => None,
        }
        .get_required_value("payment_method not implemented")
        .change_context(errors::ConnectorError::NotImplemented(
            "payment_method".to_owned(),
        ))?;

        let return_url = item.router_data.resource_common_data.get_return_url();
        Ok(Self {
            amount: item.router_data.request.minor_amount,
            currency: item.router_data.request.currency,
            payment_method,
            capture,
            payment_method_options,
            merchant_reference_id: Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
            description: None,
            error_payment_url: return_url.clone(),
            complete_payment_url: return_url,
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum RapydPaymentStatus {
    #[serde(rename = "ACT")]
    Active,
    #[serde(rename = "CAN")]
    CanceledByClientOrBank,
    #[serde(rename = "CLO")]
    Closed,
    #[serde(rename = "ERR")]
    Error,
    #[serde(rename = "EXP")]
    Expired,
    #[serde(rename = "REV")]
    ReversedByRapyd,
    #[default]
    #[serde(rename = "NEW")]
    New,
}

fn get_status(status: RapydPaymentStatus, next_action: NextAction) -> common_enums::AttemptStatus {
    match (status, next_action) {
        (RapydPaymentStatus::Closed, _) => common_enums::AttemptStatus::Charged,
        (
            RapydPaymentStatus::Active,
            NextAction::ThreedsVerification | NextAction::PendingConfirmation,
        ) => common_enums::AttemptStatus::AuthenticationPending,
        (RapydPaymentStatus::Active, NextAction::PendingCapture | NextAction::NotApplicable) => {
            common_enums::AttemptStatus::Authorized
        }
        (
            RapydPaymentStatus::CanceledByClientOrBank
            | RapydPaymentStatus::Expired
            | RapydPaymentStatus::ReversedByRapyd,
            _,
        ) => common_enums::AttemptStatus::Voided,
        (RapydPaymentStatus::Error, _) => common_enums::AttemptStatus::Failure,
        (RapydPaymentStatus::New, _) => common_enums::AttemptStatus::Authorizing,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RapydPaymentsResponse {
    pub status: Status,
    pub data: Option<ResponseData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Status {
    pub error_code: String,
    pub status: Option<String>,
    pub message: Option<String>,
    pub response_code: Option<String>,
    pub operation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NextAction {
    #[serde(rename = "3d_verification")]
    ThreedsVerification,
    #[serde(rename = "pending_capture")]
    PendingCapture,
    #[serde(rename = "not_applicable")]
    NotApplicable,
    #[serde(rename = "pending_confirmation")]
    PendingConfirmation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponseData {
    pub id: String,
    pub amount: i64,
    pub status: RapydPaymentStatus,
    pub next_action: NextAction,
    pub redirect_url: Option<String>,
    pub original_amount: Option<i64>,
    pub is_partial: Option<bool>,
    pub currency_code: Option<common_enums::Currency>,
    pub country_code: Option<String>,
    pub captured: Option<bool>,
    pub transaction_id: String,
    pub merchant_reference_id: Option<String>,
    pub paid: Option<bool>,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
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
        ResponseRouterData<
            RapydPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            RapydPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let (status, response) = match &item.response.data {
            Some(data) => {
                let attempt_status =
                    get_status(data.status.to_owned(), data.next_action.to_owned());
                match attempt_status {
                    common_enums::AttemptStatus::Failure => (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: data
                                .failure_code
                                .to_owned()
                                .unwrap_or(item.response.status.error_code.clone()),
                            status_code: item.http_code,
                            message: item.response.status.status.clone().unwrap_or_default(),
                            reason: data.failure_message.to_owned(),
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    ),
                    _ => {
                        let redirection_url = data
                            .redirect_url
                            .as_ref()
                            .filter(|redirect_str| !redirect_str.is_empty())
                            .map(|url| {
                                url::Url::parse(url).change_context(
                                    errors::ConnectorError::FailedToObtainIntegrationUrl,
                                )
                            })
                            .transpose()?;

                        let redirection_data =
                            redirection_url.map(|url| RedirectForm::from((url, Method::Get)));

                        (
                            attempt_status,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(data.id.to_owned()),
                                redirection_data: redirection_data.map(Box::new),
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: None,
                                connector_response_reference_id: data
                                    .merchant_reference_id
                                    .to_owned(),
                                incremental_authorization_allowed: None,
                                status_code: item.http_code,
                            }),
                        )
                    }
                }
            }
            None => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: item.response.status.error_code.clone(),
                    status_code: item.http_code,
                    message: item.response.status.status.clone().unwrap_or_default(),
                    reason: item.response.status.message.clone(),
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
                ..item.router_data.resource_common_data
            },
            response,
            ..item.router_data
        })
    }
}

// PSync Response
impl<F> TryFrom<ResponseRouterData<RapydPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<RapydPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let (status, response) = match &item.response.data {
            Some(data) => {
                let attempt_status =
                    get_status(data.status.to_owned(), data.next_action.to_owned());
                match attempt_status {
                    common_enums::AttemptStatus::Failure => (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: data
                                .failure_code
                                .to_owned()
                                .unwrap_or(item.response.status.error_code.clone()),
                            status_code: item.http_code,
                            message: item.response.status.status.clone().unwrap_or_default(),
                            reason: data.failure_message.to_owned(),
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    ),
                    _ => (
                        attempt_status,
                        Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(data.id.to_owned()),
                            redirection_data: None,
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: data.merchant_reference_id.to_owned(),
                            incremental_authorization_allowed: None,
                            status_code: item.http_code,
                        }),
                    ),
                }
            }
            None => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: item.response.status.error_code.clone(),
                    status_code: item.http_code,
                    message: item.response.status.status.clone().unwrap_or_default(),
                    reason: item.response.status.message.clone(),
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
                ..item.router_data.resource_common_data
            },
            response,
            ..item.router_data
        })
    }
}

// Capture Request
#[derive(Debug, Serialize, Clone)]
pub struct CaptureRequest {
    #[serde(serialize_with = "serialize_optional_amount_as_string")]
    amount: Option<MinorUnit>,
    receipt_email: Option<Secret<String>>,
    statement_descriptor: Option<String>,
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
        RapydRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for CaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: RapydRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: Some(item.router_data.request.minor_amount_to_capture),
            receipt_email: None,
            statement_descriptor: None,
        })
    }
}

// Refund Request
#[derive(Default, Debug, Serialize)]
pub struct RapydRefundRequest {
    pub payment: String,
    #[serde(serialize_with = "serialize_optional_amount_as_string")]
    pub amount: Option<MinorUnit>,
    pub currency: Option<common_enums::Currency>,
}

// Custom serializer for optional amount to ensure it's a string
fn serialize_optional_amount_as_string<S>(
    amount: &Option<MinorUnit>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match amount {
        Some(amt) => serializer.serialize_str(&amt.to_string()),
        None => serializer.serialize_none(),
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
    > TryFrom<RapydRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, T>>
    for RapydRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RapydRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            payment: item
                .router_data
                .request
                .connector_transaction_id
                .to_string(),
            amount: Some(item.router_data.request.minor_refund_amount),
            currency: Some(item.router_data.request.currency),
        })
    }
}

// Refund Response
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub enum RefundStatus {
    Completed,
    Error,
    Rejected,
    #[default]
    Pending,
}

impl From<RefundStatus> for common_enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Completed => Self::Success,
            RefundStatus::Error | RefundStatus::Rejected => Self::Failure,
            RefundStatus::Pending => Self::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    pub status: Status,
    pub data: Option<RefundResponseData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RefundResponseData {
    pub id: String,
    pub payment: String,
    pub amount: i64,
    pub currency: common_enums::Currency,
    pub status: RefundStatus,
    pub created_at: Option<i64>,
    pub failure_reason: Option<String>,
}

impl<F> TryFrom<ResponseRouterData<RefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<RefundResponse, Self>) -> Result<Self, Self::Error> {
        let (_connector_refund_id, _refund_status, response_result) = match &item.response.data {
            Some(data) => (
                data.id.clone(),
                common_enums::RefundStatus::from(data.status.clone()),
                Ok(RefundsResponseData {
                    connector_refund_id: data.id.clone(),
                    refund_status: common_enums::RefundStatus::from(data.status.clone()),
                    status_code: item.http_code,
                }),
            ),
            None => {
                // If no data, still provide a proper refund ID from the response
                let refund_id = item
                    .response
                    .status
                    .operation_id
                    .clone()
                    .unwrap_or_else(|| format!("refund_error_{}", item.response.status.error_code));
                (
                    refund_id.clone(),
                    common_enums::RefundStatus::Failure,
                    Err(ErrorResponse {
                        code: item.response.status.error_code.clone(),
                        status_code: item.http_code,
                        message: item.response.status.status.clone().unwrap_or_default(),
                        reason: item.response.status.message.clone(),
                        attempt_status: None,
                        connector_transaction_id: None,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    }),
                )
            }
        };

        Ok(Self {
            response: response_result,
            ..item.router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<RefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<RefundResponse, Self>) -> Result<Self, Self::Error> {
        let (connector_refund_id, refund_status) = match item.response.data {
            Some(data) => (data.id, common_enums::RefundStatus::from(data.status)),
            None => (
                item.response.status.error_code,
                common_enums::RefundStatus::Failure,
            ),
        };
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// Error Response
#[derive(Debug, Deserialize)]
pub struct RapydErrorResponse {
    pub status: Status,
}

// Type aliases for different flows to avoid macro conflicts
pub type RapydAuthorizeResponse = RapydPaymentsResponse;
pub type RapydPSyncResponse = RapydPaymentsResponse;
pub type RapydCaptureResponse = RapydPaymentsResponse;
pub type RapydVoidResponse = RapydPaymentsResponse;

// Void Request - for payment cancellation
#[derive(Debug, Serialize, Clone)]
pub struct VoidRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// Request type aliases to avoid macro conflicts
pub type RapydPSyncRequest = EmptyRequest;
pub type RapydVoidRequest = VoidRequest;
pub type RapydRSyncRequest = EmptyRequest;

// Response type aliases for refund flows
pub type RapydRefundResponse = RefundResponse;
pub type RapydRSyncResponse = RefundResponse;

// Additional TryFrom implementations for EmptyRequest (used by type aliases)
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        RapydRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for EmptyRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        _item: RapydRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(EmptyRequest)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        RapydRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for VoidRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: RapydRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(VoidRequest {
            description: item.router_data.request.cancellation_reason.clone(),
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        RapydRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for EmptyRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        _item: RapydRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(EmptyRequest)
    }
}
