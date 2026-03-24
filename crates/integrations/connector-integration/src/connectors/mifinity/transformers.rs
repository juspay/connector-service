use common_enums::{enums, Currency};
use common_utils::{
    pii::{self, Email},
    types::StringMajorUnit,
};
use domain_types::{
    self,
    connector_flow::Authorize,
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId,
    },
    errors::ConnectorError,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, WalletData},
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use time::Date;

use super::MifinityRouterData;
use crate::{types::ResponseRouterData, utils};
pub mod auth_headers {
    pub const API_VERSION: &str = "api-version";
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MifinityConnectorMetadataObject {
    pub brand_id: Option<Secret<String>>,
    pub destination_account_number: Option<Secret<String>>,
    pub source_account: Option<Secret<String>>,
}

impl TryFrom<&Option<pii::SecretSerdeValue>> for MifinityConnectorMetadataObject {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(meta_data: &Option<pii::SecretSerdeValue>) -> Result<Self, Self::Error> {
        let metadata: Self = utils::to_connector_meta_from_secret::<Self>(meta_data.clone())
            .change_context(ConnectorError::InvalidConnectorConfig {
                config: "merchant_connector_account.metadata",
            })?;
        Ok(metadata)
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum MifinityPaymentsRequest {
    Wallet(Box<MifinityWalletPaymentsRequest>),
    Card(Box<MifinityPacRequest>),
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MifinityWalletPaymentsRequest {
    money: Money,
    client: MifinityClient,
    address: MifinityAddress,
    validation_key: String,
    client_reference: common_utils::id_type::CustomerId,
    trace_id: String,
    description: String,
    destination_account_number: Secret<String>,
    brand_id: Secret<String>,
    return_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    language_preference: Option<String>,
}

/// Pay Any Card (PAC) request — card payout to any card
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MifinityPacRequest {
    pub money: Money,
    pub description: Option<String>,
    pub expiry_date: Secret<String>,
    pub source_account: Secret<String>,
    pub trace_id: String,
    pub card_number: Secret<String>,
    pub card_holder_country_code: String,
    pub card_holder_nationality: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_holder_address: Option<Secret<String>>,
    pub card_name: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_holder_email: Option<Secret<String>>,
    pub dob: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_holder_street: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_holder_city: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_holder_state: Option<Secret<String>>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Money {
    amount: StringMajorUnit,
    currency: Currency,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MifinityClient {
    first_name: Secret<String>,
    last_name: Secret<String>,
    phone: Secret<String>,
    dialing_code: String,
    nationality: enums::CountryAlpha2,
    email_address: Email,
    dob: Secret<Date>,
}

#[derive(Default, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MifinityAddress {
    address_line1: Secret<String>,
    country_code: enums::CountryAlpha2,
    city: Secret<String>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        MifinityRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for MifinityPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: MifinityRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(card) => {
                let metadata: MifinityConnectorMetadataObject =
                    utils::to_connector_meta_from_secret(
                        item.router_data
                            .resource_common_data
                            .connector_feature_data
                            .clone(),
                    )
                    .change_context(
                        ConnectorError::InvalidConnectorConfig {
                            config: "merchant_connector_account.metadata",
                        },
                    )?;
                let source_account =
                    metadata
                        .source_account
                        .ok_or(ConnectorError::MissingRequiredField {
                            field_name: "metadata.source_account",
                        })?;
                let money = Money {
                    amount: item
                        .connector
                        .amount_converter
                        .convert(
                            item.router_data.request.minor_amount,
                            item.router_data.request.currency,
                        )
                        .change_context(ConnectorError::RequestEncodingFailed)?,
                    currency: item.router_data.request.currency,
                };
                let billing_country = item
                    .router_data
                    .resource_common_data
                    .get_billing_country()?;
                let country_code_str = billing_country.to_string();
                // MiFinity requires MM/YY format for expiryDate
                let exp_month = card.card_exp_month.peek().to_string();
                let exp_year = card
                    .get_card_expiry_year_2_digit()
                    .change_context(ConnectorError::RequestEncodingFailed)?;
                let expiry_date = Secret::new(format!("{}/{}", exp_month, exp_year.peek()));
                let card_name = card
                    .card_holder_name
                    .clone()
                    .or_else(|| {
                        item.router_data
                            .resource_common_data
                            .get_optional_billing_full_name()
                    })
                    .ok_or(ConnectorError::MissingRequiredField {
                        field_name: "card_holder_name",
                    })?;
                let trace_id = item
                    .router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone();
                let card_holder_email = item
                    .router_data
                    .resource_common_data
                    .get_billing_email()
                    .ok()
                    .map(|email| Secret::new(email.peek().to_string()));
                let card_holder_address = item
                    .router_data
                    .resource_common_data
                    .get_optional_billing_line1();
                let card_holder_street = item
                    .router_data
                    .resource_common_data
                    .get_optional_billing_line1();
                let card_holder_city = item
                    .router_data
                    .resource_common_data
                    .get_optional_billing_city();
                let card_holder_state = item
                    .router_data
                    .resource_common_data
                    .get_optional_billing_state();

                // card_number needs to be converted from RawCardNumber<T> to Secret<String>
                let card_number_str = Secret::new(card.card_number.peek().to_string());

                Ok(Self::Card(Box::new(MifinityPacRequest {
                    money,
                    description: Some(trace_id.clone()),
                    expiry_date,
                    source_account,
                    trace_id,
                    card_number: card_number_str,
                    card_holder_country_code: country_code_str.clone(),
                    card_holder_nationality: country_code_str,
                    card_holder_address,
                    card_name,
                    card_holder_email,
                    dob: "1985-01-01".to_string(), // Placeholder — MiFinity requires DOB but it's not in card flow data
                    card_holder_street,
                    card_holder_city,
                    card_holder_state,
                })))
            }
            PaymentMethodData::Wallet(wallet_data) => match wallet_data {
                WalletData::Mifinity(data) => {
                    let metadata: MifinityConnectorMetadataObject =
                        utils::to_connector_meta_from_secret(
                            item.router_data
                                .resource_common_data
                                .connector_feature_data
                                .clone(),
                        )
                        .change_context(
                            ConnectorError::InvalidConnectorConfig {
                                config: "merchant_connector_account.metadata",
                            },
                        )?;
                    let money = Money {
                        amount: item
                            .connector
                            .amount_converter
                            .convert(
                                item.router_data.request.minor_amount,
                                item.router_data.request.currency,
                            )
                            .change_context(ConnectorError::RequestEncodingFailed)?,
                        currency: item.router_data.request.currency,
                    };
                    let phone_details =
                        item.router_data.resource_common_data.get_billing_phone()?;
                    let billing_country = item
                        .router_data
                        .resource_common_data
                        .get_billing_country()?;
                    let client = MifinityClient {
                        first_name: item
                            .router_data
                            .resource_common_data
                            .get_billing_first_name()?,
                        last_name: item
                            .router_data
                            .resource_common_data
                            .get_billing_last_name()?,
                        phone: phone_details.get_number()?,
                        dialing_code: phone_details.get_country_code()?,
                        nationality: billing_country,
                        email_address: item.router_data.resource_common_data.get_billing_email()?,
                        dob: data.date_of_birth.clone(),
                    };
                    let address = MifinityAddress {
                        address_line1: item.router_data.resource_common_data.get_billing_line1()?,
                        country_code: billing_country,
                        city: item.router_data.resource_common_data.get_billing_city()?,
                    };
                    let validation_key = format!(
                        "payment_validation_key_{}_{}",
                        item.router_data
                            .resource_common_data
                            .merchant_id
                            .get_string_repr(),
                        item.router_data
                            .resource_common_data
                            .connector_request_reference_id
                            .clone()
                    );
                    let client_reference = item.router_data.request.customer_id.clone().ok_or(
                        ConnectorError::MissingRequiredField {
                            field_name: "client_reference",
                        },
                    )?;
                    let destination_account_number = metadata.destination_account_number.ok_or(
                        ConnectorError::MissingRequiredField {
                            field_name: "metadata.destination_account_number",
                        },
                    )?;
                    let trace_id = item
                        .router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone();
                    let brand_id =
                        metadata
                            .brand_id
                            .ok_or(ConnectorError::MissingRequiredField {
                                field_name: "metadata.brand_id",
                            })?;
                    let language_preference = data.language_preference;
                    Ok(Self::Wallet(Box::new(MifinityWalletPaymentsRequest {
                        money,
                        client,
                        address,
                        validation_key,
                        client_reference,
                        trace_id: trace_id.clone(),
                        description: trace_id.clone(),
                        destination_account_number,
                        brand_id,
                        return_url: item.router_data.request.get_router_return_url()?,
                        language_preference,
                    })))
                }
                WalletData::AliPayQr(_)
                | WalletData::BluecodeRedirect {}
                | WalletData::AliPayRedirect(_)
                | WalletData::AliPayHkRedirect(_)
                | WalletData::AmazonPayRedirect(_)
                | WalletData::MomoRedirect(_)
                | WalletData::KakaoPayRedirect(_)
                | WalletData::GoPayRedirect(_)
                | WalletData::GcashRedirect(_)
                | WalletData::ApplePay(_)
                | WalletData::ApplePayRedirect(_)
                | WalletData::ApplePayThirdPartySdk(_)
                | WalletData::DanaRedirect {}
                | WalletData::GooglePay(_)
                | WalletData::GooglePayRedirect(_)
                | WalletData::GooglePayThirdPartySdk(_)
                | WalletData::MbWayRedirect(_)
                | WalletData::MobilePayRedirect(_)
                | WalletData::PaypalRedirect(_)
                | WalletData::PaypalSdk(_)
                | WalletData::Paze(_)
                | WalletData::SamsungPay(_)
                | WalletData::TwintRedirect {}
                | WalletData::VippsRedirect {}
                | WalletData::TouchNGoRedirect(_)
                | WalletData::WeChatPayRedirect(_)
                | WalletData::WeChatPayQr(_)
                | WalletData::CashappQr(_)
                | WalletData::SwishQr(_)
                | WalletData::RevolutPay(_)
                | WalletData::MbWay(_)
                | WalletData::Satispay(_)
                | WalletData::Wero(_) => Err(ConnectorError::NotImplemented(
                    utils::get_unimplemented_payment_method_error_message("Mifinity"),
                )
                .into()),
            },
            PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Err(ConnectorError::NotImplemented(
                    utils::get_unimplemented_payment_method_error_message("Mifinity"),
                )
                .into())
            }
        }
    }
}

// Auth Struct
pub struct MifinityAuthType {
    pub(super) key: Secret<String>,
}

impl TryFrom<&ConnectorSpecificConfig> for MifinityAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Mifinity { key, .. } => Ok(Self {
                key: key.to_owned(),
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

/// Unified response type that handles both wallet (init-iframe) and card (PAC) responses
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MifinityPaymentsResponse {
    /// PAC/PMC card response — has transactionReference and transactionStatus
    PacResponse(MifinityPacResponse),
    /// Wallet response — has initialization_token
    WalletResponse(MifinityWalletResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MifinityWalletResponse {
    payload: Vec<MifinityWalletPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MifinityWalletPayload {
    trace_id: String,
    initialization_token: Secret<String>,
}

/// PAC response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MifinityPacResponse {
    payload: Vec<MifinityPacPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MifinityPacPayload {
    pub transaction_reference: String,
    pub transaction_status: i32,
    pub transaction_status_description: String,
    pub transaction_last_updated: Option<String>,
    pub trace_id: String,
    #[serde(default)]
    pub arn: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
}

/// Map MiFinity PAC transaction status codes to AttemptStatus
/// Status codes from MiFinity docs:
/// 1 = Received, 2 = Internal Error, 3 = Submitted, 4 = Processed by PSP,
/// 5 = Processed by acquirer, 6 = Rejected, 7 = In Progress, 8 = On Hold KYC
fn pac_transaction_status_to_attempt_status(status: i32) -> enums::AttemptStatus {
    match status {
        1 => enums::AttemptStatus::Pending, // Received
        2 => enums::AttemptStatus::Failure, // Internal Error
        3 => enums::AttemptStatus::Charged, // Submitted (funds taken)
        4 => enums::AttemptStatus::Charged, // Processed by PSP
        5 => enums::AttemptStatus::Charged, // Processed by acquirer
        6 => enums::AttemptStatus::Failure, // Rejected
        7 => enums::AttemptStatus::Pending, // In Progress
        8 => enums::AttemptStatus::Pending, // On Hold KYC
        _ => enums::AttemptStatus::Pending,
    }
}

impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<MifinityPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<MifinityPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response {
            MifinityPaymentsResponse::PacResponse(pac_response) => {
                let payload = pac_response.payload.first();
                match payload {
                    Some(payload) => {
                        let status =
                            pac_transaction_status_to_attempt_status(payload.transaction_status);
                        let transaction_reference = payload.transaction_reference.clone();
                        let trace_id = payload.trace_id.clone();

                        if domain_types::utils::is_payment_failure(status) {
                            Ok(Self {
                                response: Err(ErrorResponse {
                                    status_code: item.http_code,
                                    code: payload.transaction_status.to_string(),
                                    message: payload.transaction_status_description.clone(),
                                    reason: payload.error_message.clone(),
                                    attempt_status: Some(status),
                                    connector_transaction_id: Some(transaction_reference),
                                    network_advice_code: None,
                                    network_decline_code: None,
                                    network_error_message: None,
                                }),
                                resource_common_data: PaymentFlowData {
                                    status,
                                    ..item.router_data.resource_common_data
                                },
                                ..item.router_data
                            })
                        } else {
                            Ok(Self {
                                response: Ok(PaymentsResponseData::TransactionResponse {
                                    resource_id: ResponseId::ConnectorTransactionId(
                                        transaction_reference,
                                    ),
                                    redirection_data: None,
                                    mandate_reference: None,
                                    connector_metadata: None,
                                    network_txn_id: None,
                                    connector_response_reference_id: Some(trace_id),
                                    incremental_authorization_allowed: None,
                                    status_code: item.http_code,
                                }),
                                resource_common_data: PaymentFlowData {
                                    status,
                                    ..item.router_data.resource_common_data
                                },
                                ..item.router_data
                            })
                        }
                    }
                    None => Ok(Self {
                        response: Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::NoResponseId,
                            redirection_data: None,
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            status_code: item.http_code,
                        }),
                        resource_common_data: PaymentFlowData {
                            status: enums::AttemptStatus::Pending,
                            ..item.router_data.resource_common_data
                        },
                        ..item.router_data
                    }),
                }
            }
            MifinityPaymentsResponse::WalletResponse(wallet_response) => {
                let payload = wallet_response.payload.first();
                match payload {
                    Some(payload) => {
                        let trace_id = payload.trace_id.clone();
                        let initialization_token = payload.initialization_token.clone();
                        Ok(Self {
                            response: Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(trace_id.clone()),
                                redirection_data: Some(Box::new(RedirectForm::Mifinity {
                                    initialization_token: initialization_token.expose(),
                                })),
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: None,
                                connector_response_reference_id: Some(trace_id),
                                incremental_authorization_allowed: None,
                                status_code: item.http_code,
                            }),
                            resource_common_data: PaymentFlowData {
                                status: enums::AttemptStatus::AuthenticationPending,
                                ..item.router_data.resource_common_data
                            },
                            ..item.router_data
                        })
                    }
                    None => Ok(Self {
                        response: Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::NoResponseId,
                            redirection_data: None,
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            status_code: item.http_code,
                        }),
                        resource_common_data: PaymentFlowData {
                            status: enums::AttemptStatus::AuthenticationPending,
                            ..item.router_data.resource_common_data
                        },
                        ..item.router_data
                    }),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MifinityPsyncResponse {
    payload: Vec<MifinityPsyncPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MifinityPsyncPayload {
    status: MifinityPaymentStatus,
    payment_response: Option<PaymentResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentResponse {
    trace_id: Option<String>,
    client_reference: Option<String>,
    validation_key: Option<String>,
    transaction_reference: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MifinityPaymentStatus {
    Successful,
    Pending,
    Failed,
    NotCompleted,
}

impl<F> TryFrom<ResponseRouterData<MifinityPsyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<MifinityPsyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let payload = item.response.payload.first();

        match payload {
            Some(payload) => {
                let status = payload.status.clone();
                let payment_response = payload.payment_response.clone();

                match payment_response {
                    Some(payment_response) => {
                        let transaction_reference = payment_response.transaction_reference.clone();

                        Ok(Self {
                            response: Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(
                                    transaction_reference,
                                ),
                                redirection_data: None,
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: None,
                                connector_response_reference_id: None,
                                incremental_authorization_allowed: None,
                                status_code: item.http_code,
                            }),
                            resource_common_data: PaymentFlowData {
                                status: enums::AttemptStatus::from(status),
                                ..item.router_data.resource_common_data
                            },
                            ..item.router_data
                        })
                    }
                    None => Ok(Self {
                        response: Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::NoResponseId,
                            redirection_data: None,
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            status_code: item.http_code,
                        }),
                        resource_common_data: PaymentFlowData {
                            status: enums::AttemptStatus::from(status),
                            ..item.router_data.resource_common_data
                        },
                        ..item.router_data
                    }),
                }
            }
            None => Ok(Self {
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::NoResponseId,
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                }),
                resource_common_data: PaymentFlowData {
                    status: enums::AttemptStatus::Unspecified,
                    ..item.router_data.resource_common_data
                },
                ..item.router_data
            }),
        }
    }
}

impl From<MifinityPaymentStatus> for enums::AttemptStatus {
    fn from(item: MifinityPaymentStatus) -> Self {
        match item {
            MifinityPaymentStatus::Successful => Self::Charged,
            MifinityPaymentStatus::Failed => Self::Failure,
            MifinityPaymentStatus::NotCompleted => Self::AuthenticationPending,
            MifinityPaymentStatus::Pending => Self::Pending,
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct MifinityErrorResponse {
    pub errors: Vec<MifinityErrorList>,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MifinityErrorList {
    #[serde(rename = "type")]
    pub error_type: String,
    pub error_code: String,
    pub message: String,
    pub field: Option<String>,
}
