use common_enums::{self, AttemptStatus, CountryAlpha2, Currency};
use common_utils::{consts, pii, request::Method, types::MinorUnit};
use domain_types::{
    connector_flow::{Authorize, CreateAccessToken, RSync, Refund, Void},
    connector_types::{
        AccessTokenRequestData, AccessTokenResponseData, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsResponseData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{BankRedirectData, PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils::is_payment_failure,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{connectors::truelayer::TruelayerRouterData, types::ResponseRouterData, utils};
const GRANT_TYPE: &str = "client_credentials";
const SCOPE: &str = "payments";

pub struct TruelayerAuthType {
    pub(super) client_id: Secret<String>,
    pub(super) client_secret: Secret<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TruelayerAccessTokenRequestData {
    grant_type: String,
    client_id: Secret<String>,
    client_secret: Secret<String>,
    scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TruelayerAccessTokenErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
    pub error_details: Option<ErrorDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TruelayerErrorResponse {
    #[serde(rename = "type")]
    pub _type: String,
    pub title: String,
    pub status: i32,
    pub trace_id: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorDetails {
    pub reason: Option<String>,
}

impl TryFrom<&ConnectorAuthType> for TruelayerAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                client_id: api_key.to_owned(),
                client_secret: key1.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TruelayerRouterData<
            RouterDataV2<
                CreateAccessToken,
                PaymentFlowData,
                AccessTokenRequestData,
                AccessTokenResponseData,
            >,
            T,
        >,
    > for TruelayerAccessTokenRequestData
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: TruelayerRouterData<
            RouterDataV2<
                CreateAccessToken,
                PaymentFlowData,
                AccessTokenRequestData,
                AccessTokenResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = TruelayerAuthType::try_from(&item.router_data.connector_auth_type)?;
        Ok(Self {
            grant_type: GRANT_TYPE.to_string(),
            client_id: auth.client_id,
            client_secret: auth.client_secret,
            scope: SCOPE.to_string(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TruelayerAccessTokenResponseData {
    access_token: Secret<String>,
    expires_in: i64,
    token_type: Option<String>,
}

impl<F, T> TryFrom<ResponseRouterData<TruelayerAccessTokenResponseData, Self>>
    for RouterDataV2<F, PaymentFlowData, T, AccessTokenResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<TruelayerAccessTokenResponseData, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(AccessTokenResponseData {
                access_token: item.response.access_token,
                expires_in: Some(item.response.expires_in),
                token_type: item.response.token_type,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TruelayerMetadata {
    merchant_account_id: Secret<String>,
    account_holder_name: Secret<String>,
    pub private_key: Secret<String>,
    pub kid: Secret<String>,
}

impl TryFrom<&Option<pii::SecretSerdeValue>> for TruelayerMetadata {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(meta_data: &Option<pii::SecretSerdeValue>) -> Result<Self, Self::Error> {
        let metadata: Self = utils::to_connector_meta_from_secret::<Self>(meta_data.clone())
            .change_context(errors::ConnectorError::InvalidConnectorConfig {
                config: "metadata",
            })?;
        Ok(metadata)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TruelayerPaymentsRequestData {
    amount_in_minor: MinorUnit,
    currency: Currency,
    hosted_page: HostedPage,
    payment_method: PaymentMethod,
    user: User,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct HostedPage {
    return_uri: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct PaymentMethod {
    #[serde(rename = "type")]
    _type: String,
    provider_selection: ProviderSelection,
    beneficiary: Beneficiary,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct ProviderSelection {
    #[serde(rename = "type")]
    _type: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct Beneficiary {
    #[serde(rename = "type")]
    _type: String,
    merchant_account_id: Secret<String>,
    account_holder_name: Secret<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct User {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    name: Secret<String>,
    email: Option<pii::Email>,
    phone: Option<Secret<String>>,
    address: Option<Address>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct Address {
    address_line1: Secret<String>,
    address_line2: Option<Secret<String>>,
    city: Secret<String>,
    state: Secret<String>,
    zip: Option<Secret<String>>,
    country_code: CountryAlpha2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TruelayerPaymentsResponseData {
    id: String,
    user: UserIdResponse,
    resource_token: Option<Secret<String>>,
    status: TruelayerPaymentStatus,
    hosted_page: Option<HostedPageResponse>,
    failure_reason: Option<String>,
    failure_stage: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct UserIdResponse {
    id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum TruelayerPaymentStatus {
    AuthorizationRequired,
    Settled,
    Failed,
    Authorized,
    Authorizing,
    AttemptFailed,
    Executed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct HostedPageResponse {
    uri: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TruelayerRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for TruelayerPaymentsRequestData
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: TruelayerRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        match &item.router_data.request.payment_method_data {
            PaymentMethodData::BankRedirect(BankRedirectData::OpenBankingUk { .. }) => {
                let currency = item.router_data.request.currency;
                let amount_in_minor = item.router_data.request.amount;

                let hosted_page = HostedPage {
                    return_uri: item.router_data.request.router_return_url.clone().ok_or(
                        errors::ConnectorError::MissingRequiredField {
                            field_name: "return_url",
                        },
                    )?,
                };

                let metadata = TruelayerMetadata::try_from(
                    &item.router_data.resource_common_data.connector_meta_data,
                )?;

                let payment_method = PaymentMethod {
                    _type: "bank_transfer".to_string(),
                    provider_selection: ProviderSelection {
                        _type: "user_selected".to_string(),
                    },
                    beneficiary: Beneficiary {
                        _type: "merchant_account".to_string(),
                        merchant_account_id: metadata.merchant_account_id.clone(),
                        account_holder_name: metadata.account_holder_name.clone(),
                    },
                };

                let email = item.router_data.request.email.clone().or_else(|| {
                    item.router_data
                        .resource_common_data
                        .get_optional_billing_email()
                });

                let phone = item
                    .router_data
                    .resource_common_data
                    .address
                    .get_payment_billing()
                    .map(|billing| billing.get_phone_with_country_code())
                    .transpose()?;

                // Ensure at least one is present
                if email.is_none() && phone.is_none() {
                    return Err(errors::ConnectorError::MissingRequiredField {
                        field_name: "either billing.email/customer_email or billing.phone",
                    }
                    .into());
                }

                let address = item
                    .router_data
                    .resource_common_data
                    .get_optional_billing()
                    .and_then(get_address);

                let user = User {
                    id: item
                        .router_data
                        .resource_common_data
                        .get_connector_customer_id()
                        .ok(),
                    name: item
                        .router_data
                        .request
                        .customer_name
                        .clone()
                        .map(Secret::new)
                        .or_else(|| {
                            item.router_data
                                .resource_common_data
                                .get_optional_billing_full_name()
                        })
                        .ok_or(errors::ConnectorError::MissingRequiredField {
                            field_name: "billing.first_name or customer_name",
                        })?,
                    email,
                    phone,
                    address,
                };

                Ok(Self {
                    amount_in_minor,
                    currency,
                    hosted_page,
                    payment_method,
                    user,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Truelayer"),
            )
            .into()),
        }
    }
}

impl<F, T> TryFrom<ResponseRouterData<TruelayerPaymentsResponseData, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<TruelayerPaymentsResponseData, Self>,
    ) -> Result<Self, Self::Error> {
        let status = get_attempt_status(item.response.status.clone());

        if is_payment_failure(status) {
            let error_response = ErrorResponse {
                code: item
                    .response
                    .failure_reason
                    .clone()
                    .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                message: item
                    .response
                    .failure_reason
                    .clone()
                    .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                reason: item.response.failure_reason.clone(),
                status_code: item.http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(item.response.id),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            };

            Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..item.router_data.resource_common_data
                },
                response: Err(error_response),
                ..item.router_data
            })
        } else {
            let redirection_url = item
                .response
                .hosted_page
                .as_ref()
                .map(|hosted_page| hosted_page.uri.clone())
                .ok_or(errors::ConnectorError::UnexpectedResponseError(
                    bytes::Bytes::from("hosted_page.uri expected".to_string()),
                ))?;

            let redirection_data = Some(RedirectForm::Form {
                endpoint: redirection_url,
                method: Method::Get,
                form_fields: Default::default(),
            });

            Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    connector_customer: Some(item.response.user.id.clone()),
                    ..item.router_data.resource_common_data
                },
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                    redirection_data: redirection_data.map(Box::new),
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: Some(item.response.id),
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                }),
                ..item.router_data
            })
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TruelayerPSyncResponseData {
    id: String,
    amount_in_minor: MinorUnit,
    currency: Currency,
    user: Option<UserIdResponse>,
    status: TruelayerPaymentStatus,
    failure_reason: Option<String>,
    failure_stage: Option<String>,
}

impl<F, T> TryFrom<ResponseRouterData<TruelayerPSyncResponseData, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<TruelayerPSyncResponseData, Self>,
    ) -> Result<Self, Self::Error> {
        let status = get_attempt_status(item.response.status.clone());

        if is_payment_failure(status)
            && item.response.failure_reason == Some("canceled".to_string())
        {
            Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Voided,
                    ..item.router_data.resource_common_data
                },
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: Some(item.response.id),
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                }),
                ..item.router_data
            })
        } else if is_payment_failure(status) {
            let error_response = ErrorResponse {
                code: item
                    .response
                    .failure_reason
                    .clone()
                    .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                message: item
                    .response
                    .failure_reason
                    .clone()
                    .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                reason: item.response.failure_reason.clone(),
                status_code: item.http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(item.response.id),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            };

            Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..item.router_data.resource_common_data
                },
                response: Err(error_response),
                ..item.router_data
            })
        } else {
            Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..item.router_data.resource_common_data
                },
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: Some(item.response.id),
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                }),
                ..item.router_data
            })
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TruelayerRefundRequest {
    amount_in_minor: MinorUnit,
    reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TruelayerRefundResponse {
    id: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TruelayerRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for TruelayerRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: TruelayerRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let reference = item
            .router_data
            .request
            .connector_transaction_id
            .chars()
            .take(35)
            .collect::<String>();

        Ok(Self {
            amount_in_minor: item.router_data.request.minor_refund_amount,
            reference,
        })
    }
}

impl TryFrom<ResponseRouterData<TruelayerRefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TruelayerRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: common_enums::RefundStatus::Pending,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TruelayerRefundStatus {
    Pending,
    Authorized,
    Executed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TruelayerRsyncResponse {
    id: String,
    amount_in_minor: MinorUnit,
    currency: Currency,
    reference: String,
    status: TruelayerRefundStatus,
    created_at: Option<String>,
    failed_at: Option<String>,
    failure_reason: Option<String>,
}

impl TryFrom<ResponseRouterData<TruelayerRsyncResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<TruelayerRsyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = get_refund_status(item.response.status.clone());

        let response = if utils::is_refund_failure(status) {
            Err(ErrorResponse {
                code: item
                    .response
                    .failure_reason
                    .clone()
                    .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                message: item
                    .response
                    .failure_reason
                    .clone()
                    .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                reason: item.response.failure_reason.clone(),
                status_code: item.http_code,
                attempt_status: None,
                connector_transaction_id: Some(item.response.id),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            Ok(RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status: status,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            response,
            ..item.router_data
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TruelayerVoidResponseData {
    id: Option<String>,
}

impl TryFrom<ResponseRouterData<TruelayerVoidResponseData, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TruelayerVoidResponseData, Self>,
    ) -> Result<Self, Self::Error> {
        let status = AttemptStatus::VoidInitiated;

        Ok(Self {
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
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

fn get_address(billing: &domain_types::payment_address::Address) -> Option<Address> {
    billing.address.clone().and_then(|address| {
        match (
            address.line1.as_ref(),
            address.city.as_ref(),
            address.state.as_ref(),
            address.country.as_ref(),
        ) {
            (Some(line1), Some(city), Some(state), Some(&country)) => Some(Address {
                address_line1: line1.clone(),
                address_line2: address.line2.clone(),
                city: city.clone(),
                state: state.clone(),
                zip: address.zip.clone(),
                country_code: country,
            }),
            _ => None,
        }
    })
}

fn get_attempt_status(item: TruelayerPaymentStatus) -> AttemptStatus {
    match item {
        TruelayerPaymentStatus::Authorized | TruelayerPaymentStatus::Executed => {
            AttemptStatus::Authorized
        }
        TruelayerPaymentStatus::Settled => AttemptStatus::Charged,
        TruelayerPaymentStatus::AuthorizationRequired => AttemptStatus::AuthenticationPending,
        TruelayerPaymentStatus::Failed | TruelayerPaymentStatus::AttemptFailed => {
            AttemptStatus::Failure
        }
        TruelayerPaymentStatus::Authorizing => AttemptStatus::Pending,
    }
}

fn get_refund_status(item: TruelayerRefundStatus) -> common_enums::RefundStatus {
    match item {
        TruelayerRefundStatus::Pending | TruelayerRefundStatus::Authorized => {
            common_enums::RefundStatus::Pending
        }
        TruelayerRefundStatus::Executed => common_enums::RefundStatus::Success,
        TruelayerRefundStatus::Failed => common_enums::RefundStatus::Failure,
    }
}
