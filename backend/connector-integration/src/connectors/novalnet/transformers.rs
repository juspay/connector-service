use std::collections::HashMap;

use cards::CardNumber;
use common_utils::{
    ext_traits::OptionExt,
    pii,
    request::Method,
    types::{MinorUnit, StringMinorUnit},
};
use domain_types::{
    connector_flow::{self, Authorize, PSync, RSync, RepeatPayment, SetupMandate, Void},
    connector_types::{
        EventType, MandateReference, MandateReferenceId, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundWebhookDetailsResponse, RefundsData,
        RefundsResponseData, RepeatPaymentData, ResponseId, SetupMandateRequestData,
        WebhookDetailsResponse,
    },
    errors::{self, ConnectorError},
    payment_method_data::{
        PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
        WalletData as WalletDataPaymentMethod,
    },
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils::{self, ForeignTryFrom},
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};
use strum::Display;

use crate::{connectors::novalnet::NovalnetRouterData, types::ResponseRouterData};

/// Default locale
const DEFAULT_LOCALE: &str = "en";

const MINIMAL_CUSTOMER_DATA_PASSED: i64 = 1;
const CREATE_TOKEN_REQUIRED: i8 = 1;

const TEST_MODE_ENABLED: i8 = 1;
const TEST_MODE_DISABLED: i8 = 0;

fn get_test_mode(item: Option<bool>) -> i8 {
    match item {
        Some(true) => TEST_MODE_ENABLED,
        Some(false) | None => TEST_MODE_DISABLED,
    }
}

#[derive(Debug, Copy, Serialize, Deserialize, Clone)]
pub enum NovalNetPaymentTypes {
    CREDITCARD,
    PAYPAL,
    GOOGLEPAY,
    APPLEPAY,
}

#[derive(Default, Debug, Serialize, Clone)]
pub struct NovalnetPaymentsRequestMerchant {
    signature: Secret<String>,
    tariff: Secret<String>,
}

#[derive(Default, Debug, Serialize, Clone)]
pub struct NovalnetPaymentsRequestBilling {
    house_no: Option<Secret<String>>,
    street: Option<Secret<String>>,
    city: Option<Secret<String>>,
    zip: Option<Secret<String>>,
    country_code: Option<common_enums::CountryAlpha2>,
}

#[derive(Default, Debug, Serialize, Clone)]
pub struct NovalnetPaymentsRequestCustomer {
    first_name: Option<Secret<String>>,
    last_name: Option<Secret<String>>,
    email: pii::Email,
    mobile: Option<Secret<String>>,
    billing: Option<NovalnetPaymentsRequestBilling>,
    no_nc: i64,
}
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct NovalnetCard<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    card_number: RawCardNumber<T>,
    card_expiry_month: Secret<String>,
    card_expiry_year: Secret<String>,
    card_cvc: Secret<String>,
    card_holder: Secret<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct NovalnetRawCardDetails {
    card_number: CardNumber,
    card_expiry_month: Secret<String>,
    card_expiry_year: Secret<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NovalnetMandate {
    token: Secret<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct NovalnetGooglePay {
    wallet_data: Secret<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct NovalnetApplePay {
    wallet_data: Secret<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum NovalNetPaymentData<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    Card(NovalnetCard<T>),
    RawCardForNTI(NovalnetRawCardDetails),
    GooglePay(NovalnetGooglePay),
    ApplePay(NovalnetApplePay),
    MandatePayment(NovalnetMandate),
}

#[derive(Default, Debug, Serialize, Clone)]
pub struct NovalnetCustom {
    lang: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum NovalNetAmount {
    StringMinor(StringMinorUnit),
    Int(i64),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NovalnetPaymentsRequestTransaction<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    test_mode: i8,
    payment_type: NovalNetPaymentTypes,
    amount: NovalNetAmount,
    currency: common_enums::Currency,
    order_no: String,
    payment_data: Option<NovalNetPaymentData<T>>,
    hook_url: Option<String>,
    return_url: Option<String>,
    error_return_url: Option<String>,
    enforce_3d: Option<i8>, //NOTE: Needed for CREDITCARD, GOOGLEPAY
    create_token: Option<i8>,
    scheme_tid: Option<Secret<String>>, // Card network's transaction ID
}

#[derive(Debug, Serialize, Clone)]
pub struct NovalnetPaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    merchant: NovalnetPaymentsRequestMerchant,
    customer: NovalnetPaymentsRequestCustomer,
    transaction: NovalnetPaymentsRequestTransaction<T>,
    custom: NovalnetCustom,
}

impl TryFrom<&common_enums::PaymentMethodType> for NovalNetPaymentTypes {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &common_enums::PaymentMethodType) -> Result<Self, Self::Error> {
        match item {
            common_enums::PaymentMethodType::ApplePay => Ok(Self::APPLEPAY),
            common_enums::PaymentMethodType::Credit | common_enums::PaymentMethodType::Debit => {
                Ok(Self::CREDITCARD)
            }
            common_enums::PaymentMethodType::GooglePay => Ok(Self::GOOGLEPAY),
            common_enums::PaymentMethodType::Paypal => Ok(Self::PAYPAL),
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Novalnet"),
            ))?,
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
        NovalnetRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for NovalnetPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: NovalnetRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = NovalnetAuthType::try_from(&item.router_data.connector_auth_type)?;

        let merchant = NovalnetPaymentsRequestMerchant {
            signature: auth.product_activation_key,
            tariff: auth.tariff_id,
        };

        let enforce_3d = match item.router_data.resource_common_data.auth_type {
            common_enums::AuthenticationType::ThreeDs => Some(1),
            common_enums::AuthenticationType::NoThreeDs => None,
        };
        let test_mode = get_test_mode(item.router_data.resource_common_data.test_mode);

        let billing = NovalnetPaymentsRequestBilling {
            house_no: item
                .router_data
                .resource_common_data
                .get_optional_billing_line1(),
            street: item
                .router_data
                .resource_common_data
                .get_optional_billing_line2(),
            city: item
                .router_data
                .resource_common_data
                .get_optional_billing_city()
                .map(Secret::new),
            zip: item
                .router_data
                .resource_common_data
                .get_optional_billing_zip(),
            country_code: item
                .router_data
                .resource_common_data
                .get_optional_billing_country(),
        };

        let customer = NovalnetPaymentsRequestCustomer {
            first_name: item
                .router_data
                .resource_common_data
                .get_optional_billing_first_name(),
            last_name: item
                .router_data
                .resource_common_data
                .get_optional_billing_last_name(),
            email: item
                .router_data
                .resource_common_data
                .get_billing_email()
                .or(item.router_data.request.get_email())?,
            mobile: item
                .router_data
                .resource_common_data
                .get_optional_billing_phone_number(),
            billing: Some(billing),
            // no_nc is used to indicate if minimal customer data is passed or not
            no_nc: MINIMAL_CUSTOMER_DATA_PASSED,
        };

        let lang = item
            .router_data
            .request
            .get_optional_language_from_browser_info()
            .unwrap_or(DEFAULT_LOCALE.to_string().to_string());
        let custom = NovalnetCustom { lang };
        let hook_url = item.router_data.request.get_webhook_url()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        let create_token = None;

        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(errors::ConnectorError::AmountConversionFailed)?;

        match item.router_data.request.payment_method_data {
            PaymentMethodData::Card(ref req_card) => {
                let novalnet_card = NovalNetPaymentData::Card(NovalnetCard {
                    card_number: req_card.card_number.clone(),
                    card_expiry_month: req_card.card_exp_month.clone(),
                    card_expiry_year: req_card.card_exp_year.clone(),
                    card_cvc: req_card.card_cvc.clone(),
                    card_holder: item
                        .router_data
                        .resource_common_data
                        .get_billing_full_name()?,
                });

                let transaction = NovalnetPaymentsRequestTransaction {
                    test_mode,
                    payment_type: NovalNetPaymentTypes::CREDITCARD,
                    amount: NovalNetAmount::StringMinor(amount.clone()),
                    currency: item.router_data.request.currency,
                    order_no: item
                        .router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                    hook_url: Some(hook_url),
                    return_url: Some(return_url.clone()),
                    error_return_url: Some(return_url.clone()),
                    payment_data: Some(novalnet_card),
                    enforce_3d,
                    create_token,
                    scheme_tid: None,
                };

                Ok(Self {
                    merchant,
                    transaction,
                    customer,
                    custom,
                })
            }
            PaymentMethodData::Wallet(ref wallet_data) => match wallet_data {
                WalletDataPaymentMethod::GooglePay(ref req_wallet) => {
                    let novalnet_google_pay: NovalNetPaymentData<T> =
                        NovalNetPaymentData::GooglePay(NovalnetGooglePay {
                            wallet_data: Secret::new(
                                req_wallet
                                    .tokenization_data
                                    .get_encrypted_google_pay_token()
                                    .change_context(errors::ConnectorError::MissingRequiredField {
                                        field_name: "gpay wallet_token",
                                    })?
                                    .clone(),
                            ),
                        });

                    let transaction = NovalnetPaymentsRequestTransaction {
                        test_mode,
                        payment_type: NovalNetPaymentTypes::GOOGLEPAY,
                        amount: NovalNetAmount::StringMinor(amount.clone()),
                        currency: item.router_data.request.currency,
                        order_no: item
                            .router_data
                            .resource_common_data
                            .connector_request_reference_id
                            .clone(),
                        hook_url: Some(hook_url),
                        return_url: None,
                        error_return_url: None,
                        payment_data: Some(novalnet_google_pay),
                        enforce_3d,
                        create_token,
                        scheme_tid: None,
                    };

                    Ok(Self {
                        merchant,
                        transaction,
                        customer,
                        custom,
                    })
                }
                WalletDataPaymentMethod::ApplePay(payment_method_data) => {
                    let transaction = NovalnetPaymentsRequestTransaction {
                        test_mode,
                        payment_type: NovalNetPaymentTypes::APPLEPAY,
                        amount: NovalNetAmount::StringMinor(amount.clone()),
                        currency: item.router_data.request.currency,
                        order_no: item
                            .router_data
                            .resource_common_data
                            .connector_request_reference_id
                            .clone(),
                        hook_url: Some(hook_url),
                        return_url: None,
                        error_return_url: None,
                        payment_data: Some(NovalNetPaymentData::ApplePay(NovalnetApplePay {
                            wallet_data: payment_method_data.get_applepay_decoded_payment_data()?,
                        })),
                        enforce_3d: None,
                        create_token,
                        scheme_tid: None,
                    };

                    Ok(Self {
                        merchant,
                        transaction,
                        customer,
                        custom,
                    })
                }
                WalletDataPaymentMethod::PaypalRedirect(_) => {
                    let transaction = NovalnetPaymentsRequestTransaction {
                        test_mode,
                        payment_type: NovalNetPaymentTypes::PAYPAL,
                        amount: NovalNetAmount::StringMinor(amount.clone()),
                        currency: item.router_data.request.currency,
                        order_no: item
                            .router_data
                            .resource_common_data
                            .connector_request_reference_id
                            .clone(),
                        hook_url: Some(hook_url),
                        return_url: Some(return_url.clone()),
                        error_return_url: Some(return_url.clone()),
                        payment_data: None,
                        enforce_3d: None,
                        create_token,
                        scheme_tid: None,
                    };
                    Ok(Self {
                        merchant,
                        transaction,
                        customer,
                        custom,
                    })
                }
                WalletDataPaymentMethod::AliPayQr(_)
                | WalletDataPaymentMethod::AliPayRedirect(_)
                | WalletDataPaymentMethod::AliPayHkRedirect(_)
                | WalletDataPaymentMethod::AmazonPayRedirect(_)
                | WalletDataPaymentMethod::MomoRedirect(_)
                | WalletDataPaymentMethod::KakaoPayRedirect(_)
                | WalletDataPaymentMethod::GoPayRedirect(_)
                | WalletDataPaymentMethod::GcashRedirect(_)
                | WalletDataPaymentMethod::ApplePayRedirect(_)
                | WalletDataPaymentMethod::ApplePayThirdPartySdk(_)
                | WalletDataPaymentMethod::DanaRedirect {}
                | WalletDataPaymentMethod::GooglePayRedirect(_)
                | WalletDataPaymentMethod::GooglePayThirdPartySdk(_)
                | WalletDataPaymentMethod::MbWayRedirect(_)
                | WalletDataPaymentMethod::MobilePayRedirect(_)
                | WalletDataPaymentMethod::RevolutPay(_)
                | WalletDataPaymentMethod::PaypalSdk(_)
                | WalletDataPaymentMethod::Paze(_)
                | WalletDataPaymentMethod::SamsungPay(_)
                | WalletDataPaymentMethod::TwintRedirect {}
                | WalletDataPaymentMethod::VippsRedirect {}
                | WalletDataPaymentMethod::TouchNGoRedirect(_)
                | WalletDataPaymentMethod::WeChatPayRedirect(_)
                | WalletDataPaymentMethod::CashappQr(_)
                | WalletDataPaymentMethod::SwishQr(_)
                | WalletDataPaymentMethod::WeChatPayQr(_)
                | WalletDataPaymentMethod::Mifinity(_) => {
                    Err(errors::ConnectorError::NotImplemented(
                        utils::get_unimplemented_payment_method_error_message("novalnet"),
                    )
                    .into())
                }
            },
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("novalnet"),
            )
            .into()),
        }
    }
}

// Auth Struct
pub struct NovalnetAuthType {
    pub(super) product_activation_key: Secret<String>,
    pub(super) payment_access_key: Secret<String>,
    pub(super) tariff_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for NovalnetAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                product_activation_key: api_key.to_owned(),
                payment_access_key: key1.to_owned(),
                tariff_id: api_secret.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// PaymentsResponse
#[derive(Debug, Display, Copy, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NovalnetTransactionStatus {
    Success,
    Failure,
    Confirmed,
    OnHold,
    Pending,
    Deactivated,
    Progress,
}

#[derive(Debug, Copy, Display, Clone, Serialize, Deserialize, PartialEq)]
#[strum(serialize_all = "UPPERCASE")]
#[serde(rename_all = "UPPERCASE")]
pub enum NovalnetAPIStatus {
    Success,
    Failure,
}

impl From<NovalnetTransactionStatus> for common_enums::AttemptStatus {
    fn from(item: NovalnetTransactionStatus) -> Self {
        match item {
            NovalnetTransactionStatus::Success | NovalnetTransactionStatus::Confirmed => {
                Self::Charged
            }
            NovalnetTransactionStatus::OnHold => Self::Authorized,
            NovalnetTransactionStatus::Pending => Self::Pending,
            NovalnetTransactionStatus::Progress => Self::AuthenticationPending,
            NovalnetTransactionStatus::Deactivated => Self::Voided,
            NovalnetTransactionStatus::Failure => Self::Failure,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultData {
    pub redirect_url: Option<Secret<url::Url>>,
    pub status: NovalnetAPIStatus,
    pub status_code: u64,
    pub status_text: String,
    pub additional_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NovalnetPaymentsResponseTransactionData {
    pub amount: Option<MinorUnit>,
    pub currency: Option<common_enums::Currency>,
    pub date: Option<String>,
    pub order_no: Option<String>,
    pub payment_data: Option<NovalnetResponsePaymentData>,
    pub payment_type: Option<String>,
    pub status_code: Option<u64>,
    pub txn_secret: Option<Secret<String>>,
    pub tid: Option<Secret<i64>>,
    pub test_mode: Option<i8>,
    pub status: Option<NovalnetTransactionStatus>,
    pub authorization: Option<NovalnetAuthorizationResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NovalnetPaymentsResponse {
    result: ResultData,
    transaction: Option<NovalnetPaymentsResponseTransactionData>,
}

pub fn get_error_response(result: ResultData, status_code: u16) -> ErrorResponse {
    let error_code = result.status;
    let error_reason = result.status_text.clone();

    ErrorResponse {
        code: error_code.to_string(),
        message: error_reason.clone(),
        reason: Some(error_reason),
        status_code,
        attempt_status: None,
        connector_transaction_id: None,
        network_advice_code: None,
        network_decline_code: None,
        network_error_message: None,
    }
}

impl NovalnetPaymentsResponseTransactionData {
    pub fn get_token(transaction_data: Option<&Self>) -> Option<String> {
        if let Some(data) = transaction_data {
            match &data.payment_data {
                Some(NovalnetResponsePaymentData::Card(card_data)) => {
                    card_data.token.clone().map(|token| token.expose())
                }
                Some(NovalnetResponsePaymentData::Paypal(paypal_data)) => {
                    paypal_data.token.clone().map(|token| token.expose())
                }
                None => None,
            }
        } else {
            None
        }
    }
}

// Specific implementations for Authorize flow
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
            NovalnetPaymentsResponse,
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
            NovalnetPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        match item.response.result.status {
            NovalnetAPIStatus::Success => {
                let redirection_data: Option<RedirectForm> =
                    item.response
                        .result
                        .redirect_url
                        .map(|url| RedirectForm::Form {
                            endpoint: url.expose().to_string(),
                            method: Method::Get,
                            form_fields: HashMap::new(),
                        });

                let transaction_id = item
                    .response
                    .transaction
                    .clone()
                    .and_then(|data| data.tid.map(|tid| tid.expose().to_string()));

                let mandate_reference_id = NovalnetPaymentsResponseTransactionData::get_token(
                    item.response.transaction.clone().as_ref(),
                );

                let transaction_status = item
                    .response
                    .transaction
                    .as_ref()
                    .and_then(|transaction_data| transaction_data.status)
                    .unwrap_or(if redirection_data.is_some() {
                        NovalnetTransactionStatus::Progress
                        // NOTE: Novalnet does not send us the transaction.status for redirection flow
                        // so status is mapped to Progress if flow has redirection data
                    } else {
                        NovalnetTransactionStatus::Pending
                    });

                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: common_enums::AttemptStatus::from(transaction_status),
                        ..item.router_data.resource_common_data
                    },
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: transaction_id
                            .clone()
                            .map(ResponseId::ConnectorTransactionId)
                            .unwrap_or(ResponseId::NoResponseId),
                        redirection_data: redirection_data.map(Box::new),
                        mandate_reference: mandate_reference_id
                            .as_ref()
                            .map(|id| MandateReference {
                                connector_mandate_id: Some(id.clone()),
                                payment_method_id: None,
                            })
                            .map(Box::new),
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: transaction_id.clone(),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            NovalnetAPIStatus::Failure => {
                let response = Err(get_error_response(item.response.result, item.http_code));
                Ok(Self {
                    response,
                    ..item.router_data
                })
            }
        }
    }
}

// Specific implementations for SetupMandate flow
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
            NovalnetPaymentsResponse,
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
        >,
    >
    for RouterDataV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            NovalnetPaymentsResponse,
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        match item.response.result.status {
            NovalnetAPIStatus::Success => {
                let redirection_data: Option<RedirectForm> =
                    item.response
                        .result
                        .redirect_url
                        .map(|url| RedirectForm::Form {
                            endpoint: url.expose().to_string(),
                            method: Method::Get,
                            form_fields: HashMap::new(),
                        });

                let transaction_id = item
                    .response
                    .transaction
                    .clone()
                    .and_then(|data| data.tid.map(|tid| tid.expose().to_string()));

                let mandate_reference_id = NovalnetPaymentsResponseTransactionData::get_token(
                    item.response.transaction.clone().as_ref(),
                );

                let transaction_status = item
                    .response
                    .transaction
                    .as_ref()
                    .and_then(|transaction_data| transaction_data.status)
                    .unwrap_or(if redirection_data.is_some() {
                        NovalnetTransactionStatus::Progress
                        // NOTE: Novalnet does not send us the transaction.status for redirection flow
                        // so status is mapped to Progress if flow has redirection data
                    } else {
                        NovalnetTransactionStatus::Pending
                    });

                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: common_enums::AttemptStatus::from(transaction_status),
                        ..item.router_data.resource_common_data
                    },
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: transaction_id
                            .clone()
                            .map(ResponseId::ConnectorTransactionId)
                            .unwrap_or(ResponseId::NoResponseId),
                        redirection_data: redirection_data.map(Box::new),
                        mandate_reference: mandate_reference_id
                            .as_ref()
                            .map(|id| MandateReference {
                                connector_mandate_id: Some(id.clone()),
                                payment_method_id: None,
                            })
                            .map(Box::new),
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: transaction_id.clone(),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            NovalnetAPIStatus::Failure => {
                let response = Err(get_error_response(item.response.result, item.http_code));
                Ok(Self {
                    response,
                    ..item.router_data
                })
            }
        }
    }
}

// Specific implementations for RepeatPayment flow
impl
    TryFrom<
        ResponseRouterData<
            NovalnetPaymentsResponse,
            RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        >,
    > for RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            NovalnetPaymentsResponse,
            RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        match item.response.result.status {
            NovalnetAPIStatus::Success => {
                let redirection_data: Option<RedirectForm> =
                    item.response
                        .result
                        .redirect_url
                        .map(|url| RedirectForm::Form {
                            endpoint: url.expose().to_string(),
                            method: Method::Get,
                            form_fields: HashMap::new(),
                        });

                let transaction_id = item
                    .response
                    .transaction
                    .clone()
                    .and_then(|data| data.tid.map(|tid| tid.expose().to_string()));

                let mandate_reference_id = NovalnetPaymentsResponseTransactionData::get_token(
                    item.response.transaction.clone().as_ref(),
                );

                let transaction_status = item
                    .response
                    .transaction
                    .as_ref()
                    .and_then(|transaction_data| transaction_data.status)
                    .unwrap_or(if redirection_data.is_some() {
                        NovalnetTransactionStatus::Progress
                        // NOTE: Novalnet does not send us the transaction.status for redirection flow
                        // so status is mapped to Progress if flow has redirection data
                    } else {
                        NovalnetTransactionStatus::Pending
                    });

                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: common_enums::AttemptStatus::from(transaction_status),
                        ..item.router_data.resource_common_data
                    },
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: transaction_id
                            .clone()
                            .map(ResponseId::ConnectorTransactionId)
                            .unwrap_or(ResponseId::NoResponseId),
                        redirection_data: redirection_data.map(Box::new),
                        mandate_reference: mandate_reference_id
                            .as_ref()
                            .map(|id| MandateReference {
                                connector_mandate_id: Some(id.clone()),
                                payment_method_id: None,
                            })
                            .map(Box::new),
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: transaction_id.clone(),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            NovalnetAPIStatus::Failure => {
                let response = Err(get_error_response(item.response.result, item.http_code));
                Ok(Self {
                    response,
                    ..item.router_data
                })
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NovalnetResponseCustomer {
    pub billing: Option<NovalnetResponseBilling>,
    pub customer_ip: Option<Secret<String>>,
    pub email: Option<pii::Email>,
    pub first_name: Option<Secret<String>>,
    pub gender: Option<Secret<String>>,
    pub last_name: Option<Secret<String>>,
    pub mobile: Option<Secret<String>>,
    pub tel: Option<Secret<String>>,
    pub fax: Option<Secret<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NovalnetResponseBilling {
    pub city: Option<Secret<String>>,
    pub country_code: Option<Secret<String>>,
    pub house_no: Option<Secret<String>>,
    pub street: Option<Secret<String>>,
    pub zip: Option<Secret<String>>,
    pub state: Option<Secret<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NovalnetResponseMerchant {
    pub project: Option<Secret<i64>>,
    pub project_name: Option<Secret<String>>,
    pub project_url: Option<url::Url>,
    pub vendor: Option<Secret<i64>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NovalnetAuthorizationResponse {
    expiry_date: Option<String>,
    auto_action: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NovalnetSyncResponseTransactionData {
    pub amount: Option<MinorUnit>,
    pub currency: Option<common_enums::Currency>,
    pub date: Option<String>,
    pub order_no: Option<String>,
    pub payment_data: Option<NovalnetResponsePaymentData>,
    pub payment_type: String,
    pub status: NovalnetTransactionStatus,
    pub status_code: u64,
    pub test_mode: u8,
    pub tid: Option<Secret<i64>>,
    pub txn_secret: Option<Secret<String>>,
    pub authorization: Option<NovalnetAuthorizationResponse>,
    pub reason: Option<String>,
    pub reason_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum NovalnetResponsePaymentData {
    Card(NovalnetResponseCard),
    Paypal(NovalnetResponsePaypal),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NovalnetResponseCard {
    pub card_brand: Option<Secret<String>>,
    pub card_expiry_month: Secret<u8>,
    pub card_expiry_year: Secret<u16>,
    pub card_holder: Secret<String>,
    pub card_number: Secret<String>,
    pub cc_3d: Option<Secret<u8>>,
    pub last_four: Option<Secret<String>>,
    pub token: Option<Secret<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NovalnetResponsePaypal {
    pub paypal_account: Option<pii::Email>,
    pub paypal_transaction_id: Option<Secret<String>>,
    pub token: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NovalnetPSyncResponse {
    pub customer: Option<NovalnetResponseCustomer>,
    pub merchant: Option<NovalnetResponseMerchant>,
    pub result: ResultData,
    pub transaction: Option<NovalnetSyncResponseTransactionData>,
}

#[derive(Debug, Copy, Serialize, Default, Deserialize, Clone)]
pub enum CaptureType {
    #[default]
    Partial,
    Final,
}

#[derive(Default, Debug, Serialize)]
pub struct Capture {
    #[serde(rename = "type")]
    cap_type: CaptureType,
    reference: String,
}
#[derive(Default, Debug, Serialize)]
pub struct NovalnetTransaction {
    tid: String,
    amount: Option<StringMinorUnit>,
    capture: Capture,
}

#[derive(Default, Debug, Serialize)]
pub struct NovalnetCaptureRequest {
    pub transaction: NovalnetTransaction,
    pub custom: NovalnetCustom,
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
        NovalnetRouterData<
            RouterDataV2<
                connector_flow::Capture,
                PaymentFlowData,
                PaymentsCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for NovalnetCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: NovalnetRouterData<
            RouterDataV2<
                connector_flow::Capture,
                PaymentFlowData,
                PaymentsCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let capture_type = CaptureType::Final;
        let reference = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        let capture = Capture {
            cap_type: capture_type,
            reference,
        };

        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount_to_capture,
                item.router_data.request.currency,
            )
            .change_context(errors::ConnectorError::AmountConversionFailed)?;

        let transaction = NovalnetTransaction {
            tid: item
                .router_data
                .request
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?,
            capture,
            amount: Some(amount.to_owned()),
        };

        let custom = NovalnetCustom {
            lang: item
                .router_data
                .request
                .get_optional_language_from_browser_info()
                .unwrap_or(DEFAULT_LOCALE.to_string()),
        };
        Ok(Self {
            transaction,
            custom,
        })
    }
}

// Type definition for RefundRequest
#[derive(Default, Debug, Serialize)]
pub struct NovalnetRefundTransaction {
    tid: String,
    amount: Option<StringMinorUnit>,
}

#[derive(Default, Debug, Serialize)]
pub struct NovalnetRefundRequest {
    pub transaction: NovalnetRefundTransaction,
    pub custom: NovalnetCustom,
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        NovalnetRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for NovalnetRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: NovalnetRouterData<
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_refund_amount,
                item.router_data.request.currency,
            )
            .change_context(errors::ConnectorError::AmountConversionFailed)?;

        let transaction = NovalnetRefundTransaction {
            tid: item.router_data.request.connector_transaction_id.clone(),
            amount: Some(amount.to_owned()),
        };

        let custom = NovalnetCustom {
            lang: item
                .router_data
                .request
                .get_optional_language_from_browser_info()
                .unwrap_or(DEFAULT_LOCALE.to_string().to_string()),
        };
        Ok(Self {
            transaction,
            custom,
        })
    }
}

impl From<NovalnetTransactionStatus> for common_enums::RefundStatus {
    fn from(item: NovalnetTransactionStatus) -> Self {
        match item {
            NovalnetTransactionStatus::Success | NovalnetTransactionStatus::Confirmed => {
                Self::Success
            }
            NovalnetTransactionStatus::Pending => Self::Pending,
            NovalnetTransactionStatus::Failure
            | NovalnetTransactionStatus::OnHold
            | NovalnetTransactionStatus::Deactivated
            | NovalnetTransactionStatus::Progress => Self::Failure,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NovalnetRefundSyncResponse {
    result: ResultData,
    transaction: Option<NovalnetSyncResponseTransactionData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NovalnetRefundsTransactionData {
    pub amount: Option<MinorUnit>,
    pub date: Option<String>,
    pub currency: Option<common_enums::Currency>,
    pub order_no: Option<String>,
    pub payment_type: String,
    pub refund: RefundData,
    pub refunded_amount: Option<u64>,
    pub status: NovalnetTransactionStatus,
    pub status_code: u64,
    pub test_mode: u8,
    pub tid: Option<Secret<i64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundData {
    amount: u64,
    currency: common_enums::Currency,
    payment_type: Option<String>,
    tid: Option<Secret<i64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NovalnetRefundResponse {
    pub customer: Option<NovalnetResponseCustomer>,
    pub merchant: Option<NovalnetResponseMerchant>,
    pub result: ResultData,
    pub transaction: Option<NovalnetRefundsTransactionData>,
}

impl<F> TryFrom<ResponseRouterData<NovalnetRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<NovalnetRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response.result.status {
            NovalnetAPIStatus::Success => {
                let refund_id = item
                    .response
                    .transaction
                    .clone()
                    .and_then(|data| data.refund.tid.map(|tid| tid.expose().to_string()))
                    .ok_or(errors::ConnectorError::ResponseHandlingFailed)?;

                let transaction_status = item
                    .response
                    .transaction
                    .map(|transaction| transaction.status)
                    .unwrap_or(NovalnetTransactionStatus::Pending);

                Ok(Self {
                    response: Ok(RefundsResponseData {
                        connector_refund_id: refund_id,
                        refund_status: common_enums::RefundStatus::from(transaction_status),
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            NovalnetAPIStatus::Failure => {
                let response = Err(get_error_response(item.response.result, item.http_code));
                Ok(Self {
                    response,
                    ..item.router_data
                })
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NovalnetRedirectionResponse {
    status: NovalnetTransactionStatus,
    tid: Secret<String>,
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
        NovalnetRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for NovalnetSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: NovalnetRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let transaction = if item
            .router_data
            .request
            .encoded_data
            .clone()
            .get_required_value("encoded_data")
            .is_ok()
        {
            let encoded_data = item
                .router_data
                .request
                .encoded_data
                .clone()
                .get_required_value("encoded_data")
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;
            let novalnet_redirection_response =
                serde_urlencoded::from_str::<NovalnetRedirectionResponse>(encoded_data.as_str())
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            NovalnetSyncTransaction {
                tid: novalnet_redirection_response.tid.expose(),
            }
        } else {
            NovalnetSyncTransaction {
                tid: item
                    .router_data
                    .request
                    .get_connector_transaction_id()
                    .change_context(errors::ConnectorError::MissingConnectorTransactionID)?,
            }
        };

        let custom = NovalnetCustom {
            lang: DEFAULT_LOCALE.to_string().to_string(),
        };
        Ok(Self {
            transaction,
            custom,
        })
    }
}

impl NovalnetSyncResponseTransactionData {
    pub fn get_token(transaction_data: Option<&Self>) -> Option<String> {
        if let Some(data) = transaction_data {
            match &data.payment_data {
                Some(NovalnetResponsePaymentData::Card(card_data)) => {
                    card_data.token.clone().map(|token| token.expose())
                }
                Some(NovalnetResponsePaymentData::Paypal(paypal_data)) => {
                    paypal_data.token.clone().map(|token| token.expose())
                }
                None => None,
            }
        } else {
            None
        }
    }
}

impl<F> TryFrom<ResponseRouterData<NovalnetPSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<NovalnetPSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response.result.status {
            NovalnetAPIStatus::Success => {
                let transaction_id = item
                    .response
                    .transaction
                    .clone()
                    .and_then(|data| data.tid)
                    .map(|tid| tid.expose().to_string());
                let transaction_status = item
                    .response
                    .transaction
                    .clone()
                    .map(|transaction_data| transaction_data.status)
                    .unwrap_or(NovalnetTransactionStatus::Pending);
                let mandate_reference_id = NovalnetSyncResponseTransactionData::get_token(
                    item.response.transaction.as_ref(),
                );

                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: common_enums::AttemptStatus::from(transaction_status),
                        ..item.router_data.resource_common_data
                    },
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: transaction_id
                            .clone()
                            .map(ResponseId::ConnectorTransactionId)
                            .unwrap_or(ResponseId::NoResponseId),
                        redirection_data: None,
                        mandate_reference: mandate_reference_id
                            .as_ref()
                            .map(|id| MandateReference {
                                connector_mandate_id: Some(id.clone()),
                                payment_method_id: None,
                            })
                            .map(Box::new),
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: transaction_id.clone(),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            NovalnetAPIStatus::Failure => {
                let response = Err(get_error_response(item.response.result, item.http_code));
                Ok(Self {
                    response,
                    ..item.router_data
                })
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NovalnetCaptureTransactionData {
    pub amount: Option<MinorUnit>,
    pub capture: CaptureData,
    pub currency: Option<common_enums::Currency>,
    pub order_no: Option<String>,
    pub payment_type: String,
    pub status: NovalnetTransactionStatus,
    pub status_code: Option<u64>,
    pub test_mode: Option<u8>,
    pub tid: Secret<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureData {
    amount: Option<u64>,
    payment_type: Option<String>,
    status: Option<String>,
    status_code: u64,
    tid: Option<Secret<i64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NovalnetCaptureResponse {
    pub result: ResultData,
    pub transaction: Option<NovalnetCaptureTransactionData>,
}

impl<F> TryFrom<ResponseRouterData<NovalnetCaptureResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<NovalnetCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response.result.status {
            NovalnetAPIStatus::Success => {
                let transaction_id = item
                    .response
                    .transaction
                    .clone()
                    .map(|data| data.tid.expose().to_string());
                let transaction_status = item
                    .response
                    .transaction
                    .map(|transaction_data| transaction_data.status)
                    .unwrap_or(NovalnetTransactionStatus::Pending);

                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: common_enums::AttemptStatus::from(transaction_status),
                        ..item.router_data.resource_common_data
                    },
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: transaction_id
                            .clone()
                            .map(ResponseId::ConnectorTransactionId)
                            .unwrap_or(ResponseId::NoResponseId),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: transaction_id.clone(),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            NovalnetAPIStatus::Failure => {
                let response = Err(get_error_response(item.response.result, item.http_code));
                Ok(Self {
                    response,
                    ..item.router_data
                })
            }
        }
    }
}

#[derive(Default, Debug, Serialize)]
pub struct NovalnetSyncTransaction {
    tid: String,
}

#[derive(Default, Debug, Serialize)]
pub struct NovalnetSyncRequest {
    pub transaction: NovalnetSyncTransaction,
    pub custom: NovalnetCustom,
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
        NovalnetRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for NovalnetSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: NovalnetRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let transaction = NovalnetSyncTransaction {
            tid: item.router_data.request.connector_transaction_id.clone(),
        };

        let custom = NovalnetCustom {
            lang: item
                .router_data
                .request
                .get_optional_language_from_browser_info()
                .unwrap_or(DEFAULT_LOCALE.to_string().to_string()),
        };
        Ok(Self {
            transaction,
            custom,
        })
    }
}

impl<F> TryFrom<ResponseRouterData<NovalnetRefundSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<NovalnetRefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response.result.status {
            NovalnetAPIStatus::Success => {
                let refund_id = item
                    .response
                    .transaction
                    .clone()
                    .and_then(|data| data.tid)
                    .map(|tid| tid.expose().to_string())
                    .unwrap_or("".to_string());
                //NOTE: Mapping refund_id with "" incase we dont get any tid

                let transaction_status = item
                    .response
                    .transaction
                    .map(|transaction_data| transaction_data.status)
                    .unwrap_or(NovalnetTransactionStatus::Pending);

                Ok(Self {
                    response: Ok(RefundsResponseData {
                        connector_refund_id: refund_id,
                        refund_status: common_enums::RefundStatus::from(transaction_status),
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            NovalnetAPIStatus::Failure => {
                let response = Err(get_error_response(item.response.result, item.http_code));
                Ok(Self {
                    response,
                    ..item.router_data
                })
            }
        }
    }
}

#[derive(Default, Debug, Serialize)]
pub struct NovalnetCancelTransaction {
    tid: String,
}

#[derive(Default, Debug, Serialize)]
pub struct NovalnetCancelRequest {
    pub transaction: NovalnetCancelTransaction,
    pub custom: NovalnetCustom,
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
        NovalnetRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for NovalnetCancelRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: NovalnetRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let transaction = NovalnetCancelTransaction {
            tid: item.router_data.request.connector_transaction_id.clone(),
        };

        let custom = NovalnetCustom {
            lang: item
                .router_data
                .request
                .get_optional_language_from_browser_info()
                .unwrap_or(DEFAULT_LOCALE.to_string().to_string()),
        };
        Ok(Self {
            transaction,
            custom,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NovalnetCancelResponse {
    result: ResultData,
    transaction: Option<NovalnetPaymentsResponseTransactionData>,
}

impl<F> TryFrom<ResponseRouterData<NovalnetCancelResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<NovalnetCancelResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response.result.status {
            NovalnetAPIStatus::Success => {
                let transaction_id = item
                    .response
                    .transaction
                    .clone()
                    .and_then(|data| data.tid.map(|tid| tid.expose().to_string()));
                let transaction_status = item
                    .response
                    .transaction
                    .and_then(|transaction_data| transaction_data.status)
                    .unwrap_or(NovalnetTransactionStatus::Pending);
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: if transaction_status == NovalnetTransactionStatus::Deactivated {
                            common_enums::AttemptStatus::Voided
                        } else {
                            common_enums::AttemptStatus::VoidFailed
                        },
                        ..item.router_data.resource_common_data
                    },

                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: transaction_id
                            .clone()
                            .map(ResponseId::ConnectorTransactionId)
                            .unwrap_or(ResponseId::NoResponseId),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: transaction_id.clone(),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            NovalnetAPIStatus::Failure => {
                let response = Err(get_error_response(item.response.result, item.http_code));
                Ok(Self {
                    response,
                    ..item.router_data
                })
            }
        }
    }
}

//TODO: Fill the struct with respective fields
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct NovalnetErrorResponse {
    pub status_code: u64,
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
}

#[derive(Display, Debug, Serialize, Deserialize)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WebhookEventType {
    Payment,
    TransactionCapture,
    TransactionCancel,
    TransactionRefund,
    Chargeback,
    Credit,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NovalnetWebhookEvent {
    pub checksum: String,
    pub tid: i64,
    pub parent_tid: Option<i64>,
    #[serde(rename = "type")]
    pub event_type: WebhookEventType,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum NovalnetWebhookTransactionData {
    SyncTransactionData(NovalnetSyncResponseTransactionData),
    CaptureTransactionData(NovalnetCaptureTransactionData),
    CancelTransactionData(NovalnetPaymentsResponseTransactionData),
    RefundsTransactionData(NovalnetRefundsTransactionData),
}
#[derive(Serialize, Deserialize, Debug)]
pub struct NovalnetWebhookNotificationResponse {
    pub event: NovalnetWebhookEvent,
    pub result: ResultData,
    pub transaction: NovalnetWebhookTransactionData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NovalnetWebhookNotificationResponseRefunds {
    pub event: NovalnetWebhookEvent,
    pub result: ResultData,
    pub transaction: NovalnetRefundsTransactionData,
}

pub fn is_refund_event(event_code: &WebhookEventType) -> bool {
    matches!(event_code, WebhookEventType::TransactionRefund)
}

pub fn reverse_string(s: &str) -> String {
    s.chars().rev().collect()
}

#[derive(Display, Debug, Serialize, Deserialize)]
pub enum WebhookDisputeStatus {
    DisputeOpened,
    DisputeWon,
    Unknown,
}

pub fn get_novalnet_dispute_status(status: WebhookEventType) -> WebhookDisputeStatus {
    match status {
        WebhookEventType::Chargeback => WebhookDisputeStatus::DisputeOpened,
        WebhookEventType::Credit => WebhookDisputeStatus::DisputeWon,
        _ => WebhookDisputeStatus::Unknown,
    }
}

impl ForeignTryFrom<WebhookDisputeStatus> for common_enums::DisputeStatus {
    type Error = ConnectorError;

    fn foreign_try_from(value: WebhookDisputeStatus) -> error_stack::Result<Self, Self::Error> {
        match value {
            WebhookDisputeStatus::DisputeOpened => Ok(Self::DisputeOpened),
            WebhookDisputeStatus::DisputeWon => Ok(Self::DisputeWon),
            WebhookDisputeStatus::Unknown => Err(ConnectorError::WebhookBodyDecodingFailed)?,
        }
    }
}

pub fn option_to_result<T>(opt: Option<T>) -> Result<T, errors::ConnectorError> {
    opt.ok_or(errors::ConnectorError::WebhookBodyDecodingFailed)
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
        NovalnetRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for NovalnetPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: NovalnetRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, error_stack::Report<ConnectorError>> {
        let auth = NovalnetAuthType::try_from(&item.router_data.connector_auth_type)?;

        let merchant = NovalnetPaymentsRequestMerchant {
            signature: auth.product_activation_key,
            tariff: auth.tariff_id,
        };

        let enforce_3d = match item.router_data.resource_common_data.auth_type {
            common_enums::AuthenticationType::ThreeDs => Some(1),
            common_enums::AuthenticationType::NoThreeDs => None,
        };
        let test_mode = get_test_mode(item.router_data.resource_common_data.test_mode);
        let req_address = item.router_data.resource_common_data.get_optional_billing();

        let billing = NovalnetPaymentsRequestBilling {
            house_no: item
                .router_data
                .resource_common_data
                .get_optional_billing_line1(),
            street: item
                .router_data
                .resource_common_data
                .get_optional_billing_line2(),
            city: item
                .router_data
                .resource_common_data
                .get_optional_billing_city()
                .map(Secret::new),
            zip: item
                .router_data
                .resource_common_data
                .get_optional_billing_zip(),
            country_code: item
                .router_data
                .resource_common_data
                .get_optional_billing_country(),
        };

        let email = item
            .router_data
            .resource_common_data
            .get_billing_email()
            .or(item.router_data.request.get_email())?;

        let customer = NovalnetPaymentsRequestCustomer {
            first_name: req_address.and_then(|addr| addr.get_optional_first_name()),
            last_name: req_address.and_then(|addr| addr.get_optional_last_name()),
            email,
            mobile: item
                .router_data
                .resource_common_data
                .get_optional_billing_phone_number(),
            billing: Some(billing),
            // no_nc is used to indicate if minimal customer data is passed or not
            no_nc: MINIMAL_CUSTOMER_DATA_PASSED,
        };

        let lang = item
            .router_data
            .request
            .get_optional_language_from_browser_info()
            .unwrap_or(DEFAULT_LOCALE.to_string().to_string());

        let custom = NovalnetCustom { lang };
        let hook_url = item.router_data.request.get_webhook_url()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        let create_token = Some(CREATE_TOKEN_REQUIRED);

        match item.router_data.request.payment_method_data {
            PaymentMethodData::Card(ref req_card) => {
                let novalnet_card = NovalNetPaymentData::Card(NovalnetCard {
                    card_number: req_card.card_number.clone(),
                    card_expiry_month: req_card.card_exp_month.clone(),
                    card_expiry_year: req_card.card_exp_year.clone(),
                    card_cvc: req_card.card_cvc.clone(),
                    card_holder: item
                        .router_data
                        .resource_common_data
                        .get_billing_address()?
                        .get_full_name()?,
                });

                let transaction = NovalnetPaymentsRequestTransaction {
                    test_mode,
                    payment_type: NovalNetPaymentTypes::CREDITCARD,
                    amount: NovalNetAmount::Int(0),
                    currency: item.router_data.request.currency,
                    order_no: item
                        .router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                    hook_url: Some(hook_url),
                    return_url: Some(return_url.clone()),
                    error_return_url: Some(return_url.clone()),
                    payment_data: Some(novalnet_card),
                    enforce_3d,
                    create_token,
                    scheme_tid: None,
                };

                Ok(Self {
                    merchant,
                    transaction,
                    customer,
                    custom,
                })
            }

            PaymentMethodData::Wallet(ref wallet_data) => match wallet_data {
                WalletDataPaymentMethod::GooglePay(ref req_wallet) => {
                    let novalnet_google_pay: NovalNetPaymentData<T> =
                        NovalNetPaymentData::GooglePay(NovalnetGooglePay {
                            wallet_data: Secret::new(
                                req_wallet
                                    .tokenization_data
                                    .get_encrypted_google_pay_token()
                                    .change_context(errors::ConnectorError::MissingRequiredField {
                                        field_name: "gpay wallet_token",
                                    })?
                                    .clone(),
                            ),
                        });

                    let transaction = NovalnetPaymentsRequestTransaction {
                        test_mode,
                        payment_type: NovalNetPaymentTypes::GOOGLEPAY,
                        amount: NovalNetAmount::Int(0),
                        currency: item.router_data.request.currency,
                        order_no: item
                            .router_data
                            .resource_common_data
                            .connector_request_reference_id
                            .clone(),
                        hook_url: Some(hook_url),
                        return_url: None,
                        error_return_url: None,
                        payment_data: Some(novalnet_google_pay),
                        enforce_3d,
                        create_token,
                        scheme_tid: None,
                    };

                    Ok(Self {
                        merchant,
                        transaction,
                        customer,
                        custom,
                    })
                }
                WalletDataPaymentMethod::ApplePay(payment_method_data) => {
                    let transaction = NovalnetPaymentsRequestTransaction {
                        test_mode,
                        payment_type: NovalNetPaymentTypes::APPLEPAY,
                        amount: NovalNetAmount::Int(0),
                        currency: item.router_data.request.currency,
                        order_no: item
                            .router_data
                            .resource_common_data
                            .connector_request_reference_id
                            .clone(),
                        hook_url: Some(hook_url),
                        return_url: None,
                        error_return_url: None,
                        payment_data: Some(NovalNetPaymentData::ApplePay(NovalnetApplePay {
                            wallet_data: payment_method_data.get_applepay_decoded_payment_data()?,
                        })),
                        enforce_3d: None,
                        create_token,
                        scheme_tid: None,
                    };

                    Ok(Self {
                        merchant,
                        transaction,
                        customer,
                        custom,
                    })
                }
                WalletDataPaymentMethod::AliPayQr(_)
                | WalletDataPaymentMethod::AliPayRedirect(_)
                | WalletDataPaymentMethod::AliPayHkRedirect(_)
                | WalletDataPaymentMethod::AmazonPayRedirect(_)
                | WalletDataPaymentMethod::MomoRedirect(_)
                | WalletDataPaymentMethod::KakaoPayRedirect(_)
                | WalletDataPaymentMethod::GoPayRedirect(_)
                | WalletDataPaymentMethod::GcashRedirect(_)
                | WalletDataPaymentMethod::ApplePayRedirect(_)
                | WalletDataPaymentMethod::ApplePayThirdPartySdk(_)
                | WalletDataPaymentMethod::DanaRedirect {}
                | WalletDataPaymentMethod::GooglePayRedirect(_)
                | WalletDataPaymentMethod::GooglePayThirdPartySdk(_)
                | WalletDataPaymentMethod::MbWayRedirect(_)
                | WalletDataPaymentMethod::MobilePayRedirect(_)
                | WalletDataPaymentMethod::RevolutPay(_) => {
                    Err(errors::ConnectorError::NotImplemented(
                        utils::get_unimplemented_payment_method_error_message("novalnet"),
                    ))?
                }
                WalletDataPaymentMethod::PaypalRedirect(_) => {
                    let transaction = NovalnetPaymentsRequestTransaction {
                        test_mode,
                        payment_type: NovalNetPaymentTypes::PAYPAL,
                        amount: NovalNetAmount::Int(0),
                        currency: item.router_data.request.currency,
                        order_no: item
                            .router_data
                            .resource_common_data
                            .connector_request_reference_id
                            .clone(),
                        hook_url: Some(hook_url),
                        return_url: Some(return_url.clone()),
                        error_return_url: Some(return_url.clone()),
                        payment_data: None,
                        enforce_3d: None,
                        create_token,
                        scheme_tid: None,
                    };

                    Ok(Self {
                        merchant,
                        transaction,
                        customer,
                        custom,
                    })
                }
                WalletDataPaymentMethod::PaypalSdk(_)
                | WalletDataPaymentMethod::Paze(_)
                | WalletDataPaymentMethod::SamsungPay(_)
                | WalletDataPaymentMethod::TwintRedirect {}
                | WalletDataPaymentMethod::VippsRedirect {}
                | WalletDataPaymentMethod::TouchNGoRedirect(_)
                | WalletDataPaymentMethod::WeChatPayRedirect(_)
                | WalletDataPaymentMethod::CashappQr(_)
                | WalletDataPaymentMethod::SwishQr(_)
                | WalletDataPaymentMethod::WeChatPayQr(_)
                | WalletDataPaymentMethod::Mifinity(_) => {
                    Err(errors::ConnectorError::NotImplemented(
                        utils::get_unimplemented_payment_method_error_message("novalnet"),
                    ))?
                }
            },
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("novalnet"),
            ))?,
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
        NovalnetRouterData<
            RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
            T,
        >,
    > for NovalnetPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: NovalnetRouterData<
            RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = NovalnetAuthType::try_from(&item.router_data.connector_auth_type)?;

        let merchant = NovalnetPaymentsRequestMerchant {
            signature: auth.product_activation_key,
            tariff: auth.tariff_id,
        };

        let enforce_3d = match item.router_data.resource_common_data.auth_type {
            common_enums::AuthenticationType::ThreeDs => Some(1),
            common_enums::AuthenticationType::NoThreeDs => None,
        };
        let test_mode = get_test_mode(item.router_data.resource_common_data.test_mode);

        let billing = NovalnetPaymentsRequestBilling {
            house_no: item
                .router_data
                .resource_common_data
                .get_optional_billing_line1(),
            street: item
                .router_data
                .resource_common_data
                .get_optional_billing_line2(),
            city: item
                .router_data
                .resource_common_data
                .get_optional_billing_city()
                .map(Secret::new),
            zip: item
                .router_data
                .resource_common_data
                .get_optional_billing_zip(),
            country_code: item
                .router_data
                .resource_common_data
                .get_optional_billing_country(),
        };

        let customer = NovalnetPaymentsRequestCustomer {
            first_name: item
                .router_data
                .resource_common_data
                .get_optional_billing_first_name(),
            last_name: item
                .router_data
                .resource_common_data
                .get_optional_billing_last_name(),
            email: item
                .router_data
                .resource_common_data
                .get_billing_email()
                .or(item.router_data.request.get_email())?,
            mobile: item
                .router_data
                .resource_common_data
                .get_optional_billing_phone_number(),
            billing: Some(billing),
            // no_nc is used to indicate if minimal customer data is passed or not
            no_nc: MINIMAL_CUSTOMER_DATA_PASSED,
        };

        let lang = item
            .router_data
            .request
            .get_optional_language_from_browser_info()
            .unwrap_or(DEFAULT_LOCALE.to_string().to_string());
        let custom = NovalnetCustom { lang };
        let hook_url = item.router_data.request.get_webhook_url()?;

        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(errors::ConnectorError::AmountConversionFailed)?;

        match item.router_data.request.mandate_reference {
            MandateReferenceId::ConnectorMandateId(mandate_data) => {
                let connector_mandate_id = mandate_data.get_connector_mandate_id().ok_or(
                    errors::ConnectorError::MissingRequiredField {
                        field_name: "connector_mandate_id",
                    },
                )?;

                let novalnet_mandate_data = NovalNetPaymentData::MandatePayment(NovalnetMandate {
                    token: Secret::new(connector_mandate_id),
                });

                let payment_type = match item.router_data.request.payment_method_type {
                    Some(pm_type) => NovalNetPaymentTypes::try_from(&pm_type)?,
                    None => NovalNetPaymentTypes::CREDITCARD,
                };

                let transaction = NovalnetPaymentsRequestTransaction {
                    test_mode,
                    payment_type,
                    amount: NovalNetAmount::StringMinor(amount.clone()),
                    currency: item.router_data.request.currency,
                    order_no: item
                        .router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                    hook_url: Some(hook_url),
                    return_url: None,
                    error_return_url: None,
                    payment_data: Some(novalnet_mandate_data),
                    enforce_3d,
                    create_token: None,
                    scheme_tid: None,
                };

                Ok(Self {
                    merchant,
                    transaction,
                    customer,
                    custom,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("novalnet"),
            )
            .into()),
        }
    }
}

pub fn get_incoming_webhook_event(
    status: WebhookEventType,
    transaction_status: NovalnetTransactionStatus,
) -> EventType {
    match status {
        WebhookEventType::Payment => match transaction_status {
            NovalnetTransactionStatus::Confirmed | NovalnetTransactionStatus::Success => {
                EventType::PaymentIntentSuccess
            }
            NovalnetTransactionStatus::OnHold => EventType::PaymentIntentAuthorizationSuccess,
            NovalnetTransactionStatus::Pending => EventType::PaymentIntentProcessing,
            NovalnetTransactionStatus::Progress => EventType::IncomingWebhookEventUnspecified,
            _ => EventType::PaymentIntentFailure,
        },
        WebhookEventType::TransactionCapture => match transaction_status {
            NovalnetTransactionStatus::Confirmed | NovalnetTransactionStatus::Success => {
                EventType::PaymentIntentCaptureSuccess
            }
            _ => EventType::PaymentIntentCaptureFailure,
        },
        WebhookEventType::TransactionCancel => match transaction_status {
            NovalnetTransactionStatus::Deactivated => EventType::PaymentIntentCancelled,
            _ => EventType::PaymentIntentCancelFailure,
        },
        WebhookEventType::TransactionRefund => match transaction_status {
            NovalnetTransactionStatus::Confirmed | NovalnetTransactionStatus::Success => {
                EventType::RefundSuccess
            }
            _ => EventType::RefundFailure,
        },
        WebhookEventType::Chargeback => EventType::DisputeOpened,
        WebhookEventType::Credit => EventType::DisputeWon,
    }
}

impl TryFrom<NovalnetWebhookNotificationResponse> for WebhookDetailsResponse {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(notif: NovalnetWebhookNotificationResponse) -> Result<Self, Self::Error> {
        match notif.transaction {
            NovalnetWebhookTransactionData::SyncTransactionData(response) => {
                match notif.result.status {
                    NovalnetAPIStatus::Success => {
                        let mandate_reference_id =
                            NovalnetSyncResponseTransactionData::get_token(Some(&response));
                        let transaction_id = response.tid.map(|tid| tid.expose().to_string());
                        let transaction_status = response.status;

                        Ok(Self {
                            status: common_enums::AttemptStatus::from(transaction_status),
                            resource_id: Some(
                                transaction_id
                                    .clone()
                                    .map(ResponseId::ConnectorTransactionId)
                                    .unwrap_or(ResponseId::NoResponseId),
                            ),
                            mandate_reference: mandate_reference_id
                                .as_ref()
                                .map(|id| MandateReference {
                                    connector_mandate_id: Some(id.clone()),
                                    payment_method_id: None,
                                })
                                .map(Box::new),
                            status_code: 200,
                            connector_response_reference_id: transaction_id.clone(),
                            error_code: None,
                            error_message: None,
                            raw_connector_response: None,
                            response_headers: None,
                        })
                    }
                    NovalnetAPIStatus::Failure => Ok(Self {
                        status: common_enums::AttemptStatus::Failure,
                        resource_id: None,
                        status_code: 200,
                        mandate_reference: None,
                        connector_response_reference_id: None,
                        error_code: Some(notif.result.status.to_string()),
                        error_message: Some(notif.result.status_text),
                        raw_connector_response: None,
                        response_headers: None,
                    }),
                }
            }
            _ => Err(ConnectorError::WebhookBodyDecodingFailed)?,
        }
    }
}

impl TryFrom<NovalnetWebhookNotificationResponseRefunds> for RefundWebhookDetailsResponse {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(notif: NovalnetWebhookNotificationResponseRefunds) -> Result<Self, Self::Error> {
        match notif.result.status {
            NovalnetAPIStatus::Success => {
                let refund_id = notif
                    .transaction
                    .tid
                    .map(|tid| tid.expose().to_string())
                    .unwrap_or("".to_string());
                //NOTE: Mapping refund_id with "" incase we dont get any tid

                let transaction_status = notif.transaction.status;

                Ok(Self {
                    connector_refund_id: Some(refund_id),
                    status: common_enums::RefundStatus::from(transaction_status),
                    status_code: 200,
                    connector_response_reference_id: None,
                    error_code: None,
                    error_message: None,
                    raw_connector_response: None,
                    response_headers: None,
                })
            }
            NovalnetAPIStatus::Failure => Ok(Self {
                status: common_enums::RefundStatus::Failure,
                connector_refund_id: None,
                status_code: 200,
                connector_response_reference_id: None,
                error_code: Some(notif.result.status.to_string()),
                error_message: Some(notif.result.status_text),
                raw_connector_response: None,
                response_headers: None,
            }),
        }
    }
}
