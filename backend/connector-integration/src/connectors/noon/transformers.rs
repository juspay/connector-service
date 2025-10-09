use common_enums::enums::{self, AttemptStatus, CountryAlpha2};
use common_utils::{ext_traits::Encode, pii, request::Method, types::StringMajorUnit};
use domain_types::{
    connector_flow::{Authorize, Capture, MandateRevoke, Refund, SetupMandate, Void},
    connector_types::{
        MandateReference, MandateReferenceId, MandateRevokeRequestData, MandateRevokeResponseData,
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId, SetupMandateRequestData,
    },
    errors::{self, ConnectorError},
    mandates::MandateDataType,
    payment_method_data::{
        GooglePayWalletData, PaymentMethodData, PaymentMethodDataTypes, RawCardNumber, WalletData,
    },
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use super::NoonRouterData;
use crate::{types::ResponseRouterData, utils};

// These needs to be accepted from SDK, need to be done after 1.0.0 stability as API contract will change
const GOOGLEPAY_API_VERSION_MINOR: u8 = 0;
const GOOGLEPAY_API_VERSION: u8 = 2;

#[derive(Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NoonChannels {
    Web,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NoonSubscriptionType {
    Unscheduled,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonSubscriptionData {
    #[serde(rename = "type")]
    subscription_type: NoonSubscriptionType,
    //Short description about the subscription.
    name: String,
    max_amount: StringMajorUnit,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonBillingAddress {
    street: Option<Secret<String>>,
    street2: Option<Secret<String>>,
    city: Option<String>,
    state_province: Option<Secret<String>>,
    country: Option<CountryAlpha2>,
    postal_code: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonBilling {
    address: NoonBillingAddress,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonOrder {
    amount: StringMajorUnit,
    currency: Option<enums::Currency>,
    channel: NoonChannels,
    category: Option<String>,
    reference: String,
    //Short description of the order.
    name: String,
    nvp: Option<NoonOrderNvp>,
    ip_address: Option<Secret<String, pii::IpAddress>>,
}

#[derive(Debug, Serialize)]
pub struct NoonOrderNvp {
    #[serde(flatten)]
    inner: std::collections::BTreeMap<String, Secret<String>>,
}

fn get_value_as_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(string) => string.to_owned(),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::Array(_)
        | serde_json::Value::Object(_) => value.to_string(),
    }
}

impl NoonOrderNvp {
    pub fn new(metadata: &serde_json::Value) -> Self {
        let metadata_as_string = metadata.to_string();
        let hash_map: std::collections::BTreeMap<String, serde_json::Value> =
            serde_json::from_str(&metadata_as_string).unwrap_or(std::collections::BTreeMap::new());
        let inner = hash_map
            .into_iter()
            .enumerate()
            .map(|(index, (hs_key, hs_value))| {
                let noon_key = format!("{}", index + 1);
                // to_string() function on serde_json::Value returns a string with "" quotes. Noon doesn't allow this. Hence get_value_as_string function
                let noon_value = format!("{hs_key}={}", get_value_as_string(&hs_value));
                (noon_key, Secret::new(noon_value))
            })
            .collect();
        Self { inner }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NoonPaymentActions {
    Authorize,
    Sale,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonConfiguration {
    tokenize_c_c: Option<bool>,
    payment_action: NoonPaymentActions,
    return_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonSubscription {
    subscription_identifier: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonCard<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    name_on_card: Option<Secret<String>>,
    number_plain: RawCardNumber<T>,
    expiry_month: Secret<String>,
    expiry_year: Secret<String>,
    cvv: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonApplePayPaymentMethod {
    pub display_name: String,
    pub network: String,
    #[serde(rename = "type")]
    pub pm_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonApplePayHeader {
    ephemeral_public_key: Secret<String>,
    public_key_hash: Secret<String>,
    transaction_id: Secret<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NoonApplePaymentData {
    version: Secret<String>,
    data: Secret<String>,
    signature: Secret<String>,
    header: NoonApplePayHeader,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonApplePayData {
    payment_data: NoonApplePaymentData,
    payment_method: NoonApplePayPaymentMethod,
    transaction_identifier: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonApplePayTokenData {
    token: NoonApplePayData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonApplePay {
    payment_info: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonGooglePay {
    api_version_minor: u8,
    api_version: u8,
    payment_method_data: GooglePayWalletData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonPayPal {
    return_url: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "UPPERCASE")]
pub enum NoonPaymentData<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    Card(NoonCard<T>),
    Subscription(NoonSubscription),
    ApplePay(NoonApplePay),
    GooglePay(NoonGooglePay),
    PayPal(NoonPayPal),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NoonApiOperations {
    Initiate,
    Capture,
    Reverse,
    Refund,
    CancelSubscription,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonPaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    api_operation: NoonApiOperations,
    order: NoonOrder,
    configuration: NoonConfiguration,
    payment_data: NoonPaymentData<T>,
    subscription: Option<NoonSubscriptionData>,
    billing: Option<NoonBilling>,
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
        NoonRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for NoonPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        data: NoonRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &data.router_data;
        let amount = data.connector.amount_converter.convert(
            data.router_data.request.minor_amount,
            data.router_data.request.currency,
        );

        let (payment_data, currency, category) = match item.request.connector_mandate_id() {
            Some(mandate_id) => (
                NoonPaymentData::Subscription(NoonSubscription {
                    subscription_identifier: Secret::new(mandate_id),
                }),
                None,
                None,
            ),
            _ => (
                match item.request.payment_method_data.clone() {
                    PaymentMethodData::Card(req_card) => Ok(NoonPaymentData::Card(NoonCard {
                        name_on_card: item.resource_common_data.get_optional_billing_full_name(),
                        number_plain: req_card.card_number.clone(),
                        expiry_month: req_card.card_exp_month.clone(),
                        expiry_year: req_card.card_exp_year.clone(),
                        cvv: req_card.card_cvc,
                    })),
                    PaymentMethodData::Wallet(wallet_data) => match wallet_data.clone() {
                        WalletData::GooglePay(google_pay_data) => {
                            Ok(NoonPaymentData::GooglePay(NoonGooglePay {
                                api_version_minor: GOOGLEPAY_API_VERSION_MINOR,
                                api_version: GOOGLEPAY_API_VERSION,
                                payment_method_data: google_pay_data,
                            }))
                        }
                        WalletData::ApplePay(apple_pay_data) => {
                            let payment_token_data = NoonApplePayTokenData {
                                token: NoonApplePayData {
                                    payment_data: wallet_data
                                        .get_wallet_token_as_json("Apple Pay".to_string())?,
                                    payment_method: NoonApplePayPaymentMethod {
                                        display_name: apple_pay_data.payment_method.display_name,
                                        network: apple_pay_data.payment_method.network,
                                        pm_type: apple_pay_data.payment_method.pm_type,
                                    },
                                    transaction_identifier: Secret::new(
                                        apple_pay_data.transaction_identifier,
                                    ),
                                },
                            };
                            let payment_token = payment_token_data
                                .encode_to_string_of_json()
                                .change_context(errors::ConnectorError::RequestEncodingFailed)?;

                            Ok(NoonPaymentData::ApplePay(NoonApplePay {
                                payment_info: Secret::new(payment_token),
                            }))
                        }
                        WalletData::PaypalRedirect(_) => Ok(NoonPaymentData::PayPal(NoonPayPal {
                            return_url: item.request.get_router_return_url()?,
                        })),
                        WalletData::AliPayQr(_)
                        | WalletData::AliPayRedirect(_)
                        | WalletData::AliPayHkRedirect(_)
                        | WalletData::AmazonPayRedirect(_)
                        | WalletData::MomoRedirect(_)
                        | WalletData::KakaoPayRedirect(_)
                        | WalletData::GoPayRedirect(_)
                        | WalletData::GcashRedirect(_)
                        | WalletData::ApplePayRedirect(_)
                        | WalletData::ApplePayThirdPartySdk(_)
                        | WalletData::DanaRedirect {}
                        | WalletData::GooglePayRedirect(_)
                        | WalletData::GooglePayThirdPartySdk(_)
                        | WalletData::MbWayRedirect(_)
                        | WalletData::MobilePayRedirect(_)
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
                        | WalletData::Mifinity(_)
                        | WalletData::BluecodeRedirect { .. }
                        | WalletData::RevolutPay(_) => Err(errors::ConnectorError::NotImplemented(
                            utils::get_unimplemented_payment_method_error_message("Noon"),
                        )),
                    },
                    PaymentMethodData::CardRedirect(_)
                    | PaymentMethodData::PayLater(_)
                    | PaymentMethodData::BankRedirect(_)
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
                        Err(errors::ConnectorError::NotImplemented(
                            utils::get_unimplemented_payment_method_error_message("Noon"),
                        ))
                    }
                }?,
                Some(item.request.currency),
                Some(item.request.order_category.clone().ok_or(
                    errors::ConnectorError::MissingRequiredField {
                        field_name: "order_category",
                    },
                )?),
            ),
        };

        let ip_address = item.request.get_ip_address_as_optional();

        let channel = NoonChannels::Web;

        let billing = item
            .resource_common_data
            .get_optional_billing()
            .and_then(|billing_address| billing_address.address.as_ref())
            .map(|address| NoonBilling {
                address: NoonBillingAddress {
                    street: address.line1.clone(),
                    street2: address.line2.clone(),
                    city: address.city.clone(),
                    // If state is passed in request, country becomes mandatory, keep a check while debugging failed payments
                    state_province: address.state.clone(),
                    country: address.country,
                    postal_code: address.zip.clone(),
                },
            });

        // The description should not have leading or trailing whitespaces, also it should not have double whitespaces and a max 50 chars according to Noon's Docs
        let name: String = item
            .resource_common_data
            .get_description()?
            .trim()
            .replace("  ", " ")
            .chars()
            .take(50)
            .collect();

        let order = NoonOrder {
            amount: amount.change_context(ConnectorError::ParsingFailed)?,
            currency,
            channel,
            category,
            reference: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            name,
            nvp: item.request.metadata.as_ref().map(NoonOrderNvp::new),
            ip_address,
        };
        let payment_action = if item.request.is_auto_capture()? {
            NoonPaymentActions::Sale
        } else {
            NoonPaymentActions::Authorize
        };
        Ok(Self {
            api_operation: NoonApiOperations::Initiate,
            order,
            billing,
            configuration: NoonConfiguration {
                payment_action,
                return_url: item.request.router_return_url.clone(),
                tokenize_c_c: None,
            },
            payment_data,
            subscription: None,
        })
    }
}

// Auth Struct
pub struct NoonAuthType {
    pub(super) api_key: Secret<String>,
    pub(super) application_identifier: Secret<String>,
    pub(super) business_identifier: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for NoonAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                api_key: api_key.to_owned(),
                application_identifier: api_secret.to_owned(),
                business_identifier: key1.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}
#[derive(Default, Debug, Deserialize, Serialize, strum::Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "UPPERCASE")]
pub enum NoonPaymentStatus {
    Initiated,
    Authorized,
    Captured,
    PartiallyCaptured,
    PartiallyRefunded,
    PaymentInfoAdded,
    #[serde(rename = "3DS_ENROLL_INITIATED")]
    ThreeDsEnrollInitiated,
    #[serde(rename = "3DS_ENROLL_CHECKED")]
    ThreeDsEnrollChecked,
    #[serde(rename = "3DS_RESULT_VERIFIED")]
    ThreeDsResultVerified,
    MarkedForReview,
    Authenticated,
    PartiallyReversed,
    #[default]
    Pending,
    Cancelled,
    Failed,
    Refunded,
    Expired,
    Reversed,
    Rejected,
    Locked,
}

fn get_payment_status(data: (NoonPaymentStatus, AttemptStatus)) -> AttemptStatus {
    let (item, current_status) = data;
    match item {
        NoonPaymentStatus::Authorized => AttemptStatus::Authorized,
        NoonPaymentStatus::Captured
        | NoonPaymentStatus::PartiallyCaptured
        | NoonPaymentStatus::PartiallyRefunded
        | NoonPaymentStatus::Refunded => AttemptStatus::Charged,
        NoonPaymentStatus::Reversed | NoonPaymentStatus::PartiallyReversed => AttemptStatus::Voided,
        NoonPaymentStatus::Cancelled | NoonPaymentStatus::Expired => {
            AttemptStatus::AuthenticationFailed
        }
        NoonPaymentStatus::ThreeDsEnrollInitiated | NoonPaymentStatus::ThreeDsEnrollChecked => {
            AttemptStatus::AuthenticationPending
        }
        NoonPaymentStatus::ThreeDsResultVerified => AttemptStatus::AuthenticationSuccessful,
        NoonPaymentStatus::Failed | NoonPaymentStatus::Rejected => AttemptStatus::Failure,
        NoonPaymentStatus::Pending | NoonPaymentStatus::MarkedForReview => AttemptStatus::Pending,
        NoonPaymentStatus::Initiated
        | NoonPaymentStatus::PaymentInfoAdded
        | NoonPaymentStatus::Authenticated => AttemptStatus::Started,
        NoonPaymentStatus::Locked => current_status,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NoonSubscriptionObject {
    identifier: Secret<String>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonPaymentsOrderResponse {
    status: NoonPaymentStatus,
    id: u64,
    error_code: u64,
    error_message: Option<String>,
    reference: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonCheckoutData {
    post_url: url::Url,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonPaymentsResponseResult {
    order: NoonPaymentsOrderResponse,
    checkout_data: Option<NoonCheckoutData>,
    subscription: Option<NoonSubscriptionObject>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NoonPaymentsResponse {
    result: NoonPaymentsResponseResult,
}

impl<F, T> TryFrom<ResponseRouterData<NoonPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<NoonPaymentsResponse, Self>) -> Result<Self, Self::Error> {
        let order = item.response.result.order;
        let current_attempt_status = item.router_data.resource_common_data.status;
        let status = get_payment_status((order.status, current_attempt_status));
        let redirection_data = item.response.result.checkout_data.map(|redirection_data| {
            Box::new(RedirectForm::Form {
                endpoint: redirection_data.post_url.to_string(),
                method: Method::Post,
                form_fields: std::collections::HashMap::new(),
            })
        });
        let mandate_reference = item.response.result.subscription.map(|subscription_data| {
            Box::new(MandateReference {
                connector_mandate_id: Some(subscription_data.identifier.expose()),
                payment_method_id: None,
            })
        });
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: match order.error_message {
                Some(error_message) => Err(ErrorResponse {
                    code: order.error_code.to_string(),
                    message: error_message.clone(),
                    reason: Some(error_message),
                    status_code: item.http_code,
                    attempt_status: Some(status),
                    connector_transaction_id: Some(order.id.to_string()),
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
                _ => {
                    let connector_response_reference_id =
                        order.reference.or(Some(order.id.to_string()));
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(order.id.to_string()),
                        redirection_data,
                        mandate_reference,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id,
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    })
                }
            },
            ..item.router_data
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonActionTransaction {
    amount: StringMajorUnit,
    currency: enums::Currency,
    transaction_reference: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonActionOrder {
    id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonPaymentsActionRequest {
    api_operation: NoonApiOperations,
    order: NoonActionOrder,
    transaction: NoonActionTransaction,
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
        NoonRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for NoonPaymentsActionRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        data: NoonRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &data.router_data;
        let amount = data.connector.amount_converter.convert(
            data.router_data.request.minor_amount_to_capture,
            data.router_data.request.currency,
        );
        let order = NoonActionOrder {
            id: item
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(ConnectorError::MissingRequiredField {
                    field_name: "connector_transaction_id",
                })?,
        };
        let transaction = NoonActionTransaction {
            amount: amount.change_context(ConnectorError::ParsingFailed)?,
            currency: item.request.currency,
            transaction_reference: None,
        };
        Ok(Self {
            api_operation: NoonApiOperations::Capture,
            order,
            transaction,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonPaymentsCancelRequest {
    api_operation: NoonApiOperations,
    order: NoonActionOrder,
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
        NoonRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for NoonPaymentsCancelRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: NoonRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let order = NoonActionOrder {
            id: item.router_data.request.connector_transaction_id.clone(),
        };
        Ok(Self {
            api_operation: NoonApiOperations::Reverse,
            order,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonRevokeMandateRequest {
    api_operation: NoonApiOperations,
    subscription: NoonSubscriptionObject,
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
        NoonRouterData<
            RouterDataV2<
                MandateRevoke,
                PaymentFlowData,
                MandateRevokeRequestData,
                MandateRevokeResponseData,
            >,
            T,
        >,
    > for NoonRevokeMandateRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: NoonRouterData<
            RouterDataV2<
                MandateRevoke,
                PaymentFlowData,
                MandateRevokeRequestData,
                MandateRevokeResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            api_operation: NoonApiOperations::CancelSubscription,
            subscription: NoonSubscriptionObject {
                identifier: Secret::new(item.router_data.request.mandate_id),
            },
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
    >
    TryFrom<
        NoonRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for NoonPaymentsActionRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        data: NoonRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &data.router_data;
        let refund_amount = data.connector.amount_converter.convert(
            data.router_data.request.minor_payment_amount,
            data.router_data.request.currency,
        );
        let order = NoonActionOrder {
            id: item.request.connector_transaction_id.clone(),
        };
        let transaction = NoonActionTransaction {
            amount: refund_amount.change_context(ConnectorError::ParsingFailed)?,
            currency: item.request.currency,
            transaction_reference: Some(item.request.refund_id.clone()),
        };
        Ok(Self {
            api_operation: NoonApiOperations::Refund,
            order,
            transaction,
        })
    }
}
#[derive(Debug, Deserialize, Serialize)]
pub enum NoonRevokeStatus {
    Cancelled,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NoonCancelSubscriptionObject {
    status: NoonRevokeStatus,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NoonRevokeMandateResult {
    subscription: NoonCancelSubscriptionObject,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NoonRevokeMandateResponse {
    result: NoonRevokeMandateResult,
}

impl TryFrom<ResponseRouterData<NoonRevokeMandateResponse, Self>>
    for RouterDataV2<
        MandateRevoke,
        PaymentFlowData,
        MandateRevokeRequestData,
        MandateRevokeResponseData,
    >
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<NoonRevokeMandateResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response.result.subscription.status {
            NoonRevokeStatus::Cancelled => Ok(Self {
                response: Ok(MandateRevokeResponseData {
                    mandate_status: common_enums::MandateStatus::Revoked,
                }),
                ..item.router_data
            }),
        }
    }
}

#[derive(Debug, Default, Deserialize, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RefundStatus {
    Success,
    Failed,
    #[default]
    Pending,
}

impl From<RefundStatus> for enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Success => Self::Success,
            RefundStatus::Failed => Self::Failure,
            RefundStatus::Pending => Self::Pending,
        }
    }
}

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonPaymentsTransactionResponse {
    id: String,
    status: RefundStatus,
}

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonRefundResponseResult {
    transaction: NoonPaymentsTransactionResponse,
}

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefundResponse {
    result: NoonRefundResponseResult,
    result_code: u32,
    class_description: String,
    message: String,
}

impl<F> TryFrom<ResponseRouterData<RefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: ResponseRouterData<RefundResponse, Self>) -> Result<Self, Self::Error> {
        let response = &item.response;
        let refund_status =
            enums::RefundStatus::from(response.result.transaction.status.to_owned());
        let response = if utils::is_refund_failure(refund_status) {
            Err(ErrorResponse {
                status_code: item.http_code,
                code: response.result_code.to_string(),
                message: response.class_description.clone(),
                reason: Some(response.message.clone()),
                attempt_status: None,
                connector_transaction_id: Some(response.result.transaction.id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            Ok(RefundsResponseData {
                connector_refund_id: item.response.result.transaction.id,
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

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonRefundResponseTransactions {
    id: String,
    status: RefundStatus,
    transaction_reference: Option<String>,
}

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonRefundSyncResponseResult {
    transactions: Vec<NoonRefundResponseTransactions>,
}

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefundSyncResponse {
    result: NoonRefundSyncResponseResult,
    result_code: u32,
    class_description: String,
    message: String,
}

impl<F> TryFrom<ResponseRouterData<RefundSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: ResponseRouterData<RefundSyncResponse, Self>) -> Result<Self, Self::Error> {
        let noon_transaction: &NoonRefundResponseTransactions = item
            .response
            .result
            .transactions
            .iter()
            .find(|transaction| transaction.transaction_reference.is_some())
            .ok_or(errors::ConnectorError::ResponseHandlingFailed)?;

        let refund_status = enums::RefundStatus::from(noon_transaction.status.to_owned());
        let response = if utils::is_refund_failure(refund_status) {
            let response = &item.response;
            Err(ErrorResponse {
                status_code: item.http_code,
                code: response.result_code.to_string(),
                message: response.class_description.clone(),
                reason: Some(response.message.clone()),
                attempt_status: None,
                connector_transaction_id: Some(noon_transaction.id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            Ok(RefundsResponseData {
                connector_refund_id: noon_transaction.id.to_owned(),
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

#[derive(Debug, Deserialize, strum::Display)]
pub enum NoonWebhookEventTypes {
    Authenticate,
    Authorize,
    Capture,
    Fail,
    Refund,
    Sale,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonWebhookBody {
    pub order_id: u64,
    pub order_status: NoonPaymentStatus,
    pub event_type: NoonWebhookEventTypes,
    pub event_id: String,
    pub time_stamp: String,
}

#[derive(Debug, Deserialize)]
pub struct NoonWebhookSignature {
    pub signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonWebhookOrderId {
    pub order_id: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonWebhookEvent {
    pub order_status: NoonPaymentStatus,
    pub event_type: NoonWebhookEventTypes,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonWebhookObject {
    pub order_status: NoonPaymentStatus,
    pub order_id: u64,
}

/// This from will ensure that webhook body would be properly parsed into PSync response
impl From<NoonWebhookObject> for NoonPaymentsResponse {
    fn from(value: NoonWebhookObject) -> Self {
        Self {
            result: NoonPaymentsResponseResult {
                order: NoonPaymentsOrderResponse {
                    status: value.order_status,
                    id: value.order_id,
                    //For successful payments Noon Always populates error_code as 0.
                    error_code: 0,
                    error_message: None,
                    reference: None,
                },
                checkout_data: None,
                subscription: None,
            },
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoonErrorResponse {
    pub result_code: u32,
    pub message: String,
    pub class_description: String,
}

#[derive(Debug, Serialize)]
pub struct SetupMandateRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>(NoonPaymentsRequest<T>);

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        NoonRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for SetupMandateRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        data: NoonRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &data.router_data;
        let amount = data.connector.amount_converter.convert(
            common_utils::types::MinorUnit::new(1),
            data.router_data.request.currency,
        );
        let mandate_amount = &data.router_data.request.setup_mandate_details;

        let (payment_data, currency, category) = match &item.request.mandate_id {
            Some(mandate_ids) => match &mandate_ids.mandate_reference_id {
                Some(MandateReferenceId::ConnectorMandateId(connector_mandate_ids)) => {
                    if let Some(mandate_id) = connector_mandate_ids.get_connector_mandate_id() {
                        (
                            NoonPaymentData::Subscription(NoonSubscription {
                                subscription_identifier: Secret::new(mandate_id),
                            }),
                            None,
                            None,
                        )
                    } else {
                        return Err(errors::ConnectorError::MissingRequiredField {
                            field_name: "connector_mandate_id",
                        }
                        .into());
                    }
                }
                _ => {
                    return Err(errors::ConnectorError::MissingRequiredField {
                        field_name: "connector_mandate_id",
                    }
                    .into());
                }
            },
            None => (
                match item.request.payment_method_data.clone() {
                    PaymentMethodData::Card(req_card) => Ok(NoonPaymentData::Card(NoonCard {
                        name_on_card: item.resource_common_data.get_optional_billing_full_name(),
                        number_plain: req_card.card_number.clone(),
                        expiry_month: req_card.card_exp_month.clone(),
                        expiry_year: req_card.card_exp_year.clone(),
                        cvv: req_card.card_cvc,
                    })),
                    PaymentMethodData::Wallet(wallet_data) => match wallet_data.clone() {
                        WalletData::GooglePay(google_pay_data) => {
                            Ok(NoonPaymentData::GooglePay(NoonGooglePay {
                                api_version_minor: GOOGLEPAY_API_VERSION_MINOR,
                                api_version: GOOGLEPAY_API_VERSION,
                                payment_method_data: google_pay_data,
                            }))
                        }
                        WalletData::ApplePay(apple_pay_data) => {
                            let payment_token_data = NoonApplePayTokenData {
                                token: NoonApplePayData {
                                    payment_data: wallet_data
                                        .get_wallet_token_as_json("Apple Pay".to_string())?,
                                    payment_method: NoonApplePayPaymentMethod {
                                        display_name: apple_pay_data.payment_method.display_name,
                                        network: apple_pay_data.payment_method.network,
                                        pm_type: apple_pay_data.payment_method.pm_type,
                                    },
                                    transaction_identifier: Secret::new(
                                        apple_pay_data.transaction_identifier,
                                    ),
                                },
                            };
                            let payment_token = payment_token_data
                                .encode_to_string_of_json()
                                .change_context(errors::ConnectorError::RequestEncodingFailed)?;

                            Ok(NoonPaymentData::ApplePay(NoonApplePay {
                                payment_info: Secret::new(payment_token),
                            }))
                        }
                        WalletData::PaypalRedirect(_) => Ok(NoonPaymentData::PayPal(NoonPayPal {
                            return_url: item.request.get_router_return_url()?,
                        })),
                        WalletData::AliPayQr(_)
                        | WalletData::AliPayRedirect(_)
                        | WalletData::AliPayHkRedirect(_)
                        | WalletData::AmazonPayRedirect(_)
                        | WalletData::MomoRedirect(_)
                        | WalletData::KakaoPayRedirect(_)
                        | WalletData::GoPayRedirect(_)
                        | WalletData::GcashRedirect(_)
                        | WalletData::ApplePayRedirect(_)
                        | WalletData::ApplePayThirdPartySdk(_)
                        | WalletData::DanaRedirect {}
                        | WalletData::GooglePayRedirect(_)
                        | WalletData::GooglePayThirdPartySdk(_)
                        | WalletData::MbWayRedirect(_)
                        | WalletData::MobilePayRedirect(_)
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
                        | WalletData::BluecodeRedirect { .. }
                        | WalletData::Mifinity(_)
                        | WalletData::RevolutPay(_) => Err(errors::ConnectorError::NotImplemented(
                            utils::get_unimplemented_payment_method_error_message("Noon"),
                        )),
                    },
                    PaymentMethodData::CardRedirect(_)
                    | PaymentMethodData::PayLater(_)
                    | PaymentMethodData::BankRedirect(_)
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
                        Err(errors::ConnectorError::NotImplemented(
                            utils::get_unimplemented_payment_method_error_message("Noon"),
                        ))
                    }
                }?,
                Some(item.request.currency),
                // Get order_category from metadata field, return error if not provided
                Some(
                    item.request
                        .metadata
                        .as_ref()
                        .and_then(|metadata| metadata.get("order_category"))
                        .and_then(|value| value.as_str())
                        .map(|s| s.to_string())
                        .ok_or(errors::ConnectorError::MissingRequiredField {
                            field_name: "order_category in metadata",
                        })?,
                ),
            ),
        };

        let ip_address = item.request.browser_info.as_ref().and_then(|browser_info| {
            browser_info
                .ip_address
                .map(|ip| Secret::new(ip.to_string()))
        });

        let channel = NoonChannels::Web;

        let billing = item
            .resource_common_data
            .get_optional_billing()
            .and_then(|billing_address| billing_address.address.as_ref())
            .map(|address| NoonBilling {
                address: NoonBillingAddress {
                    street: address.line1.clone(),
                    street2: address.line2.clone(),
                    city: address.city.clone(),
                    state_province: address.state.clone(),
                    country: address.country,
                    postal_code: address.zip.clone(),
                },
            });

        // The description should not have leading or trailing whitespaces, also it should not have double whitespaces and a max 50 chars according to Noon's Docs
        let name: String = item
            .resource_common_data
            .get_description()?
            .trim()
            .replace("  ", " ")
            .chars()
            .take(50)
            .collect();

        let subscription = mandate_amount.as_ref().and_then(|mandate_data| {
            mandate_data.mandate_type.as_ref().and_then(|mandate_type| {
                let mandate_amount_data = match mandate_type {
                    MandateDataType::SingleUse(amount_data) => Some(amount_data),
                    MandateDataType::MultiUse(amount_data_opt) => amount_data_opt.as_ref(),
                };
                mandate_amount_data.and_then(|amount_data| {
                    data.connector
                        .amount_converter
                        .convert(amount_data.amount, amount_data.currency)
                        .ok()
                        .map(|max_amount| NoonSubscriptionData {
                            subscription_type: NoonSubscriptionType::Unscheduled,
                            name: name.clone(),
                            max_amount,
                        })
                })
            })
        });

        let tokenize_c_c = subscription.is_some().then_some(true);

        let order = NoonOrder {
            amount: amount.change_context(ConnectorError::ParsingFailed)?,
            currency,
            channel,
            category,
            reference: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            name,
            nvp: item.request.metadata.as_ref().map(NoonOrderNvp::new),
            ip_address,
        };
        let payment_action = match item.request.capture_method {
            Some(common_enums::CaptureMethod::Automatic)
            | None
            | Some(common_enums::CaptureMethod::SequentialAutomatic) => NoonPaymentActions::Sale,
            Some(common_enums::CaptureMethod::Manual) => NoonPaymentActions::Authorize,
            Some(_) => NoonPaymentActions::Authorize,
        };
        Ok(SetupMandateRequest(NoonPaymentsRequest {
            api_operation: NoonApiOperations::Initiate,
            order,
            billing,
            configuration: NoonConfiguration {
                payment_action,
                return_url: item.request.router_return_url.clone(),
                tokenize_c_c,
            },
            payment_data,
            subscription,
        }))
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupMandateResponse {
    pub result_code: u32,
    pub message: String,
    pub result_class: Option<u32>,
    pub class_description: Option<String>,
    pub action_hint: Option<String>,
    pub request_reference: Option<String>,
    pub result: NoonPaymentsResponseResult,
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<SetupMandateResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<SetupMandateResponse, Self>) -> Result<Self, Self::Error> {
        let order = item.response.result.order;
        let current_attempt_status = item.router_data.resource_common_data.status;
        let status = get_payment_status((order.status, current_attempt_status));
        let redirection_data = item.response.result.checkout_data.map(|redirection_data| {
            Box::new(RedirectForm::Form {
                endpoint: redirection_data.post_url.to_string(),
                method: Method::Post,
                form_fields: std::collections::HashMap::new(),
            })
        });
        let mandate_reference = item.response.result.subscription.map(|subscription_data| {
            Box::new(MandateReference {
                connector_mandate_id: Some(subscription_data.identifier.expose()),
                payment_method_id: None,
            })
        });
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: match order.error_message {
                Some(error_message) => Err(ErrorResponse {
                    code: order.error_code.to_string(),
                    message: error_message.clone(),
                    reason: Some(error_message),
                    status_code: item.http_code,
                    attempt_status: Some(status),
                    connector_transaction_id: Some(order.id.to_string()),
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
                _ => {
                    let connector_response_reference_id =
                        order.reference.or(Some(order.id.to_string()));
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(order.id.to_string()),
                        redirection_data,
                        mandate_reference,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id,
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    })
                }
            },
            ..item.router_data
        })
    }
}
