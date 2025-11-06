use base64::{engine::general_purpose::STANDARD, Engine};
use common_enums::{self, AttemptStatus, RefundStatus};
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::CustomResult,
    ext_traits::{ByteSliceExt, OptionExt},
    request::Method,
    types::MinorUnit,
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, DefendDispute, PSync, Refund, SetupMandate, SubmitEvidence,
        Void,
    },
    connector_types::{
        AcceptDisputeData, DisputeDefendData, DisputeFlowData, DisputeResponseData, EventType,
        MandateReference, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData,
        RefundsResponseData, ResponseId, SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::{
        Card, PaymentMethodData, PaymentMethodDataTypes, RawCardNumber, WalletData,
    },
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::{Report, ResultExt};
# use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use url::Url;

use super::AdyenRouterData;
use crate::types::ResponseRouterData;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub enum Currency {
    #[default]
    USD,
    EUR,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Amount {
    pub currency: common_enums::Currency,
    pub value: MinorUnit,
}

type Error = error_stack::Report<domain_types::errors::ConnectorError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CardBrand {
    Visa,
}

#[derive(Debug, Serialize, PartialEq)]
pub enum ConnectorError {
    ParsingFailed,
    NotImplemented,
    FailedToObtainAuthType,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenCard<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    number: RawCardNumber<T>,
    expiry_month: Secret<String>,
    expiry_year: Secret<String>,
    cvc: Option<Secret<String>>,
    holder_name: Option<Secret<String>>,
    brand: Option<CardBrand>, //Mandatory for mandate using network_txns_id
    network_payment_reference: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
pub enum AdyenPaymentMethod<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    #[serde(rename = "scheme")]
    AdyenCard(Box<AdyenCard<T>>),
    #[serde(rename = "googlepay")]
    Gpay(Box<AdyenGPay>),
    ApplePay(Box<AdyenApplePay>),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdyenBrowserInfo {
    user_agent: String,
    accept_header: String,
    language: String,
    color_depth: u8,
    screen_height: u32,
    screen_width: u32,
    time_zone_offset: i32,
    java_enabled: bool,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub enum AuthType {
    #[default]
    PreAuth,
}

#[serde_with::skip_serializing_none]
#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    city: String,
    country: common_enums::CountryAlpha2,
    house_number_or_name: Secret<String>,
    postal_code: Secret<String>,
    state_or_province: Option<Secret<String>>,
    street: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum PaymentMethod<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    AdyenPaymentMethod(Box<AdyenPaymentMethod<T>>),
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdyenMpiData {
    directory_response: String,
    authentication_response: String,
    token_authentication_verification_value: Secret<String>,
    eci: Option<String>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub enum AdyenShopperInteraction {
    #[default]
    Ecommerce,
    #[serde(rename = "ContAuth")]
    ContinuedAuthentication,
    Moto,
    #[serde(rename = "POS")]
    Pos,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    From<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for AdyenShopperInteraction
{
    fn from(
        item: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> Self {
        match item.request.off_session {
            Some(true) => Self::ContinuedAuthentication,
            _ => Self::Ecommerce,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AdyenRecurringModel {
    UnscheduledCardOnFile,
    CardOnFile,
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdditionalData {
    authorisation_type: Option<AuthType>,
    manual_capture: Option<String>,
    execute_three_d: Option<String>,
    pub recurring_processing_model: Option<AdyenRecurringModel>,
    /// Enable recurring details in dashboard to receive this ID, https://docs.adyen.com/online-payments/tokenization/create-and-use-tokens#test-and-go-live
    #[serde(rename = "recurring.recurringDetailReference")]
    recurring_detail_reference: Option<Secret<String>>,
    #[serde(rename = "recurring.shopperReference")]
    recurring_shopper_reference: Option<String>,
    network_tx_reference: Option<Secret<String>>,
    funds_availability: Option<String>,
    refusal_reason_raw: Option<String>,
    refusal_code_raw: Option<String>,
    merchant_advice_code: Option<String>,
    #[serde(flatten)]
    riskdata: Option<RiskData>,
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskData {
    #[serde(rename = "riskdata.basket.item1.itemID")]
    item_i_d: Option<String>,
    #[serde(rename = "riskdata.basket.item1.productTitle")]
    product_title: Option<String>,
    #[serde(rename = "riskdata.basket.item1.amountPerItem")]
    amount_per_item: Option<String>,
    #[serde(rename = "riskdata.basket.item1.currency")]
    currency: Option<String>,
    #[serde(rename = "riskdata.basket.item1.upc")]
    upc: Option<String>,
    #[serde(rename = "riskdata.basket.item1.brand")]
    brand: Option<String>,
    #[serde(rename = "riskdata.basket.item1.manufacturer")]
    manufacturer: Option<String>,
    #[serde(rename = "riskdata.basket.item1.category")]
    category: Option<String>,
    #[serde(rename = "riskdata.basket.item1.quantity")]
    quantity: Option<String>,
    #[serde(rename = "riskdata.basket.item1.color")]
    color: Option<String>,
    #[serde(rename = "riskdata.basket.item1.size")]
    size: Option<String>,
    #[serde(rename = "riskdata.deviceCountry")]
    device_country: Option<String>,
    #[serde(rename = "riskdata.houseNumberorName")]
    house_numberor_name: Option<String>,
    #[serde(rename = "riskdata.accountCreationDate")]
    account_creation_date: Option<String>,
    #[serde(rename = "riskdata.affiliateChannel")]
    affiliate_channel: Option<String>,
    #[serde(rename = "riskdata.avgOrderValue")]
    avg_order_value: Option<String>,
    #[serde(rename = "riskdata.deliveryMethod")]
    delivery_method: Option<String>,
    #[serde(rename = "riskdata.emailName")]
    email_name: Option<String>,
    #[serde(rename = "riskdata.emailDomain")]
    email_domain: Option<String>,
    #[serde(rename = "riskdata.lastOrderDate")]
    last_order_date: Option<String>,
    #[serde(rename = "riskdata.merchantReference")]
    merchant_reference: Option<String>,
    #[serde(rename = "riskdata.paymentMethod")]
    payment_method: Option<String>,
    #[serde(rename = "riskdata.promotionName")]
    promotion_name: Option<String>,
    #[serde(rename = "riskdata.secondaryPhoneNumber")]
    secondary_phone_number: Option<String>,
    #[serde(rename = "riskdata.timefromLogintoOrder")]
    timefrom_loginto_order: Option<String>,
    #[serde(rename = "riskdata.totalSessionTime")]
    total_session_time: Option<String>,
    #[serde(rename = "riskdata.totalAuthorizedAmountInLast30Days")]
    total_authorized_amount_in_last30_days: Option<String>,
    #[serde(rename = "riskdata.totalOrderQuantity")]
    total_order_quantity: Option<String>,
    #[serde(rename = "riskdata.totalLifetimeValue")]
    total_lifetime_value: Option<String>,
    #[serde(rename = "riskdata.visitsMonth")]
    visits_month: Option<String>,
    #[serde(rename = "riskdata.visitsWeek")]
    visits_week: Option<String>,
    #[serde(rename = "riskdata.visitsYear")]
    visits_year: Option<String>,
    #[serde(rename = "riskdata.shipToName")]
    ship_to_name: Option<String>,
    #[serde(rename = "riskdata.first8charactersofAddressLine1Zip")]
    first8charactersof_address_line1_zip: Option<String>,
    #[serde(rename = "riskdata.affiliateOrder")]
    affiliate_order: Option<bool>,
}

#[serde_with::skip_serializing_none]
#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShopperName {
    first_name: Option<Secret<String>>,
    last_name: Option<Secret<String>>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LineItem {
    amount_excluding_tax: Option<MinorUnit>,
    amount_including_tax: Option<MinorUnit>,
    description: Option<String>,
    id: Option<String>,
    tax_amount: Option<MinorUnit>,
    quantity: Option<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub enum Channel {
    Web,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdyenSplitData {
    amount: Option<Amount>,
    #[serde(rename = "type")]
    split_type: AdyenSplitType,
    account: Option<String>,
    reference: String,
    description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdyenGPay {
    #[serde(rename = "googlePayToken")]
    google_pay_token: Secret<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdyenApplePay {
    #[serde(rename = "applePayToken")]
    apple_pay_token: Secret<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PaymentType {
    Affirm,
    Afterpaytouch,
    Alipay,
    #[serde(rename = "alipay_hk")]
    AlipayHk,
    #[serde(rename = "doku_alfamart")]
    Alfamart,
    Alma,
    Applepay,
    Bizum,
    Atome,
    Blik,
    #[serde(rename = "boletobancario")]
    BoletoBancario,
    ClearPay,
    Dana,
    Eps,
    Gcash,
    Googlepay,
    #[serde(rename = "gopay_wallet")]
    GoPay,
    Ideal,
    #[serde(rename = "doku_indomaret")]
    Indomaret,
    Klarna,
    Kakaopay,
    Mbway,
    MobilePay,
    #[serde(rename = "momo_wallet")]
    Momo,
    #[serde(rename = "momo_atm")]
    MomoAtm,
    #[serde(rename = "onlineBanking_CZ")]
    OnlineBankingCzechRepublic,
    #[serde(rename = "ebanking_FI")]
    OnlineBankingFinland,
    #[serde(rename = "onlineBanking_PL")]
    OnlineBankingPoland,
    #[serde(rename = "onlineBanking_SK")]
    OnlineBankingSlovakia,
    #[serde(rename = "molpay_ebanking_fpx_MY")]
    OnlineBankingFpx,
    #[serde(rename = "molpay_ebanking_TH")]
    OnlineBankingThailand,
    #[serde(rename = "paybybank")]
    OpenBankingUK,
    #[serde(rename = "oxxo")]
    Oxxo,
    #[serde(rename = "paysafecard")]
    PaySafeCard,
    PayBright,
    Paypal,
    Scheme,
    #[serde(rename = "networkToken")]
    NetworkToken,
    #[serde(rename = "trustly")]
    Trustly,
    #[serde(rename = "touchngo")]
    TouchNGo,
    Walley,
    #[serde(rename = "wechatpayWeb")]
    WeChatPayWeb,
    #[serde(rename = "ach")]
    AchDirectDebit,
    SepaDirectDebit,
    #[serde(rename = "directdebit_GB")]
    BacsDirectDebit,
    Samsungpay,
    Twint,
    Vipps,
    Giftcard,
    Knet,
    Benefit,
    Swish,
    #[serde(rename = "doku_permata_lite_atm")]
    PermataBankTransfer,
    #[serde(rename = "doku_bca_va")]
    BcaBankTransfer,
    #[serde(rename = "doku_bni_va")]
    BniVa,
    #[serde(rename = "doku_bri_va")]
    BriVa,
    #[serde(rename = "doku_cimb_va")]
    CimbVa,
    #[serde(rename = "doku_danamon_va")]
    DanamonVa,
    #[serde(rename = "doku_mandiri_va")]
    MandiriVa,
    #[serde(rename = "econtext_seven_eleven")]
    SevenEleven,
    #[serde(rename = "econtext_stores")]
    Lawson,
}

#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::EnumString,
)]
#[strum(serialize_all = "PascalCase")]
#[serde(rename_all = "PascalCase")]
pub enum AdyenSplitType {
    /// Books split amount to the specified account.
    BalanceAccount,
    /// The aggregated amount of the interchange and scheme fees.
    AcquiringFees,
    /// The aggregated amount of all transaction fees.
    PaymentFee,
    /// The aggregated amount of Adyen's commission and markup fees.
    AdyenFees,
    ///  The transaction fees due to Adyen under blended rates.
    AdyenCommission,
    /// The transaction fees due to Adyen under Interchange ++ pricing.
    AdyenMarkup,
    ///  The fees paid to the issuer for each payment made with the card network.
    Interchange,
    ///  The fees paid to the card scheme for using their network.
    SchemeFee,
    /// Your platform's commission on the payment (specified in amount), booked to your liable balance account.
    Commission,
    /// Allows you and your users to top up balance accounts using direct debit, card payments, or other payment methods.
    TopUp,
    /// The value-added tax charged on the payment, booked to your platforms liable balance account.
    Vat,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenPaymentRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    amount: Amount,
    merchant_account: Secret<String>,
    payment_method: PaymentMethod<T>,
    mpi_data: Option<AdyenMpiData>,
    reference: String,
    return_url: String,
    browser_info: Option<AdyenBrowserInfo>,
    shopper_interaction: AdyenShopperInteraction,
    recurring_processing_model: Option<AdyenRecurringModel>,
    additional_data: Option<AdditionalData>,
    shopper_reference: Option<String>,
    store_payment_method: Option<bool>,
    shopper_name: Option<ShopperName>,
    #[serde(rename = "shopperIP")]
    shopper_ip: Option<Secret<String, common_utils::pii::IpAddress>>,
    shopper_locale: Option<String>,
    shopper_email: Option<common_utils::pii::Email>,
    shopper_statement: Option<String>,
    social_security_number: Option<Secret<String>>,
    telephone_number: Option<Secret<String>>,
    billing_address: Option<Address>,
    delivery_address: Option<Address>,
    country_code: Option<common_enums::CountryAlpha2>,
    line_items: Option<Vec<LineItem>>,
    channel: Option<Channel>,
    merchant_order_reference: Option<String>,
    splits: Option<Vec<AdyenSplitData>>,
    store: Option<String>,
    device_fingerprint: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct SetupMandateRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>(AdyenPaymentRequest<T>);

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenVoidRequest {
    merchant_account: Secret<String>,
    reference: String,
}

#[derive(Debug, Serialize)]
pub struct AdyenRouterData1<T> {
    pub amount: MinorUnit,
    pub router_data: T,
}

impl<T> TryFrom<(MinorUnit, T)> for AdyenRouterData1<T> {
    type Error = domain_types::errors::ConnectorError;
    fn try_from((amount, item): (MinorUnit, T)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data: item,
        })
    }
}

fn get_amount_data<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>(
    item: &AdyenRouterData<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        T,
    >,
) -> Amount {
    Amount {
        currency: item.router_data.request.currency,
        value: item.router_data.request.minor_amount.to_owned(),
    }
}

pub struct AdyenAuthType {
    pub(super) api_key: Secret<String>,
    pub(super) merchant_account: Secret<String>,
    #[allow(dead_code)]
    pub(super) review_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for AdyenAuthType {
    type Error = domain_types::errors::ConnectorError;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                api_key: api_key.to_owned(),
                merchant_account: key1.to_owned(),
                review_key: None,
            }),
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                api_key: api_key.to_owned(),
                merchant_account: key1.to_owned(),
                review_key: Some(api_secret.to_owned()),
            }),
            _ => Err(domain_types::errors::ConnectorError::FailedToObtainAuthType),
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
    > TryFrom<(&Card<T>, Option<String>)> for AdyenPaymentMethod<T>
{
    type Error = domain_types::errors::ConnectorError;
    fn try_from((card, card_holder_name): (&Card<T>, Option<String>)) -> Result<Self, Self::Error> {
        let adyen_card = AdyenCard {
            number: card.card_number.clone(),
            expiry_month: card.card_exp_month.clone(),
            expiry_year: card.card_exp_year.clone(),
            cvc: Some(card.card_cvc.clone()),
            holder_name: card_holder_name.map(Secret::new),
            brand: Some(CardBrand::Visa),
            network_payment_reference: None,
        };
        Ok(AdyenPaymentMethod::AdyenCard(Box::new(adyen_card)))
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
    TryFrom<(
        &WalletData,
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    )> for AdyenPaymentMethod<T>
{
    type Error = Error;
    fn try_from(
        value: (
            &WalletData,
            &RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        ),
    ) -> Result<Self, Self::Error> {
        let (wallet_data, _item) = value;
        match wallet_data {
            WalletData::GooglePay(data) => {
                let gpay_data = AdyenGPay {
                    google_pay_token: Secret::new(
                        data.tokenization_data
                            .get_encrypted_google_pay_token()
                            .change_context(errors::ConnectorError::MissingRequiredField {
                                field_name: "gpay wallet_token",
                            })?
                            .to_owned(),
                    ),
                };
                Ok(AdyenPaymentMethod::Gpay(Box::new(gpay_data)))
            }
            WalletData::ApplePay(data) => {
                let apple_pay_encrypted_data = data
                    .payment_data
                    .get_encrypted_apple_pay_payment_data_mandatory()
                    .change_context(errors::ConnectorError::MissingRequiredField {
                        field_name: "Apple pay encrypted data",
                    })?;
                let apple_pay_data = AdyenApplePay {
                    apple_pay_token: Secret::new(apple_pay_encrypted_data.to_string()),
                };
                Ok(AdyenPaymentMethod::ApplePay(Box::new(apple_pay_data)))
            }

            WalletData::PaypalRedirect(_)
            | WalletData::AmazonPayRedirect(_)
            | WalletData::Paze(_)
            | WalletData::RevolutPay(_)
            | WalletData::AliPayRedirect(_)
            | WalletData::AliPayHkRedirect(_)
            | WalletData::GoPayRedirect(_)
            | WalletData::KakaoPayRedirect(_)
            | WalletData::GcashRedirect(_)
            | WalletData::MomoRedirect(_)
            | WalletData::TouchNGoRedirect(_)
            | WalletData::MbWayRedirect(_)
            | WalletData::MobilePayRedirect(_)
            | WalletData::WeChatPayRedirect(_)
            | WalletData::SamsungPay(_)
            | WalletData::TwintRedirect { .. }
            | WalletData::VippsRedirect { .. }
            | WalletData::DanaRedirect { .. }
            | WalletData::SwishQr(_)
            | WalletData::AliPayQr(_)
            | WalletData::ApplePayRedirect(_)
            | WalletData::ApplePayThirdPartySdk(_)
            | WalletData::GooglePayRedirect(_)
            | WalletData::GooglePayThirdPartySdk(_)
            | WalletData::PaypalSdk(_)
            | WalletData::WeChatPayQr(_)
            | WalletData::CashappQr(_)
            | WalletData::Mifinity(_)
            | WalletData::BluecodeRedirect { .. } => Err(errors::ConnectorError::NotImplemented(
                "payment_method".into(),
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
    TryFrom<(
        AdyenRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        &Card<T>,
    )> for AdyenPaymentRequest<T>
{
    type Error = Error;
    fn try_from(
        value: (
            AdyenRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            &Card<T>,
        ),
    ) -> Result<Self, Self::Error> {
        let (item, card_data) = value;
        let amount = get_amount_data(&item);
        let auth_type = AdyenAuthType::try_from(&item.router_data.connector_auth_type)?;
        let shopper_interaction = AdyenShopperInteraction::from(&item.router_data);
        let shopper_reference = build_shopper_reference(
            &item.router_data.request.customer_id.clone(),
            item.router_data.resource_common_data.merchant_id.clone(),
        );
        let (recurring_processing_model, store_payment_method, _) =
            get_recurring_processing_model(&item.router_data)?;

        let return_url = item.router_data.request.get_router_return_url()?;

        let billing_address = get_address_info(
            item.router_data
                .resource_common_data
                .address
                .get_payment_billing(),
        )
        .and_then(Result::ok);

        let card_holder_name = item.router_data.request.customer_name.clone();

        let additional_data = get_additional_data(&item.router_data);

        let payment_method = PaymentMethod::AdyenPaymentMethod(Box::new(
            AdyenPaymentMethod::try_from((card_data, card_holder_name))?,
        ));

        Ok(AdyenPaymentRequest {
            amount,
            merchant_account: auth_type.merchant_account,
            payment_method,
            reference: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            return_url,
            shopper_interaction,
            recurring_processing_model,
            browser_info: None,
            additional_data,
            mpi_data: None,
            telephone_number: None,
            shopper_name: None,
            shopper_email: None,
            shopper_locale: None,
            social_security_number: None,
            billing_address,
            delivery_address: None,
            country_code: None,
            line_items: None,
            shopper_reference,
            store_payment_method,
            channel: None,
            shopper_statement: item.router_data.request.statement_descriptor.clone(),
            shopper_ip: None,
            merchant_order_reference: item.router_data.request.merchant_order_reference_id.clone(),
            store: None,
            splits: None,
            device_fingerprint: None,
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
    TryFrom<(
        AdyenRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        &WalletData,
    )> for AdyenPaymentRequest<T>
{
    type Error = Error;
    fn try_from(
        value: (
            AdyenRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            &WalletData,
        ),
    ) -> Result<Self, Self::Error> {
        let (item, wallet_data) = value;
        let amount = get_amount_data(&item);
        let auth_type = AdyenAuthType::try_from(&item.router_data.connector_auth_type)?;
        let payment_method = PaymentMethod::AdyenPaymentMethod(Box::new(
            AdyenPaymentMethod::try_from((wallet_data, &item.router_data))?,
        ));
        let shopper_interaction = AdyenShopperInteraction::from(&item.router_data);
        let (recurring_processing_model, store_payment_method, shopper_reference) =
            get_recurring_processing_model(&item.router_data)?;
        let return_url = item.router_data.request.get_router_return_url()?;
        let additional_data = get_additional_data(&item.router_data);

        Ok(AdyenPaymentRequest {
            amount,
            merchant_account: auth_type.merchant_account,
            payment_method,
            reference: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            return_url,
            shopper_interaction,
            recurring_processing_model,
            browser_info: None,
            additional_data,
            mpi_data: None,
            telephone_number: None,
            shopper_name: None,
            shopper_email: None,
            shopper_locale: None,
            social_security_number: None,
            billing_address: None,
            delivery_address: None,
            country_code: None,
            line_items: None,
            shopper_reference,
            store_payment_method,
            channel: None,
            shopper_statement: item.router_data.request.statement_descriptor.clone(),
            shopper_ip: None,
            merchant_order_reference: item.router_data.request.merchant_order_reference_id.clone(),
            store: None,
            splits: None,
            device_fingerprint: None,
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
        AdyenRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for AdyenPaymentRequest<T>
{
    type Error = Error;
    fn try_from(
        item: AdyenRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        match item
            .router_data
            .request
            .mandate_id
            .to_owned()
            .and_then(|mandate_ids| mandate_ids.mandate_reference_id)
        {
            Some(_mandate_ref) => Err(domain_types::errors::ConnectorError::NotImplemented(
                "payment_method".into(),
            ))?,
            None => match item.router_data.request.payment_method_data.clone() {
                PaymentMethodData::Card(ref card) => AdyenPaymentRequest::try_from((item, card)),
                PaymentMethodData::Wallet(ref wallet_data) => {
                    AdyenPaymentRequest::try_from((item, wallet_data))
                }
                PaymentMethodData::PayLater(_)
                | PaymentMethodData::BankRedirect(_)
                | PaymentMethodData::BankDebit(_)
                | PaymentMethodData::BankTransfer(_)
                | PaymentMethodData::CardRedirect(_)
                | PaymentMethodData::Voucher(_)
                | PaymentMethodData::GiftCard(_)
                | PaymentMethodData::Crypto(_)
                | PaymentMethodData::MandatePayment
                | PaymentMethodData::Reward
                | PaymentMethodData::RealTimePayment(_)
                | PaymentMethodData::Upi(_)
                | PaymentMethodData::OpenBanking(_)
                | PaymentMethodData::CardDetailsForNetworkTransactionId(_)
                | PaymentMethodData::NetworkToken(_)
                | PaymentMethodData::MobilePayment(_)
                | PaymentMethodData::CardToken(_) => Err(
                    domain_types::errors::ConnectorError::NotImplemented("payment method".into()),
                )?,
            },
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
        AdyenRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for AdyenRedirectRequest
{
    type Error = Error;
    fn try_from(
        item: AdyenRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let encoded_data = item
            .router_data
            .request
            .encoded_data
            .clone()
            .get_required_value("encoded_data")
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let adyen_redirection_type =
            serde_urlencoded::from_str::<AdyenRedirectRequestTypes>(encoded_data.as_str())
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let adyen_redirect_request = match adyen_redirection_type {
            AdyenRedirectRequestTypes::AdyenRedirection(req) => AdyenRedirectRequest {
                details: AdyenRedirectRequestTypes::AdyenRedirection(AdyenRedirection {
                    redirect_result: req.redirect_result,
                    type_of_redirection_result: None,
                    result_code: None,
                }),
            },
            AdyenRedirectRequestTypes::AdyenThreeDS(req) => AdyenRedirectRequest {
                details: AdyenRedirectRequestTypes::AdyenThreeDS(AdyenThreeDS {
                    three_ds_result: req.three_ds_result,
                    type_of_redirection_result: None,
                    result_code: None,
                }),
            },
            AdyenRedirectRequestTypes::AdyenRefusal(req) => AdyenRedirectRequest {
                details: AdyenRedirectRequestTypes::AdyenRefusal(AdyenRefusal {
                    payload: req.payload,
                    type_of_redirection_result: None,
                    result_code: None,
                }),
            },
        };
        Ok(adyen_redirect_request)
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
        AdyenRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for AdyenVoidRequest
{
    type Error = Error;
    fn try_from(
        item: AdyenRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth_type = AdyenAuthType::try_from(&item.router_data.connector_auth_type)?;
        Ok(Self {
            merchant_account: auth_type.merchant_account,
            reference: item.router_data.request.connector_transaction_id.clone(),
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AdyenPaymentResponse {
    Response(Box<AdyenResponse>),
    RedirectionResponse(Box<RedirectionResponse>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdyenPSyncResponse(AdyenPaymentResponse);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SetupMandateResponse(AdyenPaymentResponse);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenResponse {
    psp_reference: String,
    result_code: AdyenStatus,
    amount: Option<Amount>,
    merchant_reference: String,
    refusal_reason: Option<String>,
    refusal_reason_code: Option<String>,
    additional_data: Option<AdditionalData>,
    splits: Option<Vec<AdyenSplitData>>,
    store: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenVoidResponse {
    payment_psp_reference: String,
    status: AdyenVoidStatus,
    reference: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectionResponse {
    result_code: AdyenStatus,
    action: AdyenRedirectAction,
    refusal_reason: Option<String>,
    refusal_reason_code: Option<String>,
    psp_reference: Option<String>,
    merchant_reference: Option<String>,
    store: Option<String>,
    splits: Option<Vec<AdyenSplitData>>,
    additional_data: Option<AdditionalData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenRedirectAction {
    payment_method_type: PaymentType,
    url: Option<Url>,
    method: Option<common_utils::request::Method>,
    #[serde(rename = "type")]
    type_of_response: ActionType,
    data: Option<std::collections::HashMap<String, String>>,
    payment_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionType {
    Redirect,
    Await,
    #[serde(rename = "qrCode")]
    QrCode,
    Voucher,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdyenStatus {
    AuthenticationFinished,
    AuthenticationNotRequired,
    Authorised,
    Cancelled,
    ChallengeShopper,
    Error,
    Pending,
    Received,
    RedirectShopper,
    Refused,
    PresentToShopper,
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMethod {
    /// Post the payment authorization, the capture will be executed on the full amount immediately
    #[default]
    Automatic,
    /// The capture will happen only if the merchant triggers a Capture API request
    Manual,
    /// The capture will happen only if the merchant triggers a Capture API request
    ManualMultiple,
    /// The capture can be scheduled to automatically get triggered at a specific date & time
    Scheduled,
    /// Handles separate auth and capture sequentially; same as `Automatic` for most connectors.
    SequentialAutomatic,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentMethodType {
    Credit,
}

pub trait ForeignTryFrom<F>: Sized {
    type Error;

    fn foreign_try_from(from: F) -> Result<Self, Self::Error>;
}

fn get_adyen_payment_status(
    is_manual_capture: bool,
    adyen_status: AdyenStatus,
    _pmt: Option<common_enums::PaymentMethodType>,
) -> AttemptStatus {
    match adyen_status {
        AdyenStatus::AuthenticationFinished => AttemptStatus::AuthenticationSuccessful,
        AdyenStatus::AuthenticationNotRequired | AdyenStatus::Received => AttemptStatus::Pending,
        AdyenStatus::Authorised => match is_manual_capture {
            true => AttemptStatus::Authorized,
            // In case of Automatic capture Authorized is the final status of the payment
            false => AttemptStatus::Charged,
        },
        AdyenStatus::Cancelled => AttemptStatus::Voided,
        AdyenStatus::ChallengeShopper
        | AdyenStatus::RedirectShopper
        | AdyenStatus::PresentToShopper => AttemptStatus::AuthenticationPending,
        AdyenStatus::Error | AdyenStatus::Refused => AttemptStatus::Failure,
        AdyenStatus::Pending => AttemptStatus::Pending,
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
    > TryFrom<ResponseRouterData<AdyenPaymentResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = Error;
    fn try_from(
        value: ResponseRouterData<AdyenPaymentResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;
        let is_manual_capture = false;
        let pmt = router_data.request.payment_method_type;
        let (status, error, payment_response_data) = match response {
            AdyenPaymentResponse::Response(response) => {
                get_adyen_response(*response, is_manual_capture, http_code, pmt)?
            }
            AdyenPaymentResponse::RedirectionResponse(response) => {
                get_redirection_response(*response, is_manual_capture, http_code, pmt)?
            }
        };

        Ok(Self {
            response: error.map_or_else(|| Ok(payment_response_data), Err),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<AdyenPSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = Error;
    fn try_from(value: ResponseRouterData<AdyenPSyncResponse, Self>) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;
        let pmt = router_data.request.payment_method_type;
        let is_manual_capture = false;
        let (status, error, payment_response_data) = match response {
            AdyenPSyncResponse(AdyenPaymentResponse::Response(response)) => {
                get_adyen_response(*response, is_manual_capture, http_code, pmt)?
            }
            AdyenPSyncResponse(AdyenPaymentResponse::RedirectionResponse(response)) => {
                get_redirection_response(*response, is_manual_capture, http_code, pmt)?
            }
        };

        Ok(Self {
            response: error.map_or_else(|| Ok(payment_response_data), Err),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

#[derive(Default, Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum AdyenVoidStatus {
    Received,
    #[default]
    Processing,
}

impl ForeignTryFrom<AdyenVoidStatus> for common_enums::AttemptStatus {
    type Error = domain_types::errors::ConnectorError;
    fn foreign_try_from(item: AdyenVoidStatus) -> Result<Self, Self::Error> {
        match item {
            AdyenVoidStatus::Received => Ok(Self::Voided),
            AdyenVoidStatus::Processing => Ok(Self::VoidInitiated),
        }
    }
}

impl TryFrom<ResponseRouterData<AdyenVoidResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = Error;
    fn try_from(value: ResponseRouterData<AdyenVoidResponse, Self>) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;
        let status = AttemptStatus::Pending;

        let payment_void_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.payment_psp_reference),
            redirection_data: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(response.reference),
            incremental_authorization_allowed: None,
            mandate_reference: None,
            status_code: http_code,
        };

        Ok(Self {
            response: Ok(payment_void_response_data),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

pub fn get_adyen_response(
    response: AdyenResponse,
    is_capture_manual: bool,
    status_code: u16,
    pmt: Option<common_enums::PaymentMethodType>,
) -> CustomResult<
    (
        common_enums::AttemptStatus,
        Option<domain_types::router_data::ErrorResponse>,
        PaymentsResponseData,
    ),
    domain_types::errors::ConnectorError,
> {
    let status = get_adyen_payment_status(is_capture_manual, response.result_code, pmt);
    let error = if response.refusal_reason.is_some()
        || response.refusal_reason_code.is_some()
        || status == common_enums::AttemptStatus::Failure
    {
        Some(domain_types::router_data::ErrorResponse {
            code: response
                .refusal_reason_code
                .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message: response
                .refusal_reason
                .clone()
                .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
            reason: response.refusal_reason,
            status_code,
            attempt_status: Some(common_enums::AttemptStatus::Failure),
            connector_transaction_id: Some(response.psp_reference.clone()),
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    } else {
        None
    };
    let mandate_reference = response
        .additional_data
        .as_ref()
        .and_then(|data| data.recurring_detail_reference.to_owned())
        .map(|mandate_id| MandateReference {
            connector_mandate_id: Some(mandate_id.expose()),
            payment_method_id: None,
        });
    let network_txn_id = response.additional_data.and_then(|additional_data| {
        additional_data
            .network_tx_reference
            .map(|network_tx_id| network_tx_id.expose())
    });

    let payments_response_data = PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(response.psp_reference),
        redirection_data: None,
        connector_metadata: None,
        network_txn_id,
        connector_response_reference_id: Some(response.merchant_reference),
        incremental_authorization_allowed: None,
        mandate_reference: mandate_reference.map(Box::new),
        status_code,
    };
    Ok((status, error, payments_response_data))
}

pub fn get_redirection_response(
    response: RedirectionResponse,
    is_manual_capture: bool,
    status_code: u16,
    pmt: Option<common_enums::PaymentMethodType>,
) -> CustomResult<
    (
        common_enums::AttemptStatus,
        Option<ErrorResponse>,
        PaymentsResponseData,
    ),
    domain_types::errors::ConnectorError,
> {
    let status = get_adyen_payment_status(is_manual_capture, response.result_code.clone(), pmt);
    let error = if response.refusal_reason.is_some()
        || response.refusal_reason_code.is_some()
        || status == common_enums::AttemptStatus::Failure
    {
        Some(ErrorResponse {
            code: response
                .refusal_reason_code
                .clone()
                .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message: response
                .refusal_reason
                .clone()
                .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
            reason: response.refusal_reason.to_owned(),
            status_code,
            attempt_status: None,
            connector_transaction_id: response.psp_reference.clone(),
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    } else {
        None
    };

    let redirection_data = response.action.url.clone().map(|url| {
        let form_fields = response.action.data.clone().unwrap_or_else(|| {
            std::collections::HashMap::from_iter(
                url.query_pairs()
                    .map(|(key, value)| (key.to_string(), value.to_string())),
            )
        });
        RedirectForm::Form {
            endpoint: url.to_string(),
            method: response.action.method.unwrap_or(Method::Get),
            form_fields,
        }
    });

    let connector_metadata = get_wait_screen_metadata(&response)?;

    let payments_response_data = PaymentsResponseData::TransactionResponse {
        resource_id: match response.psp_reference.as_ref() {
            Some(psp) => ResponseId::ConnectorTransactionId(psp.to_string()),
            None => ResponseId::NoResponseId,
        },
        redirection_data: redirection_data.map(Box::new),
        connector_metadata,
        network_txn_id: None,
        connector_response_reference_id: response
            .merchant_reference
            .clone()
            .or(response.psp_reference),
        incremental_authorization_allowed: None,
        mandate_reference: None,
        status_code,
    };
    Ok((status, error, payments_response_data))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaitScreenData {
    display_from_timestamp: i128,
    display_to_timestamp: Option<i128>,
}

pub fn get_wait_screen_metadata(
    next_action: &RedirectionResponse,
) -> CustomResult<Option<serde_json::Value>, domain_types::errors::ConnectorError> {
    match next_action.action.payment_method_type {
        PaymentType::Blik => {
            let current_time = OffsetDateTime::now_utc().unix_timestamp_nanos();
            Ok(Some(serde_json::json!(WaitScreenData {
                display_from_timestamp: current_time,
                display_to_timestamp: Some(current_time + Duration::minutes(1).whole_nanoseconds())
            })))
        }
        PaymentType::Mbway => {
            let current_time = OffsetDateTime::now_utc().unix_timestamp_nanos();
            Ok(Some(serde_json::json!(WaitScreenData {
                display_from_timestamp: current_time,
                display_to_timestamp: None
            })))
        }
        PaymentType::Affirm
        | PaymentType::Oxxo
        | PaymentType::Afterpaytouch
        | PaymentType::Alipay
        | PaymentType::AlipayHk
        | PaymentType::Alfamart
        | PaymentType::Alma
        | PaymentType::Applepay
        | PaymentType::Bizum
        | PaymentType::Atome
        | PaymentType::BoletoBancario
        | PaymentType::ClearPay
        | PaymentType::Dana
        | PaymentType::Eps
        | PaymentType::Gcash
        | PaymentType::Googlepay
        | PaymentType::GoPay
        | PaymentType::Ideal
        | PaymentType::Indomaret
        | PaymentType::Klarna
        | PaymentType::Kakaopay
        | PaymentType::MobilePay
        | PaymentType::Momo
        | PaymentType::MomoAtm
        | PaymentType::OnlineBankingCzechRepublic
        | PaymentType::OnlineBankingFinland
        | PaymentType::OnlineBankingPoland
        | PaymentType::OnlineBankingSlovakia
        | PaymentType::OnlineBankingFpx
        | PaymentType::OnlineBankingThailand
        | PaymentType::OpenBankingUK
        | PaymentType::PayBright
        | PaymentType::Paypal
        | PaymentType::Scheme
        | PaymentType::NetworkToken
        | PaymentType::Trustly
        | PaymentType::TouchNGo
        | PaymentType::Walley
        | PaymentType::WeChatPayWeb
        | PaymentType::AchDirectDebit
        | PaymentType::SepaDirectDebit
        | PaymentType::BacsDirectDebit
        | PaymentType::Samsungpay
        | PaymentType::Twint
        | PaymentType::Vipps
        | PaymentType::Swish
        | PaymentType::Knet
        | PaymentType::Benefit
        | PaymentType::PermataBankTransfer
        | PaymentType::BcaBankTransfer
        | PaymentType::BniVa
        | PaymentType::BriVa
        | PaymentType::CimbVa
        | PaymentType::DanamonVa
        | PaymentType::Giftcard
        | PaymentType::MandiriVa
        | PaymentType::PaySafeCard
        | PaymentType::SevenEleven
        | PaymentType::Lawson => Ok(None),
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenErrorResponse {
    pub status: i32,
    pub error_code: String,
    pub message: String,
    pub error_type: String,
    pub psp_reference: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, strum::Display, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum WebhookEventCode {
    Authorisation,
    Cancellation,
    Capture,
    CaptureFailed,
    Refund,
    RefundFailed,
    RefundReversed,
    CancelOrRefund,
    NotificationOfChargeback,
    Chargeback,
    ChargebackReversed,
    SecondChargeback,
    PrearbitrationWon,
    PrearbitrationLost,
}

#[derive(Debug, Deserialize)]
pub enum DisputeStatus {
    Undefended,
    Pending,
    Lost,
    Accepted,
    Won,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenAdditionalDataWH {
    pub dispute_status: Option<DisputeStatus>,
    pub chargeback_reason_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenNotificationRequestItemWH {
    pub original_reference: Option<String>,
    pub psp_reference: String,
    pub amount: AdyenAmountWH,
    pub event_code: WebhookEventCode,
    pub merchant_account_code: String,
    pub merchant_reference: String,
    pub success: String,
    pub reason: Option<String>,
    pub additional_data: AdyenAdditionalDataWH,
}

#[derive(Debug, Deserialize)]
pub struct AdyenAmountWH {
    pub value: MinorUnit,
    pub currency: common_enums::Currency,
}

fn is_success_scenario(is_success: &str) -> bool {
    is_success == "true"
}

pub(crate) fn get_adyen_payment_webhook_event(
    code: WebhookEventCode,
    is_success: String,
) -> Result<AttemptStatus, errors::ConnectorError> {
    match code {
        WebhookEventCode::Authorisation => {
            if is_success_scenario(&is_success) {
                Ok(AttemptStatus::Authorized)
            } else {
                Ok(AttemptStatus::Failure)
            }
        }
        WebhookEventCode::Cancellation => {
            if is_success_scenario(&is_success) {
                Ok(AttemptStatus::Voided)
            } else {
                Ok(AttemptStatus::Authorized)
            }
        }
        WebhookEventCode::Capture => {
            if is_success_scenario(&is_success) {
                Ok(AttemptStatus::Charged)
            } else {
                Ok(AttemptStatus::Failure)
            }
        }
        WebhookEventCode::CaptureFailed => Ok(AttemptStatus::Failure),
        _ => Err(errors::ConnectorError::RequestEncodingFailed),
    }
}

pub(crate) fn get_adyen_refund_webhook_event(
    code: WebhookEventCode,
    is_success: String,
) -> Result<RefundStatus, errors::ConnectorError> {
    match code {
        WebhookEventCode::Refund | WebhookEventCode::CancelOrRefund => {
            if is_success_scenario(&is_success) {
                Ok(RefundStatus::Success)
            } else {
                Ok(RefundStatus::Failure)
            }
        }
        WebhookEventCode::RefundFailed | WebhookEventCode::RefundReversed => {
            Ok(RefundStatus::Failure)
        }
        _ => Err(errors::ConnectorError::RequestEncodingFailed),
    }
}

pub(crate) fn get_adyen_webhook_event_type(code: WebhookEventCode) -> EventType {
    match code {
        WebhookEventCode::Authorisation => EventType::PaymentIntentAuthorizationSuccess,
        WebhookEventCode::Cancellation => EventType::PaymentIntentCancelled,
        WebhookEventCode::Capture => EventType::PaymentIntentCaptureSuccess,
        WebhookEventCode::CaptureFailed => EventType::PaymentIntentCaptureFailure,
        WebhookEventCode::Refund | WebhookEventCode::CancelOrRefund => EventType::RefundSuccess,
        WebhookEventCode::RefundFailed | WebhookEventCode::RefundReversed => {
            EventType::RefundFailure
        }
        WebhookEventCode::NotificationOfChargeback | WebhookEventCode::Chargeback => {
            EventType::DisputeOpened
        }
        WebhookEventCode::ChargebackReversed | WebhookEventCode::PrearbitrationWon => {
            EventType::DisputeWon
        }
        WebhookEventCode::SecondChargeback | WebhookEventCode::PrearbitrationLost => {
            EventType::DisputeLost
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AdyenItemObjectWH {
    pub notification_request_item: AdyenNotificationRequestItemWH,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenIncomingWebhook {
    pub notification_items: Vec<AdyenItemObjectWH>,
}

pub fn get_webhook_object_from_body(
    body: Vec<u8>,
) -> Result<AdyenNotificationRequestItemWH, error_stack::Report<errors::ConnectorError>> {
    let mut webhook: AdyenIncomingWebhook = body
        .parse_struct("AdyenIncomingWebhook")
        .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;

    let item_object = webhook
        .notification_items
        .drain(..)
        .next()
        .ok_or(errors::ConnectorError::WebhookBodyDecodingFailed)?;

    Ok(item_object.notification_request_item)
}

fn build_shopper_reference(
    customer_id: &Option<common_utils::id_type::CustomerId>,
    merchant_id: common_utils::id_type::MerchantId,
) -> Option<String> {
    customer_id.clone().map(|c_id| {
        format!(
            "{}_{}",
            merchant_id.get_string_repr(),
            c_id.get_string_repr()
        )
    })
}

type RecurringDetails = (Option<AdyenRecurringModel>, Option<bool>, Option<String>);

fn get_recurring_processing_model<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>(
    item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
) -> Result<RecurringDetails, Error> {
    let customer_id = item
        .request
        .customer_id
        .clone()
        .ok_or_else(Box::new(move || {
            errors::ConnectorError::MissingRequiredField {
                field_name: "customer_id",
            }
        }))?;

    match (item.request.setup_future_usage, item.request.off_session) {
        (Some(common_enums::FutureUsage::OffSession), _) => {
            let shopper_reference = format!(
                "{}_{}",
                item.resource_common_data.merchant_id.get_string_repr(),
                customer_id.get_string_repr()
            );
            let store_payment_method = is_mandate_payment(item);
            Ok((
                Some(AdyenRecurringModel::UnscheduledCardOnFile),
                Some(store_payment_method),
                Some(shopper_reference),
            ))
        }
        (_, Some(true)) => Ok((
            Some(AdyenRecurringModel::UnscheduledCardOnFile),
            None,
            Some(format!(
                "{}_{}",
                item.resource_common_data.merchant_id.get_string_repr(),
                customer_id.get_string_repr()
            )),
        )),
        _ => Ok((None, None, None)),
    }
}

fn is_mandate_payment<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>(
    item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
) -> bool {
    (item.request.setup_future_usage == Some(common_enums::FutureUsage::OffSession))
        || item
            .request
            .mandate_id
            .as_ref()
            .and_then(|mandate_ids| mandate_ids.mandate_reference_id.as_ref())
            .is_some()
}

pub fn get_address_info(
    address: Option<&domain_types::payment_address::Address>,
) -> Option<Result<Address, error_stack::Report<domain_types::errors::ConnectorError>>> {
    address.and_then(|add| {
        add.address.as_ref().map(
            |a| -> Result<Address, error_stack::Report<domain_types::errors::ConnectorError>> {
                Ok(Address {
                    city: a.city.clone().unwrap(),
                    country: a.country.unwrap(),
                    house_number_or_name: a.line1.clone().unwrap(),
                    postal_code: a.zip.clone().unwrap(),
                    state_or_province: a.state.clone(),
                    street: a.line2.clone(),
                })
            },
        )
    })
}

fn get_additional_data<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>(
    item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
) -> Option<AdditionalData> {
    let (authorisation_type, manual_capture) = match item.request.capture_method {
        Some(common_enums::CaptureMethod::Manual)
        | Some(common_enums::CaptureMethod::ManualMultiple) => {
            (Some(AuthType::PreAuth), Some("true".to_string()))
        }
        _ => (None, None),
    };
    let riskdata = item.request.metadata.clone().and_then(get_risk_data);

    let execute_three_d = if matches!(
        item.resource_common_data.auth_type,
        common_enums::AuthenticationType::ThreeDs
    ) {
        Some("true".to_string())
    } else {
        None
    };

    if authorisation_type.is_none()
        && manual_capture.is_none()
        && execute_three_d.is_none()
        && riskdata.is_none()
    {
        //without this if-condition when the above 3 values are None, additionalData will be serialized to JSON like this -> additionalData: {}
        //returning None, ensures that additionalData key will not be present in the serialized JSON
        None
    } else {
        Some(AdditionalData {
            authorisation_type,
            manual_capture,
            execute_three_d,
            network_tx_reference: None,
            recurring_detail_reference: None,
            recurring_shopper_reference: None,
            recurring_processing_model: None,
            riskdata,
            ..AdditionalData::default()
        })
    }
}

pub fn get_risk_data(metadata: serde_json::Value) -> Option<RiskData> {
    let item_i_d = get_str("riskdata.basket.item1.itemID", &metadata);
    let product_title = get_str("riskdata.basket.item1.productTitle", &metadata);
    let amount_per_item = get_str("riskdata.basket.item1.amountPerItem", &metadata);
    let currency = get_str("riskdata.basket.item1.currency", &metadata);
    let upc = get_str("riskdata.basket.item1.upc", &metadata);
    let brand = get_str("riskdata.basket.item1.brand", &metadata);
    let manufacturer = get_str("riskdata.basket.item1.manufacturer", &metadata);
    let category = get_str("riskdata.basket.item1.category", &metadata);
    let quantity = get_str("riskdata.basket.item1.quantity", &metadata);
    let color = get_str("riskdata.basket.item1.color", &metadata);
    let size = get_str("riskdata.basket.item1.size", &metadata);

    let device_country = get_str("riskdata.deviceCountry", &metadata);
    let house_numberor_name = get_str("riskdata.houseNumberorName", &metadata);
    let account_creation_date = get_str("riskdata.accountCreationDate", &metadata);
    let affiliate_channel = get_str("riskdata.affiliateChannel", &metadata);
    let avg_order_value = get_str("riskdata.avgOrderValue", &metadata);
    let delivery_method = get_str("riskdata.deliveryMethod", &metadata);
    let email_name = get_str("riskdata.emailName", &metadata);
    let email_domain = get_str("riskdata.emailDomain", &metadata);
    let last_order_date = get_str("riskdata.lastOrderDate", &metadata);
    let merchant_reference = get_str("riskdata.merchantReference", &metadata);
    let payment_method = get_str("riskdata.paymentMethod", &metadata);
    let promotion_name = get_str("riskdata.promotionName", &metadata);
    let secondary_phone_number = get_str("riskdata.secondaryPhoneNumber", &metadata);
    let timefrom_loginto_order = get_str("riskdata.timefromLogintoOrder", &metadata);
    let total_session_time = get_str("riskdata.totalSessionTime", &metadata);
    let total_authorized_amount_in_last30_days =
        get_str("riskdata.totalAuthorizedAmountInLast30Days", &metadata);
    let total_order_quantity = get_str("riskdata.totalOrderQuantity", &metadata);
    let total_lifetime_value = get_str("riskdata.totalLifetimeValue", &metadata);
    let visits_month = get_str("riskdata.visitsMonth", &metadata);
    let visits_week = get_str("riskdata.visitsWeek", &metadata);
    let visits_year = get_str("riskdata.visitsYear", &metadata);
    let ship_to_name = get_str("riskdata.shipToName", &metadata);
    let first8charactersof_address_line1_zip =
        get_str("riskdata.first8charactersofAddressLine1Zip", &metadata);
    let affiliate_order = get_bool("riskdata.affiliateOrder", &metadata);

    Some(RiskData {
        item_i_d,
        product_title,
        amount_per_item,
        currency,
        upc,
        brand,
        manufacturer,
        category,
        quantity,
        color,
        size,
        device_country,
        house_numberor_name,
        account_creation_date,
        affiliate_channel,
        avg_order_value,
        delivery_method,
        email_name,
        email_domain,
        last_order_date,
        merchant_reference,
        payment_method,
        promotion_name,
        secondary_phone_number,
        timefrom_loginto_order,
        total_session_time,
        total_authorized_amount_in_last30_days,
        total_order_quantity,
        total_lifetime_value,
        visits_month,
        visits_week,
        visits_year,
        ship_to_name,
        first8charactersof_address_line1_zip,
        affiliate_order,
    })
}

fn get_str(key: &str, riskdata: &serde_json::Value) -> Option<String> {
    riskdata
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn get_bool(key: &str, riskdata: &serde_json::Value) -> Option<bool> {
    riskdata.get(key).and_then(|v| v.as_bool())
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AdyenRedirectRequest {
    pub details: AdyenRedirectRequestTypes,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum AdyenRedirectRequestTypes {
    AdyenRedirection(AdyenRedirection),
    AdyenThreeDS(AdyenThreeDS),
    AdyenRefusal(AdyenRefusal),
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AdyenRedirection {
    pub redirect_result: String,
    #[serde(rename = "type")]
    pub type_of_redirection_result: Option<String>,
    pub result_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AdyenThreeDS {
    #[serde(rename = "threeDSResult")]
    pub three_ds_result: String,
    #[serde(rename = "type")]
    pub type_of_redirection_result: Option<String>,
    pub result_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AdyenRefusal {
    pub payload: String,
    #[serde(rename = "type")]
    pub type_of_redirection_result: Option<String>,
    pub result_code: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenRefundRequest {
    merchant_account: Secret<String>,
    amount: Amount,
    merchant_refund_reason: Option<String>,
    reference: String,
    splits: Option<Vec<AdyenSplitData>>,
    store: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenRefundResponse {
    merchant_account: Secret<String>,
    psp_reference: String,
    payment_psp_reference: String,
    reference: String,
    status: String,
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
        AdyenRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for AdyenRefundRequest
{
    type Error = Error;
    fn try_from(
        item: AdyenRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth_type = AdyenAuthType::try_from(&item.router_data.connector_auth_type)?;

        Ok(Self {
            merchant_account: auth_type.merchant_account,
            amount: Amount {
                currency: item.router_data.request.currency,
                value: item.router_data.request.minor_refund_amount,
            },
            merchant_refund_reason: item.router_data.request.reason.clone(),
            reference: item.router_data.request.refund_id.clone(),
            store: None,
            splits: None,
        })
    }
}

impl<F, Req> TryFrom<ResponseRouterData<AdyenRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, Req, RefundsResponseData>
{
    type Error = Error;
    fn try_from(value: ResponseRouterData<AdyenRefundResponse, Self>) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        let status = common_enums::RefundStatus::Pending;

        let refunds_response_data = RefundsResponseData {
            connector_refund_id: response.psp_reference,
            refund_status: status,
            status_code: http_code,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(refunds_response_data),
            ..router_data
        })
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenCaptureRequest {
    merchant_account: Secret<String>,
    amount: Amount,
    reference: String,
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
        AdyenRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for AdyenCaptureRequest
{
    type Error = Error;
    fn try_from(
        item: AdyenRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth_type = AdyenAuthType::try_from(&item.router_data.connector_auth_type)?;
        let reference = match item.router_data.request.multiple_capture_data.clone() {
            // if multiple capture request, send capture_id as our reference for the capture
            Some(multiple_capture_request_data) => multiple_capture_request_data.capture_reference,
            // if single capture request, send connector_request_reference_id(attempt_id)
            None => item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
        };
        Ok(Self {
            merchant_account: auth_type.merchant_account,
            reference,
            amount: Amount {
                currency: item.router_data.request.currency,
                value: item.router_data.request.minor_amount_to_capture.to_owned(),
            },
        })
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenCaptureResponse {
    merchant_account: Secret<String>,
    payment_psp_reference: String,
    psp_reference: String,
    reference: String,
    status: String,
    amount: Amount,
    merchant_reference: Option<String>,
    store: Option<String>,
    splits: Option<Vec<AdyenSplitData>>,
}

impl<F> TryFrom<ResponseRouterData<AdyenCaptureResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = Error;
    fn try_from(
        value: ResponseRouterData<AdyenCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;
        let is_multiple_capture_psync_flow = router_data.request.multiple_capture_data.is_some();
        let connector_transaction_id = if is_multiple_capture_psync_flow {
            response.psp_reference.clone()
        } else {
            response.payment_psp_reference
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
                redirection_data: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(response.reference),
                incremental_authorization_allowed: None,
                mandate_reference: None,
                status_code: http_code,
            }),
            resource_common_data: PaymentFlowData {
                status: AttemptStatus::Pending,
                ..router_data.resource_common_data
            },
            ..router_data
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
    TryFrom<(
        AdyenRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        &Card<T>,
    )> for SetupMandateRequest<T>
{
    type Error = Error;
    fn try_from(
        value: (
            AdyenRouterData<
                RouterDataV2<
                    SetupMandate,
                    PaymentFlowData,
                    SetupMandateRequestData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            &Card<T>,
        ),
    ) -> Result<Self, Self::Error> {
        let (item, card_data) = value;
        let amount = get_amount_data_for_setup_mandate(&item);
        let auth_type = AdyenAuthType::try_from(&item.router_data.connector_auth_type)?;
        let shopper_interaction = AdyenShopperInteraction::from(&item.router_data);
        let shopper_reference = build_shopper_reference(
            &item.router_data.request.customer_id.clone(),
            item.router_data.resource_common_data.merchant_id.clone(),
        );
        let (recurring_processing_model, store_payment_method, _) =
            get_recurring_processing_model_for_setup_mandate(&item.router_data)?;

        let return_url = item
            .router_data
            .request
            .router_return_url
            .clone()
            .ok_or_else(Box::new(move || {
                errors::ConnectorError::MissingRequiredField {
                    field_name: "return_url",
                }
            }))?;

        let billing_address = get_address_info(
            item.router_data
                .resource_common_data
                .address
                .get_payment_billing(),
        )
        .and_then(Result::ok);

        let card_holder_name = item.router_data.request.customer_name.clone();

        let additional_data = get_additional_data_for_setup_mandate(&item.router_data);

        let payment_method = PaymentMethod::AdyenPaymentMethod(Box::new(
            AdyenPaymentMethod::try_from((card_data, card_holder_name))?,
        ));

        Ok(SetupMandateRequest(AdyenPaymentRequest {
            amount,
            merchant_account: auth_type.merchant_account,
            payment_method,
            reference: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            return_url,
            shopper_interaction,
            recurring_processing_model,
            browser_info: None,
            additional_data,
            mpi_data: None,
            telephone_number: None,
            shopper_name: None,
            shopper_email: None,
            shopper_locale: None,
            social_security_number: None,
            billing_address,
            delivery_address: None,
            country_code: None,
            line_items: None,
            shopper_reference,
            store_payment_method,
            channel: None,
            shopper_statement: item.router_data.request.statement_descriptor.clone(),
            shopper_ip: None,
            merchant_order_reference: item.router_data.request.merchant_order_reference_id.clone(),
            store: None,
            splits: None,
            device_fingerprint: None,
        }))
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
        AdyenRouterData<
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
    type Error = Error;
    fn try_from(
        item: AdyenRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        match item
            .router_data
            .request
            .mandate_id
            .to_owned()
            .and_then(|mandate_ids| mandate_ids.mandate_reference_id)
        {
            Some(_mandate_ref) => Err(domain_types::errors::ConnectorError::NotImplemented(
                "payment_method".into(),
            ))?,
            None => match item.router_data.request.payment_method_data.clone() {
                PaymentMethodData::Card(ref card) => SetupMandateRequest::try_from((item, card)),
                PaymentMethodData::Wallet(_)
                | PaymentMethodData::PayLater(_)
                | PaymentMethodData::BankRedirect(_)
                | PaymentMethodData::BankDebit(_)
                | PaymentMethodData::BankTransfer(_)
                | PaymentMethodData::CardRedirect(_)
                | PaymentMethodData::Voucher(_)
                | PaymentMethodData::GiftCard(_)
                | PaymentMethodData::Crypto(_)
                | PaymentMethodData::MandatePayment
                | PaymentMethodData::Reward
                | PaymentMethodData::RealTimePayment(_)
                | PaymentMethodData::Upi(_)
                | PaymentMethodData::OpenBanking(_)
                | PaymentMethodData::CardDetailsForNetworkTransactionId(_)
                | PaymentMethodData::NetworkToken(_)
                | PaymentMethodData::MobilePayment(_)
                | PaymentMethodData::CardToken(_) => Err(
                    domain_types::errors::ConnectorError::NotImplemented("payment method".into()),
                )?,
            },
        }
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
    > TryFrom<ResponseRouterData<SetupMandateResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
{
    type Error = Error;
    fn try_from(
        value: ResponseRouterData<SetupMandateResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;
        let pmt = router_data.request.payment_method_type;
        let is_manual_capture = false;
        let (status, error, payment_response_data) = match response {
            SetupMandateResponse(AdyenPaymentResponse::Response(response)) => {
                get_adyen_response(*response, is_manual_capture, http_code, pmt)?
            }
            SetupMandateResponse(AdyenPaymentResponse::RedirectionResponse(response)) => {
                get_redirection_response(*response, is_manual_capture, http_code, pmt)?
            }
        };

        Ok(Self {
            response: error.map_or_else(|| Ok(payment_response_data), Err),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

fn get_amount_data_for_setup_mandate<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>(
    item: &AdyenRouterData<
        RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData<T>,
            PaymentsResponseData,
        >,
        T,
    >,
) -> Amount {
    Amount {
        currency: item.router_data.request.currency,
        value: MinorUnit::new(item.router_data.request.amount.unwrap_or(0)),
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
    From<
        &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData<T>,
            PaymentsResponseData,
        >,
    > for AdyenShopperInteraction
{
    fn from(
        item: &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData<T>,
            PaymentsResponseData,
        >,
    ) -> Self {
        match item.request.off_session {
            Some(true) => Self::ContinuedAuthentication,
            _ => Self::Ecommerce,
        }
    }
}

fn get_recurring_processing_model_for_setup_mandate<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>(
    item: &RouterDataV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    >,
) -> Result<RecurringDetails, Error> {
    let customer_id = item
        .request
        .customer_id
        .clone()
        .ok_or_else(Box::new(move || {
            errors::ConnectorError::MissingRequiredField {
                field_name: "customer_id",
            }
        }))?;

    match (item.request.setup_future_usage, item.request.off_session) {
        (Some(common_enums::FutureUsage::OffSession), _) => {
            let shopper_reference = format!(
                "{}_{}",
                item.resource_common_data.merchant_id.get_string_repr(),
                customer_id.get_string_repr()
            );
            let store_payment_method = is_mandate_payment_for_setup_mandate(item);
            Ok((
                Some(AdyenRecurringModel::UnscheduledCardOnFile),
                Some(store_payment_method),
                Some(shopper_reference),
            ))
        }
        (_, Some(true)) => Ok((
            Some(AdyenRecurringModel::UnscheduledCardOnFile),
            None,
            Some(format!(
                "{}_{}",
                item.resource_common_data.merchant_id.get_string_repr(),
                customer_id.get_string_repr()
            )),
        )),
        _ => Ok((None, None, None)),
    }
}

fn get_additional_data_for_setup_mandate<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>(
    item: &RouterDataV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    >,
) -> Option<AdditionalData> {
    let (authorisation_type, manual_capture) = match item.request.capture_method {
        Some(common_enums::CaptureMethod::Manual)
        | Some(common_enums::CaptureMethod::ManualMultiple) => {
            (Some(AuthType::PreAuth), Some("true".to_string()))
        }
        _ => (None, None),
    };
    let riskdata = item.request.metadata.clone().and_then(get_risk_data);

    let execute_three_d = if matches!(
        item.resource_common_data.auth_type,
        common_enums::AuthenticationType::ThreeDs
    ) {
        Some("true".to_string())
    } else {
        None
    };

    if authorisation_type.is_none()
        && manual_capture.is_none()
        && execute_three_d.is_none()
        && riskdata.is_none()
    {
        //without this if-condition when the above 3 values are None, additionalData will be serialized to JSON like this -> additionalData: {}
        //returning None, ensures that additionalData key will not be present in the serialized JSON
        None
    } else {
        Some(AdditionalData {
            authorisation_type,
            manual_capture,
            execute_three_d,
            network_tx_reference: None,
            recurring_detail_reference: None,
            recurring_shopper_reference: None,
            recurring_processing_model: None,
            riskdata,
            ..AdditionalData::default()
        })
    }
}

fn is_mandate_payment_for_setup_mandate<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>(
    item: &RouterDataV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    >,
) -> bool {
    (item.request.setup_future_usage == Some(common_enums::FutureUsage::OffSession))
        || item
            .request
            .mandate_id
            .as_ref()
            .and_then(|mandate_ids| mandate_ids.mandate_reference_id.as_ref())
            .is_some()
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenDisputeAcceptRequest {
    pub dispute_psp_reference: String,
    pub merchant_account_code: String,
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
        AdyenRouterData<
            RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
            T,
        >,
    > for AdyenDisputeAcceptRequest
{
    type Error = Error;

    fn try_from(
        item: AdyenRouterData<
            RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = AdyenAuthType::try_from(&item.router_data.connector_auth_type)?;

        Ok(Self {
            dispute_psp_reference: item
                .router_data
                .resource_common_data
                .connector_dispute_id
                .clone(),
            merchant_account_code: auth.merchant_account.peek().to_string(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenDisputeAcceptResponse {
    pub dispute_service_result: Option<DisputeServiceResult>,
}

impl<F, Req> TryFrom<ResponseRouterData<AdyenDisputeAcceptResponse, Self>>
    for RouterDataV2<F, DisputeFlowData, Req, DisputeResponseData>
{
    type Error = Error;

    fn try_from(
        value: ResponseRouterData<AdyenDisputeAcceptResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;
        let success = response
            .dispute_service_result
            .as_ref()
            .is_some_and(|r| r.success);

        if success {
            let status = common_enums::DisputeStatus::DisputeAccepted;

            let dispute_response_data = DisputeResponseData {
                dispute_status: status,
                connector_dispute_id: router_data
                    .resource_common_data
                    .connector_dispute_id
                    .clone(),
                connector_dispute_status: None,
                status_code: http_code,
            };

            Ok(Self {
                resource_common_data: DisputeFlowData {
                    ..router_data.resource_common_data
                },
                response: Ok(dispute_response_data),
                ..router_data
            })
        } else {
            let error_message = response
                .dispute_service_result
                .as_ref()
                .and_then(|r| r.error_message.clone())
                .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string());

            let error_response = ErrorResponse {
                code: NO_ERROR_CODE.to_string(),
                message: error_message.clone(),
                reason: Some(error_message.clone()),
                status_code: http_code,
                attempt_status: None,
                connector_transaction_id: None,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            };

            Ok(Self {
                resource_common_data: router_data.resource_common_data.clone(),
                response: Err(error_response),
                ..router_data
            })
        }
    }
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenDisputeSubmitEvidenceRequest {
    defense_documents: Vec<DefenseDocuments>,
    merchant_account_code: Secret<String>,
    dispute_psp_reference: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DefenseDocuments {
    content: Secret<String>,
    content_type: Option<String>,
    defense_document_type_code: String,
}

fn get_defence_documents(item: SubmitEvidenceData) -> Option<Vec<DefenseDocuments>> {
    let mut defense_documents: Vec<DefenseDocuments> = Vec::new();
    if let Some(shipping_documentation) = item.shipping_documentation {
        defense_documents.push(DefenseDocuments {
            content: get_content(shipping_documentation).into(),
            content_type: item.shipping_documentation_provider_file_id,
            defense_document_type_code: "DefenseMaterial".into(),
        })
    }
    if let Some(receipt) = item.receipt {
        defense_documents.push(DefenseDocuments {
            content: get_content(receipt).into(),
            content_type: item.receipt_file_type,
            defense_document_type_code: "DefenseMaterial".into(),
        })
    }
    if let Some(invoice_showing_distinct_transactions) = item.invoice_showing_distinct_transactions
    {
        defense_documents.push(DefenseDocuments {
            content: get_content(invoice_showing_distinct_transactions).into(),
            content_type: item.invoice_showing_distinct_transactions_file_type,
            defense_document_type_code: "DefenseMaterial".into(),
        })
    }
    if let Some(customer_communication) = item.customer_communication {
        defense_documents.push(DefenseDocuments {
            content: get_content(customer_communication).into(),
            content_type: item.customer_communication_file_type,
            defense_document_type_code: "DefenseMaterial".into(),
        })
    }
    if let Some(refund_policy) = item.refund_policy {
        defense_documents.push(DefenseDocuments {
            content: get_content(refund_policy).into(),
            content_type: item.refund_policy_file_type,
            defense_document_type_code: "DefenseMaterial".into(),
        })
    }
    if let Some(recurring_transaction_agreement) = item.recurring_transaction_agreement {
        defense_documents.push(DefenseDocuments {
            content: get_content(recurring_transaction_agreement).into(),
            content_type: item.recurring_transaction_agreement_file_type,
            defense_document_type_code: "DefenseMaterial".into(),
        })
    }
    if let Some(uncategorized_file) = item.uncategorized_file {
        defense_documents.push(DefenseDocuments {
            content: get_content(uncategorized_file).into(),
            content_type: item.uncategorized_file_type,
            defense_document_type_code: "DefenseMaterial".into(),
        })
    }
    if let Some(cancellation_policy) = item.cancellation_policy {
        defense_documents.push(DefenseDocuments {
            content: get_content(cancellation_policy).into(),
            content_type: item.cancellation_policy_file_type,
            defense_document_type_code: "DefenseMaterial".into(),
        })
    }
    if let Some(customer_signature) = item.customer_signature {
        defense_documents.push(DefenseDocuments {
            content: get_content(customer_signature).into(),
            content_type: item.customer_signature_file_type,
            defense_document_type_code: "DefenseMaterial".into(),
        })
    }
    if let Some(service_documentation) = item.service_documentation {
        defense_documents.push(DefenseDocuments {
            content: get_content(service_documentation).into(),
            content_type: item.service_documentation_file_type,
            defense_document_type_code: "DefenseMaterial".into(),
        })
    }

    if defense_documents.is_empty() {
        None
    } else {
        Some(defense_documents)
    }
}

fn get_content(item: Vec<u8>) -> String {
    STANDARD.encode(item)
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
        AdyenRouterData<
            RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
            T,
        >,
    > for AdyenDisputeSubmitEvidenceRequest
{
    type Error = Error;

    fn try_from(
        item: AdyenRouterData<
            RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = AdyenAuthType::try_from(&item.router_data.connector_auth_type)?;

        Ok(Self {
            defense_documents: get_defence_documents(item.router_data.request.clone()).ok_or(
                errors::ConnectorError::MissingRequiredField {
                    field_name: "Missing Defence Documents",
                },
            )?,
            merchant_account_code: auth.merchant_account.peek().to_string().into(),
            dispute_psp_reference: item.router_data.request.connector_dispute_id.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenSubmitEvidenceResponse {
    pub dispute_service_result: Option<DisputeServiceResult>,
}

impl<F, Req> TryFrom<ResponseRouterData<AdyenSubmitEvidenceResponse, Self>>
    for RouterDataV2<F, DisputeFlowData, Req, DisputeResponseData>
{
    type Error = Error;

    fn try_from(
        value: ResponseRouterData<AdyenSubmitEvidenceResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        let success = response
            .dispute_service_result
            .as_ref()
            .is_some_and(|r| r.success);

        if success {
            let status = common_enums::DisputeStatus::DisputeChallenged;

            let dispute_response_data = DisputeResponseData {
                dispute_status: status,
                connector_dispute_id: router_data
                    .resource_common_data
                    .connector_dispute_id
                    .clone(),
                connector_dispute_status: None,
                status_code: http_code,
            };

            Ok(Self {
                resource_common_data: DisputeFlowData {
                    ..router_data.resource_common_data
                },
                response: Ok(dispute_response_data),
                ..router_data
            })
        } else {
            let error_message = response
                .dispute_service_result
                .as_ref()
                .and_then(|r| r.error_message.clone())
                .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string());

            let error_response = ErrorResponse {
                code: NO_ERROR_CODE.to_string(),
                message: error_message.clone(),
                reason: Some(error_message.clone()),
                status_code: http_code,
                attempt_status: None,
                connector_transaction_id: None,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            };

            Ok(Self {
                resource_common_data: router_data.resource_common_data.clone(),
                response: Err(error_response),
                ..router_data
            })
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenDefendDisputeRequest {
    dispute_psp_reference: String,
    merchant_account_code: Secret<String>,
    defense_reason_code: String,
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
        AdyenRouterData<
            RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
            T,
        >,
    > for AdyenDefendDisputeRequest
{
    type Error = Error;

    fn try_from(
        item: AdyenRouterData<
            RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth_type = AdyenAuthType::try_from(&item.router_data.connector_auth_type)?;

        Ok(Self {
            dispute_psp_reference: item.router_data.request.connector_dispute_id.clone(),
            merchant_account_code: auth_type.merchant_account.clone(),
            defense_reason_code: item.router_data.request.defense_reason_code.clone(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum AdyenDefendDisputeResponse {
    DefendDisputeSuccessResponse(DefendDisputeSuccessResponse),
    DefendDisputeFailedResponse(DefendDisputeErrorResponse),
}

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DefendDisputeErrorResponse {
    error_code: String,
    error_type: String,
    message: String,
    psp_reference: String,
    status: String,
}

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DefendDisputeSuccessResponse {
    dispute_service_result: DisputeServiceResult,
}

#[derive(Default, Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DisputeServiceResult {
    error_message: Option<String>,
    success: bool,
}

impl<F, Req> TryFrom<ResponseRouterData<AdyenDefendDisputeResponse, Self>>
    for RouterDataV2<F, DisputeFlowData, Req, DisputeResponseData>
{
    type Error = Report<domain_types::errors::ConnectorError>;

    fn try_from(
        value: ResponseRouterData<AdyenDefendDisputeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;
        match response {
            AdyenDefendDisputeResponse::DefendDisputeSuccessResponse(result) => {
                let dispute_status = if result.dispute_service_result.success {
                    common_enums::DisputeStatus::DisputeWon
                } else {
                    common_enums::DisputeStatus::DisputeLost
                };

                Ok(Self {
                    response: Ok(DisputeResponseData {
                        dispute_status,
                        connector_dispute_status: None,
                        connector_dispute_id: router_data
                            .resource_common_data
                            .connector_dispute_id
                            .clone(),
                        status_code: http_code,
                    }),
                    ..router_data
                })
            }

            AdyenDefendDisputeResponse::DefendDisputeFailedResponse(result) => Ok(Self {
                response: Err(ErrorResponse {
                    code: result.error_code,
                    message: result.message.clone(),
                    reason: Some(result.message),
                    status_code: http_code,
                    attempt_status: None,
                    connector_transaction_id: Some(result.psp_reference),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data
            }),
        }
    }
}

pub(crate) fn get_dispute_stage_and_status(
    code: WebhookEventCode,
    dispute_status: Option<DisputeStatus>,
) -> (common_enums::DisputeStage, common_enums::DisputeStatus) {
    use common_enums::{DisputeStage, DisputeStatus as HSDisputeStatus};

    match code {
        WebhookEventCode::NotificationOfChargeback => {
            (DisputeStage::PreDispute, HSDisputeStatus::DisputeOpened)
        }
        WebhookEventCode::Chargeback => {
            let status = match dispute_status {
                Some(DisputeStatus::Undefended) | Some(DisputeStatus::Pending) => {
                    HSDisputeStatus::DisputeOpened
                }
                Some(DisputeStatus::Lost) | None => HSDisputeStatus::DisputeLost,
                Some(DisputeStatus::Accepted) => HSDisputeStatus::DisputeAccepted,
                Some(DisputeStatus::Won) => HSDisputeStatus::DisputeWon,
            };
            (DisputeStage::Dispute, status)
        }
        WebhookEventCode::ChargebackReversed => {
            let status = match dispute_status {
                Some(DisputeStatus::Pending) => HSDisputeStatus::DisputeChallenged,
                _ => HSDisputeStatus::DisputeWon,
            };
            (DisputeStage::Dispute, status)
        }
        WebhookEventCode::SecondChargeback => {
            (DisputeStage::PreArbitration, HSDisputeStatus::DisputeLost)
        }
        WebhookEventCode::PrearbitrationWon => {
            let status = match dispute_status {
                Some(DisputeStatus::Pending) => HSDisputeStatus::DisputeOpened,
                _ => HSDisputeStatus::DisputeWon,
            };
            (DisputeStage::PreArbitration, status)
        }
        WebhookEventCode::PrearbitrationLost => {
            (DisputeStage::PreArbitration, HSDisputeStatus::DisputeLost)
        }
        _ => (DisputeStage::Dispute, HSDisputeStatus::DisputeOpened),
    }
}
