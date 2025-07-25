use std::collections::HashMap;

use cards::CardNumber;
use common_enums::{BankNames, CaptureMethod, Currency};
use common_utils::{
    consts,
    crypto::{self, GenerateDigest},
    errors::CustomResult,
    ext_traits::Encode,
    pii::Email,
    request::Method,
    types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector},
};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        MandateReference, MandateReferenceId, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::{
        BankRedirectData, Card, CardDetailsForNetworkTransactionId, GooglePayWalletData,
        PaymentMethodData, RealTimePaymentData, WalletData,
    },
    router_data::{ApplePayPredecryptData, ConnectorAuthType, ErrorResponse, PaymentMethodToken},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum::Display;
use url::Url;

use crate::{
    connectors::{fiuu::FiuuRouterData, macros::GetFormData},
    types::ResponseRouterData,
};

// These needs to be accepted from SDK, need to be done after 1.0.0 stability as API contract will change
const GOOGLEPAY_API_VERSION_MINOR: u8 = 0;
const GOOGLEPAY_API_VERSION: u8 = 2;

pub struct FiuuAuthType {
    pub(super) merchant_id: Secret<String>,
    pub(super) verify_key: Secret<String>,
    pub(super) secret_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for FiuuAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                merchant_id: key1.to_owned(),
                verify_key: api_key.to_owned(),
                secret_key: api_secret.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum TxnType {
    Sals,
    Auts,
}

impl TryFrom<Option<CaptureMethod>> for TxnType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(capture_method: Option<CaptureMethod>) -> Result<Self, Self::Error> {
        match capture_method {
            Some(CaptureMethod::Automatic) | Some(CaptureMethod::SequentialAutomatic) | None => {
                Ok(Self::Sals)
            }
            Some(CaptureMethod::Manual) => Ok(Self::Auts),
            _ => Err(errors::ConnectorError::CaptureMethodNotSupported.into()),
        }
    }
}

#[derive(Serialize, Deserialize, Display, Debug, Clone)]
enum TxnChannel {
    #[serde(rename = "CREDITAN")]
    #[strum(serialize = "CREDITAN")]
    Creditan,
    #[serde(rename = "RPP_DUITNOWQR")]
    #[strum(serialize = "RPP_DUITNOWQR")]
    RppDuitNowQr,
}

#[derive(Serialize, Deserialize, Display, Debug, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum FPXTxnChannel {
    FpxAbb,
    FpxUob,
    FpxAbmb,
    FpxScb,
    FpxBsn,
    FpxKfh,
    FpxBmmb,
    FpxBkrm,
    FpxHsbc,
    FpxAgrobank,
    FpxBocm,
    FpxMb2u,
    FpxCimbclicks,
    FpxAmb,
    FpxHlb,
    FpxPbb,
    FpxRhb,
    FpxBimb,
    FpxOcbc,
}
#[derive(Debug, Clone, Serialize)]
pub enum BankCode {
    PHBMMYKL,
    AGOBMYK1,
    MFBBMYKL,
    ARBKMYKL,
    BKCHMYKL,
    BIMBMYKL,
    BMMBMYKL,
    BKRMMYK1,
    BSNAMYK1,
    CIBBMYKL,
    HLBBMYKL,
    HBMBMYKL,
    KFHOMYKL,
    MBBEMYKL,
    PBBEMYKL,
    RHBBMYKL,
    SCBLMYKX,
    UOVBMYKL,
    OCBCMYKL,
}

impl TryFrom<BankNames> for BankCode {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(bank: BankNames) -> Result<Self, Self::Error> {
        match bank {
            BankNames::AffinBank => Ok(Self::PHBMMYKL),
            BankNames::AgroBank => Ok(Self::AGOBMYK1),
            BankNames::AllianceBank => Ok(Self::MFBBMYKL),
            BankNames::AmBank => Ok(Self::ARBKMYKL),
            BankNames::BankOfChina => Ok(Self::BKCHMYKL),
            BankNames::BankIslam => Ok(Self::BIMBMYKL),
            BankNames::BankMuamalat => Ok(Self::BMMBMYKL),
            BankNames::BankRakyat => Ok(Self::BKRMMYK1),
            BankNames::BankSimpananNasional => Ok(Self::BSNAMYK1),
            BankNames::CimbBank => Ok(Self::CIBBMYKL),
            BankNames::HongLeongBank => Ok(Self::HLBBMYKL),
            BankNames::HsbcBank => Ok(Self::HBMBMYKL),
            BankNames::KuwaitFinanceHouse => Ok(Self::KFHOMYKL),
            BankNames::Maybank => Ok(Self::MBBEMYKL),
            BankNames::PublicBank => Ok(Self::PBBEMYKL),
            BankNames::RhbBank => Ok(Self::RHBBMYKL),
            BankNames::StandardCharteredBank => Ok(Self::SCBLMYKX),
            BankNames::UobBank => Ok(Self::UOVBMYKL),
            BankNames::OcbcBank => Ok(Self::OCBCMYKL),
            bank => Err(errors::ConnectorError::NotSupported {
                message: format!("Invalid BankName for FPX Refund: {bank:?}"),
                connector: "Fiuu",
            })?,
        }
    }
}

impl TryFrom<BankNames> for FPXTxnChannel {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(bank_names: BankNames) -> Result<Self, Self::Error> {
        match bank_names {
            BankNames::AffinBank => Ok(Self::FpxAbb),
            BankNames::AgroBank => Ok(Self::FpxAgrobank),
            BankNames::AllianceBank => Ok(Self::FpxAbmb),
            BankNames::AmBank => Ok(Self::FpxAmb),
            BankNames::BankOfChina => Ok(Self::FpxBocm),
            BankNames::BankIslam => Ok(Self::FpxBimb),
            BankNames::BankMuamalat => Ok(Self::FpxBmmb),
            BankNames::BankRakyat => Ok(Self::FpxBkrm),
            BankNames::BankSimpananNasional => Ok(Self::FpxBsn),
            BankNames::CimbBank => Ok(Self::FpxCimbclicks),
            BankNames::HongLeongBank => Ok(Self::FpxHlb),
            BankNames::HsbcBank => Ok(Self::FpxHsbc),
            BankNames::KuwaitFinanceHouse => Ok(Self::FpxKfh),
            BankNames::Maybank => Ok(Self::FpxMb2u),
            BankNames::PublicBank => Ok(Self::FpxPbb),
            BankNames::RhbBank => Ok(Self::FpxRhb),
            BankNames::StandardCharteredBank => Ok(Self::FpxScb),
            BankNames::UobBank => Ok(Self::FpxUob),
            BankNames::OcbcBank => Ok(Self::FpxOcbc),
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Fiuu"),
            ))?,
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct FiuuMandateRequest {
    #[serde(rename = "0")]
    mandate_request: Secret<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct FiuuRecurringRequest {
    record_type: FiuuRecordType,
    merchant_id: Secret<String>,
    token: Secret<String>,
    order_id: String,
    currency: Currency,
    amount: StringMajorUnit,
    billing_name: Secret<String>,
    email: Email,
    verify_key: Secret<String>,
}

#[derive(Serialize, Debug, Clone, strum::Display)]
pub enum FiuuRecordType {
    T,
}

impl
    TryFrom<
        &FiuuRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for FiuuMandateRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &FiuuRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let auth: FiuuAuthType = FiuuAuthType::try_from(&item.router_data.connector_auth_type)?;
        let record_type = FiuuRecordType::T;
        let merchant_id = auth.merchant_id;
        let order_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        let currency = item.router_data.request.currency;
        let converter = StringMajorUnitForConnector;
        let amount = converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;
        let billing_name = item
            .router_data
            .resource_common_data
            .get_billing_full_name()?;

        let email = item.router_data.resource_common_data.get_billing_email()?;
        let token = Secret::new(item.router_data.request.get_connector_mandate_id()?);
        let verify_key = auth.verify_key;
        let recurring_request = FiuuRecurringRequest {
            record_type: record_type.clone(),
            merchant_id: merchant_id.clone(),
            token: token.clone(),
            order_id: order_id.clone(),
            currency,
            amount: amount.clone(),
            billing_name: billing_name.clone(),
            email: email.clone(),
            verify_key: verify_key.clone(),
        };
        let check_sum = calculate_check_sum(recurring_request)?;
        let mandate_request = format!(
            "{}|{}||{}|{}|{}|{}|{}|{}|||{}",
            record_type,
            merchant_id.peek(),
            token.peek(),
            order_id,
            currency,
            amount.get_amount_as_string(),
            billing_name.peek(),
            email.peek(),
            check_sum.peek()
        );
        Ok(Self {
            mandate_request: mandate_request.into(),
        })
    }
}

pub fn calculate_check_sum(
    req: FiuuRecurringRequest,
) -> CustomResult<Secret<String>, errors::ConnectorError> {
    let formatted_string = format!(
        "{}{}{}{}{}{}{}",
        req.record_type,
        req.merchant_id.peek(),
        req.token.peek(),
        req.order_id,
        req.currency,
        req.amount.get_amount_as_string(),
        req.verify_key.peek()
    );
    Ok(Secret::new(hex::encode(
        crypto::Md5
            .generate_digest(formatted_string.as_bytes())
            .change_context(errors::ConnectorError::RequestEncodingFailed)?,
    )))
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FiuuPaymentRequest {
    #[serde(rename = "MerchantID")]
    merchant_id: Secret<String>,
    reference_no: String,
    txn_type: TxnType,
    txn_currency: Currency,
    txn_amount: StringMajorUnit,
    signature: Secret<String>,
    #[serde(rename = "ReturnURL")]
    return_url: Option<String>,
    #[serde(rename = "NotificationURL")]
    notification_url: Option<Url>,
    #[serde(flatten)]
    payment_method_data: FiuuPaymentMethodData,
}

#[derive(Serialize, Debug, Clone)]
#[serde(untagged)]
pub enum FiuuPaymentMethodData {
    FiuuQRData(Box<FiuuQRData>),
    FiuuCardData(Box<FiuuCardData>),
    FiuuCardWithNTI(Box<FiuuCardWithNTI>),
    FiuuFpxData(Box<FiuuFPXData>),
    FiuuGooglePayData(Box<FiuuGooglePayData>),
    FiuuApplePayData(Box<FiuuApplePayData>),
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FiuuFPXData {
    #[serde(rename = "non_3DS")]
    non_3ds: i32,
    txn_channel: FPXTxnChannel,
}
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FiuuQRData {
    txn_channel: TxnChannel,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct FiuuCardData {
    #[serde(rename = "non_3DS")]
    non_3ds: i32,
    #[serde(rename = "TxnChannel")]
    txn_channel: TxnChannel,
    cc_pan: CardNumber,
    cc_cvv2: Secret<String>,
    cc_month: Secret<String>,
    cc_year: Secret<String>,
    #[serde(rename = "mpstokenstatus")]
    mps_token_status: Option<i32>,
    #[serde(rename = "CustEmail")]
    customer_email: Option<Email>,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct FiuuCardWithNTI {
    #[serde(rename = "TxnChannel")]
    txn_channel: TxnChannel,
    cc_pan: CardNumber,
    cc_month: Secret<String>,
    cc_year: Secret<String>,
    #[serde(rename = "OriginalSchemeID")]
    original_scheme_id: Secret<String>,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct FiuuApplePayData {
    #[serde(rename = "TxnChannel")]
    txn_channel: TxnChannel,
    cc_month: Secret<String>,
    cc_year: Secret<String>,
    cc_token: Secret<String>,
    eci: Option<String>,
    token_cryptogram: Secret<String>,
    token_type: FiuuTokenType,
    #[serde(rename = "non_3DS")]
    non_3ds: i32,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum FiuuTokenType {
    ApplePay,
    GooglePay,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FiuuGooglePayData {
    txn_channel: TxnChannel,
    #[serde(rename = "GooglePay[apiVersion]")]
    api_version: u8,
    #[serde(rename = "GooglePay[apiVersionMinor]")]
    api_version_minor: u8,
    #[serde(rename = "GooglePay[paymentMethodData][info][assuranceDetails][accountVerified]")]
    account_verified: Option<bool>,
    #[serde(
        rename = "GooglePay[paymentMethodData][info][assuranceDetails][cardHolderAuthenticated]"
    )]
    card_holder_authenticated: Option<bool>,
    #[serde(rename = "GooglePay[paymentMethodData][info][cardDetails]")]
    card_details: String,
    #[serde(rename = "GooglePay[paymentMethodData][info][cardNetwork]")]
    card_network: String,
    #[serde(rename = "GooglePay[paymentMethodData][tokenizationData][token]")]
    token: Secret<String>,
    #[serde(rename = "GooglePay[paymentMethodData][tokenizationData][type]")]
    tokenization_data_type: Secret<String>,
    #[serde(rename = "GooglePay[paymentMethodData][type]")]
    pm_type: String,
    #[serde(rename = "SCREAMING_SNAKE_CASE")]
    token_type: FiuuTokenType,
    #[serde(rename = "non_3DS")]
    non_3ds: i32,
}

pub fn calculate_signature(
    signature_data: String,
) -> Result<Secret<String>, error_stack::Report<errors::ConnectorError>> {
    let message = signature_data.as_bytes();
    let encoded_data = hex::encode(
        crypto::Md5
            .generate_digest(message)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?,
    );
    Ok(Secret::new(encoded_data))
}

impl
    TryFrom<
        &FiuuRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for FiuuPaymentRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &FiuuRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = FiuuAuthType::try_from(&item.router_data.connector_auth_type)?;
        let merchant_id = auth.merchant_id.peek().to_string();
        let txn_currency = item.router_data.request.currency;
        let converter = StringMajorUnitForConnector;
        let amount = converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;
        let txn_amount = amount;
        let reference_no = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        let verify_key = auth.verify_key.peek().to_string();
        let signature = calculate_signature(format!(
            "{}{merchant_id}{reference_no}{verify_key}",
            txn_amount.get_amount_as_string()
        ))?;
        let txn_type = match item.router_data.request.is_auto_capture()? {
            true => TxnType::Sals,
            false => TxnType::Auts,
        };
        let return_url = item.router_data.request.router_return_url.clone();
        let non_3ds = match item.router_data.request.enrolled_for_3ds {
            false => 1,
            true => 0,
        };
        let notification_url = Some(
            Url::parse(&item.router_data.request.get_webhook_url()?)
                .change_context(errors::ConnectorError::RequestEncodingFailed)?,
        );
        let payment_method_data = match item
            .router_data
            .request
            .mandate_id
            .clone()
            .and_then(|mandate_id| mandate_id.mandate_reference_id)
        {
            None => match item.router_data.request.payment_method_data {
                PaymentMethodData::Card(ref card) => {
                    FiuuPaymentMethodData::try_from((card, &item.router_data))
                }
                PaymentMethodData::RealTimePayment(ref real_time_payment_data) => {
                    match *real_time_payment_data.clone() {
                        RealTimePaymentData::DuitNow {} => {
                            Ok(FiuuPaymentMethodData::FiuuQRData(Box::new(FiuuQRData {
                                txn_channel: TxnChannel::RppDuitNowQr,
                            })))
                        }
                        RealTimePaymentData::Fps {}
                        | RealTimePaymentData::PromptPay {}
                        | RealTimePaymentData::VietQr {} => {
                            Err(errors::ConnectorError::NotImplemented(
                                utils::get_unimplemented_payment_method_error_message("fiuu"),
                            )
                            .into())
                        }
                    }
                }
                PaymentMethodData::BankRedirect(ref bank_redirect_data) => match bank_redirect_data
                {
                    BankRedirectData::OnlineBankingFpx { ref issuer } => {
                        Ok(FiuuPaymentMethodData::FiuuFpxData(Box::new(FiuuFPXData {
                            txn_channel: FPXTxnChannel::try_from(*issuer)?,
                            non_3ds,
                        })))
                    }
                    BankRedirectData::BancontactCard { .. }
                    | BankRedirectData::Bizum {}
                    | BankRedirectData::Blik { .. }
                    | BankRedirectData::Eft { .. }
                    | BankRedirectData::Eps { .. }
                    | BankRedirectData::Giropay { .. }
                    | BankRedirectData::Ideal { .. }
                    | BankRedirectData::Interac { .. }
                    | BankRedirectData::OnlineBankingCzechRepublic { .. }
                    | BankRedirectData::OnlineBankingFinland { .. }
                    | BankRedirectData::OnlineBankingPoland { .. }
                    | BankRedirectData::OnlineBankingSlovakia { .. }
                    | BankRedirectData::OpenBankingUk { .. }
                    | BankRedirectData::Przelewy24 { .. }
                    | BankRedirectData::Sofort { .. }
                    | BankRedirectData::Trustly { .. }
                    | BankRedirectData::OnlineBankingThailand { .. }
                    | BankRedirectData::LocalBankRedirect {} => {
                        Err(errors::ConnectorError::NotImplemented(
                            utils::get_unimplemented_payment_method_error_message("fiuu"),
                        )
                        .into())
                    }
                },
                PaymentMethodData::Wallet(ref wallet_data) => match wallet_data {
                    WalletData::GooglePay(google_pay_data) => {
                        FiuuPaymentMethodData::try_from(google_pay_data)
                    }
                    WalletData::ApplePay(_apple_pay_data) => {
                        let payment_method_token = item
                            .router_data
                            .resource_common_data
                            .get_payment_method_token()?;
                        match payment_method_token {
                            PaymentMethodToken::Token(_) => {
                                Err(unimplemented_payment_method!("Apple Pay", "Manual", "Fiuu"))?
                            }
                            PaymentMethodToken::ApplePayDecrypt(decrypt_data) => {
                                FiuuPaymentMethodData::try_from(decrypt_data)
                            }
                            PaymentMethodToken::PazeDecrypt(_) => {
                                Err(unimplemented_payment_method!("Paze", "Fiuu"))?
                            }
                            PaymentMethodToken::GooglePayDecrypt(_) => {
                                Err(unimplemented_payment_method!("Google Pay", "Fiuu"))?
                            }
                        }
                    }
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
                    | WalletData::Mifinity(_)
                    | WalletData::RevolutPay(_) => Err(errors::ConnectorError::NotImplemented(
                        utils::get_unimplemented_payment_method_error_message("fiuu"),
                    )
                    .into()),
                },
                PaymentMethodData::CardRedirect(_)
                | PaymentMethodData::PayLater(_)
                | PaymentMethodData::BankDebit(_)
                | PaymentMethodData::BankTransfer(_)
                | PaymentMethodData::Crypto(_)
                | PaymentMethodData::MandatePayment
                | PaymentMethodData::MobilePayment(_)
                | PaymentMethodData::Reward
                | PaymentMethodData::Upi(_)
                | PaymentMethodData::Voucher(_)
                | PaymentMethodData::GiftCard(_)
                | PaymentMethodData::CardToken(_)
                | PaymentMethodData::OpenBanking(_)
                | PaymentMethodData::NetworkToken(_)
                | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                    Err(errors::ConnectorError::NotImplemented(
                        utils::get_unimplemented_payment_method_error_message("fiuu"),
                    )
                    .into())
                }
            },
            // Card payments using network transaction ID
            Some(MandateReferenceId::NetworkMandateId(network_transaction_id)) => {
                match item.router_data.request.payment_method_data {
                    PaymentMethodData::CardDetailsForNetworkTransactionId(ref raw_card_details) => {
                        FiuuPaymentMethodData::try_from((raw_card_details, network_transaction_id))
                    }
                    _ => Err(errors::ConnectorError::NotImplemented(
                        utils::get_unimplemented_payment_method_error_message("fiuu"),
                    )
                    .into()),
                }
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("fiuu"),
            )
            .into()),
        }?;

        Ok(Self {
            merchant_id: auth.merchant_id,
            reference_no,
            txn_type,
            txn_currency,
            txn_amount,
            return_url,
            payment_method_data,
            signature,
            notification_url,
        })
    }
}

impl
    TryFrom<(
        &Card,
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    )> for FiuuPaymentMethodData
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (req_card, item): (
            &Card,
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ),
    ) -> Result<Self, Self::Error> {
        let (mps_token_status, customer_email) = (Some(3), None);
        let non_3ds = match item.request.enrolled_for_3ds {
            false => 1,
            true => 0,
        };
        Ok(Self::FiuuCardData(Box::new(FiuuCardData {
            txn_channel: TxnChannel::Creditan,
            non_3ds,
            cc_pan: req_card.card_number.clone(),
            cc_cvv2: req_card.card_cvc.clone(),
            cc_month: req_card.card_exp_month.clone(),
            cc_year: req_card.card_exp_year.clone(),
            mps_token_status,
            customer_email,
        })))
    }
}

impl TryFrom<(&CardDetailsForNetworkTransactionId, String)> for FiuuPaymentMethodData {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (raw_card_data, network_transaction_id): (&CardDetailsForNetworkTransactionId, String),
    ) -> Result<Self, Self::Error> {
        Ok(Self::FiuuCardWithNTI(Box::new(FiuuCardWithNTI {
            txn_channel: TxnChannel::Creditan,
            cc_pan: raw_card_data.card_number.clone(),
            cc_month: raw_card_data.card_exp_month.clone(),
            cc_year: raw_card_data.card_exp_year.clone(),
            original_scheme_id: Secret::new(network_transaction_id),
        })))
    }
}

impl TryFrom<&GooglePayWalletData> for FiuuPaymentMethodData {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(data: &GooglePayWalletData) -> Result<Self, Self::Error> {
        Ok(Self::FiuuGooglePayData(Box::new(FiuuGooglePayData {
            txn_channel: TxnChannel::Creditan,
            api_version: GOOGLEPAY_API_VERSION,
            api_version_minor: GOOGLEPAY_API_VERSION_MINOR,
            account_verified: data
                .info
                .assurance_details
                .as_ref()
                .map(|details| details.account_verified),
            card_holder_authenticated: data
                .info
                .assurance_details
                .as_ref()
                .map(|details| details.card_holder_authenticated),
            card_details: data.info.card_details.clone(),
            card_network: data.info.card_network.clone(),
            token: data.tokenization_data.token.clone().into(),
            tokenization_data_type: data.tokenization_data.token_type.clone().into(),
            pm_type: data.pm_type.clone(),
            token_type: FiuuTokenType::GooglePay,
            // non_3ds field Applicable to card processing via specific processor using specific currency for pre-approved partner only.
            // Equal to 0 by default and 1 for non-3DS transaction, That is why it is hardcoded to 1 for googlepay transactions.
            non_3ds: 1,
        })))
    }
}

impl TryFrom<Box<ApplePayPredecryptData>> for FiuuPaymentMethodData {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(decrypt_data: Box<ApplePayPredecryptData>) -> Result<Self, Self::Error> {
        Ok(Self::FiuuApplePayData(Box::new(FiuuApplePayData {
            txn_channel: TxnChannel::Creditan,
            cc_month: decrypt_data.get_expiry_month()?,
            cc_year: decrypt_data.get_four_digit_expiry_year()?,
            cc_token: decrypt_data.application_primary_account_number,
            eci: decrypt_data.payment_data.eci_indicator,
            token_cryptogram: decrypt_data.payment_data.online_payment_cryptogram,
            token_type: FiuuTokenType::ApplePay,
            // non_3ds field Applicable to card processing via specific processor using specific currency for pre-approved partner only.
            // Equal to 0 by default and 1 for non-3DS transaction, That is why it is hardcoded to 1 for apple pay decrypt flow transactions.
            non_3ds: 1,
        })))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PaymentsResponse {
    pub reference_no: String,
    #[serde(rename = "TxnID")]
    pub txn_id: String,
    pub txn_type: TxnType,
    pub txn_currency: Currency,
    pub txn_amount: StringMajorUnit,
    pub txn_channel: String,
    pub txn_data: TxnData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DuitNowQrCodeResponse {
    pub reference_no: String,
    pub txn_type: TxnType,
    pub txn_currency: Currency,
    pub txn_amount: StringMajorUnit,
    pub txn_channel: String,
    #[serde(rename = "TxnID")]
    pub txn_id: String,
    pub txn_data: QrTxnData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct QrTxnData {
    pub request_data: QrRequestData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QrRequestData {
    pub qr_data: Secret<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FiuuPaymentsResponse {
    PaymentResponse(Box<PaymentsResponse>),
    QRPaymentResponse(Box<DuitNowQrCodeResponse>),
    Error(FiuuErrorResponse),
    RecurringResponse(Vec<Box<FiuuRecurringResponse>>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FiuuRecurringResponse {
    status: FiuuRecurringStautus,
    #[serde(rename = "orderid")]
    order_id: String,
    #[serde(rename = "tranID")]
    tran_id: Option<String>,
    reason: Option<String>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum FiuuRecurringStautus {
    Accepted,
    Failed,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TxnData {
    #[serde(rename = "RequestURL")]
    pub request_url: String,
    pub request_type: RequestType,
    pub request_data: RequestData,
    pub request_method: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RequestType {
    Redirect,
    Response,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestData {
    NonThreeDS(NonThreeDSResponseData),
    RedirectData(Option<HashMap<String, String>>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QrCodeData {
    #[serde(rename = "tranID")]
    pub tran_id: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NonThreeDSResponseData {
    #[serde(rename = "tranID")]
    pub tran_id: String,
    pub status: String,
    #[serde(rename = "extraP")]
    pub extra_parameters: Option<ExtraParameters>,
    pub error_code: Option<String>,
    pub error_desc: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExtraParameters {
    pub token: Option<Secret<String>>,
}

impl<F> TryFrom<ResponseRouterData<FiuuPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<FiuuPaymentsResponse, Self>) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code: _http_code,
        } = item;
        match response {
            FiuuPaymentsResponse::QRPaymentResponse(ref response) => Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::AuthenticationPending,
                    ..router_data.resource_common_data
                },
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(response.txn_id.clone()),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: get_qr_metadata(response)?,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    raw_connector_response: None,
                    status_code: Some(item.http_code),
                }),
                ..router_data
            }),
            FiuuPaymentsResponse::Error(error) => Ok(Self {
                response: Err(ErrorResponse {
                    code: error.error_code.clone(),
                    message: error.error_desc.clone(),
                    reason: Some(error.error_desc),
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                    raw_connector_response: None,
                }),
                ..router_data
            }),
            FiuuPaymentsResponse::PaymentResponse(data) => match data.txn_data.request_data {
                RequestData::RedirectData(redirection_data) => {
                    let redirection_data = Some(RedirectForm::Form {
                        endpoint: data.txn_data.request_url.to_string(),
                        method: if data.txn_data.request_method.as_str() == "POST" {
                            Method::Post
                        } else {
                            Method::Get
                        },
                        form_fields: redirection_data.unwrap_or_default(),
                    });
                    Ok(Self {
                        resource_common_data: PaymentFlowData {
                            status: common_enums::AttemptStatus::AuthenticationPending,
                            ..router_data.resource_common_data
                        },
                        response: Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(data.txn_id),
                            redirection_data: redirection_data.map(Box::new),
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            raw_connector_response: None,
                            status_code: Some(item.http_code),
                        }),
                        ..router_data
                    })
                }
                RequestData::NonThreeDS(non_threeds_data) => {
                    let mandate_reference =
                        non_threeds_data
                            .extra_parameters
                            .as_ref()
                            .and_then(|extra_p| {
                                extra_p.token.as_ref().map(|token| MandateReference {
                                    connector_mandate_id: Some(token.clone().expose()),
                                    payment_method_id: None,
                                })
                            });
                    let status = match non_threeds_data.status.as_str() {
                        "00" => {
                            if router_data.request.is_auto_capture()? {
                                Ok(common_enums::AttemptStatus::Charged)
                            } else {
                                Ok(common_enums::AttemptStatus::Authorized)
                            }
                        }
                        "11" => Ok(common_enums::AttemptStatus::Failure),
                        "22" => Ok(common_enums::AttemptStatus::Pending),
                        other => Err(errors::ConnectorError::UnexpectedResponseError(
                            bytes::Bytes::from(other.to_owned()),
                        )),
                    }?;
                    let response = if status == common_enums::AttemptStatus::Failure {
                        Err(ErrorResponse {
                            code: non_threeds_data
                                .error_code
                                .clone()
                                .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                            message: non_threeds_data
                                .error_desc
                                .clone()
                                .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                            reason: non_threeds_data.error_desc.clone(),
                            status_code: item.http_code,
                            attempt_status: None,
                            connector_transaction_id: Some(data.txn_id),
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                            raw_connector_response: None,
                        })
                    } else {
                        Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(data.txn_id.clone()),
                            redirection_data: None,
                            mandate_reference: mandate_reference.map(Box::new),
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            raw_connector_response: None,
                            status_code: Some(item.http_code),
                        })
                    };
                    Ok(Self {
                        resource_common_data: PaymentFlowData {
                            status,
                            ..router_data.resource_common_data
                        },
                        response,
                        ..router_data
                    })
                }
            },
            FiuuPaymentsResponse::RecurringResponse(ref recurring_response_vec) => {
                let recurring_response_item = recurring_response_vec.first();
                let router_data_response = match recurring_response_item {
                    Some(recurring_response) => {
                        let status =
                            common_enums::AttemptStatus::from(recurring_response.status.clone());
                        let connector_transaction_id = recurring_response
                            .tran_id
                            .as_ref()
                            .map_or(ResponseId::NoResponseId, |tran_id| {
                                ResponseId::ConnectorTransactionId(tran_id.clone())
                            });
                        let response = if status == common_enums::AttemptStatus::Failure {
                            Err(ErrorResponse {
                                code: recurring_response
                                    .reason
                                    .clone()
                                    .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                                message: recurring_response
                                    .reason
                                    .clone()
                                    .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                                reason: recurring_response.reason.clone(),
                                status_code: item.http_code,
                                attempt_status: None,
                                connector_transaction_id: recurring_response.tran_id.clone(),
                                network_advice_code: None,
                                network_decline_code: None,
                                network_error_message: None,
                                raw_connector_response: None,
                            })
                        } else {
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: connector_transaction_id,
                                redirection_data: None,
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: None,
                                connector_response_reference_id: None,
                                incremental_authorization_allowed: None,
                                raw_connector_response: None,
                                status_code: Some(item.http_code),
                            })
                        };
                        Self {
                            resource_common_data: PaymentFlowData {
                                status,
                                ..router_data.resource_common_data
                            },
                            response,
                            ..router_data
                        }
                    }
                    None => {
                        // It is not expected to get empty response from the connnector, if we get we are not updating the payment response since we don't have any info in the authorize response.
                        let response = Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::NoResponseId,
                            redirection_data: None,
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            raw_connector_response: None,
                            status_code: Some(item.http_code),
                        });
                        Self {
                            response,
                            ..router_data
                        }
                    }
                };
                Ok(router_data_response)
            }
        }
    }
}

impl From<FiuuRecurringStautus> for common_enums::AttemptStatus {
    fn from(status: FiuuRecurringStautus) -> Self {
        match status {
            FiuuRecurringStautus::Accepted => Self::Charged,
            FiuuRecurringStautus::Failed => Self::Failure,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct FiuuRefundRequest {
    pub refund_type: RefundType,
    #[serde(rename = "MerchantID")]
    pub merchant_id: Secret<String>,
    #[serde(rename = "RefID")]
    pub ref_id: String,
    #[serde(rename = "TxnID")]
    pub txn_id: String,
    pub amount: StringMajorUnit,
    pub signature: Secret<String>,
    #[serde(rename = "notify_url")]
    pub notify_url: Option<Url>,
}
#[derive(Debug, Serialize, Display)]
pub enum RefundType {
    #[serde(rename = "P")]
    #[strum(serialize = "P")]
    Partial,
}

impl TryFrom<FiuuRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>>
    for FiuuRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: FiuuRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let auth: FiuuAuthType = FiuuAuthType::try_from(&item.router_data.connector_auth_type)?;
        let merchant_id = auth.merchant_id.peek().to_string();
        let converter = StringMajorUnitForConnector;
        let amount = converter
            .convert(
                item.router_data.request.minor_refund_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;
        let txn_amount = amount;
        let reference_no = item
            .router_data
            .resource_common_data
            .refund_id
            .clone()
            .ok_or_else(|| errors::ConnectorError::MissingConnectorRefundID)?;
        let txn_id = item.router_data.request.connector_transaction_id.clone();
        let secret_key = auth.secret_key.peek().to_string();
        Ok(Self {
            refund_type: RefundType::Partial,
            merchant_id: auth.merchant_id,
            ref_id: reference_no.clone(),
            txn_id: txn_id.clone(),
            amount: txn_amount.clone(),
            signature: calculate_signature(format!(
                "{}{merchant_id}{reference_no}{txn_id}{}{secret_key}",
                RefundType::Partial,
                txn_amount.get_amount_as_string()
            ))?,
            notify_url: Some(
                Url::parse(&item.router_data.request.get_webhook_url()?)
                    .change_context(errors::ConnectorError::RequestEncodingFailed)?,
            ),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FiuuRefundSuccessResponse {
    #[serde(rename = "RefundID")]
    refund_id: i64,
    status: String,
    #[serde(rename = "reason")]
    reason: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FiuuRefundResponse {
    Success(FiuuRefundSuccessResponse),
    Error(FiuuErrorResponse),
}
impl<F> TryFrom<ResponseRouterData<FiuuRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<FiuuRefundResponse, Self>) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code: _http_code,
        } = item;
        match response {
            FiuuRefundResponse::Error(error) => Ok(Self {
                response: Err(ErrorResponse {
                    code: error.error_code.clone(),
                    message: error.error_desc.clone(),
                    reason: Some(error.error_desc),
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                    raw_connector_response: None,
                }),
                ..router_data
            }),
            FiuuRefundResponse::Success(refund_data) => {
                let refund_status = match refund_data.status.as_str() {
                    "00" => Ok(common_enums::RefundStatus::Success),
                    "11" => Ok(common_enums::RefundStatus::Failure),
                    "22" => Ok(common_enums::RefundStatus::Pending),
                    other => Err(errors::ConnectorError::UnexpectedResponseError(
                        bytes::Bytes::from(other.to_owned()),
                    )),
                }?;
                if refund_status == common_enums::RefundStatus::Failure {
                    Ok(Self {
                        response: Err(ErrorResponse {
                            code: refund_data.status.clone(),
                            message: refund_data
                                .reason
                                .clone()
                                .unwrap_or(consts::NO_ERROR_MESSAGE.to_string()),
                            reason: refund_data.reason.clone(),
                            status_code: item.http_code,
                            attempt_status: None,
                            connector_transaction_id: Some(refund_data.refund_id.to_string()),
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                            raw_connector_response: None,
                        }),
                        ..router_data
                    })
                } else {
                    Ok(Self {
                        response: Ok(RefundsResponseData {
                            connector_refund_id: refund_data.refund_id.clone().to_string(),
                            refund_status,
                            raw_connector_response: None,
                            status_code: Some(item.http_code),
                        }),
                        ..router_data
                    })
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FiuuErrorResponse {
    pub error_code: String,
    pub error_desc: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FiuuPaymentSyncRequest {
    amount: StringMajorUnit,
    #[serde(rename = "txID")]
    tx_id: String,
    domain: String,
    skey: Secret<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum FiuuPaymentResponse {
    FiuuPaymentSyncResponse(FiuuPaymentSyncResponse),
    FiuuWebhooksPaymentResponse(FiuuWebhooksPaymentResponse),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FiuuPaymentSyncResponse {
    stat_code: StatCode,
    stat_name: StatName,
    #[serde(rename = "TranID")]
    tran_id: String,
    error_code: Option<String>,
    error_desc: Option<String>,
    #[serde(rename = "miscellaneous")]
    miscellaneous: Option<HashMap<String, Secret<String>>>,
    #[serde(rename = "SchemeTransactionID")]
    scheme_transaction_id: Option<Secret<String>>,
}

#[derive(Debug, Serialize, Deserialize, Display, Clone, PartialEq)]
pub enum StatCode {
    #[serde(rename = "00")]
    Success,
    #[serde(rename = "11")]
    Failure,
    #[serde(rename = "22")]
    Pending,
}

#[derive(Debug, Serialize, Deserialize, Display, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StatName {
    Captured,
    Settled,
    Authorized,
    Failed,
    Cancelled,
    Chargeback,
    Release,
    #[serde(rename = "reject/hold")]
    RejectHold,
    Blocked,
    #[serde(rename = "ReqCancel")]
    ReqCancel,
    #[serde(rename = "ReqChargeback")]
    ReqChargeback,
    #[serde(rename = "Pending")]
    Pending,
    #[serde(rename = "Unknown")]
    Unknown,
}
impl
    TryFrom<
        FiuuRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for FiuuPaymentSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: FiuuRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = FiuuAuthType::try_from(&item.router_data.connector_auth_type)?;
        let txn_id = item
            .router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
        let merchant_id = auth.merchant_id.peek().to_string();
        let verify_key = auth.verify_key.peek().to_string();
        let amount = StringMajorUnitForConnector
            .convert(
                item.router_data.request.amount,
                item.router_data.request.currency,
            )
            .change_context(errors::ConnectorError::AmountConversionFailed)?;
        Ok(Self {
            amount: amount.clone(),
            tx_id: txn_id.clone(),
            domain: merchant_id.clone(),
            skey: calculate_signature(format!(
                "{txn_id}{merchant_id}{verify_key}{}",
                amount.get_amount_as_string()
            ))?,
        })
    }
}

struct ErrorInputs {
    encoded_data: Option<String>,
    response_error_code: Option<String>,
    response_error_desc: Option<String>,
}

struct ErrorDetails {
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
}

impl TryFrom<ErrorInputs> for ErrorDetails {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(value: ErrorInputs) -> Result<Self, Self::Error> {
        let query_params = value
            .encoded_data
            .as_ref()
            .map(|encoded_data| {
                serde_urlencoded::from_str::<FiuuPaymentRedirectResponse>(encoded_data)
            })
            .transpose()
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)
            .attach_printable("Failed to deserialize FiuuPaymentRedirectResponse")?;
        let error_message = value
            .response_error_desc
            .as_ref()
            .filter(|s| !s.is_empty())
            .cloned()
            .or_else(|| {
                query_params
                    .as_ref()
                    .and_then(|qp| qp.error_desc.as_ref())
                    .filter(|s| !s.is_empty())
                    .cloned()
            });
        let error_code = value
            .response_error_code
            .as_ref()
            .filter(|s| !s.is_empty())
            .cloned()
            .or_else(|| {
                query_params
                    .as_ref()
                    .and_then(|qp| qp.error_code.as_ref())
                    .filter(|s| !s.is_empty())
                    .cloned()
            })
            .unwrap_or_else(|| consts::NO_ERROR_CODE.to_owned());
        Ok(Self {
            code: error_code,
            message: error_message
                .clone()
                .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_owned()),
            reason: error_message,
        })
    }
}

impl<F> TryFrom<ResponseRouterData<FiuuPaymentResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<FiuuPaymentResponse, Self>) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code: _http_code,
        } = item;
        match response {
            FiuuPaymentResponse::FiuuPaymentSyncResponse(response) => {
                let stat_name = response.stat_name;
                let stat_code = response.stat_code.clone();
                let txn_id = response.tran_id;
                let status = common_enums::AttemptStatus::try_from(FiuuSyncStatus {
                    stat_name,
                    stat_code,
                })?;
                let error_response = if status == common_enums::AttemptStatus::Failure {
                    let error_details = ErrorDetails::try_from(ErrorInputs {
                        encoded_data: router_data.request.encoded_data.clone(),
                        response_error_code: response.error_code.clone(),
                        response_error_desc: response.error_desc.clone(),
                    })?;
                    Some(ErrorResponse {
                        status_code: item.http_code,
                        code: error_details.code,
                        message: error_details.message,
                        reason: error_details.reason,
                        attempt_status: Some(common_enums::AttemptStatus::Failure),
                        connector_transaction_id: Some(txn_id.clone()),
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                        raw_connector_response: None,
                    })
                } else {
                    None
                };
                let payments_response_data = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(txn_id.clone().to_string()),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: response
                        .scheme_transaction_id
                        .as_ref()
                        .map(|id| id.clone().expose()),
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    raw_connector_response: None,
                    status_code: Some(item.http_code),
                };
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        ..router_data.resource_common_data
                    },
                    response: error_response.map_or_else(|| Ok(payments_response_data), Err),
                    ..router_data
                })
            }
            FiuuPaymentResponse::FiuuWebhooksPaymentResponse(response) => {
                let status = common_enums::AttemptStatus::try_from(FiuuWebhookStatus {
                    capture_method: router_data.request.capture_method,
                    status: response.status,
                })?;
                let txn_id = response.tran_id;
                let mandate_reference = response.extra_parameters.as_ref().and_then(|extra_p| {
                    let mandate_token: Result<ExtraParameters, _> =
                        serde_json::from_str(&extra_p.clone().expose());
                    match mandate_token {
                        Ok(token) => token.token.as_ref().map(|token| MandateReference {
                            connector_mandate_id: Some(token.clone().expose()),
                            payment_method_id: None,
                        }),
                        Err(_err) => None,
                    }
                });
                let error_response = if status == common_enums::AttemptStatus::Failure {
                    let error_details = ErrorDetails::try_from(ErrorInputs {
                        encoded_data: router_data.request.encoded_data.clone(),
                        response_error_code: response.error_code.clone(),
                        response_error_desc: response.error_desc.clone(),
                    })?;
                    Some(ErrorResponse {
                        status_code: item.http_code,
                        code: error_details.code,
                        message: error_details.message,
                        reason: error_details.reason,
                        attempt_status: Some(common_enums::AttemptStatus::Failure),
                        connector_transaction_id: Some(txn_id.clone()),
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                        raw_connector_response: None,
                    })
                } else {
                    None
                };
                let payments_response_data = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(txn_id.clone().to_string()),
                    redirection_data: None,
                    mandate_reference: mandate_reference.map(Box::new),
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    raw_connector_response: None,
                    status_code: Some(item.http_code),
                };
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        ..router_data.resource_common_data
                    },
                    response: error_response.map_or_else(|| Ok(payments_response_data), Err),
                    ..router_data
                })
            }
        }
    }
}

pub struct FiuuWebhookStatus {
    pub capture_method: Option<CaptureMethod>,
    pub status: FiuuPaymentWebhookStatus,
}

impl TryFrom<FiuuWebhookStatus> for common_enums::AttemptStatus {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(webhook_status: FiuuWebhookStatus) -> Result<Self, Self::Error> {
        match webhook_status.status {
            FiuuPaymentWebhookStatus::Success => match webhook_status.capture_method {
                Some(CaptureMethod::Automatic) | Some(CaptureMethod::SequentialAutomatic) => {
                    Ok(Self::Charged)
                }
                Some(CaptureMethod::Manual) => Ok(Self::Authorized),
                _ => Err(errors::ConnectorError::UnexpectedResponseError(
                    bytes::Bytes::from(webhook_status.status.to_string()),
                ))?,
            },
            FiuuPaymentWebhookStatus::Failure => Ok(Self::Failure),
            FiuuPaymentWebhookStatus::Pending => Ok(Self::AuthenticationPending),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentCaptureRequest {
    domain: String,
    #[serde(rename = "tranID")]
    tran_id: String,
    amount: StringMajorUnit,
    #[serde(rename = "RefID")]
    ref_id: String,
    skey: Secret<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PaymentCaptureResponse {
    #[serde(rename = "TranID")]
    tran_id: String,
    stat_code: String,
}

pub struct FiuuSyncStatus {
    pub stat_name: StatName,
    pub stat_code: StatCode,
}

impl TryFrom<FiuuSyncStatus> for common_enums::AttemptStatus {
    type Error = errors::ConnectorError;
    fn try_from(sync_status: FiuuSyncStatus) -> Result<Self, Self::Error> {
        match (sync_status.stat_code, sync_status.stat_name) {
            (StatCode::Success, StatName::Captured | StatName::Settled) => Ok(Self::Charged), // For Success as StatCode we can only expect Captured,Settled and Authorized as StatName.
            (StatCode::Success, StatName::Authorized) => Ok(Self::Authorized),
            (StatCode::Pending, StatName::Pending) => Ok(Self::AuthenticationPending), // For Pending as StatCode we can only expect Pending and Unknown as StatName.
            (StatCode::Pending, StatName::Unknown) => Ok(Self::Pending),
            (StatCode::Failure, StatName::Cancelled) | (StatCode::Failure, StatName::ReqCancel) => {
                Ok(Self::Voided)
            }
            (StatCode::Failure, _) => Ok(Self::Failure),
            (other, _) => Err(errors::ConnectorError::UnexpectedResponseError(
                bytes::Bytes::from(other.to_string()),
            )),
        }
    }
}

impl
    TryFrom<
        FiuuRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for PaymentCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: FiuuRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = FiuuAuthType::try_from(&item.router_data.connector_auth_type)?;
        let merchant_id = auth.merchant_id.peek().to_string();
        let converter = StringMajorUnitForConnector;
        let amount = converter
            .convert(
                item.router_data.request.minor_amount_to_capture,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;
        let txn_id = match item.router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(tid) => tid,
            _ => {
                return Err(errors::ConnectorError::MissingConnectorTransactionID.into());
            }
        };
        let verify_key = auth.verify_key.peek().to_string();
        let signature = calculate_signature(format!(
            "{txn_id}{}{merchant_id}{verify_key}",
            amount.get_amount_as_string()
        ))?;
        Ok(Self {
            domain: merchant_id,
            tran_id: txn_id,
            amount,
            ref_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            skey: signature,
        })
    }
}
fn capture_status_codes() -> HashMap<&'static str, &'static str> {
    [
        ("00", "Capture successful"),
        ("11", "Capture failed"),
        ("12", "Invalid or unmatched security hash string"),
        ("13", "Not a credit card transaction"),
        ("15", "Requested day is on settlement day"),
        ("16", "Forbidden transaction"),
        ("17", "Transaction not found"),
        ("18", "Missing required parameter"),
        ("19", "Domain not found"),
        ("20", "Temporary out of service"),
        ("21", "Authorization expired"),
        ("23", "Partial capture not allowed"),
        ("24", "Transaction already captured"),
        ("25", "Requested amount exceeds available capture amount"),
        ("99", "General error (contact payment gateway support)"),
    ]
    .into_iter()
    .collect()
}

impl<F> TryFrom<ResponseRouterData<PaymentCaptureResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaymentCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code: _http_code,
        } = item;
        let status_code = response.stat_code;

        let status = match status_code.as_str() {
            "00" => Ok(common_enums::AttemptStatus::Charged),
            "22" => Ok(common_enums::AttemptStatus::Pending),
            "11" | "12" | "13" | "15" | "16" | "17" | "18" | "19" | "20" | "21" | "23" | "24"
            | "25" | "99" => Ok(common_enums::AttemptStatus::Failure),
            other => Err(errors::ConnectorError::UnexpectedResponseError(
                bytes::Bytes::from(other.to_owned()),
            )),
        }?;
        let capture_message_status = capture_status_codes();
        let error_response = if status == common_enums::AttemptStatus::Failure {
            let optional_message = capture_message_status
                .get(status_code.as_str())
                .copied()
                .map(String::from);
            Some(ErrorResponse {
                status_code: item.http_code,
                code: status_code.to_owned(),
                message: optional_message
                    .clone()
                    .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                reason: optional_message,
                attempt_status: None,
                connector_transaction_id: Some(response.tran_id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                raw_connector_response: None,
            })
        } else {
            None
        };
        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.tran_id.clone().to_string()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            raw_connector_response: None,
            status_code: Some(item.http_code),
        };
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: error_response.map_or_else(|| Ok(payments_response_data), Err),
            ..router_data
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FiuuPaymentCancelRequest {
    #[serde(rename = "txnID")]
    txn_id: String,
    domain: String,
    skey: Secret<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FiuuPaymentCancelResponse {
    #[serde(rename = "TranID")]
    tran_id: String,
    stat_code: String,
    #[serde(rename = "miscellaneous")]
    miscellaneous: Option<HashMap<String, Secret<String>>>,
}

impl
    TryFrom<
        FiuuRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>,
    > for FiuuPaymentCancelRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: FiuuRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = FiuuAuthType::try_from(&item.router_data.connector_auth_type)?;
        let txn_id = item.router_data.request.connector_transaction_id.clone();
        let merchant_id = auth.merchant_id.peek().to_string();
        let secret_key = auth.secret_key.peek().to_string();
        Ok(Self {
            txn_id: txn_id.clone(),
            domain: merchant_id.clone(),
            skey: calculate_signature(format!("{txn_id}{merchant_id}{secret_key}"))?,
        })
    }
}

fn void_status_codes() -> HashMap<&'static str, &'static str> {
    [
        ("00", "Success (will proceed the request)"),
        ("11", "Failure"),
        ("12", "Invalid or unmatched security hash string"),
        ("13", "Not a refundable transaction"),
        ("14", "Transaction date more than 180 days"),
        ("15", "Requested day is on settlement day"),
        ("16", "Forbidden transaction"),
        ("17", "Transaction not found"),
        ("18", "Duplicate partial refund request"),
        ("19", "Merchant not found"),
        ("20", "Missing required parameter"),
        (
            "21",
            "Transaction must be in authorized/captured/settled status",
        ),
    ]
    .into_iter()
    .collect()
}
impl<F> TryFrom<ResponseRouterData<FiuuPaymentCancelResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiuuPaymentCancelResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code: _http_code,
        } = item;
        let status_code = response.stat_code;
        let status = match status_code.as_str() {
            "00" => Ok(common_enums::AttemptStatus::Voided),
            "11" | "12" | "13" | "14" | "15" | "16" | "17" | "18" | "19" | "20" | "21" => {
                Ok(common_enums::AttemptStatus::VoidFailed)
            }
            other => Err(errors::ConnectorError::UnexpectedResponseError(
                bytes::Bytes::from(other.to_owned()),
            )),
        }?;
        let void_message_status = void_status_codes();
        let error_response = if status == common_enums::AttemptStatus::VoidFailed {
            let optional_message = void_message_status
                .get(status_code.as_str())
                .copied()
                .map(String::from);

            Some(ErrorResponse {
                status_code: item.http_code,
                code: status_code.to_owned(),
                message: optional_message
                    .clone()
                    .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                reason: optional_message,
                attempt_status: None,
                connector_transaction_id: Some(response.tran_id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                raw_connector_response: None,
            })
        } else {
            None
        };
        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.tran_id.clone().to_string()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            raw_connector_response: None,
            status_code: Some(item.http_code),
        };
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: error_response.map_or_else(|| Ok(payments_response_data), Err),
            ..router_data
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FiuuRefundSyncRequest {
    #[serde(rename = "TxnID")]
    txn_id: String,
    #[serde(rename = "MerchantID")]
    merchant_id: Secret<String>,
    signature: Secret<String>,
}

impl
    TryFrom<
        FiuuRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>,
    > for FiuuRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: FiuuRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = FiuuAuthType::try_from(&item.router_data.connector_auth_type)?;
        let (txn_id, merchant_id, verify_key) = (
            item.router_data.request.connector_transaction_id.clone(),
            auth.merchant_id.peek().to_string(),
            auth.verify_key.peek().to_string(),
        );
        let signature = calculate_signature(format!("{txn_id}{merchant_id}{verify_key}"))?;
        Ok(Self {
            txn_id,
            merchant_id: auth.merchant_id,
            signature,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FiuuRefundSyncResponse {
    Success(Vec<RefundData>),
    Error(FiuuErrorResponse),
    Webhook(FiuuWebhooksRefundResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RefundData {
    #[serde(rename = "RefundID")]
    refund_id: String,
    status: RefundStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RefundStatus {
    Success,
    Pending,
    Rejected,
    Processing,
}

impl<F> TryFrom<ResponseRouterData<FiuuRefundSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<FiuuRefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code: _http_code,
        } = item;
        match response {
            FiuuRefundSyncResponse::Error(error) => Ok(Self {
                response: Err(ErrorResponse {
                    code: error.error_code.clone(),
                    message: error.error_desc.clone(),
                    reason: Some(error.error_desc),
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                    raw_connector_response: None,
                }),
                ..router_data
            }),
            FiuuRefundSyncResponse::Success(refund_data) => {
                let refund = refund_data
                    .iter()
                    .find(|refund| {
                        Some(refund.refund_id.clone())
                            == Some(router_data.request.connector_refund_id.clone())
                    })
                    .ok_or_else(|| errors::ConnectorError::MissingConnectorRefundID)?;
                Ok(Self {
                    response: Ok(RefundsResponseData {
                        connector_refund_id: refund.refund_id.clone(),
                        refund_status: common_enums::RefundStatus::from(refund.status.clone()),
                        raw_connector_response: None,
                        status_code: Some(item.http_code),
                    }),
                    ..router_data
                })
            }
            FiuuRefundSyncResponse::Webhook(fiuu_webhooks_refund_response) => Ok(Self {
                response: Ok(RefundsResponseData {
                    connector_refund_id: fiuu_webhooks_refund_response.refund_id,
                    refund_status: common_enums::RefundStatus::from(
                        fiuu_webhooks_refund_response.status.clone(),
                    ),
                    raw_connector_response: None,
                    status_code: Some(item.http_code),
                }),
                ..router_data
            }),
        }
    }
}

impl From<RefundStatus> for common_enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Pending => Self::Pending,
            RefundStatus::Success => Self::Success,
            RefundStatus::Rejected => Self::Failure,
            RefundStatus::Processing => Self::Pending,
        }
    }
}

pub fn get_qr_metadata(
    response: &DuitNowQrCodeResponse,
) -> CustomResult<Option<serde_json::Value>, errors::ConnectorError> {
    let image_data = QrImage::new_colored_from_data(
        response.txn_data.request_data.qr_data.peek().clone(),
        DUIT_NOW_BRAND_COLOR,
    )
    .change_context(errors::ConnectorError::ResponseHandlingFailed)?;

    let image_data_url = Url::parse(image_data.data.clone().as_str()).ok();
    let display_to_timestamp = None;

    if let Some(color_image_data_url) = image_data_url {
        let qr_code_info = QrCodeInformation::QrColorDataUrl {
            color_image_data_url,
            display_to_timestamp,
            display_text: Some(DUIT_NOW_BRAND_TEXT.to_string()),
            border_color: Some(DUIT_NOW_BRAND_COLOR.to_string()),
        };

        Some(qr_code_info.encode_to_value())
            .transpose()
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    } else {
        Ok(None)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum FiuuWebhooksResponse {
    FiuuWebhookPaymentResponse(FiuuWebhooksPaymentResponse),
    FiuuWebhookRefundResponse(FiuuWebhooksRefundResponse),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FiuuWebhooksPaymentResponse {
    pub skey: Secret<String>,
    pub status: FiuuPaymentWebhookStatus,
    #[serde(rename = "orderid")]
    pub order_id: String,
    #[serde(rename = "tranID")]
    pub tran_id: String,
    pub nbcb: String,
    pub amount: StringMajorUnit,
    pub currency: String,
    pub domain: Secret<String>,
    pub appcode: Option<Secret<String>>,
    pub paydate: String,
    pub channel: String,
    pub error_desc: Option<String>,
    pub error_code: Option<String>,
    #[serde(rename = "extraP")]
    pub extra_parameters: Option<Secret<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FiuuPaymentRedirectResponse {
    pub skey: Secret<String>,
    #[serde(rename = "tranID")]
    pub tran_id: String,
    pub status: FiuuPaymentWebhookStatus,
    pub appcode: Option<String>,
    pub error_code: Option<String>,
    pub error_desc: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FiuuWebhooksRefundResponse {
    pub refund_type: FiuuWebhooksRefundType,
    #[serde(rename = "MerchantID")]
    pub merchant_id: Secret<String>,
    #[serde(rename = "RefID")]
    pub ref_id: String,
    #[serde(rename = "RefundID")]
    pub refund_id: String,
    #[serde(rename = "TxnID")]
    pub txn_id: String,
    pub amount: StringMajorUnit,
    pub status: FiuuRefundsWebhookStatus,
    pub signature: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, strum::Display)]
pub enum FiuuRefundsWebhookStatus {
    #[strum(serialize = "00")]
    #[serde(rename = "00")]
    RefundSuccess,
    #[strum(serialize = "11")]
    #[serde(rename = "11")]
    RefundFailure,
    #[strum(serialize = "22")]
    #[serde(rename = "22")]
    RefundPending,
}

#[derive(Debug, Deserialize, Serialize, Clone, strum::Display)]
pub enum FiuuWebhooksRefundType {
    P,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FiuuWebhookSignature {
    pub skey: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FiuuWebhookResourceId {
    pub skey: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FiuWebhookEvent {
    pub status: FiuuPaymentWebhookStatus,
}

#[derive(Debug, Deserialize, Serialize, Clone, strum::Display)]
pub enum FiuuPaymentWebhookStatus {
    #[strum(serialize = "00")]
    #[serde(rename = "00")]
    Success,
    #[strum(serialize = "11")]
    #[serde(rename = "11")]
    Failure,
    #[strum(serialize = "22")]
    #[serde(rename = "22")]
    Pending,
}

impl From<FiuuPaymentWebhookStatus> for StatCode {
    fn from(value: FiuuPaymentWebhookStatus) -> Self {
        match value {
            FiuuPaymentWebhookStatus::Success => Self::Success,
            FiuuPaymentWebhookStatus::Failure => Self::Failure,
            FiuuPaymentWebhookStatus::Pending => Self::Pending,
        }
    }
}

impl From<FiuuPaymentWebhookStatus> for interfaces::webhooks::IncomingWebhookEvent {
    fn from(value: FiuuPaymentWebhookStatus) -> Self {
        match value {
            FiuuPaymentWebhookStatus::Success => Self::PaymentIntentSuccess,
            FiuuPaymentWebhookStatus::Failure => Self::PaymentIntentFailure,
            FiuuPaymentWebhookStatus::Pending => Self::PaymentIntentProcessing,
        }
    }
}

impl From<FiuuRefundsWebhookStatus> for interfaces::webhooks::IncomingWebhookEvent {
    fn from(value: FiuuRefundsWebhookStatus) -> Self {
        match value {
            FiuuRefundsWebhookStatus::RefundSuccess => Self::RefundSuccess,
            FiuuRefundsWebhookStatus::RefundFailure => Self::RefundFailure,
            FiuuRefundsWebhookStatus::RefundPending => Self::EventNotSupported,
        }
    }
}

impl From<FiuuRefundsWebhookStatus> for common_enums::RefundStatus {
    fn from(value: FiuuRefundsWebhookStatus) -> Self {
        match value {
            FiuuRefundsWebhookStatus::RefundFailure => Self::Failure,
            FiuuRefundsWebhookStatus::RefundSuccess => Self::Success,
            FiuuRefundsWebhookStatus::RefundPending => Self::Pending,
        }
    }
}

//new additions  structs
#[derive(Serialize, Debug, Clone)]
#[serde(untagged)]
pub enum FiuuPaymentsRequest {
    FiuuPaymentRequest(Box<FiuuPaymentRequest>),
    FiuuMandateRequest(FiuuMandateRequest),
}

impl GetFormData for FiuuPaymentsRequest {
    fn get_form_data(&self) -> reqwest::multipart::Form {
        match self {
            FiuuPaymentsRequest::FiuuPaymentRequest(req) => {
                build_form_from_struct(req).unwrap_or_else(|_| reqwest::multipart::Form::new())
            }
            FiuuPaymentsRequest::FiuuMandateRequest(req) => {
                build_form_from_struct(req).unwrap_or_else(|_| reqwest::multipart::Form::new())
            }
        }
    }
}

impl GetFormData for FiuuPaymentSyncRequest {
    fn get_form_data(&self) -> reqwest::multipart::Form {
        build_form_from_struct(self).unwrap_or_else(|_| reqwest::multipart::Form::new())
    }
}
impl GetFormData for PaymentCaptureRequest {
    fn get_form_data(&self) -> reqwest::multipart::Form {
        build_form_from_struct(self).unwrap_or_else(|_| reqwest::multipart::Form::new())
    }
}
impl GetFormData for FiuuPaymentCancelRequest {
    fn get_form_data(&self) -> reqwest::multipart::Form {
        build_form_from_struct(self).unwrap_or_else(|_| reqwest::multipart::Form::new())
    }
}
impl GetFormData for FiuuRefundRequest {
    fn get_form_data(&self) -> reqwest::multipart::Form {
        build_form_from_struct(self).unwrap_or_else(|_| reqwest::multipart::Form::new())
    }
}
impl GetFormData for FiuuRefundSyncRequest {
    fn get_form_data(&self) -> reqwest::multipart::Form {
        build_form_from_struct(self).unwrap_or_else(|_| reqwest::multipart::Form::new())
    }
}

pub fn build_form_from_struct<T: Serialize>(
    data: T,
) -> Result<reqwest::multipart::Form, errors::ParsingError> {
    let mut form = reqwest::multipart::Form::new();
    let serialized =
        serde_json::to_value(&data).map_err(|_| errors::ParsingError::EncodeError("json-value"))?;
    let serialized_object = serialized
        .as_object()
        .ok_or(errors::ParsingError::EncodeError("Expected object"))?;
    for (key, values) in serialized_object {
        let value = match values {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Array(_) | Value::Object(_) | Value::Null => "".to_string(),
        };
        form = form.text(key.clone(), value.clone());
    }
    Ok(form)
}

impl
    TryFrom<
        FiuuRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for FiuuPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: FiuuRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let optional_is_mit_flow = item.router_data.request.off_session;
        let optional_is_nti_flow = item
            .router_data
            .request
            .mandate_id
            .as_ref()
            .map(|mandate_id| mandate_id.is_network_transaction_id_flow());
        match (optional_is_mit_flow, optional_is_nti_flow) {
            (Some(true), Some(false)) => {
                let recurring_request = FiuuMandateRequest::try_from(&item)?;
                Ok(FiuuPaymentsRequest::FiuuMandateRequest(recurring_request))
            }
            _ => {
                let payment_request: FiuuPaymentRequest = FiuuPaymentRequest::try_from(&item)?;
                Ok(FiuuPaymentsRequest::FiuuPaymentRequest(Box::new(
                    payment_request,
                )))
            }
        }
    }
}

#[macro_export]
macro_rules! unimplemented_payment_method {
    ($payment_method:expr, $connector:expr) => {
        errors::ConnectorError::NotImplemented(format!(
            "{} through {}",
            $payment_method, $connector
        ))
    };
    ($payment_method:expr, $flow:expr, $connector:expr) => {
        errors::ConnectorError::NotImplemented(format!(
            "{} {} through {}",
            $payment_method, $flow, $connector
        ))
    };
}

use crate::unimplemented_payment_method;

pub const DUIT_NOW_BRAND_COLOR: &str = "#ED2E67";

pub const DUIT_NOW_BRAND_TEXT: &str = "MALAYSIA NATIONAL QR";

#[derive(Debug)]
pub struct QrImage {
    pub data: String,
}

// Qr Image data source starts with this string
// The base64 image data will be appended to it to image data source
pub(crate) const QR_IMAGE_DATA_SOURCE_STRING: &str = "data:image/png;base64";

impl QrImage {
    pub fn new_from_data(data: String) -> Result<Self, error_stack::Report<QrCodeError>> {
        let qr_code = qrcode::QrCode::new(data.as_bytes())
            .change_context(QrCodeError::FailedToCreateQrCode)?;

        let qrcode_image_buffer = qr_code.render::<Luma<u8>>().build();
        let qrcode_dynamic_image = DynamicImage::ImageLuma8(qrcode_image_buffer);

        let mut image_bytes = std::io::BufWriter::new(std::io::Cursor::new(Vec::new()));

        // Encodes qrcode_dynamic_image and write it to image_bytes
        let _ = qrcode_dynamic_image.write_to(&mut image_bytes, ImageFormat::Png);

        let image_data_source = format!(
            "{},{}",
            QR_IMAGE_DATA_SOURCE_STRING,
            BASE64_ENGINE.encode(image_bytes.buffer())
        );
        Ok(Self {
            data: image_data_source,
        })
    }

    pub fn new_colored_from_data(
        data: String,
        hex_color: &str,
    ) -> Result<Self, error_stack::Report<QrCodeError>> {
        let qr_code = qrcode::QrCode::new(data.as_bytes())
            .change_context(QrCodeError::FailedToCreateQrCode)?;

        let qrcode_image_buffer = qr_code.render::<Luma<u8>>().build();
        let (width, height) = qrcode_image_buffer.dimensions();
        let mut colored_image = ImageBuffer::new(width, height);
        let rgb = Self::parse_hex_color(hex_color)?;

        for (x, y, pixel) in qrcode_image_buffer.enumerate_pixels() {
            let luminance = pixel.0[0];
            let color = if luminance == 0 {
                Rgba([rgb.0, rgb.1, rgb.2, 255])
            } else {
                Rgba([255, 255, 255, 255])
            };
            colored_image.put_pixel(x, y, color);
        }

        let qrcode_dynamic_image = DynamicImage::ImageRgba8(colored_image);
        let mut image_bytes = std::io::Cursor::new(Vec::new());
        qrcode_dynamic_image
            .write_to(&mut image_bytes, ImageFormat::Png)
            .change_context(QrCodeError::FailedToCreateQrCode)?;

        let image_data_source = format!(
            "{},{}",
            QR_IMAGE_DATA_SOURCE_STRING,
            BASE64_ENGINE.encode(image_bytes.get_ref())
        );

        Ok(Self {
            data: image_data_source,
        })
    }

    pub fn parse_hex_color(hex: &str) -> Result<(u8, u8, u8), QrCodeError> {
        let hex = hex.trim_start_matches('#');
        if hex.len() == 6 {
            let r = u8::from_str_radix(&hex[0..2], 16).ok();
            let g = u8::from_str_radix(&hex[2..4], 16).ok();
            let b = u8::from_str_radix(&hex[4..6], 16).ok();
            if let (Some(r), Some(g), Some(b)) = (r, g, b) {
                return Ok((r, g, b));
            }
        }
        Err(QrCodeError::InvalidHexColor)
    }
}

/// Errors for Qr code handling
#[derive(Debug, thiserror::Error)]
pub enum QrCodeError {
    /// Failed to encode data into Qr code
    #[error("Failed to create Qr code")]
    FailedToCreateQrCode,
    /// Failed to parse hex color
    #[error("Invalid hex color code supplied")]
    InvalidHexColor,
}

use base64::Engine;

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

use image::{DynamicImage, ImageBuffer, ImageFormat, Luma, Rgba};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
// the enum order shouldn't be changed as this is being used during serialization and deserialization
pub enum QrCodeInformation {
    QrCodeUrl {
        image_data_url: Url,
        qr_code_url: Url,
        display_to_timestamp: Option<i64>,
    },
    QrDataUrl {
        image_data_url: Url,
        display_to_timestamp: Option<i64>,
    },
    QrCodeImageUrl {
        qr_code_url: Url,
        display_to_timestamp: Option<i64>,
    },
    QrColorDataUrl {
        color_image_data_url: Url,
        display_to_timestamp: Option<i64>,
        display_text: Option<String>,
        border_color: Option<String>,
    },
}
