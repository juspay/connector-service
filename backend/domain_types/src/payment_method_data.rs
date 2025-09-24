use std::fmt::Debug;

use base64::Engine;
use common_enums::{CardNetwork, CountryAlpha2, RegulatedName, SamsungPayCardBrand};
use common_utils::{
    ext_traits::OptionExt, new_types::MaskedBankAccount, pii::UpiVpaMaskingStrategy, Email,
    ValidationError,
};
use error_stack::{self, ResultExt};
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use time::Date;
use utoipa::ToSchema;

use crate::{
    errors,
    router_data::NetworkTokenNumber,
    utils::{get_card_issuer, missing_field_err, CardIssuer, Error},
};

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, Default)]
pub struct Card<T: PaymentMethodDataTypes> {
    pub card_number: RawCardNumber<T>,
    pub card_exp_month: Secret<String>,
    pub card_exp_year: Secret<String>,
    pub card_cvc: Secret<String>,
    pub card_issuer: Option<String>,
    pub card_network: Option<CardNetwork>,
    pub card_type: Option<String>,
    pub card_issuing_country: Option<String>,
    pub bank_code: Option<String>,
    pub nick_name: Option<Secret<String>>,
    pub card_holder_name: Option<Secret<String>>,
    pub co_badged_card_data: Option<CoBadgedCardData>,
}

pub trait PaymentMethodDataTypes: Clone {
    type Inner: Default + Debug + Send + Eq + PartialEq + Serialize + DeserializeOwned + Clone;
}

/// PCI holder implementation for handling raw PCI data
#[derive(Default, Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct DefaultPCIHolder;

/// Vault token holder implementation for handling vault token data
#[derive(Default, Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct VaultTokenHolder;
/// Generic CardNumber struct that uses PaymentMethodDataTypes trait
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RawCardNumber<T: PaymentMethodDataTypes>(pub T::Inner);

impl RawCardNumber<DefaultPCIHolder> {
    pub fn peek(&self) -> &str {
        self.0.peek()
    }
}

impl RawCardNumber<VaultTokenHolder> {
    pub fn peek(&self) -> &str {
        &self.0
    }
}

impl PaymentMethodDataTypes for DefaultPCIHolder {
    type Inner = cards::CardNumber;
}

impl PaymentMethodDataTypes for VaultTokenHolder {
    type Inner = String; //Token
}

impl Card<DefaultPCIHolder> {
    pub fn get_card_expiry_year_2_digit(
        &self,
    ) -> Result<Secret<String>, crate::errors::ConnectorError> {
        let binding = self.card_exp_year.clone();
        let year = binding.peek();
        Ok(Secret::new(
            year.get(year.len() - 2..)
                .ok_or(crate::errors::ConnectorError::RequestEncodingFailed)?
                .to_string(),
        ))
    }
    pub fn get_card_issuer(&self) -> Result<CardIssuer, Error> {
        get_card_issuer(self.card_number.peek())
    }
    pub fn get_card_expiry_month_year_2_digit_with_delimiter(
        &self,
        delimiter: String,
    ) -> Result<Secret<String>, crate::errors::ConnectorError> {
        let year = self.get_card_expiry_year_2_digit()?;
        Ok(Secret::new(format!(
            "{}{}{}",
            self.card_exp_month.peek(),
            delimiter,
            year.peek()
        )))
    }
    pub fn get_expiry_date_as_yyyymm(&self, delimiter: &str) -> Secret<String> {
        let year = self.get_expiry_year_4_digit();
        Secret::new(format!(
            "{}{}{}",
            year.peek(),
            delimiter,
            self.card_exp_month.peek()
        ))
    }
    pub fn get_expiry_date_as_mmyyyy(&self, delimiter: &str) -> Secret<String> {
        let year = self.get_expiry_year_4_digit();
        Secret::new(format!(
            "{}{}{}",
            self.card_exp_month.peek(),
            delimiter,
            year.peek()
        ))
    }
    pub fn get_expiry_year_4_digit(&self) -> Secret<String> {
        let mut year = self.card_exp_year.peek().clone();
        if year.len() == 2 {
            year = format!("20{year}");
        }
        Secret::new(year)
    }
    pub fn get_expiry_date_as_yymm(&self) -> Result<Secret<String>, crate::errors::ConnectorError> {
        let year = self.get_card_expiry_year_2_digit()?.expose();
        let month = self.card_exp_month.clone().expose();
        Ok(Secret::new(format!("{year}{month}")))
    }
    pub fn get_expiry_month_as_i8(&self) -> Result<Secret<i8>, Error> {
        self.card_exp_month
            .peek()
            .clone()
            .parse::<i8>()
            .change_context(crate::errors::ConnectorError::ResponseDeserializationFailed)
            .map(Secret::new)
    }
    pub fn get_expiry_year_as_i32(&self) -> Result<Secret<i32>, Error> {
        self.card_exp_year
            .peek()
            .clone()
            .parse::<i32>()
            .change_context(crate::errors::ConnectorError::ResponseDeserializationFailed)
            .map(Secret::new)
    }
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum PaymentMethodData<T: PaymentMethodDataTypes> {
    Card(Card<T>),
    CardDetailsForNetworkTransactionId(CardDetailsForNetworkTransactionId),
    CardRedirect(CardRedirectData),
    Wallet(WalletData),
    PayLater(PayLaterData),
    BankRedirect(BankRedirectData),
    BankDebit(BankDebitData),
    BankTransfer(Box<BankTransferData>),
    Crypto(CryptoData),
    MandatePayment,
    Reward,
    RealTimePayment(Box<RealTimePaymentData>),
    Upi(UpiData),
    Voucher(VoucherData),
    GiftCard(Box<GiftCardData>),
    CardToken(CardToken),
    OpenBanking(OpenBankingData),
    NetworkToken(NetworkTokenData),
    MobilePayment(MobilePaymentData),
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenBankingData {
    OpenBankingPIS {},
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobilePaymentData {
    DirectCarrierBilling {
        /// The phone number of the user
        msisdn: String,
        /// Unique user identifier
        client_uid: Option<String>,
    },
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, Default)]
pub struct NetworkTokenData {
    pub network_token: cards::NetworkToken,
    pub network_token_exp_month: Secret<String>,
    pub network_token_exp_year: Secret<String>,
    pub cryptogram: Option<Secret<String>>,
    pub card_issuer: Option<String>, //since network token is tied to card, so its issuer will be same as card issuer
    pub card_network: Option<common_enums::CardNetwork>,
    pub card_type: Option<CardType>,
    pub card_issuing_country: Option<common_enums::CountryAlpha2>,
    pub bank_code: Option<String>,
    pub card_holder_name: Option<Secret<String>>,
    pub nick_name: Option<Secret<String>>,
    pub eci: Option<String>,
}

impl NetworkTokenData {
    pub fn get_card_issuer(&self) -> Result<CardIssuer, Error> {
        get_card_issuer(self.network_token.peek())
    }

    pub fn get_expiry_year_4_digit(&self) -> Secret<String> {
        let mut year = self.network_token_exp_year.peek().clone();
        if year.len() == 2 {
            year = format!("20{year}");
        }
        Secret::new(year)
    }

    pub fn get_network_token(&self) -> NetworkTokenNumber {
        self.network_token.clone()
    }

    pub fn get_network_token_expiry_month(&self) -> Secret<String> {
        self.network_token_exp_month.clone()
    }

    pub fn get_network_token_expiry_year(&self) -> Secret<String> {
        self.network_token_exp_year.clone()
    }

    pub fn get_cryptogram(&self) -> Option<Secret<String>> {
        self.cryptogram.clone()
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GiftCardData {
    Givex(GiftCardDetails),
    PaySafeCard {},
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct GiftCardDetails {
    /// The gift card number
    pub number: Secret<String>,
    /// The card verification code.
    pub cvc: Secret<String>,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct CardToken {
    /// The card holder's name
    pub card_holder_name: Option<Secret<String>>,

    /// The CVC number for the card
    pub card_cvc: Option<Secret<String>>,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BoletoVoucherData {
    /// The shopper's social security number
    pub social_security_number: Option<Secret<String>>,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AlfamartVoucherData {}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IndomaretVoucherData {}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct JCSVoucherData {}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherData {
    Boleto(Box<BoletoVoucherData>),
    Efecty,
    PagoEfectivo,
    RedCompra,
    RedPagos,
    Alfamart(Box<AlfamartVoucherData>),
    Indomaret(Box<IndomaretVoucherData>),
    Oxxo,
    SevenEleven(Box<JCSVoucherData>),
    Lawson(Box<JCSVoucherData>),
    MiniStop(Box<JCSVoucherData>),
    FamilyMart(Box<JCSVoucherData>),
    Seicomart(Box<JCSVoucherData>),
    PayEasy(Box<JCSVoucherData>),
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpiData {
    UpiCollect(UpiCollectData),
    UpiIntent(UpiIntentData),
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct UpiCollectData {
    pub vpa_id: Option<Secret<String, UpiVpaMaskingStrategy>>,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct UpiIntentData {}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum RealTimePaymentData {
    DuitNow {},
    Fps {},
    PromptPay {},
    VietQr {},
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CryptoData {
    pub pay_currency: Option<String>,
    pub network: Option<String>,
}

impl CryptoData {
    pub fn get_pay_currency(&self) -> Result<String, Error> {
        self.pay_currency
            .clone()
            .ok_or_else(missing_field_err("crypto_data.pay_currency"))
    }
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BankTransferData {
    AchBankTransfer {},
    SepaBankTransfer {},
    BacsBankTransfer {},
    MultibancoBankTransfer {},
    PermataBankTransfer {},
    BcaBankTransfer {},
    BniVaBankTransfer {},
    BriVaBankTransfer {},
    CimbVaBankTransfer {},
    DanamonVaBankTransfer {},
    MandiriVaBankTransfer {},
    Pix {
        /// Unique key for pix transfer
        pix_key: Option<Secret<String>>,
        /// CPF is a Brazilian tax identification number
        cpf: Option<Secret<String>>,
        /// CNPJ is a Brazilian company tax identification number
        cnpj: Option<Secret<String>>,
        /// Source bank account UUID
        source_bank_account_id: Option<MaskedBankAccount>,
        /// Destination bank account UUID.
        destination_bank_account_id: Option<MaskedBankAccount>,
    },
    Pse {},
    LocalBankTransfer {
        bank_code: Option<String>,
    },
    InstantBankTransfer {},
    InstantBankTransferFinland {},
    InstantBankTransferPoland {},
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BankDebitData {
    AchBankDebit {
        account_number: Secret<String>,
        routing_number: Secret<String>,
        card_holder_name: Option<Secret<String>>,
        bank_account_holder_name: Option<Secret<String>>,
        bank_name: Option<common_enums::BankNames>,
        bank_type: Option<common_enums::BankType>,
        bank_holder_type: Option<common_enums::BankHolderType>,
    },
    SepaBankDebit {
        iban: Secret<String>,
        bank_account_holder_name: Option<Secret<String>>,
    },
    BecsBankDebit {
        account_number: Secret<String>,
        bsb_number: Secret<String>,
        bank_account_holder_name: Option<Secret<String>>,
    },
    BacsBankDebit {
        account_number: Secret<String>,
        sort_code: Secret<String>,
        bank_account_holder_name: Option<Secret<String>>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum BankRedirectData {
    BancontactCard {
        card_number: Option<cards::CardNumber>,
        card_exp_month: Option<Secret<String>>,
        card_exp_year: Option<Secret<String>>,
        card_holder_name: Option<Secret<String>>,
    },
    Bizum {},
    Blik {
        blik_code: Option<String>,
    },
    Eps {
        bank_name: Option<common_enums::BankNames>,
        country: Option<CountryAlpha2>,
    },
    Giropay {
        bank_account_bic: Option<Secret<String>>,
        bank_account_iban: Option<Secret<String>>,
        country: Option<CountryAlpha2>,
    },
    Ideal {
        bank_name: Option<common_enums::BankNames>,
    },
    Interac {
        country: Option<CountryAlpha2>,
        email: Option<Email>,
    },
    OnlineBankingCzechRepublic {
        issuer: common_enums::BankNames,
    },
    OnlineBankingFinland {
        email: Option<Email>,
    },
    OnlineBankingPoland {
        issuer: common_enums::BankNames,
    },
    OnlineBankingSlovakia {
        issuer: common_enums::BankNames,
    },
    OpenBankingUk {
        issuer: Option<common_enums::BankNames>,
        country: Option<CountryAlpha2>,
    },
    Przelewy24 {
        bank_name: Option<common_enums::BankNames>,
    },
    Sofort {
        country: Option<CountryAlpha2>,
        preferred_language: Option<String>,
    },
    Trustly {
        country: Option<CountryAlpha2>,
    },
    OnlineBankingFpx {
        issuer: common_enums::BankNames,
    },
    OnlineBankingThailand {
        issuer: common_enums::BankNames,
    },
    LocalBankRedirect {},
    Eft {
        provider: String,
    },
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum PayLaterData {
    KlarnaRedirect {},
    KlarnaSdk { token: String },
    AffirmRedirect {},
    AfterpayClearpayRedirect {},
    PayBrightRedirect {},
    WalleyRedirect {},
    AlmaRedirect {},
    AtomeRedirect {},
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum WalletData {
    AliPayQr(Box<AliPayQr>),
    AliPayRedirect(AliPayRedirection),
    AliPayHkRedirect(AliPayHkRedirection),
    BluecodeRedirect {},
    AmazonPayRedirect(Box<AmazonPayRedirectData>),
    MomoRedirect(MomoRedirection),
    KakaoPayRedirect(KakaoPayRedirection),
    GoPayRedirect(GoPayRedirection),
    GcashRedirect(GcashRedirection),
    ApplePay(ApplePayWalletData),
    ApplePayRedirect(Box<ApplePayRedirectData>),
    ApplePayThirdPartySdk(Box<ApplePayThirdPartySdkData>),
    DanaRedirect {},
    GooglePay(GooglePayWalletData),
    GooglePayRedirect(Box<GooglePayRedirectData>),
    GooglePayThirdPartySdk(Box<GooglePayThirdPartySdkData>),
    MbWayRedirect(Box<MbWayRedirection>),
    MobilePayRedirect(Box<MobilePayRedirection>),
    PaypalRedirect(PaypalRedirection),
    PaypalSdk(PayPalWalletData),
    Paze(PazeWalletData),
    SamsungPay(Box<SamsungPayWalletData>),
    TwintRedirect {},
    VippsRedirect {},
    TouchNGoRedirect(Box<TouchNGoRedirection>),
    WeChatPayRedirect(Box<WeChatPayRedirection>),
    WeChatPayQr(Box<WeChatPayQr>),
    CashappQr(Box<CashappQr>),
    SwishQr(SwishQrData),
    Mifinity(MifinityData),
    RevolutPay(RevolutPayData),
}

impl WalletData {
    pub fn get_wallet_token(&self) -> Result<Secret<String>, Error> {
        match self {
            Self::GooglePay(data) => Ok(data.get_googlepay_encrypted_payment_data()?),
            Self::ApplePay(data) => Ok(data.get_applepay_decoded_payment_data()?),
            Self::PaypalSdk(data) => Ok(Secret::new(data.token.clone())),
            _ => Err(crate::errors::ConnectorError::InvalidWallet.into()),
        }
    }
    pub fn get_wallet_token_as_json<T>(&self, wallet_name: String) -> Result<T, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        serde_json::from_str::<T>(self.get_wallet_token()?.peek())
            .change_context(crate::errors::ConnectorError::InvalidWalletToken { wallet_name })
    }

    pub fn get_encoded_wallet_token(&self) -> Result<String, Error> {
        match self {
            Self::GooglePay(_) => {
                let json_token: serde_json::Value =
                    self.get_wallet_token_as_json("Google Pay".to_owned())?;
                let token_as_vec = serde_json::to_vec(&json_token).change_context(
                    crate::errors::ConnectorError::InvalidWalletToken {
                        wallet_name: "Google Pay".to_string(),
                    },
                )?;
                let encoded_token = base64::engine::general_purpose::STANDARD.encode(token_as_vec);
                Ok(encoded_token)
            }
            _ => Err(crate::errors::ConnectorError::NotImplemented(
                "SELECTED PAYMENT METHOD".to_owned(),
            )
            .into()),
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct RevolutPayData {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct MifinityData {
    #[schema(value_type = Date)]
    pub date_of_birth: Secret<Date>,
    pub language_preference: Option<String>,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct SwishQrData {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct CashappQr {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct WeChatPayQr {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct WeChatPayRedirection {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct TouchNGoRedirection {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SamsungPayWalletCredentials {
    pub method: Option<String>,
    pub recurring_payment: Option<bool>,
    pub card_brand: common_enums::SamsungPayCardBrand,
    pub dpan_last_four_digits: Option<String>,
    #[serde(rename = "card_last4digits")]
    pub card_last_four_digits: String,
    #[serde(rename = "3_d_s")]
    pub token_data: SamsungPayTokenData,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SamsungPayTokenData {
    #[serde(rename = "type")]
    pub three_ds_type: Option<String>,
    pub version: String,
    pub data: Secret<String>,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SamsungPayWalletData {
    pub payment_credential: SamsungPayWalletCredentials,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PazeWalletData {
    #[schema(value_type = String)]
    pub complete_response: Secret<String>,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct PayPalWalletData {
    /// Token generated for the Apple pay
    pub token: String,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct PaypalRedirection {
    /// paypal's email address
    #[schema(max_length = 255, value_type = Option<String>, example = "johntest@test.com")]
    pub email: Option<Email>,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct GooglePayThirdPartySdkData {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct GooglePayWalletData {
    /// The type of payment method
    #[serde(rename = "type")]
    pub pm_type: String,
    /// User-facing message to describe the payment method that funds this transaction.
    pub description: String,
    /// The information of the payment method
    pub info: GooglePayPaymentMethodInfo,
    /// The tokenization data of Google pay
    pub tokenization_data: GpayTokenizationData,
}

impl GooglePayWalletData {
    fn get_googlepay_encrypted_payment_data(&self) -> Result<Secret<String>, Error> {
        let encrypted_data = self
            .tokenization_data
            .get_encrypted_google_pay_payment_data_mandatory()
            .change_context(errors::ConnectorError::InvalidWalletToken {
                wallet_name: "Google Pay".to_string(),
            })?;

        Ok(Secret::new(encrypted_data.token.clone()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
/// This enum is used to represent the Gpay payment data, which can either be encrypted or decrypted.
pub enum GpayTokenizationData {
    /// This variant contains the decrypted Gpay payment data as a structured object.
    Decrypted(GPayPredecryptData),
    /// This variant contains the encrypted Gpay payment data as a string.
    Encrypted(GpayEcryptedTokenizationData),
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
/// This struct represents the decrypted Google Pay payment data
pub struct GPayPredecryptData {
    /// The card's expiry month
    pub card_exp_month: Secret<String>,

    /// The card's expiry year
    pub card_exp_year: Secret<String>,

    /// The Primary Account Number (PAN) of the card
    pub application_primary_account_number: cards::CardNumber,

    /// Cryptogram generated by the Network
    pub cryptogram: Option<Secret<String>>,

    /// Electronic Commerce Indicator
    pub eci_indicator: Option<String>,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
/// This struct represents the encrypted Gpay payment data
pub struct GpayEcryptedTokenizationData {
    /// The type of the token
    #[serde(rename = "type")]
    pub token_type: String,
    /// Token generated for the wallet
    pub token: String,
}

impl GpayTokenizationData {
    /// Get the encrypted Google Pay payment data, returning an error if it does not exist
    pub fn get_encrypted_google_pay_payment_data_mandatory(
        &self,
    ) -> error_stack::Result<&GpayEcryptedTokenizationData, ValidationError> {
        match self {
            Self::Encrypted(encrypted_data) => Ok(encrypted_data),
            Self::Decrypted(_) => Err(ValidationError::InvalidValue {
                message: "Encrypted Google Pay payment data is mandatory".to_string(),
            }
            .into()),
        }
    }
    /// Get the token from Google Pay tokenization data
    /// Returns the token string if encrypted data exists, otherwise returns an error
    pub fn get_encrypted_google_pay_token(&self) -> error_stack::Result<String, ValidationError> {
        Ok(self
            .get_encrypted_google_pay_payment_data_mandatory()?
            .token
            .clone())
    }

    /// Get the token type from Google Pay tokenization data
    /// Returns the token_type string if encrypted data exists, otherwise returns an error
    pub fn get_encrypted_token_type(&self) -> error_stack::Result<String, ValidationError> {
        Ok(self
            .get_encrypted_google_pay_payment_data_mandatory()?
            .token_type
            .clone())
    }
}

impl GPayPredecryptData {
    /// Get the four-digit expiration year from the Google Pay pre-decrypt data
    pub fn get_four_digit_expiry_year(
        &self,
    ) -> error_stack::Result<Secret<String>, ValidationError> {
        let mut year = self.card_exp_year.peek().clone();

        // If it's a 2-digit year, convert to 4-digit
        if year.len() == 2 {
            year = format!("20{year}");
        } else if year.len() != 4 {
            return Err(ValidationError::InvalidValue {
                message: format!(
                    "Invalid expiry year length: {}. Must be 2 or 4 digits",
                    year.len()
                ),
            }
            .into());
        }
        Ok(Secret::new(year))
    }
    /// Get the 2-digit expiration year from the Google Pay pre-decrypt data
    pub fn get_two_digit_expiry_year(
        &self,
    ) -> error_stack::Result<Secret<String>, ValidationError> {
        let binding = self.card_exp_year.clone();
        let year = binding.peek();
        Ok(Secret::new(
            year.get(year.len() - 2..)
                .ok_or(ValidationError::InvalidValue {
                    message: "Invalid two-digit year".to_string(),
                })?
                .to_string(),
        ))
    }
    /// Get the expiry date in MMYY format from the Google Pay pre-decrypt data
    pub fn get_expiry_date_as_mmyy(&self) -> error_stack::Result<Secret<String>, ValidationError> {
        let year = self.get_two_digit_expiry_year()?.expose();
        let month = self.get_expiry_month()?.clone().expose();
        Ok(Secret::new(format!("{month}{year}")))
    }

    /// Get the expiration month from the Google Pay pre-decrypt data
    pub fn get_expiry_month(&self) -> error_stack::Result<Secret<String>, ValidationError> {
        let month_str = self.card_exp_month.peek();
        let month = month_str
            .parse::<u8>()
            .map_err(|_| ValidationError::InvalidValue {
                message: format!("Failed to parse expiry month: {month_str}"),
            })?;

        if !(1..=12).contains(&month) {
            return Err(ValidationError::InvalidValue {
                message: format!("Invalid expiry month: {month}. Must be between 1 and 12"),
            }
            .into());
        }
        Ok(self.card_exp_month.clone())
    }
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct GooglePayPaymentMethodInfo {
    /// The name of the card network
    pub card_network: String,
    /// The details of the card
    pub card_details: String,
    //assurance_details of the card
    pub assurance_details: Option<GooglePayAssuranceDetails>,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct GooglePayAssuranceDetails {
    ///indicates that Cardholder possession validation has been performed
    pub card_holder_authenticated: bool,
    /// indicates that identification and verifications (ID&V) was performed
    pub account_verified: bool,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct GooglePayRedirectData {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct ApplePayThirdPartySdkData {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct ApplePayRedirectData {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct ApplepayPaymentMethod {
    /// The name to be displayed on Apple Pay button
    pub display_name: String,
    /// The network of the Apple pay payment method
    pub network: String,
    /// The type of the payment method
    #[serde(rename = "type")]
    pub pm_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
/// This struct represents the decrypted Apple Pay payment data
pub struct ApplePayPredecryptData {
    /// The primary account number
    pub application_primary_account_number: cards::CardNumber,
    /// The application expiration date (PAN expiry month)
    pub application_expiration_month: Secret<String>,
    /// The application expiration date (PAN expiry year)
    pub application_expiration_year: Secret<String>,
    /// The payment data, which contains the cryptogram and ECI indicator
    pub payment_data: ApplePayCryptogramData,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
/// This struct represents the cryptogram data for Apple Pay transactions
pub struct ApplePayCryptogramData {
    /// The online payment cryptogram
    pub online_payment_cryptogram: Secret<String>,
    /// The ECI (Electronic Commerce Indicator) value
    pub eci_indicator: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
/// This enum is used to represent the Apple Pay payment data, which can either be encrypted or decrypted.
pub enum ApplePayPaymentData {
    /// This variant contains the decrypted Apple Pay payment data as a structured object.
    Decrypted(ApplePayPredecryptData),
    /// This variant contains the encrypted Apple Pay payment data as a string.
    Encrypted(String),
}

impl ApplePayPaymentData {
    /// Get the encrypted Apple Pay payment data if it exists
    pub fn get_encrypted_apple_pay_payment_data_optional(&self) -> Option<&String> {
        match self {
            Self::Encrypted(encrypted_data) => Some(encrypted_data),
            Self::Decrypted(_) => None,
        }
    }

    /// Get the decrypted Apple Pay payment data if it exists
    pub fn get_decrypted_apple_pay_payment_data_optional(&self) -> Option<&ApplePayPredecryptData> {
        match self {
            Self::Encrypted(_) => None,
            Self::Decrypted(decrypted_data) => Some(decrypted_data),
        }
    }

    /// Get the encrypted Apple Pay payment data, returning an error if it does not exist
    pub fn get_encrypted_apple_pay_payment_data_mandatory(
        &self,
    ) -> error_stack::Result<&String, ValidationError> {
        self.get_encrypted_apple_pay_payment_data_optional()
            .get_required_value("Encrypted Apple Pay payment data")
            .attach_printable("Encrypted Apple Pay payment data is mandatory")
    }

    /// Get the decrypted Apple Pay payment data, returning an error if it does not exist
    pub fn get_decrypted_apple_pay_payment_data_mandatory(
        &self,
    ) -> error_stack::Result<&ApplePayPredecryptData, ValidationError> {
        self.get_decrypted_apple_pay_payment_data_optional()
            .get_required_value("Decrypted Apple Pay payment data")
            .attach_printable("Decrypted Apple Pay payment data is mandatory")
    }
}

impl ApplePayPredecryptData {
    /// Get the four-digit expiration year from the Apple Pay pre-decrypt data
    pub fn get_two_digit_expiry_year(
        &self,
    ) -> error_stack::Result<Secret<String>, ValidationError> {
        let binding = self.application_expiration_year.clone();
        let year = binding.peek();
        Ok(Secret::new(
            year.get(year.len() - 2..)
                .ok_or(ValidationError::InvalidValue {
                    message: "Invalid two-digit year".to_string(),
                })?
                .to_string(),
        ))
    }

    /// Get the four-digit expiration year from the Apple Pay pre-decrypt data
    pub fn get_four_digit_expiry_year(&self) -> Secret<String> {
        let mut year = self.application_expiration_year.peek().clone();
        if year.len() == 2 {
            year = format!("20{year}");
        }
        Secret::new(year)
    }

    /// Get the expiration month from the Apple Pay pre-decrypt data
    pub fn get_expiry_month(&self) -> Secret<String> {
        self.application_expiration_month.clone()
    }

    /// Get the expiry date in MMYY format from the Apple Pay pre-decrypt data
    pub fn get_expiry_date_as_mmyy(&self) -> error_stack::Result<Secret<String>, ValidationError> {
        let year = self.get_two_digit_expiry_year()?.expose();
        let month = self.application_expiration_month.clone().expose();
        Ok(Secret::new(format!("{month}{year}")))
    }
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct ApplePayWalletData {
    /// The payment data of Apple pay
    pub payment_data: ApplePayPaymentData,
    /// The payment method of Apple pay
    pub payment_method: ApplepayPaymentMethod,
    /// The unique identifier for the transaction
    pub transaction_identifier: String,
}

impl ApplePayWalletData {
    pub fn get_applepay_decoded_payment_data(&self) -> Result<Secret<String>, Error> {
        let apple_pay_encrypted_data = self
            .payment_data
            .get_encrypted_apple_pay_payment_data_mandatory()
            .change_context(crate::errors::ConnectorError::MissingRequiredField {
                field_name: "Apple pay encrypted data",
            })?;
        let token = Secret::new(
            String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(apple_pay_encrypted_data)
                    .change_context(crate::errors::ConnectorError::InvalidWalletToken {
                        wallet_name: "Apple Pay".to_string(),
                    })?,
            )
            .change_context(crate::errors::ConnectorError::InvalidWalletToken {
                wallet_name: "Apple Pay".to_string(),
            })?,
        );
        Ok(token)
    }
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct GoPayRedirection {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct GcashRedirection {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct MobilePayRedirection {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct MbWayRedirection {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct KakaoPayRedirection {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct MomoRedirection {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct AliPayHkRedirection {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct AliPayRedirection {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct AliPayQr {}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum CardRedirectData {
    Knet {},
    Benefit {},
    MomoAtm {},
    CardRedirect {},
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, Default)]
pub struct CardDetailsForNetworkTransactionId {
    pub card_number: cards::CardNumber,
    pub card_exp_month: Secret<String>,
    pub card_exp_year: Secret<String>,
    pub card_issuer: Option<String>,
    pub card_network: Option<common_enums::CardNetwork>,
    pub card_type: Option<String>,
    pub card_issuing_country: Option<String>,
    pub bank_code: Option<String>,
    pub nick_name: Option<Secret<String>>,
    pub card_holder_name: Option<Secret<String>>,
}

impl CardDetailsForNetworkTransactionId {
    pub fn get_card_expiry_year_2_digit(
        &self,
    ) -> Result<Secret<String>, crate::errors::ConnectorError> {
        let binding = self.card_exp_year.clone();
        let year = binding.peek();
        Ok(Secret::new(
            year.get(year.len() - 2..)
                .ok_or(crate::errors::ConnectorError::RequestEncodingFailed)?
                .to_string(),
        ))
    }
    pub fn get_card_issuer(&self) -> Result<CardIssuer, Error> {
        get_card_issuer(self.card_number.peek())
    }
    pub fn get_card_expiry_month_year_2_digit_with_delimiter(
        &self,
        delimiter: String,
    ) -> Result<Secret<String>, crate::errors::ConnectorError> {
        let year = self.get_card_expiry_year_2_digit()?;
        Ok(Secret::new(format!(
            "{}{}{}",
            self.card_exp_month.peek(),
            delimiter,
            year.peek()
        )))
    }
    pub fn get_expiry_date_as_yyyymm(&self, delimiter: &str) -> Secret<String> {
        let year = self.get_expiry_year_4_digit();
        Secret::new(format!(
            "{}{}{}",
            year.peek(),
            delimiter,
            self.card_exp_month.peek()
        ))
    }
    pub fn get_expiry_date_as_mmyyyy(&self, delimiter: &str) -> Secret<String> {
        let year = self.get_expiry_year_4_digit();
        Secret::new(format!(
            "{}{}{}",
            self.card_exp_month.peek(),
            delimiter,
            year.peek()
        ))
    }
    pub fn get_expiry_year_4_digit(&self) -> Secret<String> {
        let mut year = self.card_exp_year.peek().clone();
        if year.len() == 2 {
            year = format!("20{year}");
        }
        Secret::new(year)
    }
    pub fn get_expiry_date_as_yymm(&self) -> Result<Secret<String>, crate::errors::ConnectorError> {
        let year = self.get_card_expiry_year_2_digit()?.expose();
        let month = self.card_exp_month.clone().expose();
        Ok(Secret::new(format!("{year}{month}")))
    }
    pub fn get_expiry_month_as_i8(&self) -> Result<Secret<i8>, Error> {
        self.card_exp_month
            .peek()
            .clone()
            .parse::<i8>()
            .change_context(crate::errors::ConnectorError::ResponseDeserializationFailed)
            .map(Secret::new)
    }
    pub fn get_expiry_year_as_i32(&self) -> Result<Secret<i32>, Error> {
        self.card_exp_year
            .peek()
            .clone()
            .parse::<i32>()
            .change_context(crate::errors::ConnectorError::ResponseDeserializationFailed)
            .map(Secret::new)
    }
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SamsungPayWebWalletData {
    /// Specifies authentication method used
    pub method: Option<String>,
    /// Value if credential is enabled for recurring payment
    pub recurring_payment: Option<bool>,
    /// Brand of the payment card
    pub card_brand: SamsungPayCardBrand,
    /// Last 4 digits of the card number
    #[serde(rename = "card_last4digits")]
    pub card_last_four_digits: String,
    /// Samsung Pay token data
    #[serde(rename = "3_d_s")]
    pub token_data: SamsungPayTokenData,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct AmazonPayRedirectData {}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CoBadgedCardData {
    pub co_badged_card_networks: Vec<CardNetwork>,
    pub issuer_country_code: CountryAlpha2,
    pub is_regulated: bool,
    pub regulated_name: Option<RegulatedName>,
}

#[derive(
    Debug,
    serde::Deserialize,
    serde::Serialize,
    Clone,
    ToSchema,
    strum::EnumString,
    strum::Display,
    Eq,
    PartialEq,
)]
#[serde(rename_all = "snake_case")]
pub enum CardType {
    Credit,
    Debit,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, ToSchema)]
#[serde(tag = "wallet_name")]
#[serde(rename_all = "snake_case")]
pub enum SessionToken {
    /// The session response structure for Google Pay
    GooglePay(Box<GpaySessionTokenResponse>),
    /// The session response structure for Apple Pay
    ApplePay(Box<ApplepaySessionTokenResponse>),
    /// Whenever there is no session token response or an error in session response
    NoSessionTokenReceived,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, ToSchema)]
#[serde(untagged)]
pub enum GpaySessionTokenResponse {
    /// Google pay response involving third party sdk
    ThirdPartyResponse(GooglePayThirdPartySdk),
    /// Google pay session response for non third party sdk
    GooglePaySession(GooglePaySessionResponse),
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub struct GooglePayThirdPartySdk {
    /// Identifier for the delayed session response
    pub delayed_session_token: bool,
    /// The name of the connector
    pub connector: String,
    /// The next action for the sdk (ex: calling confirm or sync call)
    pub sdk_next_action: SdkNextAction,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub struct ApplepaySessionTokenResponse {
    /// Session object for Apple Pay
    /// The session_token_data will be null for iOS devices because the Apple Pay session call is skipped, as there is no web domain involved
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token_data: Option<ApplePaySessionResponse>,
    /// Payment request object for Apple Pay
    pub payment_request_data: Option<ApplePayPaymentRequest>,
    /// The session token is w.r.t this connector
    pub connector: String,
    /// Identifier for the delayed session response
    pub delayed_session_token: bool,
    /// The next action for the sdk (ex: calling confirm or sync call)
    pub sdk_next_action: SdkNextAction,
}
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, ToSchema)]
#[serde(untagged)]
pub enum ApplePaySessionResponse {
    ///  We get this session response, when third party sdk is involved
    ThirdPartySdk(ThirdPartySdkSessionResponse),
}
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, ToSchema)]
pub struct ThirdPartySdkSessionResponse {
    pub secrets: SecretInfoToInitiateSdk,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, ToSchema, serde::Deserialize)]
pub struct ApplePayPaymentRequest {
    /// The code for country
    #[schema(value_type = CountryAlpha2, example = "US")]
    pub country_code: CountryAlpha2,
    /// The code for currency
    #[schema(value_type = Currency, example = "USD")]
    pub currency_code: common_enums::Currency,
    /// Represents the total for the payment.
    pub total: AmountInfo,
    /// The list of merchant capabilities(ex: whether capable of 3ds or no-3ds)
    pub merchant_capabilities: Option<Vec<String>>,
    /// The list of supported networks
    pub supported_networks: Option<Vec<String>>,
}
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, ToSchema, serde::Deserialize)]
pub struct SecretInfoToInitiateSdk {
    // Authorization secrets used by client to initiate sdk
    #[schema(value_type = String)]
    pub display: Secret<String>,
    // Authorization secrets used by client for payment
    #[schema(value_type = String)]
    pub payment: Secret<String>,
}
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, ToSchema, serde::Deserialize)]
pub struct AmountInfo {
    /// The label must be the name of the merchant.
    pub label: String,
    /// A value that indicates whether the line item(Ex: total, tax, discount, or grand total) is final or pending.
    #[serde(rename = "type")]
    pub total_type: Option<String>,
    /// The total amount for the payment in majot unit string (Ex: 38.02)
    #[schema(value_type = String, example = "38.02")]
    pub amount: common_utils::StringMajorUnit,
}
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub struct GooglePaySessionResponse {
    /// The merchant info
    pub merchant_info: GpayMerchantInfo,
    /// Is shipping address required
    pub shipping_address_required: bool,
    /// Is email required
    pub email_required: bool,
    /// Shipping address parameters
    pub shipping_address_parameters: GpayShippingAddressParameters,
    /// List of the allowed payment meythods
    pub allowed_payment_methods: Vec<GpayAllowedPaymentMethods>,
    /// The transaction info Google Pay requires
    pub transaction_info: GpayTransactionInfo,
    /// Identifier for the delayed session response
    pub delayed_session_token: bool,
    /// The name of the connector
    pub connector: String,
    /// The next action for the sdk (ex: calling confirm or sync call)
    pub sdk_next_action: SdkNextAction,
    /// Secrets for sdk display and payment
    pub secrets: Option<SecretInfoToInitiateSdk>,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct GpayTransactionInfo {
    /// The country code
    #[schema(value_type = CountryAlpha2, example = "US")]
    pub country_code: CountryAlpha2,
    /// The currency code
    #[schema(value_type = Currency, example = "USD")]
    pub currency_code: common_enums::Currency,
    /// The total price status (ex: 'FINAL')
    pub total_price_status: String,
    /// The total price
    #[schema(value_type = String, example = "38.02")]
    pub total_price: common_utils::StringMajorUnit,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct GpayAllowedPaymentMethods {
    /// The type of payment method
    #[serde(rename = "type")]
    pub payment_method_type: String,
    /// The parameters Google Pay requires
    pub parameters: GpayAllowedMethodsParameters,
    /// The tokenization specification for Google Pay
    pub tokenization_specification: GpayTokenizationSpecification,
}
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct GpayAllowedMethodsParameters {
    /// The list of allowed auth methods (ex: 3DS, No3DS, PAN_ONLY etc)
    pub allowed_auth_methods: Vec<String>,
    /// The list of allowed card networks (ex: AMEX,JCB etc)
    pub allowed_card_networks: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct GpayTokenizationSpecification {
    /// The token specification type(ex: PAYMENT_GATEWAY)
    #[serde(rename = "type")]
    pub token_specification_type: String,
    /// The parameters for the token specification Google Pay
    pub parameters: GpayTokenParameters,
}
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct GpayTokenParameters {
    /// The name of the connector
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// The merchant ID registered in the connector associated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_merchant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "stripe:version")]
    pub stripe_version: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "stripe:publishableKey"
    )]
    pub stripe_publishable_key: Option<String>,
    /// The protocol version for encryption
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    /// The public key provided by the merchant
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub public_key: Option<Secret<String>>,
}
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct GpayMerchantInfo {
    /// The merchant Identifier that needs to be passed while invoking Gpay SDK
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_id: Option<String>,
    /// The name of the merchant that needs to be displayed on Gpay PopUp
    pub merchant_name: String,
}

#[derive(Debug, Eq, PartialEq, serde::Serialize, Clone, ToSchema)]
pub struct SdkNextAction {
    /// The type of next action
    pub next_action: NextActionCall,
}

#[derive(Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, Clone, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NextActionCall {
    /// The next action call is Post Session Tokens
    PostSessionTokens,
    /// The next action call is confirm
    Confirm,
    /// The next action call is sync
    Sync,
    /// The next action call is Complete Authorize
    CompleteAuthorize,
}
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub struct GpayShippingAddressParameters {
    /// Is shipping phone number required
    pub phone_number_required: bool,
}
