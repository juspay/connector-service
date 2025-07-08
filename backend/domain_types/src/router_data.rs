use std::collections::HashMap;

use cards::{
    validate::{CardExpirationMonth, CardExpirationYear},
    NetworkToken,
};
use common_utils::ext_traits::{OptionExt, ValueExt};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};

use crate::utils::missing_field_err;

pub type Error = error_stack::Report<crate::errors::ConnectorError>;

#[derive(Default, Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(tag = "auth_type")]
pub enum ConnectorAuthType {
    TemporaryAuth,
    HeaderKey {
        api_key: Secret<String>,
    },
    BodyKey {
        api_key: Secret<String>,
        key1: Secret<String>,
    },
    SignatureKey {
        api_key: Secret<String>,
        key1: Secret<String>,
        api_secret: Secret<String>,
    },
    MultiAuthKey {
        api_key: Secret<String>,
        key1: Secret<String>,
        api_secret: Secret<String>,
        key2: Secret<String>,
    },
    CurrencyAuthKey {
        auth_key_map: HashMap<common_enums::enums::Currency, common_utils::pii::SecretSerdeValue>,
    },
    CertificateAuth {
        certificate: Secret<String>,
        private_key: Secret<String>,
    },
    #[default]
    NoKey,
}

impl ConnectorAuthType {
    pub fn from_option_secret_value(
        value: Option<common_utils::pii::SecretSerdeValue>,
    ) -> common_utils::errors::CustomResult<Self, common_utils::errors::ParsingError> {
        value
            .parse_value::<Self>("ConnectorAuthType")
            .change_context(common_utils::errors::ParsingError::StructParseFailure(
                "ConnectorAuthType",
            ))
    }

    pub fn from_secret_value(
        value: common_utils::pii::SecretSerdeValue,
    ) -> common_utils::errors::CustomResult<Self, common_utils::errors::ParsingError> {
        value
            .parse_value::<Self>("ConnectorAuthType")
            .change_context(common_utils::errors::ParsingError::StructParseFailure(
                "ConnectorAuthType",
            ))
    }

    // show only first and last two digits of the key and mask others with *
    // mask the entire key if it's length is less than or equal to 4
    fn mask_key(&self, key: String) -> Secret<String> {
        let key_len = key.len();
        let masked_key = if key_len <= 4 {
            "*".repeat(key_len)
        } else {
            // Show the first two and last two characters, mask the rest with '*'
            let mut masked_key = String::new();
            let key_len = key.len();
            // Iterate through characters by their index
            for (index, character) in key.chars().enumerate() {
                if index < 2 || index >= key_len - 2 {
                    masked_key.push(character); // Keep the first two and last two characters
                } else {
                    masked_key.push('*'); // Mask the middle characters
                }
            }
            masked_key
        };
        Secret::new(masked_key)
    }

    // Mask the keys in the auth_type
    pub fn get_masked_keys(&self) -> Self {
        match self {
            Self::TemporaryAuth => Self::TemporaryAuth,
            Self::NoKey => Self::NoKey,
            Self::HeaderKey { api_key } => Self::HeaderKey {
                api_key: self.mask_key(api_key.clone().expose()),
            },
            Self::BodyKey { api_key, key1 } => Self::BodyKey {
                api_key: self.mask_key(api_key.clone().expose()),
                key1: self.mask_key(key1.clone().expose()),
            },
            Self::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Self::SignatureKey {
                api_key: self.mask_key(api_key.clone().expose()),
                key1: self.mask_key(key1.clone().expose()),
                api_secret: self.mask_key(api_secret.clone().expose()),
            },
            Self::MultiAuthKey {
                api_key,
                key1,
                api_secret,
                key2,
            } => Self::MultiAuthKey {
                api_key: self.mask_key(api_key.clone().expose()),
                key1: self.mask_key(key1.clone().expose()),
                api_secret: self.mask_key(api_secret.clone().expose()),
                key2: self.mask_key(key2.clone().expose()),
            },
            Self::CurrencyAuthKey { auth_key_map } => Self::CurrencyAuthKey {
                auth_key_map: auth_key_map.clone(),
            },
            Self::CertificateAuth {
                certificate,
                private_key,
            } => Self::CertificateAuth {
                certificate: self.mask_key(certificate.clone().expose()),
                private_key: self.mask_key(private_key.clone().expose()),
            },
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
    pub status_code: u16,
    pub attempt_status: Option<common_enums::enums::AttemptStatus>,
    pub connector_transaction_id: Option<String>,
    pub network_decline_code: Option<String>,
    pub network_advice_code: Option<String>,
    pub network_error_message: Option<String>,
    pub raw_connector_response: Option<String>,
}

impl Default for ErrorResponse {
    fn default() -> Self {
        Self {
            code: "HE_00".to_string(),
            message: "Something went wrong".to_string(),
            reason: None,
            status_code: http::StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
            raw_connector_response: None,
        }
    }
}

impl ErrorResponse {
    pub fn get_not_implemented() -> Self {
        Self {
            code: "IR_00".to_string(),
            message: "This API is under development and will be made available soon.".to_string(),
            reason: None,
            status_code: http::StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
            raw_connector_response: None,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplePayCryptogramData {
    pub online_payment_cryptogram: Secret<String>,
    pub eci_indicator: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplePayPredecryptData {
    pub application_primary_account_number: Secret<String>,
    pub application_expiration_date: String,
    pub currency_code: String,
    pub transaction_amount: i64,
    pub device_manufacturer_identifier: Secret<String>,
    pub payment_data_type: Secret<String>,
    pub payment_data: ApplePayCryptogramData,
}

impl ApplePayPredecryptData {
    pub fn get_four_digit_expiry_year(&self) -> Result<Secret<String>, Error> {
        Ok(Secret::new(format!(
            "20{}",
            self.application_expiration_date
                .get(0..2)
                .ok_or(crate::errors::ConnectorError::RequestEncodingFailed)?
        )))
    }

    pub fn get_expiry_month(&self) -> Result<Secret<String>, Error> {
        Ok(Secret::new(
            self.application_expiration_date
                .get(2..4)
                .ok_or(crate::errors::ConnectorError::RequestEncodingFailed)?
                .to_owned(),
        ))
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayDecryptedData {
    pub message_expiration: String,
    pub message_id: String,
    #[serde(rename = "paymentMethod")]
    pub payment_method_type: String,
    pub payment_method_details: GooglePayPaymentMethodDetails,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayPaymentMethodDetails {
    pub auth_method: common_enums::enums::GooglePayAuthMethod,
    pub expiration_month: CardExpirationMonth,
    pub expiration_year: CardExpirationYear,
    pub pan: cards::CardNumber,
    pub cryptogram: Option<Secret<String>>,
    pub eci_indicator: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PazeDecryptedData {
    pub client_id: Secret<String>,
    pub profile_id: String,
    pub token: PazeToken,
    pub payment_card_network: common_enums::enums::CardNetwork,
    pub dynamic_data: Vec<PazeDynamicData>,
    pub billing_address: PazeAddress,
    pub consumer: PazeConsumer,
    pub eci: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PazeToken {
    pub payment_token: NetworkTokenNumber,
    pub token_expiration_month: Secret<String>,
    pub token_expiration_year: Secret<String>,
    pub payment_account_reference: Secret<String>,
}

pub type NetworkTokenNumber = NetworkToken;

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PazeConsumer {
    // This is consumer data not customer data.
    pub first_name: Option<Secret<String>>,
    pub last_name: Option<Secret<String>>,
    pub full_name: Secret<String>,
    pub email_address: common_utils::pii::Email,
    pub mobile_number: Option<PazePhoneNumber>,
    pub country_code: Option<common_enums::enums::CountryAlpha2>,
    pub language_code: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PazePhoneNumber {
    pub country_code: Secret<String>,
    pub phone_number: Secret<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PazeAddress {
    pub name: Option<Secret<String>>,
    pub line1: Option<Secret<String>>,
    pub line2: Option<Secret<String>>,
    pub line3: Option<Secret<String>>,
    pub city: Option<Secret<String>>,
    pub state: Option<Secret<String>>,
    pub zip: Option<Secret<String>>,
    pub country_code: Option<common_enums::enums::CountryAlpha2>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PazeDynamicData {
    pub dynamic_data_value: Option<Secret<String>>,
    pub dynamic_data_type: Option<String>,
    pub dynamic_data_expiration: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub enum PaymentMethodToken {
    Token(Secret<String>),
    ApplePayDecrypt(Box<ApplePayPredecryptData>),
    GooglePayDecrypt(Box<GooglePayDecryptedData>),
    PazeDecrypt(Box<PazeDecryptedData>),
}

#[derive(Debug, Default, Clone)]
pub struct RecurringMandatePaymentData {
    pub payment_method_type: Option<common_enums::enums::PaymentMethodType>, //required for making recurring payment using saved payment method through stripe
    pub original_payment_authorized_amount: Option<i64>,
    pub original_payment_authorized_currency: Option<common_enums::enums::Currency>,
    pub mandate_metadata: Option<common_utils::pii::SecretSerdeValue>,
}

impl RecurringMandatePaymentData {
    pub fn get_original_payment_amount(&self) -> Result<i64, Error> {
        self.original_payment_authorized_amount
            .ok_or_else(missing_field_err("original_payment_authorized_amount"))
    }
    pub fn get_original_payment_currency(&self) -> Result<common_enums::Currency, Error> {
        self.original_payment_authorized_currency
            .ok_or_else(missing_field_err("original_payment_authorized_currency"))
    }
}
