// Type definitions for the connector service

use std::fmt;

use common_enums::Currency;
use common_utils::errors::CustomResult;
use common_utils::types::MinorUnit;
use masking::Secret;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectorEnum {
    Adyen,
    Authorizedotnet,
    Cashtocode,
    Checkout,
    Coinbase,
    Cybersource,
    Fiserv,
    Globalpay,
    Nuvei,
    PayTMv2,
    Razorpay,
    Stripe,
    Worldpay,
}

impl fmt::Display for ConnectorEnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectorEnum::Adyen => write!(f, "adyen"),
            ConnectorEnum::Authorizedotnet => write!(f, "authorizedotnet"),
            ConnectorEnum::Cashtocode => write!(f, "cashtocode"),
            ConnectorEnum::Checkout => write!(f, "checkout"),
            ConnectorEnum::Coinbase => write!(f, "coinbase"),
            ConnectorEnum::Cybersource => write!(f, "cybersource"),
            ConnectorEnum::Fiserv => write!(f, "fiserv"),
            ConnectorEnum::Globalpay => write!(f, "globalpay"),
            ConnectorEnum::Nuvei => write!(f, "nuvei"),
            ConnectorEnum::PayTMv2 => write!(f, "paytmv2"),
            ConnectorEnum::Razorpay => write!(f, "razorpay"),
            ConnectorEnum::Stripe => write!(f, "stripe"),
            ConnectorEnum::Worldpay => write!(f, "worldpay"),
        }
    }
}

impl From<&str> for ConnectorEnum {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "adyen" => ConnectorEnum::Adyen,
            "authorizedotnet" => ConnectorEnum::Authorizedotnet,
            "cashtocode" => ConnectorEnum::Cashtocode,
            "checkout" => ConnectorEnum::Checkout,
            "coinbase" => ConnectorEnum::Coinbase,
            "cybersource" => ConnectorEnum::Cybersource,
            "fiserv" => ConnectorEnum::Fiserv,
            "globalpay" => ConnectorEnum::Globalpay,
            "nuvei" => ConnectorEnum::Nuvei,
            "paytmv2" => ConnectorEnum::PayTMv2,
            "razorpay" => ConnectorEnum::Razorpay,
            "stripe" => ConnectorEnum::Stripe,
            "worldpay" => ConnectorEnum::Worldpay,
            _ => panic!("Unknown connector: {}", s),
        }
    }
}

// Connector authentication types
#[derive(Debug, Clone)]
pub enum ConnectorAuthType {
    SignatureKey {
        api_key: masking::Secret<String>,
        key: masking::Secret<String>,
    },
    BodyKey {
        api_key: masking::Secret<String>,
        key1: masking::Secret<String>,
    },
    MultiAuthKey {
        api_key: masking::Secret<String>,
        key1: masking::Secret<String>,
        key2: masking::Secret<String>,
    },
    HeaderKey {
        api_key: masking::Secret<String>,
        key1: masking::Secret<String>,
    },
    CustomAuth {
        custom_auth_type: String,
        api_key: masking::Secret<String>,
        key1: masking::Secret<String>,
    },
}

// Amount converter trait
pub trait AmountConverterTrait: Send + Sync {
    type Output;

    fn convert(&self, amount: common_utils::types::MinorUnit, currency: common_enums::Currency) -> CustomResult<Self::Output, errors::ConnectorError>;
}

// String minor unit converter
pub struct StringMinorUnit;

impl AmountConverterTrait for StringMinorUnit {
    type Output = String;

    fn convert(&self, amount: common_utils::types::MinorUnit, _currency: common_enums::Currency) -> CustomResult<Self::Output, errors::ConnectorError> {
        Ok(amount.get_amount_as_string())
    }
}

// String major unit converter
pub struct StringMajorUnit;

impl AmountConverterTrait for StringMajorUnit {
    type Output = String;

    fn convert(&self, amount: common_utils::types::MinorUnit, _currency: common_enums::Currency) -> CustomResult<Self::Output, errors::ConnectorError> {
        Ok(amount.get_amount_as_major_unit_string())
    }
}

// Minor unit converter
pub struct MinorUnit;

impl AmountConverterTrait for MinorUnit {
    type Output = i64;

    fn convert(&self, amount: common_utils::types::MinorUnit, _currency: common_enums::Currency) -> CustomResult<Self::Output, errors::ConnectorError> {
        Ok(amount.get_amount_as_i64())
    }
}