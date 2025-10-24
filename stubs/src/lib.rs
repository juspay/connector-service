// Stub implementations for common_enums

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

#[derive(Debug, Clone, Serialize, Deserialize, Display, EnumString, PartialEq)]
pub enum AttemptStatus {
    #[serde(rename = "started")]
    Started,
    #[serde(rename = "authentication_initiated")]
    AuthenticationInitiated,
    #[serde(rename = "authentication_successful")]
    AuthenticationSuccessful,
    #[serde(rename = "authentication_failed")]
    AuthenticationFailed,
    #[serde(rename = "authorization_initiated")]
    AuthorizationInitiated,
    #[serde(rename = "authorization_successful")]
    AuthorizationSuccessful,
    #[serde(rename = "authorization_failed")]
    AuthorizationFailed,
    #[serde(rename = "capture_initiated")]
    CaptureInitiated,
    #[serde(rename = "capture_successful")]
    CaptureSuccessful,
    #[serde(rename = "capture_failed")]
    CaptureFailed,
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "charged_back")]
    ChargedBack,
    #[serde(rename = "void_initiated")]
    VoidInitiated,
    #[serde(rename = "void_successful")]
    VoidSuccessful,
    #[serde(rename = "void_failed")]
    VoidFailed,
    #[serde(rename = "failure")]
    Failure,
}

#[derive(Debug, Clone, Serialize, Deserialize, Display, EnumString, PartialEq)]
pub enum Currency {
    #[serde(rename = "USD")]
    Usd,
    #[serde(rename = "EUR")]
    Eur,
    #[serde(rename = "GBP")]
    Gbp,
    #[serde(rename = "INR")]
    Inr,
}

impl std::str::FromStr for Currency {
    type Err = thiserror::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "USD" => Ok(Currency::Usd),
            "EUR" => Ok(Currency::Eur),
            "GBP" => Ok(Currency::Gbp),
            "INR" => Ok(Currency::Inr),
            _ => Err(thiserror::Error::msg(format!("Invalid currency: {}", s))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Display, EnumString, PartialEq)]
pub enum PaymentMethodType {
    #[serde(rename = "card")]
    Card,
    #[serde(rename = "upi")]
    Upi,
    #[serde(rename = "netbanking")]
    Netbanking,
    #[serde(rename = "wallet")]
    Wallet,
}