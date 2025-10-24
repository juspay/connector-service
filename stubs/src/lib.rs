// Stub implementations for common_enums

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

impl fmt::Display for AttemptStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttemptStatus::Started => write!(f, "started"),
            AttemptStatus::AuthenticationInitiated => write!(f, "authentication_initiated"),
            AttemptStatus::AuthenticationSuccessful => write!(f, "authentication_successful"),
            AttemptStatus::AuthenticationFailed => write!(f, "authentication_failed"),
            AttemptStatus::AuthorizationInitiated => write!(f, "authorization_initiated"),
            AttemptStatus::AuthorizationSuccessful => write!(f, "authorization_successful"),
            AttemptStatus::AuthorizationFailed => write!(f, "authorization_failed"),
            AttemptStatus::CaptureInitiated => write!(f, "capture_initiated"),
            AttemptStatus::CaptureSuccessful => write!(f, "capture_successful"),
            AttemptStatus::CaptureFailed => write!(f, "capture_failed"),
            AttemptStatus::Pending => write!(f, "pending"),
            AttemptStatus::ChargedBack => write!(f, "charged_back"),
            AttemptStatus::VoidInitiated => write!(f, "void_initiated"),
            AttemptStatus::VoidSuccessful => write!(f, "void_successful"),
            AttemptStatus::VoidFailed => write!(f, "void_failed"),
            AttemptStatus::Failure => write!(f, "failure"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Currency::Usd => write!(f, "USD"),
            Currency::Eur => write!(f, "EUR"),
            Currency::Gbp => write!(f, "GBP"),
            Currency::Inr => write!(f, "INR"),
        }
    }
}

impl std::str::FromStr for Currency {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "USD" => Ok(Currency::Usd),
            "EUR" => Ok(Currency::Eur),
            "GBP" => Ok(Currency::Gbp),
            "INR" => Ok(Currency::Inr),
            _ => Err(format!("Invalid currency: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

impl fmt::Display for PaymentMethodType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaymentMethodType::Card => write!(f, "card"),
            PaymentMethodType::Upi => write!(f, "upi"),
            PaymentMethodType::Netbanking => write!(f, "netbanking"),
            PaymentMethodType::Wallet => write!(f, "wallet"),
        }
    }
}