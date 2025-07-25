use std::{
    collections::{HashMap, HashSet},
    sync::LazyLock,
};

use base64::Engine;
use common_enums::{CurrencyUnit, PaymentMethodType};
use common_utils::{consts, AmountConvertor, CustomResult, MinorUnit};
use error_stack::{report, Result, ResultExt};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use time::PrimitiveDateTime;

use crate::{
    errors::{self, ParsingError},
    payment_method_data::{Card, PaymentMethodData},
    router_data::ErrorResponse,
    router_response_types::Response,
    types::PaymentMethodDataType,
};

pub type Error = error_stack::Report<errors::ConnectorError>;

/// Trait for converting from one foreign type to another
pub trait ForeignTryFrom<F>: Sized {
    /// Custom error for conversion failure
    type Error;

    /// Convert from a foreign type to the current type and return an error if the conversion fails
    fn foreign_try_from(from: F) -> Result<Self, Self::Error>;
}

pub trait ForeignFrom<F>: Sized {
    /// Convert from a foreign type to the current type and return an error if the conversion fails
    fn foreign_from(from: F) -> Self;
}

pub trait ValueExt {
    /// Convert `serde_json::Value` into type `<T>` by using `serde::Deserialize`
    fn parse_value<T>(self, type_name: &'static str) -> Result<T, ParsingError>
    where
        T: serde::de::DeserializeOwned;
}

impl ValueExt for serde_json::Value {
    fn parse_value<T>(self, type_name: &'static str) -> Result<T, ParsingError>
    where
        T: serde::de::DeserializeOwned,
    {
        let debug = format!(
            "Unable to parse {type_name} from serde_json::Value: {:?}",
            &self
        );
        serde_json::from_value::<T>(self)
            .change_context(ParsingError::StructParseFailure(type_name))
            .attach_printable_lazy(|| debug)
    }
}

pub trait Encode<'e>
where
    Self: 'e + std::fmt::Debug,
{
    fn encode_to_value(&'e self) -> Result<serde_json::Value, ParsingError>
    where
        Self: Serialize;
}

impl<'e, A> Encode<'e> for A
where
    Self: 'e + std::fmt::Debug,
{
    fn encode_to_value(&'e self) -> Result<serde_json::Value, ParsingError>
    where
        Self: Serialize,
    {
        serde_json::to_value(self)
            .change_context(ParsingError::EncodeError("json-value"))
            .attach_printable_lazy(|| format!("Unable to convert {self:?} to a value"))
    }
}

pub fn handle_json_response_deserialization_failure(
    res: Response,
    _: &'static str,
) -> CustomResult<ErrorResponse, crate::errors::ConnectorError> {
    let response_data = String::from_utf8(res.response.to_vec())
        .change_context(crate::errors::ConnectorError::ResponseDeserializationFailed)?;

    // check for whether the response is in json format
    match serde_json::from_str::<Value>(&response_data) {
        // in case of unexpected response but in json format
        Ok(_) => Err(crate::errors::ConnectorError::ResponseDeserializationFailed)?,
        // in case of unexpected response but in html or string format
        Err(_) => Ok(ErrorResponse {
            status_code: res.status_code,
            code: consts::NO_ERROR_CODE.to_string(),
            message: consts::UNSUPPORTED_ERROR_MESSAGE.to_string(),
            reason: Some(response_data.clone()),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            raw_connector_response: Some(response_data),
        }),
    }
}

pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    // returns random bytes of length n
    let mut rng = rand::thread_rng();
    (0..length).map(|_| rand::Rng::gen(&mut rng)).collect()
}

pub fn missing_field_err(
    message: &'static str,
) -> Box<dyn Fn() -> error_stack::Report<errors::ConnectorError> + 'static> {
    Box::new(move || {
        errors::ConnectorError::MissingRequiredField {
            field_name: message,
        }
        .into()
    })
}

pub fn construct_not_supported_error_report(
    capture_method: common_enums::CaptureMethod,
    connector_name: &'static str,
) -> error_stack::Report<errors::ConnectorError> {
    errors::ConnectorError::NotSupported {
        message: capture_method.to_string(),
        connector: connector_name,
    }
    .into()
}

pub fn to_currency_base_unit_with_zero_decimal_check(
    amount: i64,
    currency: common_enums::Currency,
) -> core::result::Result<String, error_stack::Report<errors::ConnectorError>> {
    currency
        .to_currency_base_unit_with_zero_decimal_check(amount)
        .change_context(errors::ConnectorError::RequestEncodingFailed)
}

pub fn get_timestamp_in_milliseconds(datetime: &PrimitiveDateTime) -> i64 {
    let utc_datetime = datetime.assume_utc();
    utc_datetime.unix_timestamp() * 1000
}

pub fn get_amount_as_string(
    currency_unit: &CurrencyUnit,
    amount: i64,
    currency: common_enums::Currency,
) -> core::result::Result<String, error_stack::Report<errors::ConnectorError>> {
    let amount = match currency_unit {
        CurrencyUnit::Minor => amount.to_string(),
        CurrencyUnit::Base => to_currency_base_unit(amount, currency)?,
    };
    Ok(amount)
}

pub fn base64_decode(
    data: String,
) -> core::result::Result<Vec<u8>, error_stack::Report<errors::ConnectorError>> {
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)
}

pub(crate) fn to_currency_base_unit(
    amount: i64,
    currency: common_enums::Currency,
) -> core::result::Result<String, error_stack::Report<errors::ConnectorError>> {
    currency
        .to_currency_base_unit(amount)
        .change_context(errors::ConnectorError::ParsingFailed)
}

pub const SELECTED_PAYMENT_METHOD: &str = "Selected payment method";

pub fn get_unimplemented_payment_method_error_message(connector: &str) -> String {
    format!("{SELECTED_PAYMENT_METHOD} through {connector}")
}

pub fn get_header_key_value<'a>(
    key: &str,
    headers: &'a actix_web::http::header::HeaderMap,
) -> CustomResult<&'a str, errors::ConnectorError> {
    get_header_field(headers.get(key))
}

fn get_header_field(
    field: Option<&http::HeaderValue>,
) -> CustomResult<&str, errors::ConnectorError> {
    field
        .map(|header_value| {
            header_value
                .to_str()
                .change_context(errors::ConnectorError::WebhookSignatureNotFound)
        })
        .ok_or(report!(
            errors::ConnectorError::WebhookSourceVerificationFailed
        ))?
}

pub fn is_payment_failure(status: common_enums::AttemptStatus) -> bool {
    match status {
        common_enums::AttemptStatus::AuthenticationFailed
        | common_enums::AttemptStatus::AuthorizationFailed
        | common_enums::AttemptStatus::CaptureFailed
        | common_enums::AttemptStatus::VoidFailed
        | common_enums::AttemptStatus::Failure => true,
        common_enums::AttemptStatus::Started
        | common_enums::AttemptStatus::RouterDeclined
        | common_enums::AttemptStatus::AuthenticationPending
        | common_enums::AttemptStatus::AuthenticationSuccessful
        | common_enums::AttemptStatus::Authorized
        | common_enums::AttemptStatus::Charged
        | common_enums::AttemptStatus::Authorizing
        | common_enums::AttemptStatus::CodInitiated
        | common_enums::AttemptStatus::Voided
        | common_enums::AttemptStatus::VoidInitiated
        | common_enums::AttemptStatus::CaptureInitiated
        | common_enums::AttemptStatus::AutoRefunded
        | common_enums::AttemptStatus::PartialCharged
        | common_enums::AttemptStatus::PartialChargedAndChargeable
        | common_enums::AttemptStatus::Unresolved
        | common_enums::AttemptStatus::Pending
        | common_enums::AttemptStatus::PaymentMethodAwaited
        | common_enums::AttemptStatus::ConfirmationAwaited
        | common_enums::AttemptStatus::DeviceDataCollectionPending
        | common_enums::AttemptStatus::IntegrityFailure
        | common_enums::AttemptStatus::Unknown => false,
    }
}

pub fn get_card_details(
    payment_method_data: PaymentMethodData,
    connector_name: &'static str,
) -> Result<Card, errors::ConnectorError> {
    match payment_method_data {
        PaymentMethodData::Card(details) => Ok(details),
        _ => Err(errors::ConnectorError::NotSupported {
            message: SELECTED_PAYMENT_METHOD.to_string(),
            connector: connector_name,
        })?,
    }
}

pub fn is_mandate_supported(
    selected_pmd: PaymentMethodData,
    payment_method_type: Option<PaymentMethodType>,
    mandate_implemented_pmds: HashSet<PaymentMethodDataType>,
    connector: &'static str,
) -> core::result::Result<(), Error> {
    if mandate_implemented_pmds.contains(&PaymentMethodDataType::from(selected_pmd.clone())) {
        Ok(())
    } else {
        match payment_method_type {
            Some(pm_type) => Err(errors::ConnectorError::NotSupported {
                message: format!("{pm_type} mandate payment"),
                connector,
            }
            .into()),
            None => Err(errors::ConnectorError::NotSupported {
                message: " mandate payment".to_string(),
                connector,
            }
            .into()),
        }
    }
}

pub fn convert_amount<T>(
    amount_convertor: &dyn AmountConvertor<Output = T>,
    amount: MinorUnit,
    currency: common_enums::Currency,
) -> core::result::Result<T, Error> {
    amount_convertor
        .convert(amount, currency)
        .change_context(errors::ConnectorError::AmountConversionFailed)
}

pub fn convert_back_amount_to_minor_units<T>(
    amount_convertor: &dyn AmountConvertor<Output = T>,
    amount: T,
    currency: common_enums::Currency,
) -> core::result::Result<MinorUnit, error_stack::Report<errors::ConnectorError>> {
    amount_convertor
        .convert_back(amount, currency)
        .change_context(errors::ConnectorError::AmountConversionFailed)
}

#[derive(Debug, Copy, Clone, strum::Display, Eq, Hash, PartialEq)]
pub enum CardIssuer {
    AmericanExpress,
    Master,
    Maestro,
    Visa,
    Discover,
    DinersClub,
    JCB,
    CarteBlanche,
    CartesBancaires,
}

#[track_caller]
pub fn get_card_issuer(card_number: &str) -> core::result::Result<CardIssuer, Error> {
    for (k, v) in CARD_REGEX.iter() {
        let regex: Regex = v
            .clone()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        if regex.is_match(card_number) {
            return Ok(*k);
        }
    }
    Err(error_stack::Report::new(
        errors::ConnectorError::NotImplemented("Card Type".into()),
    ))
}

static CARD_REGEX: LazyLock<HashMap<CardIssuer, core::result::Result<Regex, regex::Error>>> =
    LazyLock::new(|| {
        let mut map = HashMap::new();
        // Reference: https://gist.github.com/michaelkeevildown/9096cd3aac9029c4e6e05588448a8841
        // [#379]: Determine card issuer from card BIN number
        map.insert(CardIssuer::Master, Regex::new(r"^5[1-5][0-9]{14}$"));
        map.insert(CardIssuer::AmericanExpress, Regex::new(r"^3[47][0-9]{13}$"));
        map.insert(CardIssuer::Visa, Regex::new(r"^4[0-9]{12}(?:[0-9]{3})?$"));
        map.insert(CardIssuer::Discover, Regex::new(r"^65[4-9][0-9]{13}|64[4-9][0-9]{13}|6011[0-9]{12}|(622(?:12[6-9]|1[3-9][0-9]|[2-8][0-9][0-9]|9[01][0-9]|92[0-5])[0-9]{10})$"));
        map.insert(
            CardIssuer::Maestro,
            Regex::new(r"^(5018|5020|5038|5893|6304|6759|6761|6762|6763)[0-9]{8,15}$"),
        );
        map.insert(
            CardIssuer::DinersClub,
            Regex::new(r"^3(?:0[0-5]|[68][0-9])[0-9]{11}$"),
        );
        map.insert(
            CardIssuer::JCB,
            Regex::new(r"^(3(?:088|096|112|158|337|5(?:2[89]|[3-8][0-9]))\d{12})$"),
        );
        map.insert(CardIssuer::CarteBlanche, Regex::new(r"^389[0-9]{11}$"));
        map
    });
