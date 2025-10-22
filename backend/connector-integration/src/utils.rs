pub mod xml_utils;
use common_utils::{types::MinorUnit, CustomResult};
use domain_types::{
    connector_types::{
        PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsSyncData,
        RepeatPaymentData, SetupMandateRequestData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ErrorResponse,
    router_response_types::Response,
};
use error_stack::{Report, ResultExt};
use hyperswitch_masking::{ExposeInterface, Secret};
use serde_json::Value;
use std::str::FromStr;
pub use xml_utils::preprocess_xml_response_bytes;

type Error = error_stack::Report<errors::ConnectorError>;
use common_enums::enums;
use serde::Deserialize;

#[macro_export]
macro_rules! with_error_response_body {
    ($event_builder:ident, $response:ident) => {
        if let Some(body) = $event_builder {
            body.set_error_response_body(&$response);
        }
    };
}

#[macro_export]
macro_rules! with_response_body {
    ($event_builder:ident, $response:ident) => {
        if let Some(body) = $event_builder {
            body.set_response_body(&$response);
        }
    };
}

pub trait PaymentsAuthorizeRequestData {
    fn get_router_return_url(&self) -> Result<String, Error>;
}

impl<
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
    > PaymentsAuthorizeRequestData for PaymentsAuthorizeData<T>
{
    fn get_router_return_url(&self) -> Result<String, Error> {
        self.router_return_url
            .clone()
            .ok_or_else(missing_field_err("return_url"))
    }
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

pub(crate) fn get_unimplemented_payment_method_error_message(connector: &str) -> String {
    format!("Selected payment method through {connector}")
}

pub(crate) fn to_connector_meta_from_secret<T>(
    connector_meta: Option<Secret<Value>>,
) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned,
{
    let connector_meta_secret =
        connector_meta.ok_or_else(missing_field_err("connector_meta_data"))?;

    let json_value = connector_meta_secret.expose();

    let parsed: T = match json_value {
        Value::String(json_str) => serde_json::from_str(&json_str)
            .map_err(Report::from)
            .change_context(errors::ConnectorError::InvalidConnectorConfig {
                config: "merchant_connector_account.metadata",
            })?,
        _ => serde_json::from_value(json_value.clone())
            .map_err(Report::from)
            .change_context(errors::ConnectorError::InvalidConnectorConfig {
                config: "merchant_connector_account.metadata",
            })?,
    };

    Ok(parsed)
}

pub(crate) fn handle_json_response_deserialization_failure(
    res: Response,
    _connector: &'static str,
) -> CustomResult<ErrorResponse, errors::ConnectorError> {
    let response_data = String::from_utf8(res.response.to_vec())
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

    // check for whether the response is in json format
    match serde_json::from_str::<Value>(&response_data) {
        // in case of unexpected response but in json format
        Ok(_) => Err(errors::ConnectorError::ResponseDeserializationFailed)?,
        // in case of unexpected response but in html or string format
        Err(_error_msg) => Ok(ErrorResponse {
            status_code: res.status_code,
            code: "No error code".to_string(),
            message: "Unsupported response type".to_string(),
            reason: Some(response_data),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        }),
    }
}

pub fn is_refund_failure(status: enums::RefundStatus) -> bool {
    match status {
        common_enums::RefundStatus::Failure | common_enums::RefundStatus::TransactionFailure => {
            true
        }
        common_enums::RefundStatus::ManualReview
        | common_enums::RefundStatus::Pending
        | common_enums::RefundStatus::Success => false,
    }
}

pub fn deserialize_zero_minor_amount_as_none<'de, D>(
    deserializer: D,
) -> Result<Option<MinorUnit>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let amount = Option::<MinorUnit>::deserialize(deserializer)?;
    match amount {
        Some(value) if value.get_amount_as_i64() == 0 => Ok(None),
        _ => Ok(amount),
    }
}

pub fn convert_uppercase<'de, D, T>(v: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Debug + std::fmt::Display + std::error::Error,
{
    use serde::de::Error;
    let output = <&str>::deserialize(v)?;
    output.to_uppercase().parse::<T>().map_err(D::Error::custom)
}

pub trait SplitPaymentData {
    fn get_split_payment_data(&self)
        -> Option<domain_types::connector_types::SplitPaymentsRequest>;
}

impl SplitPaymentData for PaymentsCaptureData {
    fn get_split_payment_data(
        &self,
    ) -> Option<domain_types::connector_types::SplitPaymentsRequest> {
        None
    }
}

impl<T: PaymentMethodDataTypes> SplitPaymentData for PaymentsAuthorizeData<T> {
    fn get_split_payment_data(
        &self,
    ) -> Option<domain_types::connector_types::SplitPaymentsRequest> {
        self.split_payments.clone()
    }
}

impl SplitPaymentData for RepeatPaymentData {
    fn get_split_payment_data(
        &self,
    ) -> Option<domain_types::connector_types::SplitPaymentsRequest> {
        self.split_payments.clone()
    }
}

impl SplitPaymentData for PaymentsSyncData {
    fn get_split_payment_data(
        &self,
    ) -> Option<domain_types::connector_types::SplitPaymentsRequest> {
        self.split_payments.clone()
    }
}

impl SplitPaymentData for PaymentVoidData {
    fn get_split_payment_data(
        &self,
    ) -> Option<domain_types::connector_types::SplitPaymentsRequest> {
        None
    }
}

impl<T: PaymentMethodDataTypes> SplitPaymentData for SetupMandateRequestData<T> {
    fn get_split_payment_data(
        &self,
    ) -> Option<domain_types::connector_types::SplitPaymentsRequest> {
        None
    }
}
