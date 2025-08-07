pub mod xml_utils;
use common_utils::CustomResult;
use error_stack::{Report, ResultExt};
pub use xml_utils::preprocess_xml_response_bytes;

use domain_types::{
    
    connector_types::PaymentsAuthorizeData, errors, payment_method_data::PaymentMethodDataTypes,
, router_data::ErrorResponse,
    router_response_types::Response,
};
use hyperswitch_masking::{ExposeInterface, Secret};
use serde_json::Value;

type Error = error_stack::Report<errors::ConnectorError>;

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

    let json_str = json_value.as_str().ok_or_else(|| {
        Report::new(errors::ConnectorError::InvalidConnectorConfig {
            config: "merchant_connector_account.metadata",
        })
    })?;

    let parsed: T = serde_json::from_str(json_str)
        .map_err(Report::from)
        .change_context(errors::ConnectorError::InvalidConnectorConfig {
            config: "merchant_connector_account.metadata",
        })?;

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
            raw_connector_response: None,
        }),
    }
}
