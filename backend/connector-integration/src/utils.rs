use domain_types::connector_types::PaymentsAuthorizeData;
use domain_types::errors;

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

impl PaymentsAuthorizeRequestData for PaymentsAuthorizeData {
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

pub mod xml_utils;
pub use xml_utils::preprocess_xml_response_bytes;
