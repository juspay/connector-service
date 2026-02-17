pub mod transformers;

use std::fmt::Debug;

use common_enums::CurrencyUnit;
use common_utils::{errors::CustomResult, events, ext_traits::ByteSliceExt};
use domain_types::{
    connector_flow, connector_types::*, errors, payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType, router_response_types::Response, types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Maskable};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
};
use serde::Serialize;
use transformers as fiservemea;

use crate::with_error_response_body;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const API_KEY: &str = "Api-Key";
    pub(crate) const CLIENT_REQUEST_ID: &str = "Client-Request-Id";
    pub(crate) const TIMESTAMP: &str = "Timestamp";
    pub(crate) const MESSAGE_SIGNATURE: &str = "Message-Signature";
}

#[derive(Debug, Clone)]
pub struct Fiservemea<T: PaymentMethodDataTypes> {
    payment_method_type: std::marker::PhantomData<T>,
}

impl<T: PaymentMethodDataTypes> Fiservemea<T> {
    pub const fn new() -> &'static Self {
        &Self {
            payment_method_type: std::marker::PhantomData,
        }
    }
}

// =============================================================================

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Fiservemea<T>
{
    fn id(&self) -> &'static str {
        "fiservemea"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        "https://prod.emea.api.fiservapps.com/sandbox"
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = fiservemea::FiservemeaAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![
            (headers::AUTHORIZATION.to_string(), format!("Bearer {}", auth.api_key.expose()).into()),
        ])
    }

    fn build_headers_with_signature(
        &self,
        auth: &fiservemea::FiservemeaAuthType,
        request_body_str: &str,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let client_request_id = fiservemea::FiservemeaAuthType::generate_client_request_id();
        let timestamp = fiservemea::FiservemeaAuthType::generate_timestamp();

        let api_key_value = auth.api_key.clone().expose();
        let message_signature = auth.generate_hmac_signature(
            &api_key_value,
            &client_request_id,
            &timestamp,
            request_body_str,
        )?;

        Ok(vec![
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
            headers::API_KEY.to_string(),
            Secret::new(api_key_value).into_masked(),
            headers::CLIENT_REQUEST_ID.to_string(),
            client_request_id.into(),
            headers::TIMESTAMP.to_string(),
            timestamp.into(),
            headers::MESSAGE_SIGNATURE.to_string(),
            message_signature.into(),
        ])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        let response: fiservemea::FiservemeaErrorResponse = res
            .response
            .parse_struct("FiservemeaErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(domain_types::router_data::ErrorResponse {
            status_code: res.status_code,
            code: response.code.unwrap_or_default(),
            message: response.message.unwrap_or_default(),
            reason: response.api_trace_id,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// =============================================================================

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

// =============================================================================

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Fiservemea<T>
{
}

// =============================================================================

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Fiservemea<T>
{
}

// ===== MACRO PREREQUISITES =====
macros::create_all_prerequisites!(
    connector_name: Fiservemea,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: FiservemeaAuthorizeRequest<T>,
            response_body: FiservemeaAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        fn build_headers_with_signature(
            &self,
            auth: &fiservemea::FiservemeaAuthType,
            request_body_str: &str,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let client_request_id = fiservemea::FiservemeaAuthType::generate_client_request_id();
            let timestamp = fiservemea::FiservemeaAuthType::generate_timestamp();

            let api_key_value = auth.api_key.clone().expose();
            let message_signature = auth.generate_hmac_signature(
                &api_key_value,
                &client_request_id,
                &timestamp,
                request_body_str,
            )?;

            Ok(vec![
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
                headers::API_KEY.to_string(),
                Secret::new(api_key_value).into_masked(),
                headers::CLIENT_REQUEST_ID.to_string(),
                client_request_id.into(),
                headers::TIMESTAMP.to_string(),
                timestamp.into(),
                headers::MESSAGE_SIGNATURE.to_string(),
                message_signature.into(),
            ])
        }
    }
);

// ===== AUTHORIZE FLOW IMPLEMENTATION =====
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiservemea,
    curl_request: Json(FiservemeaAuthorizeRequest<T>),
    curl_response: FiservemeaAuthorizeResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let auth = fiservemea::FiservemeaAuthType::try_from(&req.connector_auth_type)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

            let connector_req = FiservemeaAuthorizeRequest::try_from(req)?;
            let request_body_str = serde_json::to_string(&connector_req)
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;

            self.build_headers_with_signature(&auth, &request_body_str)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok("https://prod.emea.api.fiservapps.com/sandbox".to_string())
        }
    }
);
