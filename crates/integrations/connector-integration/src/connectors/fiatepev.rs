pub mod transformers;

use std::fmt::Debug;

use common_enums::CurrencyUnit;
use common_utils::errors::CustomResult;
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::*,
    errors::IntegrationError,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2,
    connector_types, decode::BodyDecoding, verification::SourceVerification,
};
use serde::Serialize;
use transformers as fiatepev;

use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const X_API_KEY: &str = "X-Api-Key";
    pub(crate) const X_CHECKSUM: &str = "X-Checksum";
}

macros::create_all_prerequisites!(
    connector_name: Fiatepev,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: FiatepevAuthorizeRequest<T>,
            response_body: FiatepevAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let mut headers = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/x-www-form-urlencoded".to_string().into(),
            )];

            // Add API key header
            let auth = fiatepev::FiatepevAuthType::try_from(&req.connector_config)
                .change_context(IntegrationError::FailedToObtainAuthType {
                    context: Default::default(),
                })?;
            headers.push((
                headers::X_API_KEY.to_string(),
                auth.api_key.peek().to_string().into(),
            ));

            Ok(headers)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.fiatepev.base_url
        }

        pub fn generate_hmac_checksum(&self, data: &str, salt_key: &str) -> String {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            type HmacSha256 = Hmac<Sha256>;

            let mut mac = HmacSha256::new_from_slice(salt_key.as_bytes())
                .expect("HMAC can take key of any size");
            mac.update(data.as_bytes());
            let result = mac.finalize();
            hex::encode(result.into_bytes()).to_uppercase()
        }
    }
);

// =============================================================================
// CONNECTOR COMMON IMPLEMENTATION
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Fiatepev<T>
{
    fn id(&self) -> &'static str {
        "fiatepev"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Major
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.fiatepev.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
        let auth = fiatepev::FiatepevAuthType::try_from(auth_type).change_context(
            IntegrationError::FailedToObtainAuthType {
                context: Default::default(),
            },
        )?;
        Ok(vec![(
            headers::X_API_KEY.to_string(),
            auth.api_key.peek().to_string().into(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut common_utils::events::Event>,
    ) -> CustomResult<ErrorResponse, domain_types::errors::ConnectorError> {
        let response: fiatepev::FiatepevErrorResponse = res
            .response
            .parse_struct("FiatepevErrorResponse")
            .change_context(domain_types::errors::ConnectorError::ResponseDeserializationFailed {
                context: Default::default(),
            })?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.code,
            message: response.message,
            reason: None,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// =============================================================================
// AUTHORIZE FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiatepev,
    curl_request: FormUrlEncoded(FiatepevAuthorizeRequest),
    curl_response: FiatepevAuthorizeResponse,
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
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!("{}/initiate-payment/", self.connector_base_url_payments(req)))
        }
    }
);

// =============================================================================
// BODY DECODING IMPLEMENTATION
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> BodyDecoding
    for Fiatepev<T>
{
}

// =============================================================================
// SOURCE VERIFICATION IMPLEMENTATION
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> SourceVerification
    for Fiatepev<T>
{
}

// =============================================================================
// DEFAULT FLOW IMPLEMENTATIONS
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Fiatepev<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Fiatepev<T>
{
}
