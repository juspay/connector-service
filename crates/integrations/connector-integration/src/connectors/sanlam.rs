pub mod transformers;

use super::macros;
use crate::types::ResponseRouterData;
use common_enums::CurrencyUnit;
use common_utils::{
    errors::CustomResult,
    events,
    request::{KafkaRecord, KafkaRecordBuilder, TransportType},
};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData},
    errors::IntegrationError,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    decode::BodyDecoding, verification::SourceVerification,
};
use serde::Serialize;
use std::fmt::Debug;
use transformers::{self as sanlam, SanlamPaymentsRequest, SanlamPaymentsResponse};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const MERCHANT_ID: &str = "Merchant-Id";
}

macros::macro_connector_payout_implementation!(
    connector: Sanlam,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize]
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Sanlam<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Sanlam<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Sanlam<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> SourceVerification
    for Sanlam<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> BodyDecoding
    for Sanlam<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Sanlam<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Sanlam<T>
{
}

macros::create_all_prerequisites!(
    connector_name: Sanlam,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: SanlamPaymentsRequest,
            response_body: SanlamPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        )
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                Self::common_get_content_type(self).to_string().into(),
            )];

            let mut api_key = self.get_auth_header(&req.connector_config)?;
            header.append(&mut api_key);

            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.sanlam.base_url
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Sanlam,
    curl_request: Json(SanlamPaymentsRequest),
    curl_response: SanlamPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_transport_type(&self) -> TransportType {
            TransportType::Kafka
        }

        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            crate::utils::no_request_url(self.id(), "authorize")
        }

        fn get_kafka_topic(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!("{}_payments_queue", self.connector_base_url_payments(req)))
        }

        fn get_kafka_key(
            &self,
            _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Option<String>, IntegrationError> {
            Ok(None)
        }

        fn build_kafka_record(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Option<KafkaRecord>, IntegrationError> {
            Ok(Some(
                KafkaRecordBuilder::new()
                    .topic(self.get_kafka_topic(req)?.as_str())
                    .attach_default_headers()
                    .headers(self.get_headers(req)?)
                    .set_optional_payload(self.get_request_body(req)?)
                    .build(),
            ))
        }
    }
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Sanlam<T>
{
    fn id(&self) -> &'static str {
        "sanlam"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.sanlam.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
        let auth = sanlam::SanlamAuthType::try_from(auth_type).change_context(
            IntegrationError::FailedToObtainAuthType {
                context: Default::default(),
            },
        )?;
        Ok(vec![
            (
                headers::AUTHORIZATION.to_string(),
                auth.api_key.peek().to_owned().into_masked(),
            ),
            (
                headers::MERCHANT_ID.to_string(),
                auth.merchant_id.peek().to_owned().into(),
            ),
        ])
    }
}

macros::macro_connector_flow_status_impls!(
    connector: Sanlam,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    not_implemented: [
        PSync,
        Capture,
        Refund,
        RSync,
        PreAuthenticate,
        Authenticate,
        PostAuthenticate,
        MandateRevoke,
        SetupMandate,
        RepeatPayment,
        PaymentMethodToken,
    ],
    not_supported: [
        Void,
        CreateOrder,
        SubmitEvidence,
        DefendDispute,
        Accept,
        ServerSessionAuthenticationToken,
        ServerAuthenticationToken,
        VoidPC,
        ClientAuthenticationToken,
        CreateConnectorCustomer,
        IncrementalAuthorization,
    ],
);
