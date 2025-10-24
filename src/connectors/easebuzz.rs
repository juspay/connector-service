// EaseBuzz Connector Implementation
pub mod constants;
pub mod transformers;

use std::fmt::Debug;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        ConnectorCommon, ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData,
        RefundSyncData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface, Secret};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;
use transformers::{self as easebuzz, EaseBuzzPaymentsRequest, EaseBuzzPaymentsResponse};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

// Trait implementations with generic type parameters
impl<
        T: PaymentMethodDataTypes
            + Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ConnectorServiceTrait<T> for EaseBuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentAuthorizeV2<T> for EaseBuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentSyncV2 for EaseBuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RefundV2 for EaseBuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RefundSyncV2 for EaseBuzz<T>
{
}

// Create all prerequisites using the mandatory macro framework
macros::create_all_prerequisites!(
    connector_name: EaseBuzz,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: EaseBuzzPaymentsRequest,
            response_body: EaseBuzzPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: EaseBuzzPaymentsSyncRequest,
            response_body: EaseBuzzPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: EaseBuzzRefundRequest,
            response_body: EaseBuzzRefundResponse,
            router_data: RouterDataV2<Refund, PaymentFlowData, RefundFlowData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: EaseBuzzRefundSyncRequest,
            response_body: EaseBuzzRefundSyncResponse,
            router_data: RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            let mut header = vec![(
                "Content-Type".to_string(),
                self.common_get_content_type().to_string().into(),
            )];
            Ok(header)
        }

        fn get_content_type(&self) -> &'static str {
            "application/x-www-form-urlencoded"
        }

        fn get_error_response_v2(
            &self,
            res: Response,
            event_builder: Option<&mut ConnectorEvent>,
        ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
            self.build_error_response(res, event_builder)
        }

        fn build_error_response(
            &self,
            res: Response,
            _event_builder: Option<&mut ConnectorEvent>,
        ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
            let error_response: transformers::EaseBuzzErrorResponse = res
                .response
                .parse_struct("EaseBuzzErrorResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            Ok(ErrorResponse {
                status_code: res.status_code,
                code: error_response.error_code,
                message: error_response.error_desc,
                reason: None,
            })
        }
    }
);

// Implement connector common traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommon for EaseBuzz<T>
{
    fn get_id(&self) -> &'static str {
        "easebuzz"
    }

    fn get_name(&self) -> &'static str {
        "EaseBuzz"
    }

    fn get_connector_type(&self) -> domain_types::ConnectorType {
        domain_types::ConnectorType::PaymentGateway
    }

    fn get_connector_metadata(&self) -> Option<domain_types::ConnectorMetadata> {
        Some(domain_types::ConnectorMetadata {
            description: Some("EaseBuzz payment gateway supporting UPI transactions".to_string()),
            website: Some("https://easebuzz.in".to_string()),
            supported_payment_methods: vec![PaymentMethodType::Upi],
            supported_currencies: vec!["INR".parse().unwrap()],
            supported_countries: vec!["IN".parse().unwrap()],
            ..Default::default()
        })
    }

    fn get_webhook_secret(&self) -> Option<&Secret<String>> {
        None
    }

    fn get_webhook_url(&self) -> Option<&str> {
        None
    }

    fn get_webhook_details(&self) -> Option<ConnectorWebhookSecrets> {
        None
    }

    fn get_connector_specifications(&self) -> ConnectorSpecifications {
        ConnectorSpecifications {
            connector_name: "easebuzz".to_string(),
            connector_type: domain_types::ConnectorType::PaymentGateway,
            supported_payment_methods: vec![PaymentMethodType::Upi],
            supported_currencies: vec!["INR".parse().unwrap()],
            supported_countries: vec!["IN".parse().unwrap()],
            ..Default::default()
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommonV2 for EaseBuzz<T>
{
    fn get_api_tag(&self, flow: &str) -> &'static str {
        match flow {
            "Authorize" => "payment",
            "PSync" => "sync",
            "RSync" => "refund_sync",
            "Refund" => "refund",
            _ => "default",
        }
    }
}

// Implement Authorize flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Form(EaseBuzzPaymentsRequest),
    curl_response: EaseBuzzPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
            let connector_request = transformers::EaseBuzzPaymentsRequest::try_from(req)?;
            let request = services::RequestBuilder::new()
                .method(services::Method::Post)
                .url(&types::PaymentsAuthorizeType::get_url(
                    self,
                    req,
                    &self.base_url,
                )?)
                .attach_default_headers()
                .set_body(types::RequestBody::Form(connector_request))
                .build();

            Ok(Some(request))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            res: services::Response,
        ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, errors::ConnectorError> {
            let response: transformers::EaseBuzzPaymentsResponse = res
                .response
                .parse_struct("EaseBuzzPaymentsResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            let router_response = transformers::EaseBuzzPaymentsResponse::try_from(response)?;

            Ok(req.get_response(
                router_response.status,
                router_response.error_desc,
                router_response,
            ))
        }
    }
);

// Implement PSync flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Form(EaseBuzzPaymentsSyncRequest),
    curl_response: EaseBuzzPaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
            let connector_request = transformers::EaseBuzzPaymentsSyncRequest::try_from(req)?;
            let request = services::RequestBuilder::new()
                .method(services::Method::Post)
                .url(&types::PaymentsSyncType::get_url(
                    self,
                    req,
                    &self.base_url,
                )?)
                .attach_default_headers()
                .set_body(types::RequestBody::Form(connector_request))
                .build();

            Ok(Some(request))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            res: services::Response,
        ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> {
            let response: transformers::EaseBuzzPaymentsSyncResponse = res
                .response
                .parse_struct("EaseBuzzPaymentsSyncResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            let router_response = transformers::EaseBuzzPaymentsSyncResponse::try_from(response)?;

            Ok(req.get_response(
                router_response.status,
                Some(router_response.msg),
                router_response,
            ))
        }
    }
);

// Implement Refund flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Form(EaseBuzzRefundRequest),
    curl_response: EaseBuzzRefundResponse,
    flow_name: Refund,
    resource_common_data: PaymentFlowData,
    flow_request: RefundFlowData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<Refund, PaymentFlowData, RefundFlowData, RefundsResponseData>,
        ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
            let connector_request = transformers::EaseBuzzRefundRequest::try_from(req)?;
            let request = services::RequestBuilder::new()
                .method(services::Method::Post)
                .url(&types::RefundType::get_url(
                    self,
                    req,
                    &self.base_url,
                )?)
                .attach_default_headers()
                .set_body(types::RequestBody::Form(connector_request))
                .build();

            Ok(Some(request))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<Refund, PaymentFlowData, RefundFlowData, RefundsResponseData>,
            res: services::Response,
        ) -> CustomResult<RouterDataV2<Refund, PaymentFlowData, RefundFlowData, RefundsResponseData>, errors::ConnectorError> {
            let response: transformers::EaseBuzzRefundResponse = res
                .response
                .parse_struct("EaseBuzzRefundResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            let router_response = transformers::EaseBuzzRefundResponse::try_from(response)?;

            Ok(req.get_response(
                router_response.status,
                router_response.reason,
                router_response,
            ))
        }
    }
);

// Implement RSync flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Form(EaseBuzzRefundSyncRequest),
    curl_response: EaseBuzzRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: PaymentFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
            let connector_request = transformers::EaseBuzzRefundSyncRequest::try_from(req)?;
            let request = services::RequestBuilder::new()
                .method(services::Method::Post)
                .url(&types::RefundSyncType::get_url(
                    self,
                    req,
                    &self.base_url,
                )?)
                .attach_default_headers()
                .set_body(types::RequestBody::Form(connector_request))
                .build();

            Ok(Some(request))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
            res: services::Response,
        ) -> CustomResult<RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>, errors::ConnectorError> {
            let response: transformers::EaseBuzzRefundSyncResponse = res
                .response
                .parse_struct("EaseBuzzRefundSyncResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            let router_response = transformers::EaseBuzzRefundSyncResponse::try_from(response)?;

            Ok(req.get_response(
                router_response.status,
                Some(router_response.message),
                router_response,
            ))
        }
    }
);

// Add source verification stubs for all flows
impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(Refund, PaymentFlowData, RefundFlowData, RefundsResponseData);
impl_source_verification_stub!(RSync, PaymentFlowData, RefundSyncData, RefundsResponseData);

// Implement connector types traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::PaymentAuthorizeV2 for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::PaymentSyncV2 for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::RefundV2 for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::RefundSyncV2 for EaseBuzz<T>
{
}