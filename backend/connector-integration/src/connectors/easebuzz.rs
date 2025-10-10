pub mod constants;
pub mod transformers;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::{self, StringMinorUnit},
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, RSync,
        Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, ConnectorWebhookSecrets, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, RequestDetails, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
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

use self::transformers as easebuzz;
use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

// Create all prerequisites using UCS v2 macro framework
macros::create_all_prerequisites!(
    connector_name: EaseBuzz,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: easebuzz::EaseBuzzPaymentsRequest,
            response_body: easebuzz::EaseBuzzPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: easebuzz::EaseBuzzPaymentsSyncRequest,
            response_body: easebuzz::EaseBuzzPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: RSync,
            request_body: easebuzz::EaseBuzzRefundSyncRequest,
            response_body: easebuzz::EaseBuzzRefundSyncResponse,
            router_data: RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/x-www-form-urlencoded"
        }

        fn get_error_response_v2(
            &self,
            res: &Response,
        ) -> CustomResult<errors::ConnectorError, errors::ConnectorError> {
            let response: easebuzz::EaseBuzzErrorResponse = res
                .response
                .parse_struct("EaseBuzzErrorResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            match response.status {
                0 => Ok(errors::ConnectorError::NoResponseBody),
                _ => Err(errors::ConnectorError::NoResponseBody),
            }
        }
    }
);

// Implement connector common trait
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommon for EaseBuzz<T>
{
    fn get_id(&self) -> &'static str {
        "easebuzz"
    }

    fn get_base_url(&self) -> &'static str {
        constants::BASE_URL
    }

    fn get_connector_name(&self) -> String {
        "EaseBuzz".to_string()
    }

    fn get_connector_version(&self) -> String {
        "1.0.0".to_string()
    }

    fn get_api_tag(&self) -> String {
        match self.flow_type {
            api::FlowType::Authorize => "payment_initiate".to_string(),
            api::FlowType::PSync => "payment_sync".to_string(),
            api::FlowType::RSync => "refund_sync".to_string(),
            _ => "default".to_string(),
        }
    }

    fn get_webhook_secret(&self) -> Option<&ConnectorWebhookSecrets> {
        None
    }

    fn get_connector_specifications(&self) -> ConnectorSpecifications {
        ConnectorSpecifications {
            connector_name: "EaseBuzz".to_string(),
            supported_payment_methods: vec![PaymentMethodType::Upi],
            supported_flows: vec![
                api::FlowType::Authorize,
                api::FlowType::PSync,
                api::FlowType::RSync,
            ],
            supported_currencies: vec!["INR".to_string()],
            supported_countries: vec!["IN".to_string()],
            ..Default::default()
        }
    }
}

// Implement Authorize flow using macro
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Form(easebuzz::EaseBuzzPaymentsRequest),
    curl_response: easebuzz::EaseBuzzPaymentsResponse,
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
            let auth = easebuzz::EaseBuzzAuthType::try_from(&req.connector_auth_type)?;
            let request = easebuzz::EaseBuzzPaymentsRequest::try_from(req)?;
            
            let url = if req.resource_common_data.test_mode.unwrap_or(false) {
                constants::TEST_PAYMENT_INITIATE_URL.to_string()
            } else {
                constants::PROD_PAYMENT_INITIATE_URL.to_string()
            };

            Ok(Some(
                services::RequestBuilder::new()
                    .method(services::Method::Post)
                    .url(&url)
                    .attach_default_headers()
                    .headers(vec![(
                        "Authorization".to_string(),
                        format!("Basic {}", auth.get_auth_header()),
                    )])
                    .set_body(services::RequestBody::Form(request))
                    .build(),
            ))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            res: &common_utils::types::Response,
        ) -> CustomResult<domain_types::PaymentsResponseData, errors::ConnectorError> {
            let response: easebuzz::EaseBuzzPaymentsResponse = res
                .response
                .parse_struct("EaseBuzzPaymentsResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            easebuzz::EaseBuzzPaymentsResponse::try_from(response)
                .and_then(|response| domain_types::PaymentsResponseData::try_from(response))
                .change_context(errors::ConnectorError::ResponseHandlingFailed)
        }
    }
);

// Implement PSync flow using macro
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Form(easebuzz::EaseBuzzPaymentsSyncRequest),
    curl_response: easebuzz::EaseBuzzPaymentsSyncResponse,
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
            let auth = easebuzz::EaseBuzzAuthType::try_from(&req.connector_auth_type)?;
            let request = easebuzz::EaseBuzzPaymentsSyncRequest::try_from(req)?;
            
            let url = if req.resource_common_data.test_mode.unwrap_or(false) {
                constants::TEST_TXN_SYNC_URL.to_string()
            } else {
                constants::PROD_TXN_SYNC_URL.to_string()
            };

            Ok(Some(
                services::RequestBuilder::new()
                    .method(services::Method::Post)
                    .url(&url)
                    .attach_default_headers()
                    .headers(vec![(
                        "Authorization".to_string(),
                        format!("Basic {}", auth.get_auth_header()),
                    )])
                    .set_body(services::RequestBody::Form(request))
                    .build(),
            ))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            res: &common_utils::types::Response,
        ) -> CustomResult<domain_types::PaymentsResponseData, errors::ConnectorError> {
            let response: easebuzz::EaseBuzzPaymentsSyncResponse = res
                .response
                .parse_struct("EaseBuzzPaymentsSyncResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            easebuzz::EaseBuzzPaymentsSyncResponse::try_from(response)
                .and_then(|response| domain_types::PaymentsResponseData::try_from(response))
                .change_context(errors::ConnectorError::ResponseHandlingFailed)
        }
    }
);

// Implement RSync flow using macro
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Form(easebuzz::EaseBuzzRefundSyncRequest),
    curl_response: easebuzz::EaseBuzzRefundSyncResponse,
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
            let auth = easebuzz::EaseBuzzAuthType::try_from(&req.connector_auth_type)?;
            let request = easebuzz::EaseBuzzRefundSyncRequest::try_from(req)?;
            
            let url = if req.resource_common_data.test_mode.unwrap_or(false) {
                constants::TEST_REFUND_SYNC_URL.to_string()
            } else {
                constants::PROD_REFUND_SYNC_URL.to_string()
            };

            Ok(Some(
                services::RequestBuilder::new()
                    .method(services::Method::Post)
                    .url(&url)
                    .attach_default_headers()
                    .headers(vec![(
                        "Authorization".to_string(),
                        format!("Basic {}", auth.get_auth_header()),
                    )])
                    .set_body(services::RequestBody::Form(request))
                    .build(),
            ))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
            res: &common_utils::types::Response,
        ) -> CustomResult<domain_types::RefundsResponseData, errors::ConnectorError> {
            let response: easebuzz::EaseBuzzRefundSyncResponse = res
                .response
                .parse_struct("EaseBuzzRefundSyncResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            easebuzz::EaseBuzzRefundSyncResponse::try_from(response)
                .and_then(|response| domain_types::RefundsResponseData::try_from(response))
                .change_context(errors::ConnectorError::ResponseHandlingFailed)
        }
    }
);

// Add source verification stubs for implemented flows
impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
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
    domain_types::connector_types::RefundSyncV2 for EaseBuzz<T>
{
}