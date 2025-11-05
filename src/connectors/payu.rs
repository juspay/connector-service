// Payu Connector Implementation
pub mod transformers;
pub mod constants;

use std::marker::PhantomData;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        ConnectorSpecifications, ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData,
        PaymentsResponseData, PaymentsSyncData, RefundSyncData, RefundsResponseData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use masking::ExposeInterface;

use crate::{
    connectors::utils::ConnectorRequestType,
    services::{self, ConnectorCommon, ConnectorCommonV2},
    types,
};

// Create all prerequisites using the mandatory macro framework
macros::create_all_prerequisites!(
    connector_name: Payu,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: transformers::PayuPaymentsRequest,
            response_body: transformers::PayuPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: transformers::PayuPaymentsSyncRequest,
            response_body: transformers::PayuPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: RSync,
            request_body: transformers::PayuRefundSyncRequest,
            response_body: transformers::PayuRefundSyncResponse,
            router_data: RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        get_content_type: |&self, _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>| {
            Ok(services::ContentType::Form)
        },
        get_error_response_v2: |&self, response: &[u8], flow: &str| {
            services::handle_unsupported_connector_error(response, flow, self.get_base_url())
        },
        get_api_tag: |&self, flow: &str| {
            match flow {
                "Authorize" => "upi_transaction",
                "PSync" => "payment_status",
                "RSync" => "refund_status",
                _ => "default"
            }
        }
    }
);

// Implement the connector using the mandatory macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Payu,
    curl_request: Form(transformers::PayuPaymentsRequest),
    curl_response: transformers::PayuPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        get_base_url: |&self, req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>| {
            if req.resource_common_data.test_mode.unwrap_or(false) {
                Ok("https://test.payu.in".to_string())
            } else {
                Ok("https://info.payu.in".to_string())
            }
        },
        build_request_v2: |&self, req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>| {
            let request = transformers::PayuPaymentsRequest::try_from(req)?;
            let url = self.get_base_url(req)? + "/merchant/postservice.php?form=2";
            Ok(Some(
                services::RequestBuilder::new()
                    .method(services::Method::Post)
                    .url(&url)
                    .attach_default_headers()
                    .set_body(RequestContent::Form(request))
                    .build(),
            ))
        },
        handle_response_v2: |&self, req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, response: &[u8]| {
            let response: transformers::PayuPaymentsResponse = response
                .parse_struct("PayuPaymentsResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            Ok(types::ResponseRouterDataV2::from((
                req,
                transformers::PayuPaymentsResponse::try_from(response)?,
            )))
        }
    }
);

// Implement PSync flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Payu,
    curl_request: Form(transformers::PayuPaymentsSyncRequest),
    curl_response: transformers::PayuPaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        get_base_url: |&self, req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>| {
            if req.resource_common_data.test_mode.unwrap_or(false) {
                Ok("https://test.payu.in".to_string())
            } else {
                Ok("https://info.payu.in".to_string())
            }
        },
        build_request_v2: |&self, req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>| {
            let request = transformers::PayuPaymentsSyncRequest::try_from(req)?;
            let url = self.get_base_url(req)? + "/merchant/postservice.php?form=2";
            Ok(Some(
                services::RequestBuilder::new()
                    .method(services::Method::Post)
                    .url(&url)
                    .attach_default_headers()
                    .set_body(RequestContent::Form(request))
                    .build(),
            ))
        },
        handle_response_v2: |&self, req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, response: &[u8]| {
            let response: transformers::PayuPaymentsSyncResponse = response
                .parse_struct("PayuPaymentsSyncResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            Ok(types::ResponseRouterDataV2::from((
                req,
                transformers::PayuPaymentsSyncResponse::try_from(response)?,
            )))
        }
    }
);

// Implement RSync flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Payu,
    curl_request: Form(transformers::PayuRefundSyncRequest),
    curl_response: transformers::PayuRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: PaymentFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        get_base_url: |&self, req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>| {
            if req.resource_common_data.test_mode.unwrap_or(false) {
                Ok("https://test.payu.in".to_string())
            } else {
                Ok("https://info.payu.in".to_string())
            }
        },
        build_request_v2: |&self, req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>| {
            let request = transformers::PayuRefundSyncRequest::try_from(req)?;
            let url = self.get_base_url(req)? + "/merchant/postservice.php?form=2";
            Ok(Some(
                services::RequestBuilder::new()
                    .method(services::Method::Post)
                    .url(&url)
                    .attach_default_headers()
                    .set_body(RequestContent::Form(request))
                    .build(),
            ))
        },
        handle_response_v2: |&self, req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>, response: &[u8]| {
            let response: transformers::PayuRefundSyncResponse = response
                .parse_struct("PayuRefundSyncResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            Ok(types::ResponseRouterDataV2::from((
                req,
                transformers::PayuRefundSyncResponse::try_from(response)?,
            )))
        }
    }
);

// Implement ConnectorCommon trait for Payu
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorCommon for Payu<T>
{
    fn get_id(&self) -> &'static str {
        "payu"
    }

    fn get_name(&self) -> &'static str {
        "PayU"
    }

    fn get_connector_type(&self) -> domain_types::connector_types::ConnectorType {
        domain_types::connector_types::ConnectorType::PaymentProcessor
    }

    fn get_supported_payment_methods(&self) -> Vec<PaymentMethodType> {
        vec![
            PaymentMethodType::Upi,
            PaymentMethodType::UpiCollect,
            PaymentMethodType::UpiIntent,
        ]
    }

    fn get_connector_specifications(&self) -> ConnectorSpecifications {
        ConnectorSpecifications {
            connector_name: "PayU".to_string(),
            connector_type: domain_types::connector_types::ConnectorType::PaymentProcessor,
            supported_payment_methods: self.get_supported_payment_methods(),
            supported_currencies: vec![
                common_enums::Currency::INR,
            ],
            supported_countries: vec![
                common_enums::Country::IN,
            ],
            supports_three_ds: false,
            supports_webhook: true,
            supports_refund: true,
            supports_capture: false,
            supports_void: false,
            supports_mandate: true,
            supports_session_token: false,
            supports_create_order: false,
            supports_accept_dispute: false,
            supports_defend_dispute: false,
            supports_submit_evidence: false,
            supports_repeat_payment: false,
        }
    }
}

// Implement ConnectorCommonV2 trait
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorCommonV2 for Payu<T>
{
    fn get_webhook_secret(&self) -> Option<&ConnectorWebhookSecrets> {
        None
    }

    fn validate_webhook_source(&self, _request: &[u8]) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

// Source verification stubs for all flows
impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(RSync, PaymentFlowData, RefundSyncData, RefundsResponseData);

// Implement all required connector traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentAuthorizeV2 for Payu<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentSyncV2 for Payu<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::RefundSyncV2 for Payu<T> {}

// Stub implementations for unsupported flows
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentCaptureV2 for Payu<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentVoidV2 for Payu<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::RefundV2 for Payu<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentOrderCreate for Payu<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentSessionToken for Payu<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::SetupMandateV2 for Payu<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::RepeatPaymentV2 for Payu<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::AcceptDisputeV2 for Payu<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::DefendDisputeV2 for Payu<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::SubmitEvidenceV2 for Payu<T> {}