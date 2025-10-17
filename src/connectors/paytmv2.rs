pub mod transformers;

use std::marker::PhantomData;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    consts::BASE_URL,
    crypto,
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{self, StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        ConnectorSpecifications, ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData,
        PaymentsResponseData, PaymentsSyncData, RefundSyncData, RefundsResponseData,
    },
    errors,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    router_data_v2::{self, ConnectorCommonData},
    router_request_types::ResponseId,
};
use hyperswitch_interfaces::ConnectorCommon;
use masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    connectors::utils::construct_payment_method_data,
    types::{self, ConnectorAuthType},
};

#[derive(Debug, Clone)]
pub struct PayTMv2<T> {
    amount_converter: &'static (dyn types::AmountConverterTrait<Output = String> + Sync),
    connector_name: &'static str,
    payment_method_data: PhantomData<T>,
}

impl<T> Clone for PayTMv2<T> {
    fn clone(&self) -> Self {
        Self {
            amount_converter: self.amount_converter,
            connector_name: self.connector_name,
            payment_method_data: PhantomData,
        }
    }
}

impl<T> Default for PayTMv2<T> {
    fn default() -> Self {
        Self {
            amount_converter: &StringMinorUnit,
            connector_name: "paytmv2",
            payment_method_data: PhantomData,
        }
    }
}

impl<T> ConnectorCommon for PayTMv2<T>
where
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
{
    fn get_id(&self) -> &'static str {
        self.connector_name
    }

    fn get_base_url(&self) -> &'static str {
        BASE_URL
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, masking::Secret<String>)>, errors::ConnectorError> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key } => {
                let auth_header = format!("{}:{}", api_key.expose(), key.expose());
                Ok(vec![("Authorization".to_string(), auth_header.into())])
            }
            _ => Err(errors::ConnectorError::AuthenticationFailed.into()),
        }
    }

    fn build_error_response(
        &self,
        res: hyperswitch_interfaces::Response,
    ) -> CustomResult<errors::ConnectorError, errors::ConnectorError> {
        let response: transformers::PayTMv2ErrorResponse = res
            .response
            .parse_struct("PayTMv2ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        match response.error_code.as_str() {
            "400" => Ok(errors::ConnectorError::RequestEncodingFailed.into()),
            "401" => Ok(errors::ConnectorError::AuthenticationFailed.into()),
            "403" => Ok(errors::ConnectorError::AccessForbidden.into()),
            "404" => Ok(errors::ConnectorError::ResourceNotFound.into()),
            "429" => Ok(errors::ConnectorError::RateLimitExceeded.into()),
            "500" => Ok(errors::ConnectorError::InternalServerError.into()),
            _ => Ok(errors::ConnectorError::UnexpectedError(response.error_message).into()),
        }
    }
}

// Create all prerequisites using the mandatory macro framework
macros::create_all_prerequisites!(
    connector_name: PayTMv2,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: transformers::PayTMv2PaymentsRequest,
            response_body: transformers::PayTMv2PaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: transformers::PayTMv2PaymentsSyncRequest,
            response_body: transformers::PayTMv2PaymentsResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: RSync,
            request_body: transformers::PayTMv2RefundSyncRequest,
            response_body: transformers::PayTMv2RefundSyncResponse,
            router_data: RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        fn get_api_tag(&self, flow: &str) -> &'static str {
            match flow {
                "Authorize" => "payments/initiate",
                "PSync" => "payments/status",
                "RSync" => "refunds/status",
                _ => "",
            }
        }

        fn get_content_type(&self) -> &'static str {
            "application/json"
        }

        fn get_error_response_v2(
            &self,
            res: hyperswitch_interfaces::Response,
        ) -> CustomResult<errors::ConnectorError, errors::ConnectorError> {
            self.build_error_response(res)
        }
    }
);

// Implement the Authorize flow using the mandatory macro
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: PayTMv2,
    curl_request: Json(transformers::PayTMv2PaymentsRequest),
    curl_response: transformers::PayTMv2PaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_api_tag(&self, _flow: &str) -> &'static str {
            "payments/initiate"
        }
    }
);

// Implement the PSync flow using the mandatory macro
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: PayTMv2,
    curl_request: Json(transformers::PayTMv2PaymentsSyncRequest),
    curl_response: transformers::PayTMv2PaymentsResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_api_tag(&self, _flow: &str) -> &'static str {
            "payments/status"
        }
    }
);

// Implement the RSync flow using the mandatory macro
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: PayTMv2,
    curl_request: Json(transformers::PayTMv2RefundSyncRequest),
    curl_response: transformers::PayTMv2RefundSyncResponse,
    flow_name: RSync,
    resource_common_data: PaymentFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_api_tag(&self, _flow: &str) -> &'static str {
            "refunds/status"
        }
    }
);

// Implement connector traits for all required flows
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentAuthorizeV2 for PayTMv2<T> {}
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentSyncV2 for PayTMv2<T> {}
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::RefundSyncV2 for PayTMv2<T> {}

// Stub implementations for other flows (not implemented in this migration)
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
            hyperswitch_interfaces::ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for PayTMv2<T>
        {
            fn build_request_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
            ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
                let flow_name = stringify!($flow);
                Err(errors::ConnectorError::NotImplemented(flow_name.to_string()).into())
            }

            fn handle_response_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _res: hyperswitch_interfaces::Response,
            ) -> CustomResult<router_data_v2::RouterDataV2<$flow, $common_data, $req, $resp>, errors::ConnectorError> {
                let flow_name = stringify!($flow);
                Err(errors::ConnectorError::NotImplemented(flow_name.to_string()).into())
            }
        }
    };
}

// Implement stubs for all other flows
impl_not_implemented_flow!(domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::Refund, PaymentFlowData, domain_types::connector_types::RefundsData, RefundsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::CreateOrder, PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse);
impl_not_implemented_flow!(domain_types::connector_flow::CreateSessionToken, PaymentFlowData, domain_types::connector_types::SessionTokenRequestData, domain_types::connector_types::SessionTokenResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::SetupMandate, PaymentFlowData, domain_types::connector_types::SetupMandateRequestData, domain_types::connector_types::PaymentsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::RepeatPayment, PaymentFlowData, domain_types::connector_types::RepeatPaymentData, PaymentsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::Accept, PaymentFlowData, domain_types::connector_types::AcceptDisputeData, domain_types::connector_types::DisputeResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::DefendDispute, PaymentFlowData, domain_types::connector_types::DisputeDefendData, domain_types::connector_types::DisputeResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::SubmitEvidence, PaymentFlowData, domain_types::connector_types::SubmitEvidenceData, domain_types::connector_types::DisputeResponseData);

// Source verification stubs for all flows
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
            hyperswitch_interfaces::SourceVerificationV2<$flow, $common_data, $req, $resp> for PayTMv2<T>
        {
            fn verify_source(
                &self,
                _request: &RouterDataV2<$flow, $common_data, $req, $resp>,
            ) -> CustomResult<domain_types::connector_types::VerifyResponseData, errors::ConnectorError> {
                Err(errors::ConnectorError::NotImplemented("Source verification not implemented".to_string()).into())
            }
        }
    };
}

impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(RSync, PaymentFlowData, RefundSyncData, RefundsResponseData);
impl_source_verification_stub!(domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData);
impl_source_verification_stub!(domain_types::connector_flow::Refund, PaymentFlowData, domain_types::connector_types::RefundsData, RefundsResponseData);
impl_source_verification_stub!(domain_types::connector_flow::CreateOrder, PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse);
impl_source_verification_stub!(domain_types::connector_flow::CreateSessionToken, PaymentFlowData, domain_types::connector_types::SessionTokenRequestData, domain_types::connector_types::SessionTokenResponseData);
impl_source_verification_stub!(domain_types::connector_flow::SetupMandate, PaymentFlowData, domain_types::connector_types::SetupMandateRequestData, domain_types::connector_types::PaymentsResponseData);
impl_source_verification_stub!(domain_types::connector_flow::RepeatPayment, PaymentFlowData, domain_types::connector_types::RepeatPaymentData, PaymentsResponseData);
impl_source_verification_stub!(domain_types::connector_flow::Accept, PaymentFlowData, domain_types::connector_types::AcceptDisputeData, domain_types::connector_types::DisputeResponseData);
impl_source_verification_stub!(domain_types::connector_flow::DefendDispute, PaymentFlowData, domain_types::connector_types::DisputeDefendData, domain_types::connector_types::DisputeResponseData);
impl_source_verification_stub!(domain_types::connector_flow::SubmitEvidence, PaymentFlowData, domain_types::connector_types::SubmitEvidenceData, domain_types::connector_types::DisputeResponseData);

// Implement connector traits for stub flows
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentVoidV2 for PayTMv2<T> {}
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentCaptureV2 for PayTMv2<T> {}
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentRefundV2 for PayTMv2<T> {}
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentOrderCreate for PayTMv2<T> {}
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentSessionToken for PayTMv2<T> {}
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::MandateSetupV2 for PayTMv2<T> {}
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentRepeatV2 for PayTMv2<T> {}
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::DisputeAcceptV2 for PayTMv2<T> {}
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::DisputeDefendV2 for PayTMv2<T> {}
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::DisputeSubmitEvidenceV2 for PayTMv2<T> {}

// Connector specifications
impl<T> ConnectorSpecifications for PayTMv2<T>
where
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
{
    fn get_supported_payment_methods(&self) -> Vec<PaymentMethodType> {
        vec![PaymentMethodType::Upi]
    }

    fn get_webhook_secret(&self) -> Option<&ConnectorWebhookSecrets> {
        None
    }
}