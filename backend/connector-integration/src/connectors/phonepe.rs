pub mod constants;
pub mod headers;
pub mod transformers;

use self::transformers::{PhonepePaymentsRequest, PhonepePaymentsResponse};
use common_enums as enums;
use common_utils::{
    errors::CustomResult, ext_traits::BytesExt, request::RequestContent, types::MinorUnit,
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund,
        RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, ConnectorSpecifications, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::{ConnectorInfo, Connectors},
};
use error_stack::ResultExt;
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent, verification::SourceVerification,
};
use transformers as phonepe;

use super::macros;
use crate::{types::ResponseRouterData, with_response_body};

// Define connector prerequisites
macros::create_all_prerequisites!(
    connector_name: Phonepe,
    api: [
        (
            flow: Authorize,
            request_body: PhonepePaymentsRequest,
            response_body: PhonepePaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
        )
    ],
    amount_converters: [minor_unit_for_converter: MinorUnit],
    member_functions: {
        pub fn connector_base_url<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> String {
            req.resource_common_data.connectors.phonepe.base_url.to_string()
        }

        fn preprocess_response_bytes(
            &self,
            bytes: bytes::Bytes,
        ) -> CustomResult<bytes::Bytes, errors::ConnectorError> {
            Ok(bytes)
        }
    }
);

// Authorize flow implementation using macros
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Phonepe,
    curl_request: Json(PhonepePaymentsRequest),
    curl_response: PhonepePaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: false,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            // Get base headers first
            let mut headers = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/json".to_string().into(),
                ),
            ];

            // Build the request to get the checksum for X-VERIFY header
            let amount = req.request.minor_amount;
            let connector_router_data = phonepe::PhonepeRouterData::try_from((amount, req))?;
            let connector_req = phonepe::PhonepePaymentsRequest::try_from(&connector_router_data)?;
            headers.push((headers::X_VERIFY.to_string(), connector_req.checksum.into()));

            Ok(headers)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.connector_base_url(req);
            Ok(format!("{}{}", base_url, constants::API_PAY_ENDPOINT))
        }
    }
);

impl connector_types::ValidationTrait for Phonepe {}
impl connector_types::PaymentAuthorizeV2 for Phonepe {}

// Default empty implementations for unsupported flows
impl connector_types::PaymentSyncV2 for Phonepe {}
impl connector_types::PaymentOrderCreate for Phonepe {}
impl connector_types::PaymentVoidV2 for Phonepe {}
impl connector_types::IncomingWebhook for Phonepe {}
impl connector_types::RefundV2 for Phonepe {}
impl connector_types::PaymentCapture for Phonepe {}
impl connector_types::SetupMandateV2 for Phonepe {}
impl connector_types::RepeatPaymentV2 for Phonepe {}
impl connector_types::AcceptDispute for Phonepe {}
impl connector_types::RefundSyncV2 for Phonepe {}
impl connector_types::DisputeDefend for Phonepe {}
impl connector_types::SubmitEvidenceV2 for Phonepe {}

// Implement ConnectorServiceTrait by virtue of implementing all required traits
impl connector_types::ConnectorServiceTrait for Phonepe {}

impl ConnectorCommon for Phonepe {
    fn id(&self) -> &'static str {
        "phonepe"
    }

    fn get_currency_unit(&self) -> enums::CurrencyUnit {
        enums::CurrencyUnit::Minor
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let _auth = phonepe::PhonepeAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            "Content-Type".to_string(),
            "application/json".to_string().into(),
        )])
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.phonepe.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: phonepe::PhonepePaymentsResponse = res
            .response
            .parse_struct("PhonePe ErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        let error_message = response.message.clone();
        let error_code = response.code.clone();

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: error_code,
            message: error_message.clone(),
            reason: Some(error_message),
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
        })
    }
}

// Default empty implementations for unsupported flows - the traits will use default implementations
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Phonepe
{
}
impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Phonepe
{
}
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Phonepe
{
}
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Phonepe {}
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Phonepe
{
}
impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Phonepe
{
}
impl ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Phonepe
{
}
impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Phonepe
{
}
impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Phonepe
{
}
impl
    ConnectorIntegrationV2<
        DefendDispute,
        DisputeFlowData,
        domain_types::connector_types::DisputeDefendData,
        DisputeResponseData,
    > for Phonepe
{
}
impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Phonepe
{
}

impl ConnectorSpecifications for Phonepe {
    fn get_supported_payment_methods(
        &self,
    ) -> Option<&'static domain_types::types::SupportedPaymentMethods> {
        None // TODO: Add UPI payment methods support
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        None // TODO: Add webhook support
    }

    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        None // TODO: Add connector info
    }
}

// SourceVerification implementations for all flows - using macro to generate stubs
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl SourceVerification<$flow, $common_data, $req, $resp> for Phonepe {
            fn get_secrets(
                &self,
                _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // Stub implementation
            }
            fn get_algorithm(
                &self,
            ) -> CustomResult<
                Box<dyn common_utils::crypto::VerifySignature + Send>,
                errors::ConnectorError,
            > {
                Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
            }
            fn get_signature(
                &self,
                _payload: &[u8],
                _router_data: &domain_types::router_data_v2::RouterDataV2<
                    $flow,
                    $common_data,
                    $req,
                    $resp,
                >,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // Stub implementation
            }
            fn get_message(
                &self,
                payload: &[u8],
                _router_data: &domain_types::router_data_v2::RouterDataV2<
                    $flow,
                    $common_data,
                    $req,
                    $resp,
                >,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(payload.to_owned()) // Stub implementation
            }
        }
    };
}

// Apply to all flows
impl_source_verification_stub!(
    Authorize,
    PaymentFlowData,
    PaymentsAuthorizeData,
    PaymentsResponseData
);
impl_source_verification_stub!(
    CreateOrder,
    PaymentFlowData,
    PaymentCreateOrderData,
    PaymentCreateOrderResponse
);
impl_source_verification_stub!(
    PSync,
    PaymentFlowData,
    PaymentsSyncData,
    PaymentsResponseData
);
impl_source_verification_stub!(
    Capture,
    PaymentFlowData,
    PaymentsCaptureData,
    PaymentsResponseData
);
impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
impl_source_verification_stub!(
    SetupMandate,
    PaymentFlowData,
    SetupMandateRequestData,
    PaymentsResponseData
);
impl_source_verification_stub!(
    RepeatPayment,
    PaymentFlowData,
    RepeatPaymentData,
    PaymentsResponseData
);
impl_source_verification_stub!(
    Accept,
    DisputeFlowData,
    AcceptDisputeData,
    DisputeResponseData
);
impl_source_verification_stub!(
    SubmitEvidence,
    DisputeFlowData,
    SubmitEvidenceData,
    DisputeResponseData
);
impl_source_verification_stub!(
    DefendDispute,
    DisputeFlowData,
    domain_types::connector_types::DisputeDefendData,
    DisputeResponseData
);
