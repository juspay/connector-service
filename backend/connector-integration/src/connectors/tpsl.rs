pub mod constants;
pub mod transformers;

use base64::Engine;
use common_enums::CurrencyUnit;
use common_utils::{
    errors::CustomResult, ext_traits::ByteSliceExt,
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{
        Authorize, PSync,
    },
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;
use transformers::{self as tpsl, TpslPaymentsRequest, TpslPaymentsResponse, TpslPaymentsSyncRequest, TpslPaymentsSyncResponse};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

// MANDATORY: Use UCS v2 macro framework - create_all_prerequisites! macro
macros::create_all_prerequisites!(
    connector_name: TPSL,
    generic_type: T,
    api: [
        // UPI and Sync flows only as specified in requirements
        (
            flow: Authorize,
            request_body: TpslPaymentsRequest,
            response_body: TpslPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: TpslPaymentsSyncRequest,
            response_body: TpslPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        // CRITICAL: TPSL expects amounts in minor units as string based on Haskell implementation
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            let mut header = vec![(
                crate::connectors::tpsl::constants::headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];

            let auth_type = tpsl::TpslAuthType::try_from(&req.connector_auth_type)?;

            let mut auth_header = vec![(
                crate::connectors::tpsl::constants::headers::AUTHORIZATION.to_string(),
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(format!(
                        "{}:{}",
                        auth_type.merchant_code.peek(),
                        auth_type.merchant_key.peek()
                    ))
                ).into(),
            )];

            header.append(&mut auth_header);
            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.tpsl.base_url
        }

        pub fn get_api_tag<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> &'static str {
            // CRITICAL: Proper API tag implementation for routing
            std::any::type_name::<F>()
                .split("::")
                .last()
                .unwrap_or("unknown")
        }
    }
);

// MANDATORY: Use macro_connector_implementation! for Authorize flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: TPSL,
    curl_request: Json(TpslPaymentsRequest),
    curl_response: TpslPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}{}",
                self.connector_base_url_payments(req),
                constants::endpoints::UPI_TOKEN_GENERATION
            ))
        }
    }
);

// MANDATORY: Use macro_connector_implementation! for PSync flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: TPSL,
    curl_request: Json(TpslPaymentsSyncRequest),
    curl_response: TpslPaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}{}",
                self.connector_base_url_payments(req),
                constants::endpoints::UPI_TOKEN_GENERATION
            ))
        }
    }
);

// MANDATORY: Implement all required traits for ConnectorServiceTrait<T>
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentSessionToken for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentAccessToken for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::IncomingWebhook for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundV2 for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentCapture for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RepeatPaymentV2 for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::AcceptDispute for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundSyncV2 for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::DisputeDefend for TPSL<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for TPSL<T>
{
}

// MANDATORY: Implement ConnectorServiceTrait<T> manually
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for TPSL<T>
{
}

// MANDATORY: ConnectorCommon implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommon for TPSL<T>
{
    fn id(&self) -> &'static str {
        "tpsl"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        constants::base_urls::PRODUCTION
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // TPSL uses custom auth in get_headers
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: tpsl::TpslErrorResponse = res
            .response
            .parse_struct("TpslErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code,
            message: response.error_message.clone(),
            reason: Some(response.error_message),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

// MANDATORY: SourceVerification stub implementations for implemented flows only
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<
                T: PaymentMethodDataTypes
                    + std::fmt::Debug
                    + std::marker::Sync
                    + std::marker::Send
                    + 'static
                    + Serialize,
            > SourceVerification<$flow, $common_data, $req, $resp> for TPSL<T>
        {
            fn get_secrets(
                &self,
                _secrets: ConnectorSourceVerificationSecrets,
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // STUB - will be implemented in Phase 10
            }
            fn get_algorithm(
                &self,
            ) -> CustomResult<
                Box<dyn common_utils::crypto::VerifySignature + Send>,
                errors::ConnectorError,
            > {
                Ok(Box::new(common_utils::crypto::NoAlgorithm)) // STUB - will be implemented in Phase 10
            }
            fn get_signature(
                &self,
                _payload: &[u8],
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // STUB - will be implemented in Phase 10
            }
            fn get_message(
                &self,
                payload: &[u8],
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(payload.to_owned()) // STUB - will be implemented in Phase 10
            }
        }
    };
}

// Apply to implemented flows only
impl_source_verification_stub!(
    Authorize,
    PaymentFlowData,
    PaymentsAuthorizeData<T>,
    PaymentsResponseData
);
impl_source_verification_stub!(
    PSync,
    PaymentFlowData,
    PaymentsSyncData,
    PaymentsResponseData
);