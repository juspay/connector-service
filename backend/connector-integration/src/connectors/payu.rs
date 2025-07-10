pub mod transformers;
use common_utils::types::{AmountConvertor, StringMajorUnitForConnector};
use error_stack::ResultExt;
use serde::{Deserialize, Serialize};

// Import all necessary framework components
use domain_types::{
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
    },
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
};
use domain_types::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use common_utils::{
    errors::CustomResult, ext_traits::ByteSliceExt, request::RequestContent, types::StringMajorUnit,
};
use super::macros;

use transformers::{
    self as payu, PayuPaymentRequest, PayuPaymentResponse
};

// #[derive(Clone)]
// pub struct Payu {
//     pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = String> + Sync),
// }

// impl Payu {
//     pub const fn new() -> &'static Self {
//         &Self {
//             // Based on Payu gateway analysis: uses string major units (e.g., "10.50")
//             amount_converter: &StringMajorUnitForConnector,
//         }
//     }
// }

// Set up connector using macros with all framework integrations
macros::create_all_prerequisites!(
    connector_name: Payu,
    api: [
        (
            flow: Authorize,
            request_body: PayuPaymentRequest,
            response_body: PayuPaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit // Must match the converter chosen above
    ],
    member_functions: {
        // Payu-specific helper functions will be added here
    }
);

// Implement authorize flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Payu,
    curl_request: Json(PayuPaymentRequest),
    curl_response: PayuPaymentResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let auth = PayuAuthType::try_from(&req.connector_auth_type)?;
            Ok(vec![
                ("Content-Type".to_string(), "application/x-www-form-urlencoded".into()),
                ("Accept".to_string(), "application/json".into()),
            ])
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
            connectors: &Connectors,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/payment/op/v1/user/card", self.base_url(connectors)))
        }
    }
);

// Implement ConnectorCommon trait
impl ConnectorCommon for Payu {
    fn id(&self) -> &'static str { "payu" }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor // Standard currency unit
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.payu.base_url
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = PayuAuthType::try_from(auth_type)?;
        // Payu uses form-based authentication, not headers
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: PayuErrorResponse = res
            .response
            .parse_struct("Payu ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.unwrap_or_default(),
            message: response.error_message.unwrap_or_default(),
            reason: response.error_description,
            attempt_status: Some(enums::AttemptStatus::Failure),
            connector_transaction_id: response.transaction_id,
        })
    }
}

// Core service traits
impl connector_types::ConnectorServiceTrait for Payu {}
impl connector_types::PaymentAuthorizeV2 for Payu {}

// **STUB IMPLEMENTATIONS**: Source Verification Framework stubs for main development
// These will be replaced with actual implementations in Phase 10
use crate::interfaces::verification::SourceVerification;
use crate::types::{ConnectorSourceVerificationSecrets, crypto};

impl SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> for Payu {
    fn get_secrets(&self, _secrets: ConnectorSourceVerificationSecrets) -> CustomResult<Vec<u8>, ConnectorError> {
        // STUB: Return empty secrets - will be implemented in Phase 10
        Ok(Vec::new())
    }

    fn get_algorithm(&self) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, ConnectorError> {
        // STUB: Use NoAlgorithm - will be replaced with actual algorithm in Phase 10
        Ok(Box::new(crypto::NoAlgorithm))
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, ConnectorError> {
        // STUB: Return empty signature - will extract actual signature in Phase 10
        Ok(Vec::new())
    }

    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, ConnectorError> {
        // STUB: Return payload as-is - will implement gateway-specific message format in Phase 10
        Ok(payload.to_owned())
    }
}

// Add Source Verification stubs for all other flows
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl SourceVerification<$flow, $common_data, $req, $resp> for Payu {
            fn get_secrets(&self, _secrets: ConnectorSourceVerificationSecrets) -> CustomResult<Vec<u8>, ConnectorError> {
                Ok(Vec::new()) // STUB - will be implemented in Phase 10
            }
            fn get_algorithm(&self) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, ConnectorError> {
                Ok(Box::new(crypto::NoAlgorithm)) // STUB - will be implemented in Phase 10
            }
            fn get_signature(&self, _payload: &[u8], _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>, _secrets: &[u8]) -> CustomResult<Vec<u8>, ConnectorError> {
                Ok(Vec::new()) // STUB - will be implemented in Phase 10
            }
            fn get_message(&self, payload: &[u8], _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>, _secrets: &[u8]) -> CustomResult<Vec<u8>, ConnectorError> {
                Ok(payload.to_owned()) // STUB - will be implemented in Phase 10
            }
        }
    };
}

// Apply stub implementations to all flows
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);

// Connector integration implementations for unsupported flows (stubs)
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Payu {}
impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Payu {}
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Payu {}
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Payu {}
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Payu {}

// Trait aliases (required for compilation)
impl connector_types::RefundV2 for Payu {}
impl connector_types::RefundSyncV2 for Payu {}
impl connector_types::PaymentSyncV2 for Payu {}
impl connector_types::PaymentVoidV2 for Payu {}
impl connector_types::PaymentCapture for Payu {}
impl connector_types::ValidationTrait for Payu {}