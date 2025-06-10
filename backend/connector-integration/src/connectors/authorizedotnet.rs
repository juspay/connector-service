pub mod transformers;

use self::transformers::{
    // Import the flow-specific response types
    AuthorizedotnetAuthorizeResponse,
    AuthorizedotnetCaptureRequest,
    AuthorizedotnetCaptureResponse,
    AuthorizedotnetCreateSyncRequest,
    AuthorizedotnetPSyncResponse,
    AuthorizedotnetPaymentsRequest,
    AuthorizedotnetVoidRequest,
    AuthorizedotnetVoidResponse,
};
use super::macros;
use crate::{types::ResponseRouterData, with_response_body};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDispute, AcceptDisputeData, ConnectorServiceTrait, DisputeDefend, DisputeDefendData,
        DisputeFlowData, DisputeResponseData, IncomingWebhook, PaymentAuthorizeV2, PaymentCapture,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentOrderCreate,
        PaymentSyncV2, PaymentVoidData, PaymentVoidV2, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundSyncV2,
        RefundV2, RefundsData, RefundsResponseData, SetupMandateRequestData, SetupMandateV2,
        SubmitEvidenceData, SubmitEvidenceV2, ValidationTrait,
    },
};
use error_stack::ResultExt;
use hyperswitch_common_utils::{
    errors::CustomResult, ext_traits::ByteSliceExt, request::RequestContent,
};
use hyperswitch_domain_models::{router_data::ErrorResponse, router_data_v2::RouterDataV2};
use hyperswitch_interfaces::errors::ConnectorError;
use hyperswitch_interfaces::{
    api::{self, ConnectorCommon},
    configs::Connectors,
    connector_integration_v2::ConnectorIntegrationV2,
    consts, errors,
    events::connector_api_logs::ConnectorEvent,
    types::Response,
};
use hyperswitch_masking::Maskable;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
}

// Implement all required traits for ConnectorServiceTrait
impl ConnectorServiceTrait for Authorizedotnet {}
impl ValidationTrait for Authorizedotnet {}
impl IncomingWebhook for Authorizedotnet {}
impl SubmitEvidenceV2 for Authorizedotnet {}
impl DisputeDefend for Authorizedotnet {}
impl RefundSyncV2 for Authorizedotnet {}
impl AcceptDispute for Authorizedotnet {}
impl SetupMandateV2 for Authorizedotnet {}
impl PaymentOrderCreate for Authorizedotnet {}
impl PaymentAuthorizeV2 for Authorizedotnet {}
impl PaymentSyncV2 for Authorizedotnet {}
impl PaymentVoidV2 for Authorizedotnet {}
impl RefundV2 for Authorizedotnet {}
impl PaymentCapture for Authorizedotnet {}

// Basic connector implementation
impl ConnectorCommon for Authorizedotnet {
    fn id(&self) -> &'static str {
        "authorizedotnet"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.authorizedotnet.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: transformers::ResponseMessages = res
            .response
            .parse_struct("ResponseMessages")
            .map_err(|_| ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response
                .message
                .first()
                .map(|m| m.code.clone())
                .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
            message: response
                .message
                .first()
                .map(|m| m.text.clone())
                .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
            reason: None,
            attempt_status: None,
            connector_transaction_id: None,
        })
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Base
    }
}

// Define connector prerequisites
macros::create_all_prerequisites!(
    connector_name: Authorizedotnet,
    api: [
        (
            flow: Authorize,
            request_body: AuthorizedotnetPaymentsRequest,
            response_body: AuthorizedotnetAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
        ),
        (
            flow: PSync,
            request_body: AuthorizedotnetCreateSyncRequest,
            response_body: AuthorizedotnetPSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
        ),
        (
            flow: Capture,
            request_body: AuthorizedotnetCaptureRequest,
            response_body: AuthorizedotnetCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        ),
        (
            flow: Void,
            request_body: AuthorizedotnetVoidRequest,
            response_body: AuthorizedotnetVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
        )
    ],
    amount_converters: [],
    member_functions: {
        fn preprocess_response_bytes(
            &self,
            bytes: bytes::Bytes,
        ) -> CustomResult<bytes::Bytes, errors::ConnectorError> {
            // Check if the bytes begin with UTF-8 BOM (EF BB BF)
            let encoding = encoding_rs::UTF_8;
            let intermediate_response_bytes = encoding.decode_with_bom_removal(&bytes);
            let processed_bytes = bytes::Bytes::copy_from_slice(intermediate_response_bytes.0.as_bytes());

            Ok(processed_bytes)
        }
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }

        pub fn connector_base_url_payments<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> String {
            req.resource_common_data.connectors.authorizedotnet.base_url.to_string()
        }

    }
);

// Implement the specific flows
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Authorizedotnet,
    curl_request: Json(AuthorizedotnetPaymentsRequest),
    curl_response: AuthorizedotnetAuthorizeResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true, // Keeping true for Authorize.net which needs BOM handling
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(self.connector_base_url_payments(req).to_string())
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Authorizedotnet,
    curl_request: Json(AuthorizedotnetCreateSyncRequest),
    curl_response: AuthorizedotnetPSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true, // Keeping true for Authorize.net which needs BOM handling
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(self.connector_base_url_payments(req).to_string())
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Authorizedotnet,
    curl_request: Json(AuthorizedotnetCaptureRequest),
    curl_response: AuthorizedotnetCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true, // Keeping true for Authorize.net which needs BOM handling
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(self.connector_base_url_payments(req).to_string())
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Authorizedotnet,
    curl_request: Json(AuthorizedotnetVoidRequest),
    curl_response: AuthorizedotnetVoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true, // Keeping true for Authorize.net which needs BOM handling
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(self.connector_base_url_payments(req).to_string())
        }
    }
);

// Refund implementation is commented out as it requires L2 changes
// macros::macro_connector_implementation!(
//     connector_default_implementations: [get_content_type, get_error_response_v2],
//     connector: Authorizedotnet,
//     curl_request: Json(AuthorizedotnetRefundRequest),
//     curl_response: AuthorizedotnetRefundResponse,
//     flow_name: Refund,
//     resource_common_data: RefundFlowData,
//     flow_request: RefundsData,
//     flow_response: RefundsResponseData,
//     http_method: Post,
//     preprocess_response: true, // Keeping true for Authorize.net which needs BOM handling
//     other_functions: {
//         fn get_headers(
//             &self,
//             req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
//         ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
//             self.build_headers(req)
//         }
//
//         fn get_url(
//             &self,
//             req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
//         ) -> CustomResult<String, ConnectorError> {
//             Ok(self.connector_base_url_refunds(req).to_string())
//         }
//     }
// );

// Add stub implementations for flows we're not implementing yet
impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Authorizedotnet
{
}
impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Authorizedotnet
{
}
impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Authorizedotnet
{
}
impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Authorizedotnet
{
}
impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Authorizedotnet
{
}
impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Authorizedotnet
{
}
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Authorizedotnet
{
}
