pub mod transformers;

use super::macros;
use crate::types::ResponseRouterData;
use crate::utils::preprocess_xml_response_bytes;
use crate::with_error_response_body;
use bytes::Bytes;
use common_utils::{
    errors::CustomResult, ext_traits::ByteSliceExt, request::RequestContent, types::StringMajorUnit,
};
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
use hyperswitch_domain_models::{
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use hyperswitch_interfaces::errors::ConnectorError;
use hyperswitch_interfaces::{
    api::ConnectorCommon,
    configs::Connectors,
    connector_integration_v2::{self, ConnectorIntegrationV2},
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::Response,
};
use hyperswitch_masking::Maskable;
use transformers::{
    self as elavon, ElavonCaptureResponse, ElavonPSyncResponse, ElavonPaymentsResponse,
    ElavonRSyncResponse, ElavonRefundResponse, XMLCaptureRequest, XMLElavonRequest,
    XMLPSyncRequest, XMLRSyncRequest, XMLRefundRequest,
};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
}

impl ConnectorServiceTrait for Elavon {}
impl PaymentAuthorizeV2 for Elavon {}
impl PaymentSyncV2 for Elavon {}
impl PaymentVoidV2 for Elavon {}
impl RefundSyncV2 for Elavon {}
impl RefundV2 for Elavon {}

impl ValidationTrait for Elavon {}
impl PaymentCapture for Elavon {}
impl SetupMandateV2 for Elavon {}
impl AcceptDispute for Elavon {}
impl SubmitEvidenceV2 for Elavon {}
impl DisputeDefend for Elavon {}
impl IncomingWebhook for Elavon {}
impl PaymentOrderCreate for Elavon {}

impl ConnectorCommon for Elavon {
    fn id(&self) -> &'static str {
        "elavon"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        Ok(Vec::new())
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        "https://api.demo.convergepay.com/VirtualMerchantDemo/"
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        match res
            .response
            .parse_struct::<elavon::ElavonPaymentsResponse>("ElavonPaymentsResponse")
            .map_err(|_| ConnectorError::ResponseDeserializationFailed)
        {
            Ok(elavon_response) => {
                with_error_response_body!(event_builder, elavon_response);
                match elavon_response.result {
                    elavon::ElavonResult::Error(error_payload) => Ok(ErrorResponse {
                        status_code: res.status_code,
                        code: error_payload.error_code.unwrap_or_else(|| "".to_string()),
                        message: error_payload.error_message,
                        reason: error_payload.error_name,
                        attempt_status: Some(common_enums::AttemptStatus::Failure),
                        connector_transaction_id: error_payload.ssl_txn_id,
                    }),
                    elavon::ElavonResult::Success(success_payload) => Ok(ErrorResponse {
                        status_code: res.status_code,
                        code: "".to_string(),
                        message: "Received success response in error flow".to_string(),
                        reason: Some(format!(
                            "Unexpected success: {:?}",
                            success_payload.ssl_result_message
                        )),
                        attempt_status: Some(common_enums::AttemptStatus::Failure),
                        connector_transaction_id: Some(success_payload.ssl_txn_id),
                    }),
                }
            }
            Err(_parsing_error) => {
                let (message, reason) = match res.status_code {
                    500..=599 => (
                        "Elavon server error".to_string(),
                        Some(String::from_utf8_lossy(&res.response).into_owned()),
                    ),
                    _ => (
                        "Elavon error response".to_string(),
                        Some(String::from_utf8_lossy(&res.response).into_owned()),
                    ),
                };
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: "".to_string(),
                    message,
                    reason,
                    attempt_status: Some(common_enums::AttemptStatus::Failure),
                    connector_transaction_id: None,
                })
            }
        }
    }
}

macros::create_all_prerequisites!(
    connector_name: Elavon,
    api: [
        (
            flow: Authorize,
            request_body: XMLElavonRequest,
            response_body: ElavonPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
        ),
        (
            flow: PSync,
            request_body: XMLPSyncRequest,
            response_body: ElavonPSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
        ),
        (
            flow: Capture,
            request_body: XMLCaptureRequest,
            response_body: ElavonCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        ),
        (
            flow: Refund,
            request_body: XMLRefundRequest,
            response_body: ElavonRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
        ),
        (
            flow: RSync,
            request_body: XMLRSyncRequest,
            response_body: ElavonRSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    ],
    member_functions: {
        pub fn preprocess_response_bytes(
            &self,
            response_bytes: Bytes,
        ) -> Result<Bytes, errors::ConnectorError> {
            // Use the utility function to preprocess XML response bytes
            preprocess_xml_response_bytes(response_bytes)
        }
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            Ok(vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )])
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Elavon,
    curl_request: FormUrlEncoded(XMLElavonRequest),
    curl_response: ElavonPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true,
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
            Ok(format!(
                "{}processxml.do",
                req.resource_common_data.connectors.elavon.base_url
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Elavon,
    curl_request: FormUrlEncoded(XMLPSyncRequest),
    curl_response: ElavonPSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true,
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
            Ok(format!(
                "{}processxml.do",
                req.resource_common_data.connectors.elavon.base_url
            ))
        }
    }
);

impl
    connector_integration_v2::ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Elavon
{
}

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Elavon,
    curl_request: FormUrlEncoded(XMLCaptureRequest),
    curl_response: ElavonCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true,
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
            Ok(format!(
                "{}processxml.do",
                req.resource_common_data.connectors.elavon.base_url
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Elavon,
    curl_request: FormUrlEncoded(XMLRefundRequest),
    curl_response: ElavonRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    preprocess_response: true,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!(
                "{}processxml.do",
                req.resource_common_data.connectors.elavon.base_url
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Elavon,
    curl_request: FormUrlEncoded(XMLRSyncRequest),
    curl_response: ElavonRSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    preprocess_response: true,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!(
                "{}processxml.do",
                req.resource_common_data.connectors.elavon.base_url
            ))
        }
    }
);

impl
    connector_integration_v2::ConnectorIntegrationV2<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Elavon
{
}

impl
    connector_integration_v2::ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Elavon
{
}

impl
    connector_integration_v2::ConnectorIntegrationV2<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Elavon
{
}

impl
    connector_integration_v2::ConnectorIntegrationV2<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Elavon
{
}

impl
    connector_integration_v2::ConnectorIntegrationV2<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Elavon
{
}
