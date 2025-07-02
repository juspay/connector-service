pub mod transformers;

use common_enums::CurrencyUnit;
use transformers::{
    self as xendit, RefundResponse, RefundResponse as RefundSyncResponse, XenditErrorResponse,
    XenditPaymentResponse, XenditPaymentResponse as XenditCaptureResponse,
    XenditPaymentsCaptureRequest, XenditPaymentsRequest, XenditRefundRequest, XenditResponse,
};

use super::macros;
use crate::types::ResponseRouterData;

use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, SetupMandateRequestData,
        SubmitEvidenceData,
    },
    types::Connectors,
};

use common_utils::{
    errors::CustomResult, ext_traits::ByteSliceExt, request::RequestContent, types::FloatMajorUnit,
};

use domain_types::{
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};

use common_utils::consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE};
use domain_types::errors;
use domain_types::router_response_types::Response;
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};

use hyperswitch_masking::{Mask, Maskable, PeekInterface};

use crate::with_error_response_body;

use base64::Engine;

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

use error_stack::ResultExt;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

impl ConnectorCommon for Xendit {
    fn id(&self) -> &'static str {
        "xendit"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = xendit::XenditAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let encoded_api_key = BASE64_ENGINE.encode(format!("{}:", auth.api_key.peek()));

        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("Basic {encoded_api_key}").into_masked(),
        )])
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        ""
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: XenditErrorResponse = res
            .response
            .parse_struct("XenditErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response
                .error_code
                .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message: response
                .message
                .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
            reason: response.reason,
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

//marker traits
impl connector_types::ConnectorServiceTrait for Xendit {}
impl connector_types::PaymentAuthorizeV2 for Xendit {}
impl connector_types::PaymentSyncV2 for Xendit {}
impl connector_types::PaymentVoidV2 for Xendit {}
impl connector_types::RefundSyncV2 for Xendit {}
impl connector_types::RefundV2 for Xendit {}
impl connector_types::PaymentCapture for Xendit {}
impl connector_types::ValidationTrait for Xendit {}
impl connector_types::PaymentOrderCreate for Xendit {}
impl connector_types::SetupMandateV2 for Xendit {}
impl connector_types::AcceptDispute for Xendit {}
impl connector_types::SubmitEvidenceV2 for Xendit {}
impl connector_types::DisputeDefend for Xendit {}
impl connector_types::IncomingWebhook for Xendit {}

macros::create_all_prerequisites!(
    connector_name: Xendit,
    api: [
        (
            flow: Authorize,
            request_body: XenditPaymentsRequest,
            response_body: XenditPaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
        ),
        (
            flow: PSync,
            response_body: XenditResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
        ),
        (
            flow: Capture,
            request_body: XenditPaymentsCaptureRequest,
            response_body: XenditCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        ),
        (
            flow: Refund,
            request_body: XenditRefundRequest,
            response_body: RefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
        ),
        (
            flow: RSync,
            response_body: RefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
        )
    ],
    amount_converters: [
        amount_converter: FloatMajorUnit
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
                headers::CONTENT_TYPE.to_string(),
                self.get_content_type().to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.xendit.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.xendit.base_url
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Xendit,
    curl_request: Json(XenditPaymentsRequest),
    curl_response: XenditResponse,
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
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/payment_requests", self.connector_base_url_payments(req)))
        }
    }
);

// Macro implementations for PSync, Capture, Refund, and RSync flows
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Xendit,
    curl_response: XenditPaymentResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let connector_payment_id = req
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

            Ok(format!(
                "{}/payment_requests/{connector_payment_id}",
                self.connector_base_url_payments(req),
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Xendit,
    curl_request: Json(XenditPaymentsCaptureRequest),
    curl_response: XenditCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let connector_payment_id = req
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
            Ok(format!(
                "{}/payment_requests/{connector_payment_id}/captures",
                self.connector_base_url_payments(req)
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Xendit,
    curl_request: Json(XenditRefundRequest),
    curl_response: RefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}/refunds",
                self.connector_base_url_refunds(req)
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Xendit,
    curl_response: RefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Get,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let connector_refund_id = req.request.connector_refund_id.clone();
            Ok(format!(
                "{}/refunds/{}",
                self.connector_base_url_refunds(req), connector_refund_id
            ))
        }
    }
);

impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Xendit
{
}

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Xendit
{
}

impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Xendit
{
}

impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Xendit
{
}

impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Xendit
{
}

impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Xendit
{
}

// SourceVerification implementations for all flows
impl
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData,
        PaymentsResponseData,
    > for Xendit
{
}

impl
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Xendit
{
}

impl
    interfaces::verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Xendit
{
}

impl
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Xendit
{
}

impl
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Xendit
{
}

impl
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Xendit
{
}

impl
    interfaces::verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Xendit
{
}

impl
    interfaces::verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Xendit
{
}

impl
    interfaces::verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Xendit
{
}

impl
    interfaces::verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Xendit
{
}

impl
    interfaces::verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Xendit
{
}
