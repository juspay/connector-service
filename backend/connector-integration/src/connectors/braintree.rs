use common_utils::{
    errors::CustomResult, ext_traits::BytesExt, request::RequestContent, types::StringMajorUnit,
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    }, connector_types::{
        AcceptDisputeData, ConnectorSpecifications, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    }, router_request_types::PaymentsCancelData, types::Connectors
};
use error_stack::{report, Report, ResultExt};

use domain_types::{
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};

use base64::Engine;
pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
use common_utils::consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE};
use hyperswitch_masking::{ExposeInterface, Mask, Maskable, PeekInterface};
use common_enums::CurrencyUnit;

use domain_types::errors;
use domain_types::router_response_types::Response;
use interfaces::{
    api::{self, ConnectorCommon}, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use ring::hmac;
use time::OffsetDateTime;
use uuid::Uuid;

pub mod transformers;

use transformers::{
    BraintreeCaptureRequest, BraintreeCaptureResponse, BraintreePaymentsRequest, BraintreePaymentResponse,
    BraintreeRefundRequest, BraintreeRefundResponse, BraintreeRSyncRequest, BraintreeRSyncResponse,
    BraintreePSyncRequest, BraintreePSyncResponse, BraintreeCancelRequest, BraintreeCancelResponse,
};

use super::macros;
use crate::{connectors::braintree::transformers::CancelResponseData, types::ResponseRouterData};
use crate::with_error_response_body;

// Local headers module
mod headers {
    pub const API_KEY: &str = "Api-Key";
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

// Flow-Specific Marker Traits
impl connector_types::ConnectorServiceTrait for Braintree {}
impl connector_types::PaymentAuthorizeV2 for Braintree {}
impl connector_types::PaymentSyncV2 for Braintree {}
impl connector_types::PaymentVoidV2 for Braintree {}
impl connector_types::RefundSyncV2 for Braintree {}
impl connector_types::RefundV2 for Braintree {}
impl connector_types::PaymentCapture for Braintree {}
impl connector_types::ValidationTrait for Braintree {}
impl connector_types::PaymentOrderCreate for Braintree {}
impl connector_types::SetupMandateV2 for Braintree {}
impl connector_types::AcceptDispute for Braintree {}
impl connector_types::SubmitEvidenceV2 for Braintree {}
impl connector_types::DisputeDefend for Braintree {}
impl connector_types::IncomingWebhook for Braintree {}

pub const BRAINTREE_VERSION: &str = "Braintree-Version";
pub const BRAINTREE_VERSION_VALUE: &str = "2019-01-01";

// Create all prerequisites using the macro
macros::create_all_prerequisites!(
    connector_name: Braintree,
    api: [
        (
            flow: Authorize,
            request_body: BraintreePaymentsRequest,
            response_body: BraintreePaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
        )
        // (
        //     flow: PSync,
        //     request_body: BraintreePSyncRequest,
        //     response_body: BraintreePSyncResponse,
        //     router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
        // ),
        // (
        //     flow: Capture,
        //     request_body: BraintreeCaptureRequest,
        //     response_body: BraintreeCaptureResponse,
        //     router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        // ),
        // (
        //     flow: Void,
        //     request_body: BraintreeCancelRequest,
        //     response_body: BraintreeCancelResponse,
        //     router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
        // ),
        // (
        //     flow: Refund,
        //     request_body: BraintreeRefundRequest,
        //     response_body: BraintreeRefundResponse,
        //     router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
        // ),
        // (
        //     flow: RSync,
        //     request_body: BraintreeRSyncRequest,
        //     response_body: BraintreeRSyncResponse,
        //     router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
        // )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            let mut header = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    self.common_get_content_type().into(),
                ),
                (
                    BRAINTREE_VERSION.to_string(),
                    BRAINTREE_VERSION_VALUE.to_string().into(),
                ),
            ];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.braintree.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.braintree.base_url
        }
    }
);

impl ConnectorCommon for Braintree {
    fn id(&self) -> &'static str {
        "braintree"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.braintree.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
        let auth = transformers::BraintreeAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let auth_key = format!("{}:{}", auth.public_key.peek(), auth.private_key.peek());
        let auth_header = format!("Basic {}", BASE64_ENGINE.encode(auth_key));
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            auth_header.into_masked(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        let response:transformers::ErrorResponses = res
            .response
            .parse_struct("Braintree Error Response")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        match response {
            transformers::ErrorResponses::BraintreeApiErrorResponse(response) => {
                
                with_error_response_body!(event_builder, response);

                let error_object = response.api_error_response.errors;
                let error = error_object.errors.first().or(error_object
                    .transaction
                    .as_ref()
                    .and_then(|transaction_error| {
                        transaction_error.errors.first().or(transaction_error
                            .credit_card
                            .as_ref()
                            .and_then(|credit_card_error| credit_card_error.errors.first()))
                    }));
                let (code, message) = error.map_or(
                    (NO_ERROR_CODE.to_string(), NO_ERROR_MESSAGE.to_string()),
                    |error| (error.code.clone(), error.message.clone()),
                );
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code,
                    message,
                    reason: Some(response.api_error_response.message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                })
            }
            transformers::ErrorResponses::BraintreeErrorResponse(response) => {
                
                with_error_response_body!(event_builder, response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: NO_ERROR_CODE.to_string(),
                    message: NO_ERROR_MESSAGE.to_string(),
                    reason: Some(response.errors),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                })
            }
        }
    }
}

// Implement ConnectorIntegrationV2 for Authorize flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Braintree,
    curl_request: Json(BraintreePaymentsRequest),
    curl_response: BraintreePaymentsResponse,
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
            Ok(self.connector_base_url_payments(req).to_string())
        } 
    }
);

/* 
// Implement ConnectorIntegrationV2 for PSync flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Braintree,
    curl_request: Json(transformers::BraintreePSyncRequest),
    curl_response: transformers::BraintreePSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}v1/payments/status",
                self.connector_base_url_payments(req)
            ))
        }
    }
);

// Implement ConnectorIntegrationV2 for Capture flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Braintree,
    curl_request: Json(transformers::BraintreeCaptureRequest),
    curl_response: transformers::BraintreeCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let connector_txn_id = req.request.connector_transaction_id.get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
            Ok(format!(
                "{}v1/payments/{}/capture",
                self.connector_base_url_payments(req),
                connector_txn_id
            ))
        }
    }
);

// Implement ConnectorIntegrationV2 for Void flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Braintree,
    curl_request: Json(transformers::BraintreeVoidRequest),
    curl_response: transformers::BraintreeVoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}v1/payments/{}/void",
                self.connector_base_url_payments(req),
                req.request.connector_transaction_id
            ))
        }
    }
);

// Implement ConnectorIntegrationV2 for Refund flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Braintree,
    curl_request: Json(transformers::BraintreeRefundRequest),
    curl_response: transformers::BraintreeRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}v1/refunds",
                self.connector_base_url_refunds(req)
            ))
        }
    }
);

// Implement ConnectorIntegrationV2 for RSync flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Braintree,
    curl_request: Json(transformers::BraintreeRSyncRequest),
    curl_response: transformers::BraintreeRSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}v1/refunds/status",
                self.connector_base_url_refunds(req)
            ))
        }
    }
);
*/

// Implementation for empty stubs - these will need to be properly implemented later
impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Braintree
{
}
impl
    ConnectorIntegrationV2<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Braintree
{
}
impl
    ConnectorIntegrationV2<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Braintree
{
}
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Braintree
{
}
impl
    ConnectorIntegrationV2<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Braintree
{
}
impl
    ConnectorIntegrationV2<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Braintree
{
}



impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Braintree
{
}
impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Braintree
{
}
impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Braintree
{
}
impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Braintree
{
}

// SourceVerification implementations for all flows
impl
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData,
        PaymentsResponseData,
    > for Braintree
{
}

impl
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Braintree
{
}

impl
    interfaces::verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Braintree
{
}

impl
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Braintree
{
}

impl
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Braintree
{
}

impl
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Braintree
{
}

impl
    interfaces::verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Braintree
{
}

impl
    interfaces::verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Braintree
{
}

impl
    interfaces::verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Braintree
{
}

impl
    interfaces::verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Braintree
{
}

impl
    interfaces::verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Braintree
{
}

impl ConnectorSpecifications for Braintree {
}
