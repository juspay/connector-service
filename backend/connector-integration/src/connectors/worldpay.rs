pub mod transformers;
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
};
use domain_types::{
    connector_flow::{
        Authorize, Capture, PSync, Refund, Void,
    },
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData,
    },
    errors,
    payment_method_data::{PaymentMethodDataTypes},
    router_data::{ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2,
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;
use transformers as worldpay;
use transformers::{
    WorldpayPaymentRequest, WorldpayPaymentResponse, WorldpayCaptureRequest, WorldpayCaptureResponse,
    WorldpayVoidRequest, WorldpayVoidResponse, WorldpayRefundRequest, WorldpayRefundResponse,
    WorldpaySyncRequest, WorldpaySyncResponse,
};

use super::macros;
use crate::types::ResponseRouterData;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const WP_API_VERSION: &str = "WP-Api-Version";
}




impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorCommon for Worldpay<T>
{
    fn id(&self) -> &'static str {
        "worldpay"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn base_url<'a>(&self, connectors: &'a domain_types::types::Connectors) -> &'a str {
        connectors.worldpay.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &domain_types::router_data::ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = worldpay::WorldpayAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![
            (
                headers::AUTHORIZATION.to_string(),
                auth.basic_auth.into_masked(),
            ),
            (
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            ),
            (
                headers::WP_API_VERSION.to_string(),
                "2024-06-01".to_string().into(),
            ),
        ])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        let response: worldpay::WorldpayErrorResponse = res
            .response
            .parse_struct("WorldpayErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_error_response_body(&response));
        tracing::warn!(connector_response=?response);

        Ok(domain_types::router_data::ErrorResponse {
            status_code: res.status_code,
            code: response.error_name.clone(),
            message: response.message.clone(),
            reason: Some(response.message),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::ConnectorServiceTrait<T> for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::PaymentAuthorizeV2<T> for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::PaymentSyncV2 for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::RefundV2 for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::PaymentCapture for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::PaymentVoidV2 for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::SubmitEvidenceV2 for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::DisputeDefend for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::AcceptDispute for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::RefundSyncV2 for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::PaymentSessionToken for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::PaymentAccessToken for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::SetupMandateV2<T> for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::RepeatPaymentV2 for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::PaymentTokenV2<T> for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::IncomingWebhook for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::PaymentOrderCreate for Worldpay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::ValidationTrait for Worldpay<T> {}

macros::create_all_prerequisites!(
    connector_name: Worldpay,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: WorldpayPaymentRequest<T>,
            response_body: WorldpayPaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: WorldpayCaptureRequest,
            response_body: WorldpayCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: WorldpayVoidRequest,
            response_body: WorldpayVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: WorldpayRefundRequest,
            response_body: WorldpayRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: PSync,
            request_body: WorldpaySyncRequest,
            response_body: WorldpaySyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        )
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];
            let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut auth_header);
            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.worldpay.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.worldpay.base_url
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Worldpay,
    curl_request: Json(WorldpayPaymentRequest),
    curl_response: WorldpayPaymentResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}api/payments", self.connector_base_url_payments(req)))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Worldpay,
    curl_request: Json(WorldpayCaptureRequest),
    curl_response: WorldpayCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
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
            let connector_tx_id = req.request.get_connector_transaction_id()?;
            Ok(format!("{}api/payments/{}/settlements", self.connector_base_url_payments(req), connector_tx_id))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Worldpay,
    curl_request: Json(WorldpayVoidRequest),
    curl_response: WorldpayVoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let connector_tx_id = &req.request.connector_transaction_id;
            Ok(format!("{}api/payments/{}/cancellations", self.connector_base_url_payments(req), connector_tx_id))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Worldpay,
    curl_request: Json(WorldpayRefundRequest),
    curl_response: WorldpayRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
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
            let connector_tx_id = &req.request.connector_transaction_id;
            Ok(format!("{}api/payments/{}/refunds", self.connector_base_url_refunds(req), connector_tx_id))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Worldpay,
    curl_request: Json(WorldpaySyncRequest),
    curl_response: WorldpaySyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
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
            let connector_tx_id = req.request.get_connector_transaction_id()?;
            Ok(format!("{}api/payments/{}", self.connector_base_url_payments(req), connector_tx_id))
        }
    }
);

// Empty implementations for advanced flows not supported by Worldpay
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::SetupMandate,
        PaymentFlowData,
        domain_types::connector_types::SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::CreateSessionToken,
        PaymentFlowData,
        domain_types::connector_types::SessionTokenRequestData,
        domain_types::connector_types::SessionTokenResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::CreateAccessToken,
        PaymentFlowData,
        domain_types::connector_types::AccessTokenRequestData,
        domain_types::connector_types::AccessTokenResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::Accept,
        domain_types::connector_types::DisputeFlowData,
        domain_types::connector_types::AcceptDisputeData,
        domain_types::connector_types::DisputeResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::SubmitEvidence,
        domain_types::connector_types::DisputeFlowData,
        domain_types::connector_types::SubmitEvidenceData,
        domain_types::connector_types::DisputeResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::DefendDispute,
        domain_types::connector_types::DisputeFlowData,
        domain_types::connector_types::DisputeDefendData,
        domain_types::connector_types::DisputeResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::CreateOrder,
        PaymentFlowData,
        domain_types::connector_types::PaymentCreateOrderData,
        domain_types::connector_types::PaymentCreateOrderResponse,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::PaymentMethodToken,
        PaymentFlowData,
        domain_types::connector_types::PaymentMethodTokenizationData<T>,
        domain_types::connector_types::PaymentMethodTokenResponse,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::RepeatPayment,
        PaymentFlowData,
        domain_types::connector_types::RepeatPaymentData,
        PaymentsResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::RSync,
        RefundFlowData,
        domain_types::connector_types::RefundSyncData,
        RefundsResponseData,
    > for Worldpay<T>
{
}

// SourceVerification implementations for all flows
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::RSync,
        RefundFlowData,
        domain_types::connector_types::RefundSyncData,
        RefundsResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::SetupMandate,
        PaymentFlowData,
        domain_types::connector_types::SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::CreateSessionToken,
        PaymentFlowData,
        domain_types::connector_types::SessionTokenRequestData,
        domain_types::connector_types::SessionTokenResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::CreateAccessToken,
        PaymentFlowData,
        domain_types::connector_types::AccessTokenRequestData,
        domain_types::connector_types::AccessTokenResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::Accept,
        domain_types::connector_types::DisputeFlowData,
        domain_types::connector_types::AcceptDisputeData,
        domain_types::connector_types::DisputeResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::SubmitEvidence,
        domain_types::connector_types::DisputeFlowData,
        domain_types::connector_types::SubmitEvidenceData,
        domain_types::connector_types::DisputeResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::DefendDispute,
        domain_types::connector_types::DisputeFlowData,
        domain_types::connector_types::DisputeDefendData,
        domain_types::connector_types::DisputeResponseData,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::CreateOrder,
        PaymentFlowData,
        domain_types::connector_types::PaymentCreateOrderData,
        domain_types::connector_types::PaymentCreateOrderResponse,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::PaymentMethodToken,
        PaymentFlowData,
        domain_types::connector_types::PaymentMethodTokenizationData<T>,
        domain_types::connector_types::PaymentMethodTokenResponse,
    > for Worldpay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::RepeatPayment,
        PaymentFlowData,
        domain_types::connector_types::RepeatPaymentData,
        PaymentsResponseData,
    > for Worldpay<T>
{
}
