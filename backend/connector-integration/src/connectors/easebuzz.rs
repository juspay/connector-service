pub mod transformers;

use common_enums::CurrencyUnit;
use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt, types::StringMinorUnit};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        PaymentFlowData, PaymentsSyncData, PaymentsAuthorizeData, PaymentsResponseData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::SourceVerification,
};
use serde::Serialize;
use transformers::{
    self as easebuzz, EasebuzzPaymentsRequest, EasebuzzPaymentsResponse, EasebuzzPaymentsSyncRequest,
    EasebuzzPaymentsSyncResponse, EasebuzzRefundRequest, EasebuzzRefundResponse,
    EasebuzzRefundSyncRequest, EasebuzzRefundSyncResponse,
};

use super::macros;
use crate::types::ResponseRouterData;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

// Trait implementations with generic type parameters
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ConnectorServiceTrait<T> for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentAuthorizeV2<T> for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentSyncV2 for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RefundV2 for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RefundSyncV2 for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentSessionToken for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentVoidV2 for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentCapture for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::SetupMandateV2<T> for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::AcceptDispute for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::SubmitEvidenceV2 for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::DisputeDefend for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::IncomingWebhook for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentOrderCreate for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ValidationTrait for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RepeatPaymentV2 for Easebuzz<T>
{
}

// Define connector prerequisites using UCS v2 macros
macros::create_all_prerequisites!(
    connector_name: Easebuzz,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: EasebuzzPaymentsRequest,
            response_body: EasebuzzPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: EasebuzzPaymentsSyncRequest,
            response_body: EasebuzzPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: EasebuzzRefundRequest,
            response_body: EasebuzzRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: EasebuzzRefundSyncRequest,
            response_body: EasebuzzRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        pub fn connector_base_url<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> String {
            req.resource_common_data.connectors.easebuzz.base_url.to_string()
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.easebuzz.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.easebuzz.base_url
        }

        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            Ok(vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/x-www-form-urlencoded".to_string().into(),
            )])
        }
    }
);

// Authorize flow implementation using macros
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Easebuzz,
    curl_request: FormUrlEncoded(EasebuzzPaymentsRequest),
    curl_response: EasebuzzPaymentsResponse,
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
            let base_url = self.connector_base_url(req);
            Ok(format!("{}/initiate_seamless_payment/", base_url))
        }
    }
);

// PSync flow implementation using macros
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Easebuzz,
    curl_request: FormUrlEncoded(EasebuzzPaymentsSyncRequest),
    curl_response: EasebuzzPaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
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
            let base_url = self.connector_base_url(req);
            Ok(format!("{}/transaction/v1/retrieve", base_url))
        }
    }
);

// Refund flow implementation using macros
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Easebuzz,
    curl_request: FormUrlEncoded(EasebuzzRefundRequest),
    curl_response: EasebuzzRefundResponse,
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
            let base_url = self.connector_base_url_refunds(req);
            Ok(format!("{}/transaction/v2/refund", base_url))
        }
    }
);

// RSync flow implementation using macros
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Easebuzz,
    curl_request: FormUrlEncoded(EasebuzzRefundSyncRequest),
    curl_response: EasebuzzRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
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
            let base_url = self.connector_base_url_refunds(req);
            Ok(format!("{}/refund/v1/retrieve", base_url))
        }
    }
);

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorCommon for Easebuzz<T>
{
    fn id(&self) -> &'static str {
        "easebuzz"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn base_url<'a>(&self, connectors: &'a domain_types::types::Connectors) -> &'a str {
        connectors.easebuzz.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = easebuzz::EasebuzzAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            auth.api_key.into_masked(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: easebuzz::EasebuzzErrorResponse = res
            .response
            .parse_struct("EasebuzzErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_error_response_body(&response));

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.unwrap_or_else(|| "NO_ERROR_CODE".to_string()),
            message: response.error_desc.unwrap_or_else(|| "NO_ERROR_MESSAGE".to_string()),
            reason: response.reason,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// SourceVerification implementations for all flows
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData> for Easebuzz<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> SourceVerification<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Easebuzz<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> SourceVerification<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Easebuzz<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> SourceVerification<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Easebuzz<T> {}

// Default implementations for unsupported flows
use domain_types::connector_types::{
    AcceptDisputeData, DisputeDefendData, DisputeFlowData, DisputeResponseData,
    PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentVoidData,
    PaymentsCaptureData, RepeatPaymentData, SessionTokenRequestData,
    SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
};
use domain_types::connector_flow::{
    Accept, Capture, CreateOrder, CreateSessionToken, DefendDispute, RepeatPayment,
    SetupMandate, SubmitEvidence, Void,
};

// CreateSessionToken flow - not supported
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorIntegrationV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>
    for Easebuzz<T>
{
    fn build_request_v2(
        &self,
        _req: &RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotSupported {
            message: "Session token creation".to_string(),
            connector: "Easebuzz",
        }
        .into())
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> SourceVerification<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData> for Easebuzz<T> {}

// Void flow - not supported
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Easebuzz<T>
{
    fn build_request_v2(
        &self,
        _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotSupported {
            message: "Payment void".to_string(),
            connector: "Easebuzz",
        }
        .into())
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> SourceVerification<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Easebuzz<T> {}

// Capture flow - not supported
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Easebuzz<T>
{
    fn build_request_v2(
        &self,
        _req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotSupported {
            message: "Payment capture".to_string(),
            connector: "Easebuzz",
        }
        .into())
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> SourceVerification<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Easebuzz<T> {}

// SetupMandate flow - not supported
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
    for Easebuzz<T>
{
    fn build_request_v2(
        &self,
        _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotSupported {
            message: "Setup mandate".to_string(),
            connector: "Easebuzz",
        }
        .into())
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> SourceVerification<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData> for Easebuzz<T> {}

// AcceptDispute flow - not supported
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Easebuzz<T>
{
    fn build_request_v2(
        &self,
        _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotSupported {
            message: "Accept dispute".to_string(),
            connector: "Easebuzz",
        }
        .into())
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> SourceVerification<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData> for Easebuzz<T> {}

// SubmitEvidence flow - not supported
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Easebuzz<T>
{
    fn build_request_v2(
        &self,
        _req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotSupported {
            message: "Submit evidence".to_string(),
            connector: "Easebuzz",
        }
        .into())
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> SourceVerification<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData> for Easebuzz<T> {}

// DefendDispute flow - not supported
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Easebuzz<T>
{
    fn build_request_v2(
        &self,
        _req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotSupported {
            message: "Defend dispute".to_string(),
            connector: "Easebuzz",
        }
        .into())
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> SourceVerification<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData> for Easebuzz<T> {}

// CreateOrder flow - not supported
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>
    for Easebuzz<T>
{
    fn build_request_v2(
        &self,
        _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotSupported {
            message: "Create order".to_string(),
            connector: "Easebuzz",
        }
        .into())
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> SourceVerification<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for Easebuzz<T> {}

// RepeatPayment flow - not supported
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Easebuzz<T>
{
    fn build_request_v2(
        &self,
        _req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotSupported {
            message: "Repeat payment".to_string(),
            connector: "Easebuzz",
        }
        .into())
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> SourceVerification<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData> for Easebuzz<T> {}