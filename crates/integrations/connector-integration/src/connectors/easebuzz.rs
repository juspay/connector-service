pub mod transformers;

use std::{fmt::Debug, sync::LazyLock};

use common_enums::{self as enums, CurrencyUnit};
use common_utils::{
    errors::CustomResult,
    events,
    ext_traits::ByteSliceExt,
    types::MinorUnit,
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, IncrementalAuthorization, MandateRevoke,
        PSync, PaymentMethodToken, PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment,
        SdkSessionToken, SetupMandate, SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, ConnectorSpecifications, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, MandateRevokeRequestData, MandateRevokeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsIncrementalAuthorizationData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSdkSessionTokenData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, ResponseId, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData, SupportedPaymentMethodsExt,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::{
        ConnectorInfo, Connectors, FeatureStatus, PaymentConnectorCategory, PaymentMethodDetails,
        SupportedPaymentMethods,
    },
};
use error_stack::ResultExt;
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    decode::BodyDecoding,
    verification::SourceVerification,
};
use serde::Serialize;
use transformers::{
    self as easebuzz, EasebuzzCaptureRequest, EasebuzzCaptureResponse, EasebuzzPaymentsRequest,
    EasebuzzPaymentsResponse, EasebuzzRefundRequest, EasebuzzRefundResponse,
    EasebuzzRefundSyncRequest, EasebuzzRefundSyncResponse, EasebuzzSyncRequest, EasebuzzSyncResponse,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

// ============================================================================
// SUPPORTED PAYMENT METHODS
// ============================================================================

static EASEBUZZ_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(|| {
        let mut supported = SupportedPaymentMethods::new();

        // UPI Intent (UPI_PAY)
        supported.add(
            enums::PaymentMethod::Upi,
            enums::PaymentMethodType::UpiIntent,
            PaymentMethodDetails {
                mandates: FeatureStatus::NotSupported,
                refunds: FeatureStatus::Supported,
                supported_capture_methods: vec![enums::CaptureMethod::Automatic],
                specific_features: None,
            },
        );

        // UPI Collect (UPI_COLLECT)
        supported.add(
            enums::PaymentMethod::Upi,
            enums::PaymentMethodType::UpiCollect,
            PaymentMethodDetails {
                mandates: FeatureStatus::NotSupported,
                refunds: FeatureStatus::Supported,
                supported_capture_methods: vec![enums::CaptureMethod::Automatic],
                specific_features: None,
            },
        );

        // UPI QR (UPI_QR)
        supported.add(
            enums::PaymentMethod::Upi,
            enums::PaymentMethodType::UpiQr,
            PaymentMethodDetails {
                mandates: FeatureStatus::NotSupported,
                refunds: FeatureStatus::Supported,
                supported_capture_methods: vec![enums::CaptureMethod::Automatic],
                specific_features: None,
            },
        );

        supported
    });

static EASEBUZZ_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Easebuzz",
    description: "Easebuzz is an Indian payment gateway providing UPI, Net Banking, Wallet, and Card payment solutions.",
    connector_type: PaymentConnectorCategory::PaymentGateway,
};

// ============================================================================
// FLOW TRAIT IMPLEMENTATIONS (before create_all_prerequisites! macro)
// ============================================================================

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::MandateRevokeV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentIncrementalAuthorization for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SdkSessionTokenV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyWebhookSourceV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> BodyDecoding
    for Easebuzz<T>
{
}

// ============================================================================
// PREREQUISITES MACRO — creates Easebuzz<T> struct + bridges for Authorize
// ============================================================================

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
            request_body: EasebuzzSyncRequest,
            response_body: EasebuzzSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: EasebuzzCaptureRequest,
            response_body: EasebuzzCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
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
        amount_converter: MinorUnit
    ],
    member_functions: {
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.easebuzz.base_url
        }

        pub fn connector_dashboard_base_url<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> CustomResult<&'a str, errors::ConnectorError> {
            req.resource_common_data
                .connectors
                .easebuzz
                .secondary_base_url
                .as_deref()
                .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                    config: "secondary_base_url",
                })
                .map_err(error_stack::Report::from)
        }
    }
);

// ============================================================================
// CONNECTOR COMMON IMPLEMENTATION
// ============================================================================

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Easebuzz<T>
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

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.easebuzz.base_url
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Easebuzz uses hash-based auth in the request body, not headers
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        let response: easebuzz::EasebuzzErrorResponse = res
            .response
            .parse_struct("EasebuzzErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(domain_types::router_data::ErrorResponse {
            status_code: res.status_code,
            code: response.code,
            message: response.message,
            reason: None,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// ============================================================================
// CONNECTOR SPECIFICATIONS
// ============================================================================

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorSpecifications
    for Easebuzz<T>
{
    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&EASEBUZZ_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        None
    }

    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&EASEBUZZ_CONNECTOR_INFO)
    }
}

// ============================================================================
// AUTHORIZE FLOW IMPLEMENTATION (via macro)
// ============================================================================

macros::macro_connector_implementation!(
    connector_default_implementations: [],
    connector: Easebuzz,
    curl_request: FormUrlEncoded(EasebuzzPaymentsRequest),
    curl_response: EasebuzzPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            Ok(vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/x-www-form-urlencoded".to_string().into(),
            )])
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{base_url}/initiate_seamless_payment/"))
        }

        fn get_content_type(&self) -> &'static str {
            "application/x-www-form-urlencoded"
        }

        fn get_error_response_v2(
            &self,
            res: Response,
            _event_builder: Option<&mut events::Event>,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            let response: easebuzz::EasebuzzErrorResponse = res
                .response
                .parse_struct("EasebuzzErrorResponse")
                .change_context(ConnectorError::ResponseDeserializationFailed)?;

            Ok(ErrorResponse {
                status_code: res.status_code,
                code: response.code,
                message: response.message,
                reason: None,
                attempt_status: Some(enums::AttemptStatus::Failure),
                connector_transaction_id: None,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            })
        }
    }
);

// ============================================================================
// OTHER FLOW STUBS
// ============================================================================

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        MandateRevoke,
        PaymentFlowData,
        MandateRevokeRequestData,
        MandateRevokeResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Easebuzz<T>
{
}


impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        IncrementalAuthorization,
        PaymentFlowData,
        PaymentsIncrementalAuthorizationData,
        PaymentsResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Easebuzz<T>
{
}

// ============================================================================
// PSYNC FLOW IMPLEMENTATION (via macro)
// ============================================================================

macros::macro_connector_implementation!(
    connector_default_implementations: [],
    connector: Easebuzz,
    curl_request: FormUrlEncoded(EasebuzzSyncRequest),
    curl_response: EasebuzzSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            Ok(vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/x-www-form-urlencoded".to_string().into(),
            )])
        }

        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            let base_url = self.connector_dashboard_base_url(req)?;
            Ok(format!("{base_url}/transaction/v1/retrieve"))
        }

        fn get_content_type(&self) -> &'static str {
            "application/x-www-form-urlencoded"
        }

        fn get_error_response_v2(
            &self,
            res: Response,
            _event_builder: Option<&mut events::Event>,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            let response: easebuzz::EasebuzzErrorResponse = res
                .response
                .parse_struct("EasebuzzErrorResponse")
                .change_context(ConnectorError::ResponseDeserializationFailed)?;

            Ok(ErrorResponse {
                status_code: res.status_code,
                code: response.code,
                message: response.message,
                reason: None,
                attempt_status: Some(enums::AttemptStatus::Failure),
                connector_transaction_id: None,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            })
        }
    }
);

// ============================================================================
// CAPTURE FLOW IMPLEMENTATION (via macro)
// ============================================================================

macros::macro_connector_implementation!(
    connector_default_implementations: [],
    connector: Easebuzz,
    curl_request: FormUrlEncoded(EasebuzzCaptureRequest),
    curl_response: EasebuzzCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            _req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            Ok(vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/x-www-form-urlencoded".to_string().into(),
            )])
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{base_url}/payment/v1/capture/direct"))
        }

        fn get_content_type(&self) -> &'static str {
            "application/x-www-form-urlencoded"
        }

        fn get_error_response_v2(
            &self,
            res: Response,
            _event_builder: Option<&mut events::Event>,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            let response: easebuzz::EasebuzzErrorResponse = res
                .response
                .parse_struct("EasebuzzErrorResponse")
                .change_context(ConnectorError::ResponseDeserializationFailed)?;

            Ok(ErrorResponse {
                status_code: res.status_code,
                code: response.code,
                message: response.message,
                reason: None,
                attempt_status: Some(enums::AttemptStatus::Failure),
                connector_transaction_id: None,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            })
        }
    }
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Easebuzz<T>
{
}

// ============================================================================
// RSYNC FLOW IMPLEMENTATION (via macro)
// ============================================================================

macros::macro_connector_implementation!(
    connector_default_implementations: [],
    connector: Easebuzz,
    curl_request: FormUrlEncoded(EasebuzzRefundSyncRequest),
    curl_response: EasebuzzRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            _req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            Ok(vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/x-www-form-urlencoded".to_string().into(),
            )])
        }

        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            let secondary_base_url = req
                .resource_common_data
                .connectors
                .easebuzz
                .secondary_base_url
                .as_deref()
                .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                    config: "secondary_base_url",
                })
                .map_err(error_stack::Report::from)?;
            Ok(format!("{secondary_base_url}/refund/v1/retrieve"))
        }

        fn get_content_type(&self) -> &'static str {
            "application/x-www-form-urlencoded"
        }

        fn get_error_response_v2(
            &self,
            res: Response,
            _event_builder: Option<&mut events::Event>,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            let response: easebuzz::EasebuzzErrorResponse = res
                .response
                .parse_struct("EasebuzzErrorResponse")
                .change_context(ConnectorError::ResponseDeserializationFailed)?;

            Ok(ErrorResponse {
                status_code: res.status_code,
                code: response.code,
                message: response.message,
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            })
        }
    }
);

// ============================================================================
// REFUND FLOW IMPLEMENTATION (via macro)
// ============================================================================

macros::macro_connector_implementation!(
    connector_default_implementations: [],
    connector: Easebuzz,
    curl_request: FormUrlEncoded(EasebuzzRefundRequest),
    curl_response: EasebuzzRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            _req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            Ok(vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/x-www-form-urlencoded".to_string().into(),
            )])
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            let secondary_base_url = req
                .resource_common_data
                .connectors
                .easebuzz
                .secondary_base_url
                .as_deref()
                .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                    config: "secondary_base_url",
                })
                .map_err(error_stack::Report::from)?;
            Ok(format!("{secondary_base_url}/transaction/v2/refund"))
        }

        fn get_content_type(&self) -> &'static str {
            "application/x-www-form-urlencoded"
        }

        fn get_error_response_v2(
            &self,
            res: Response,
            _event_builder: Option<&mut events::Event>,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            let response: easebuzz::EasebuzzErrorResponse = res
                .response
                .parse_struct("EasebuzzErrorResponse")
                .change_context(ConnectorError::ResponseDeserializationFailed)?;

            Ok(ErrorResponse {
                status_code: res.status_code,
                code: response.code,
                message: response.message,
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            })
        }
    }
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData<T>,
        PaymentsResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SdkSessionToken,
        PaymentFlowData,
        PaymentsSdkSessionTokenData,
        PaymentsResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::VerifyWebhookSource,
        domain_types::connector_types::VerifyWebhookSourceFlowData,
        domain_types::router_request_types::VerifyWebhookSourceRequestData,
        domain_types::router_response_types::VerifyWebhookSourceResponseData,
    > for Easebuzz<T>
{
}

// ============================================================================
// SOURCE VERIFICATION
// ============================================================================

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> SourceVerification
    for Easebuzz<T>
{
}
