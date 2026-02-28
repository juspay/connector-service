pub mod transformers;

use transformers::*;
use super::macros;

use common_utils::{
    crypto::VerifySignature, errors::CustomResult, events, ext_traits::ByteSliceExt,
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
        ConnectorCustomerResponse, ConnectorSpecifications, ConnectorWebhookSecrets, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, EventType, MandateRevokeRequestData, MandateRevokeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsIncrementalAuthorizationData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSdkSessionTokenData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, RequestDetails, ResponseId, SessionTokenRequestData,
        SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
        SupportedPaymentMethodsExt, WebhookDetailsResponse,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorSpecificAuth, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::{
        ConnectorInfo, FeatureStatus, PaymentConnectorCategory, PaymentMethodDetails,
        SupportedPaymentMethods,
    },
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, PeekInterface};
use interfaces::{
    api::ConnectorCommon, 
    connector_integration_v2::ConnectorIntegrationV2, 
    connector_types,
};

use serde::Serialize;
use std::fmt::Debug;
use std::sync::LazyLock;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon for Ppro<T> {
    fn id(&self) -> &'static str {
        "ppro"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a domain_types::types::Connectors) -> &'a str {
        connectors.ppro.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorSpecificAuth,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
        match auth_type {
            ConnectorSpecificAuth::Ppro { api_key, merchant_id } => Ok(vec![
                (
                    headers::AUTHORIZATION.to_string(),
                    format!("Bearer {}", api_key.peek()).into_masked(),
                ),
                (
                    "Merchant-Id".to_string(),
                    merchant_id.clone().into_masked(),
                ),
            ]),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: PproErrorResponse = res
            .response
            .parse_struct("Ppro ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.status.to_string(),
            message: response.failure_message,
            reason: None,
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentIncrementalAuthorization for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Ppro<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::MandateRevokeV2 for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SdkSessionToken,
        PaymentFlowData,
        PaymentsSdkSessionTokenData,
        PaymentsResponseData,
    > for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData<T>,
        PaymentsResponseData,
    > for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        MandateRevoke,
        PaymentFlowData,
        MandateRevokeRequestData,
        MandateRevokeResponseData,
    > for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        IncrementalAuthorization,
        PaymentFlowData,
        PaymentsIncrementalAuthorizationData,
        PaymentsResponseData,
    > for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Ppro<T>
{
    fn get_event_type(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificAuth>,
    ) -> Result<EventType, error_stack::Report<errors::ConnectorError>> {
        let event: PproWebhookEvent = request
            .body
            .parse_struct("PproWebhookEvent")
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;

        match event.r#type.as_str() {
            "payment-charges.captured" => Ok(EventType::PaymentIntentCaptureSuccess),
            "payment-charges.failed" => Ok(EventType::PaymentIntentFailure),
            "payment-charges.authorization-async" => Ok(EventType::PaymentIntentAuthorizationSuccess),
            "payment-charges.refunded" => Ok(EventType::RefundSuccess),
            "payment-charges.refund-failed" => Ok(EventType::RefundFailure),
            _ => Ok(EventType::IncomingWebhookEventUnspecified),
        }
    }

    fn process_payment_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificAuth>,
    ) -> Result<WebhookDetailsResponse, error_stack::Report<errors::ConnectorError>> {
        let event: PproWebhookEvent = request
            .body
            .parse_struct("PproWebhookEvent")
            .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)?;

        let status = match event.data.status.as_str() {
            "AUTHORIZATION_PROCESSING" | "CAPTURE_PROCESSING" => common_enums::AttemptStatus::Pending,
            "AUTHENTICATION_PENDING" => common_enums::AttemptStatus::AuthenticationPending,
            "AUTHORIZATION_ASYNC" | "CAPTURE_PENDING" => common_enums::AttemptStatus::Authorized,
            "CAPTURED" => common_enums::AttemptStatus::Charged,
            "FAILED" | "DISCARDED" => common_enums::AttemptStatus::Failure,
            "VOIDED" => common_enums::AttemptStatus::Voided,
            _ => common_enums::AttemptStatus::Pending,
        };

        let (error_code, error_message, error_reason) = if let Some(failure) = &event.data.failure {
            (
                failure.failure_code.clone(),
                Some(failure.failure_message.clone()),
                Some(format!("{}: {}", failure.failure_type, failure.failure_code.as_deref().unwrap_or("UNKNOWN"))),
            )
        } else {
            (None, None, None)
        };

        Ok(WebhookDetailsResponse {
            resource_id: Some(ResponseId::ConnectorTransactionId(event.data.id.clone())),
            status,
            connector_response_reference_id: Some(event.data.id),
            error_code,
            error_message,
            error_reason,
            raw_connector_response: Some(String::from_utf8_lossy(&request.body).to_string()),
            status_code: 200,
            mandate_reference: None,
            response_headers: None,
            transformation_status: common_enums::WebhookTransformationStatus::Complete,
            amount_captured: None,
            minor_amount_captured: None,
            network_txn_id: None,
        })
    }

    fn process_refund_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificAuth>,
    ) -> Result<domain_types::connector_types::RefundWebhookDetailsResponse, error_stack::Report<errors::ConnectorError>>
    {
        let event: PproWebhookEvent = request
            .body
            .parse_struct("PproWebhookEvent")
            .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)?;

        let status = match event.data.status.as_str() {
            "CAPTURED" | "REFUND_SETTLED" | "SUCCESS" | "REFUNDED" => {
                common_enums::RefundStatus::Success
            }
            "FAILED" | "REJECTED" | "DECLINED" => common_enums::RefundStatus::Failure,
            _ => common_enums::RefundStatus::Pending,
        };

        let (error_code, error_message) = if let Some(failure) = &event.data.failure {
            (
                failure.failure_code.clone(),
                Some(failure.failure_message.clone()),
            )
        } else {
            (None, None)
        };

        Ok(domain_types::connector_types::RefundWebhookDetailsResponse {
            connector_refund_id: Some(event.data.id.clone()),
            status,
            connector_response_reference_id: Some(event.data.id),
            error_code,
            error_message,
            raw_connector_response: Some(String::from_utf8_lossy(&request.body).to_string()),
            status_code: 200,
            response_headers: None,
        })
    }

    fn process_dispute_webhook(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificAuth>,
    ) -> Result<domain_types::connector_types::DisputeWebhookDetailsResponse, error_stack::Report<errors::ConnectorError>>
    {
        Err(errors::ConnectorError::NotImplemented("process_dispute_webhook".to_string()).into())
    }

    fn verify_webhook_source(
        &self,
        request: RequestDetails,
        connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificAuth>,
    ) -> Result<bool, error_stack::Report<errors::ConnectorError>> {
        let connector_webhook_secrets = match connector_webhook_secret {
            Some(secrets) => secrets,
            None => return Ok(false),
        };

        let signature = request
            .headers
            .get("Webhook-Signature")
            .ok_or(errors::ConnectorError::WebhookSignatureNotFound)?;

        let algorithm = common_utils::crypto::HmacSha256;
        let expected_signature = hex::decode(signature)
            .change_context(errors::ConnectorError::WebhookSignatureNotFound)?;

        algorithm
            .verify_signature(
                &connector_webhook_secrets.secret,
                &expected_signature,
                &request.body,
            )
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)
    }

    fn get_webhook_resource_object(
        &self,
        request: RequestDetails,
    ) -> Result<Box<dyn hyperswitch_masking::ErasedMaskSerialize>, error_stack::Report<errors::ConnectorError>> {
        let event: PproWebhookEvent = request
            .body
            .parse_struct("PproWebhookEvent")
            .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)?;

        let response = PproPaymentsResponse {
            id: event.data.id,
            status: event.data.status,
            amount: None,
            authentication_methods: None,
            failure: event.data.failure,
        };
        Ok(Box::new(response))
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::decode::BodyDecoding for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Ppro<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SdkSessionTokenV2 for Ppro<T>
{
}

static PPRO_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Ppro",
    description: "Ppro is a global provider of local payment infrastructure.",
    connector_type: PaymentConnectorCategory::PaymentGateway,
};

static PPRO_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> = LazyLock::new(|| {
    let mut ppro_supported_payment_methods = SupportedPaymentMethods::new();

    let ppro_bridge_supported_capture_methods = vec![common_enums::CaptureMethod::Automatic];

    ppro_supported_payment_methods.add(
        common_enums::PaymentMethod::Wallet,
        common_enums::PaymentMethodType::AliPay,
        PaymentMethodDetails {
            mandates: FeatureStatus::NotSupported,
            refunds: FeatureStatus::Supported,
            supported_capture_methods: ppro_bridge_supported_capture_methods.clone(),
            specific_features: None,
        },
    );
    ppro_supported_payment_methods.add(
        common_enums::PaymentMethod::Wallet,
        common_enums::PaymentMethodType::WeChatPay,
        PaymentMethodDetails {
            mandates: FeatureStatus::NotSupported,
            refunds: FeatureStatus::Supported,
            supported_capture_methods: ppro_bridge_supported_capture_methods.clone(),
            specific_features: None,
        },
    );

    let bank_redirect_methods = vec![
        common_enums::PaymentMethodType::Ideal,
        common_enums::PaymentMethodType::Sofort,
        common_enums::PaymentMethodType::Giropay,
        common_enums::PaymentMethodType::BancontactCard,
        common_enums::PaymentMethodType::Eps,
        common_enums::PaymentMethodType::Przelewy24,
        common_enums::PaymentMethodType::Trustly,
    ];

    for pm_type in bank_redirect_methods {
        ppro_supported_payment_methods.add(
            common_enums::PaymentMethod::BankRedirect,
            pm_type,
            PaymentMethodDetails {
                mandates: FeatureStatus::NotSupported,
                refunds: FeatureStatus::Supported,
                supported_capture_methods: ppro_bridge_supported_capture_methods.clone(),
                specific_features: None,
            },
        );
    }

    ppro_supported_payment_methods.add(
        common_enums::PaymentMethod::PayLater,
        common_enums::PaymentMethodType::Klarna,
        PaymentMethodDetails {
            mandates: FeatureStatus::NotSupported,
            refunds: FeatureStatus::Supported,
            supported_capture_methods: ppro_bridge_supported_capture_methods.clone(),
            specific_features: None,
        },
    );

    ppro_supported_payment_methods
});

static PPRO_SUPPORTED_WEBHOOK_FLOWS: &[common_enums::EventClass] =
    &[common_enums::EventClass::Payments, common_enums::EventClass::Refunds];

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorSpecifications
    for Ppro<T>
{
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&PPRO_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&PPRO_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [common_enums::EventClass]> {
        Some(PPRO_SUPPORTED_WEBHOOK_FLOWS)
    }
}

macros::create_all_prerequisites!(
    connector_name: Ppro,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: PproPaymentsRequest,
            response_body: PproAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            response_body: PproPSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: PproCaptureRequest,
            response_body: PproCaptureResponse, 
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: PproVoidRequest,
            response_body: PproVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: PproRefundRequest,
            response_body: PproRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            response_body: PproRSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [],
    member_functions: {
        fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
            _connectors: &domain_types::types::Connectors,
        ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type()
                    .to_string()
                    .into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Ppro,
    curl_request: Json(PproPaymentsRequest),
    curl_response: PproAuthorizeResponse,
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
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req, &req.resource_common_data.connectors)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/v1/payment-charges", self.base_url(&req.resource_common_data.connectors)))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Ppro,
    curl_response: PproPSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req, &req.resource_common_data.connectors)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let id = req.request.connector_transaction_id.get_connector_transaction_id().change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
            Ok(format!("{}/v1/payment-charges/{}", self.base_url(&req.resource_common_data.connectors), id))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Ppro,
    curl_request: Json(PproCaptureRequest),
    curl_response: PproCaptureResponse,
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
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req, &req.resource_common_data.connectors)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let id = req.request.get_connector_transaction_id().change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
            Ok(format!("{}/v1/payment-charges/{}/capture", self.base_url(&req.resource_common_data.connectors), id))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Ppro,
    curl_request: Json(PproVoidRequest),
    curl_response: PproVoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req, &req.resource_common_data.connectors)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let id = req.request.connector_transaction_id.clone();
            Ok(format!("{}/v1/payment-charges/{}/void", self.base_url(&req.resource_common_data.connectors), id))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Ppro,
    curl_request: Json(PproRefundRequest),
    curl_response: PproRefundResponse,
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
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req, &req.resource_common_data.connectors)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let id = req.request.connector_transaction_id.clone();
            Ok(format!("{}/v1/payment-charges/{}/refund", self.base_url(&req.resource_common_data.connectors), id))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Ppro,
    curl_response: PproRSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req, &req.resource_common_data.connectors)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let refund_id = req.request.connector_refund_id.clone();
            Ok(format!("{}/v1/payment-charges/{}", self.base_url(&req.resource_common_data.connectors), refund_id))
        }
    }
);

#[cfg(test)]
mod test;

