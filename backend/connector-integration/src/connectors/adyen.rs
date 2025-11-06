mod test;
use common_utils::Maskable;
pub mod transformers;
use std::{
    fmt::Debug,
    marker::{Send, Sync},
    sync::LazyLock,
};

use common_enums::{
    AttemptStatus, CaptureMethod, CardNetwork, EventClass, PaymentMethod, PaymentMethodType,
};
use common_utils::{
    errors::CustomResult, ext_traits::ByteSliceExt, pii::SecretSerdeValue, types::StringMinorUnit,
    Maskable, Secret,
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, PSync, PaymentMethodToken,
        PostAuthenticate, PreAuthenticate, RSync, Refund, SetupMandate, SubmitEvidence, Void,
        VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, ConnectorSpecifications, ConnectorWebhookSecrets,
        DisputeDefendData, DisputeFlowData, DisputeResponseData, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentMethodTokenResponse,
        PaymentMethodTokenizationData, PaymentVoidData, PaymentsAuthenticateData,
        PaymentsAuthorizeData, PaymentsCancelPostCaptureData, PaymentsCaptureData,
        PaymentsPostAuthenticateData, PaymentsPreAuthenticateData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundWebhookDetailsResponse,
        RefundsData, RefundsResponseData, RequestDetails, ResponseId, SessionTokenRequestData,
        SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
        SupportedPaymentMethodsExt, WebhookDetailsResponse,
    },
    errors,
    payment_method_data::{DefaultPCIHolder, PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::{
        self, CardSpecificFeatures, ConnectorInfo, Connectors, FeatureStatus,
        PaymentMethodDataType, PaymentMethodDetails, PaymentMethodSpecificFeatures,
        SupportedPaymentMethods,
    },
    utils,
};
use error_stack::report;
// use crate::masking::{Mask, Maskable};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::{self, is_mandate_supported, ConnectorValidation},
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;
use transformers::{
    self as adyen, AdyenCaptureRequest, AdyenCaptureResponse, AdyenDefendDisputeRequest,
    AdyenDefendDisputeResponse, AdyenDisputeAcceptRequest, AdyenDisputeAcceptResponse,
    AdyenDisputeSubmitEvidenceRequest, AdyenNotificationRequestItemWH, AdyenPSyncResponse,
    AdyenPaymentRequest, AdyenPaymentResponse, AdyenRedirectRequest, AdyenRefundRequest,
    AdyenRefundResponse, AdyenSubmitEvidenceResponse, AdyenVoidRequest, AdyenVoidResponse,
    SetupMandateRequest, SetupMandateResponse,
};
use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const X_API_KEY: &str = "X-Api-Key";
}
// Type alias for non-generic trait implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Adyen<T>
{
    connector_types::PaymentAuthorizeV2<T> for Adyen<T>
    connector_types::PaymentSessionToken for Adyen<T>
    connector_types::PaymentAccessToken for Adyen<T>
    connector_types::CreateConnectorCustomer for Adyen<T>
    connector_types::PaymentSyncV2 for Adyen<T>
    connector_types::PaymentVoidV2 for Adyen<T>
    connector_types::RefundSyncV2 for Adyen<T>
    connector_types::RefundV2 for Adyen<T>
    connector_types::PaymentCapture for Adyen<T>
    connector_types::SetupMandateV2<T> for Adyen<T>
    connector_types::AcceptDispute for Adyen<T>
    connector_types::SubmitEvidenceV2 for Adyen<T>
    connector_types::DisputeDefend for Adyen<T>
    connector_types::RepeatPaymentV2 for Adyen<T>
    connector_types::PaymentTokenV2<T> for Adyen<T>
    connector_types::PaymentPreAuthenticateV2<T> for Adyen<T>
    connector_types::PaymentAuthenticateV2<T> for Adyen<T>
    connector_types::PaymentPostAuthenticateV2<T> for Adyen<T>
    connector_types::PaymentVoidPostCaptureV2 for Adyen<T>
    ConnectorIntegrationV2<
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Adyen<T>
{
}

macros::create_all_prerequisites!(
    connector_name: Adyen,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: AdyenPaymentRequest<T>,
            response_body: AdyenPaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: AdyenRedirectRequest,
            response_body: AdyenPSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: AdyenCaptureRequest,
            response_body: AdyenCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: AdyenVoidRequest,
            response_body: AdyenVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: AdyenRefundRequest,
            response_body: AdyenRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: SetupMandateRequest<T>,
            response_body: SetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            request_body: AdyenDisputeAcceptRequest,
            response_body: AdyenDisputeAcceptResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ),
        (
            flow: SubmitEvidence,
            request_body: AdyenDisputeSubmitEvidenceRequest,
            response_body: AdyenSubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        ),
        (
            flow: DefendDispute,
            request_body: AdyenDefendDisputeRequest,
            response_body: AdyenDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        )
    ],
    amount_converters: [
        amount_converter_webhooks: StringMinorUnit
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.adyen.base_url
        }
        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.adyen.base_url
        }
        pub fn connector_base_url_disputes<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, DisputeFlowData, Req, Res>,
        ) -> Option<&'a str> {
            req.resource_common_data.connectors.adyen.dispute_base_url.as_deref()
        }
);
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Adyen<T>
{
    fn id(&self) -> &'static str {
        "adyen"
    }
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = adyen::AdyenAuthType::try_from(auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::X_API_KEY.to_string(),
            auth.api_key.into_masked(),
        )])
    }
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.adyen.base_url.as_ref()
    }
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: adyen::AdyenErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code,
            message: response.message.to_owned(),
            reason: Some(response.message),
            attempt_status: None,
            connector_transaction_id: response.psp_reference,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}
const ADYEN_API_VERSION: &str = "v68";
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenPaymentRequest),
    curl_response: AdyenPaymentResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize ],
    other_functions: {
        fn get_headers(
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}{}/payments", self.connector_base_url_payments(req), ADYEN_API_VERSION))
        }
);

// Additional trait implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Adyen<T>
{
// Additional trait implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Adyen<T>
{
    fn get_event_type(
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<domain_types::connector_types::EventType, error_stack::Report<errors::ConnectorError>>
    {
        let notif: AdyenNotificationRequestItemWH =
            transformers::get_webhook_object_from_body(request.body).map_err(|err| {
                report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                    .attach_printable(format!("error while decoding webhook body {err}"))
            })?;
        Ok(transformers::get_adyen_webhook_event_type(notif.event_code))
    }
    
    fn process_payment_webhook(
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<WebhookDetailsResponse, error_stack::Report<errors::ConnectorError>> {
        let request_body_copy = request.body.clone();
        Ok(WebhookDetailsResponse {
            resource_id: Some(ResponseId::ConnectorTransactionId(
                notif.psp_reference.clone(),
            )),
            status: transformers::get_adyen_payment_webhook_event(notif.event_code, notif.success)?,
            connector_response_reference_id: Some(notif.psp_reference),
            error_code: notif.reason.clone(),
            mandate_reference: None,
            error_message: notif.reason,
            raw_connector_response: Some(String::from_utf8_lossy(&request_body_copy).to_string()),
            status_code: 200,
            response_headers: None,
            transformation_status: common_enums::WebhookTransformationStatus::Complete,
            minor_amount_captured: None,
            amount_captured: None,
            error_reason: None,
            network_txn_id: None,
        })
    }
    
    fn process_refund_webhook(
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<
        domain_types::connector_types::RefundWebhookDetailsResponse,
        error_stack::Report<errors::ConnectorError>,
    > {
        let notif: AdyenNotificationRequestItemWH =
            transformers::get_webhook_object_from_body(request.body).map_err(|err| {
                report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                    .attach_printable(format!("error while decoding webhook body {err}"))
            })?;
        Ok(RefundWebhookDetailsResponse {
            connector_refund_id: Some(notif.psp_reference.clone()),
            status: transformers::get_adyen_refund_webhook_event(notif.event_code, notif.success)?,
            connector_response_reference_id: Some(notif.psp_reference.clone()),
        })
    }
    
    fn process_dispute_webhook(
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<domain_types::connector_types::DisputeWebhookDetailsResponse, error_stack::Report<errors::ConnectorError>> {
        let notif: AdyenNotificationRequestItemWH =
            transformers::get_webhook_object_from_body(request.body).map_err(|err| {
                report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                    .attach_printable(format!("error while decoding webhook body {err}"))
            })?;
        let request_body_copy = request.body.clone();
        let (stage, status) = transformers::get_dispute_stage_and_status(
            notif.event_code,
            notif.additional_data.dispute_status,
        );
        let amount = utils::convert_amount(
            &StringMinorUnit,
            notif.amount.value,
            notif.amount.currency,
        )?;
        Ok(
            domain_types::connector_types::DisputeWebhookDetailsResponse {
                amount,
                currency: notif.amount.currency,
                dispute_id: notif.psp_reference.clone(),
                stage,
                status,
                connector_response_reference_id: Some(notif.psp_reference.clone()),
                dispute_message: notif.reason,
                connector_reason_code: notif.additional_data.chargeback_reason_code,
                raw_connector_response: Some(
                    String::from_utf8_lossy(&request_body_copy).to_string(),
                ),
                status_code: 200,
                response_headers: None,
            },
        )
    }
}

// Additional trait implementations can be added here as needed
    flow_name: SubmitEvidence,
    flow_request: SubmitEvidenceData,
            req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
            Ok(format!("{dispute_url}ca/services/DisputeService/v30/supplyDefenseDocument"))
static ADYEN_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> = LazyLock::new(|| {
    let adyen_supported_capture_methods = vec![
        CaptureMethod::Automatic,
        CaptureMethod::Manual,
        CaptureMethod::ManualMultiple,
        // CaptureMethod::Scheduled,
    ];
    let adyen_supported_card_network = vec![
        CardNetwork::AmericanExpress,
        CardNetwork::CartesBancaires,
        CardNetwork::UnionPay,
        CardNetwork::DinersClub,
        CardNetwork::Discover,
        CardNetwork::Interac,
        CardNetwork::JCB,
        CardNetwork::Maestro,
        CardNetwork::Mastercard,
        CardNetwork::Visa,
    ];
    let mut adyen_supported_payment_methods = SupportedPaymentMethods::new();
    adyen_supported_payment_methods.add(
        PaymentMethod::Card,
        PaymentMethodType::Credit,
        PaymentMethodDetails {
            mandates: FeatureStatus::Supported,
            refunds: FeatureStatus::Supported,
            supported_capture_methods: adyen_supported_capture_methods.clone(),
            specific_features: Some(PaymentMethodSpecificFeatures::Card(CardSpecificFeatures {
                three_ds: FeatureStatus::Supported,
                no_three_ds: FeatureStatus::Supported,
                supported_card_networks: adyen_supported_card_network.clone(),
            })),
        },
    );
    adyen_supported_payment_methods.add(
        PaymentMethod::Card,
        PaymentMethodType::Debit,
        PaymentMethodDetails {
            mandates: FeatureStatus::Supported,
            refunds: FeatureStatus::Supported,
            supported_capture_methods: adyen_supported_capture_methods.clone(),
            specific_features: Some(PaymentMethodSpecificFeatures::Card(CardSpecificFeatures {
                three_ds: FeatureStatus::Supported,
                no_three_ds: FeatureStatus::Supported,
                supported_card_networks: adyen_supported_card_network.clone(),
            })),
        },
    );
    adyen_supported_payment_methods
});
static ADYEN_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Adyen", 
    description: "Adyen is a Dutch payment company with the status of an acquiring bank that allows businesses to accept e-commerce, mobile, and point-of-sale payments. It is listed on the stock exchange Euronext Amsterdam.",
    connector_type: types::PaymentConnectorCategory::PaymentGateway,
};
static ADYEN_SUPPORTED_WEBHOOK_FLOWS: &[EventClass] = &[EventClass::Payments, EventClass::Refunds];
impl ConnectorSpecifications for Adyen<DefaultPCIHolder> {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&ADYEN_CONNECTOR_INFO)
    }
    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&ADYEN_SUPPORTED_PAYMENT_METHODS)
    }
    fn get_supported_webhook_flows(&self) -> Option<&'static [EventClass]> {
        Some(ADYEN_SUPPORTED_WEBHOOK_FLOWS)
    }
}
impl ConnectorValidation for Adyen<DefaultPCIHolder> {
    fn validate_mandate_payment(
        &self,
        pm_type: Option<PaymentMethodType>,
        pm_data: PaymentMethodData<DefaultPCIHolder>,
    ) -> CustomResult<(), errors::ConnectorError> {
        let mandate_supported_pmd = std::collections::HashSet::from([PaymentMethodDataType::Card]);
        is_mandate_supported(pm_data, pm_type, mandate_supported_pmd, self.id())
    }
    fn validate_psync_reference_id(
        &self,
        data: &PaymentsSyncData,
        _is_three_ds: bool,
        _status: AttemptStatus,
        _connector_meta_data: Option<SecretSerdeValue>,
    ) -> CustomResult<(), errors::ConnectorError> {
        if data.encoded_data.is_some() {
            return Ok(());
        }
        Err(errors::ConnectorError::MissingRequiredField {
            field_name: "encoded_data",
        }
        .into())
    }
    fn is_webhook_source_verification_mandatory(&self) -> bool {
        false
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Adyen<T>
{
    fn get_request_body(
        &self,
        req: &RouterDataV2<
            domain_types::connector_flow::RepeatPayment,
            PaymentFlowData,
            domain_types::connector_types::RepeatPaymentData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<serde_json::Value, errors::ConnectorError> {
        todo!("Implement RepeatPaymentV2 for Adyen")
    }
}
