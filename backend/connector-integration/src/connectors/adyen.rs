mod test;
pub mod transformers;
use crate::types::ResponseRouterData;
use crate::with_error_response_body;
use domain_types::{
    capture_method_not_supported,
    connector_types::{is_mandate_supported, ConnectorSpecifications},
    connector_types::{ConnectorValidation, SupportedPaymentMethodsExt},
    payment_method_not_supported,
    types::{
        self, CardSpecificFeatures, ConnectorInfo, FeatureStatus, PaymentMethodDataType,
        PaymentMethodDetails, PaymentMethodSpecificFeatures, SupportedPaymentMethods,
    },
};
use hyperswitch_common_enums::{
    AttemptStatus, CaptureMethod, CardNetwork, EventClass, PaymentMethod, PaymentMethodType,
};
use hyperswitch_common_utils::{
    errors::CustomResult, ext_traits::ByteSliceExt, pii::SecretSerdeValue, request::RequestContent,
};
use std::sync::LazyLock;

use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};

use error_stack::report;
use hyperswitch_interfaces::errors::ConnectorError;
use hyperswitch_interfaces::{
    api::{self, ConnectorCommon},
    configs::Connectors,
    connector_integration_v2::ConnectorIntegrationV2,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::Response,
};
use hyperswitch_masking::{Mask, Maskable};

use super::macros;
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDispute, AcceptDisputeData, ConnectorServiceTrait, ConnectorWebhookSecrets,
        DisputeDefend, DisputeDefendData, DisputeFlowData, DisputeResponseData, IncomingWebhook,
        PaymentAuthorizeV2, PaymentCapture, PaymentCreateOrderData, PaymentCreateOrderResponse,
        PaymentFlowData, PaymentOrderCreate, PaymentSyncV2, PaymentVoidData, PaymentVoidV2,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundSyncV2, RefundV2, RefundWebhookDetailsResponse,
        RefundsData, RefundsResponseData, RequestDetails, ResponseId, SetupMandateRequestData,
        SetupMandateV2, SubmitEvidenceData, SubmitEvidenceV2, ValidationTrait,
        WebhookDetailsResponse,
    },
};
use transformers::{
    self as adyen, AdyenCaptureRequest, AdyenCaptureResponse, AdyenDefendDisputeRequest,
    AdyenDefendDisputeResponse, AdyenDisputeAcceptRequest, AdyenDisputeAcceptResponse,
    AdyenDisputeSubmitEvidenceRequest, AdyenNotificationRequestItemWH, AdyenPSyncResponse,
    AdyenPaymentRequest, AdyenPaymentResponse, AdyenRedirectRequest, AdyenRefundRequest,
    AdyenRefundResponse, AdyenSubmitEvidenceResponse, AdyenVoidRequest, AdyenVoidResponse,
    SetupMandateRequest, SetupMandateResponse,
};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const X_API_KEY: &str = "X-Api-Key";
}

impl ConnectorServiceTrait for Adyen {}
impl PaymentAuthorizeV2 for Adyen {}
impl PaymentSyncV2 for Adyen {}
impl PaymentVoidV2 for Adyen {}
impl RefundSyncV2 for Adyen {}
impl RefundV2 for Adyen {}
impl PaymentCapture for Adyen {}
impl SetupMandateV2 for Adyen {}
impl AcceptDispute for Adyen {}
impl SubmitEvidenceV2 for Adyen {}
impl DisputeDefend for Adyen {}

macros::create_all_prerequisites!(
    connector_name: Adyen,
    api: [
        (
            flow: Authorize,
            request_body: AdyenPaymentRequest,
            response_body: AdyenPaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
        ),
        (
            flow: PSync,
            request_body: AdyenRedirectRequest,
            response_body: AdyenPSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
        ),
        (
            flow: Capture,
            request_body: AdyenCaptureRequest,
            response_body: AdyenCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        ),
        (
            flow: Void,
            request_body: AdyenVoidRequest,
            response_body: AdyenVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
        ),
        (
            flow: Refund,
            request_body: AdyenRefundRequest,
            response_body: AdyenRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
        )
        ,
        (
            flow: SetupMandate,
            request_body: SetupMandateRequest,
            response_body: SetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>
        ),
        (
            flow: Accept,
            request_body: AdyenDisputeAcceptRequest,
            response_body: AdyenDisputeAcceptResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
        ),
        (
            flow: SubmitEvidence,
            request_body: AdyenDisputeSubmitEvidenceRequest,
            response_body: AdyenSubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
        ),
        (
            flow: DefendDispute,
            request_body: AdyenDefendDisputeRequest,
            response_body: AdyenDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
        )
    ],
    amount_converters: [],
    member_functions: {
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

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.adyen.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.adyen.base_url
        }

        pub fn connector_base_url_disputes<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, DisputeFlowData, Req, Res>,
        ) -> Option<&'a str> {
            req.resource_common_data.connectors.adyen.dispute_base_url.as_deref()
        }
    }
);

impl ConnectorCommon for Adyen {
    fn id(&self) -> &'static str {
        "adyen"
    }
    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Minor
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
        &self,
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
            Ok(format!("{}{}/payments", self.connector_base_url_payments(req), ADYEN_API_VERSION))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenRedirectRequest),
    curl_response: AdyenPSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
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
            Ok(format!("{}{}/payments/details", self.connector_base_url_payments(req), ADYEN_API_VERSION))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenCaptureRequest),
    curl_response: AdyenCaptureResponse,
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
            let id = match &req.request.connector_transaction_id {
                ResponseId::ConnectorTransactionId(id) => id,
                _ => return Err(errors::ConnectorError::MissingConnectorTransactionID.into())
            };
            Ok(format!("{}{}/payments/{}/captures", self.connector_base_url_payments(req), ADYEN_API_VERSION, id))
        }
    }
);

impl ValidationTrait for Adyen {}

impl PaymentOrderCreate for Adyen {}

impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Adyen
{
}

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenVoidRequest),
    curl_response: AdyenVoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
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
            let id = req.request.connector_transaction_id.clone();
            Ok(format!("{}{}/payments/{}/cancels", self.connector_base_url_payments(req), ADYEN_API_VERSION, id))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenDefendDisputeRequest),
    curl_response: AdyenDefendDisputeResponse,
    flow_name: DefendDispute,
    resource_common_data: DisputeFlowData,
    flow_request: DisputeDefendData,
    flow_response: DisputeResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let dispute_url = self.connector_base_url_disputes(req)
                .ok_or(hyperswitch_interfaces::errors::ConnectorError::FailedToObtainIntegrationUrl)?;
            Ok(format!("{}ca/services/DisputeService/v30/defendDispute", dispute_url))
        }
    }
);

impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Adyen {}

impl IncomingWebhook for Adyen {
    fn get_event_type(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<domain_types::connector_types::EventType, error_stack::Report<errors::ConnectorError>>
    {
        let notif: AdyenNotificationRequestItemWH =
            transformers::get_webhook_object_from_body(request.body).map_err(|err| {
                report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                    .attach_printable(format!("error while decoing webhook body {err}"))
            })?;
        Ok(transformers::get_adyen_webhook_event_type(notif.event_code))
    }

    fn process_payment_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<WebhookDetailsResponse, error_stack::Report<errors::ConnectorError>> {
        let notif: AdyenNotificationRequestItemWH =
            transformers::get_webhook_object_from_body(request.body).map_err(|err| {
                report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                    .attach_printable(format!("error while decoing webhook body {err}"))
            })?;
        Ok(WebhookDetailsResponse {
            resource_id: Some(ResponseId::ConnectorTransactionId(
                notif.psp_reference.clone(),
            )),
            status: transformers::get_adyen_payment_webhook_event(notif.event_code, notif.success)?,
            connector_response_reference_id: Some(notif.psp_reference),
            error_code: notif.reason.clone(),
            error_message: notif.reason,
        })
    }

    fn process_refund_webhook(
        &self,
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
                    .attach_printable(format!("error while decoing webhook body {err}"))
            })?;

        Ok(RefundWebhookDetailsResponse {
            connector_refund_id: Some(notif.psp_reference.clone()),
            status: transformers::get_adyen_refund_webhook_event(notif.event_code, notif.success)?,
            connector_response_reference_id: Some(notif.psp_reference.clone()),
            error_code: notif.reason.clone(),
            error_message: notif.reason,
        })
    }
}

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenRefundRequest),
    curl_response: AdyenRefundResponse,
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
            let connector_payment_id = req.request.connector_transaction_id.clone();
            Ok(format!("{}{}/payments/{}/refunds", self.connector_base_url_refunds(req), ADYEN_API_VERSION, connector_payment_id))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(SetupMandateRequest),
    curl_response: SetupMandateResponse,
    flow_name: SetupMandate,
    resource_common_data: PaymentFlowData,
    flow_request: SetupMandateRequestData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}{}/payments", self.connector_base_url_payments(req), ADYEN_API_VERSION))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenDisputeAcceptRequest),
    curl_response: AdyenDisputeAcceptResponse,
    flow_name: Accept,
    resource_common_data: DisputeFlowData,
    flow_request: AcceptDisputeData,
    flow_response: DisputeResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let dispute_url = self.connector_base_url_disputes(req)
                                  .ok_or(hyperswitch_interfaces::errors::ConnectorError::FailedToObtainIntegrationUrl)?;
            Ok(format!("{}ca/services/DisputeService/v30/acceptDispute", dispute_url))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenDisputeSubmitEvidenceRequest),
    curl_response: AdyenSubmitEvidenceResponse,
    flow_name: SubmitEvidence,
    resource_common_data: DisputeFlowData,
    flow_request: SubmitEvidenceData,
    flow_response: DisputeResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let dispute_url = self.connector_base_url_disputes(req)
                                  .ok_or(hyperswitch_interfaces::errors::ConnectorError::FailedToObtainIntegrationUrl)?;
            Ok(format!("{}ca/services/DisputeService/v30/supplyDefenseDocument", dispute_url))
        }
    }
);

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

impl ConnectorSpecifications for Adyen {
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

impl ConnectorValidation for Adyen {
    fn validate_connector_against_payment_request(
        &self,
        capture_method: Option<CaptureMethod>,
        payment_method: PaymentMethod,
        pmt: Option<PaymentMethodType>,
    ) -> CustomResult<(), ConnectorError> {
        let capture_method = capture_method.unwrap_or_default();
        let connector = self.id();

        match pmt {
            Some(payment_method_type) => match payment_method_type {
                PaymentMethodType::Credit | PaymentMethodType::Debit => match capture_method {
                    CaptureMethod::Automatic
                    | CaptureMethod::Manual
                    | CaptureMethod::ManualMultiple => Ok(()),
                    CaptureMethod::Scheduled => {
                        capture_method_not_supported!(
                            connector,
                            capture_method,
                            payment_method_type
                        )
                    }
                },
                _ => {
                    payment_method_not_supported!(connector, payment_method, payment_method_type)
                }
            },
            None => match capture_method {
                    CaptureMethod::Automatic    //confirm the capture methods once
                    | CaptureMethod::Manual
                    | CaptureMethod::ManualMultiple => Ok(()),
                    CaptureMethod::Scheduled => {
                        capture_method_not_supported!(connector, capture_method)
                    }
                },
        }
    }

    fn validate_mandate_payment(
        &self,
        pm_type: Option<PaymentMethodType>,
        pm_data: PaymentMethodData,
    ) -> CustomResult<(), ConnectorError> {
        let mandate_supported_pmd = std::collections::HashSet::from([PaymentMethodDataType::Card]);
        is_mandate_supported(pm_data, pm_type, mandate_supported_pmd, self.id())
    }

    fn validate_psync_reference_id(
        &self,
        data: &hyperswitch_domain_models::router_request_types::PaymentsSyncData,
        _is_three_ds: bool,
        _status: AttemptStatus,
        _connector_meta_data: Option<SecretSerdeValue>,
    ) -> CustomResult<(), ConnectorError> {
        if data.encoded_data.is_some() {
            return Ok(());
        }
        Err(errors::ConnectorError::MissingRequiredField {
            field_name: "encoded_data",
        }
        .into())
    }
    fn is_webhook_source_verification_mandatory(&self) -> bool {
        false //Since webhooks is unimplemented so far out
    }
}
