// pub mod test;
pub mod transformers;
use crate::{with_error_response_body, with_response_body};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        is_mandate_supported, ConnectorSpecifications, ConnectorValidation,
        SupportedPaymentMethodsExt,
    },
    connector_types::{
        AcceptDispute, AcceptDisputeData, ConnectorServiceTrait, ConnectorWebhookSecrets,
        DisputeDefend, DisputeDefendData, DisputeFlowData, DisputeResponseData, EventType,
        IncomingWebhook, PaymentAuthorizeV2, PaymentCapture, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentOrderCreate, PaymentSyncV2,
        PaymentVoidData, PaymentVoidV2, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundSyncV2,
        RefundV2, RefundWebhookDetailsResponse, RefundsData, RefundsResponseData, RequestDetails,
        ResponseId, SetupMandateRequestData, SetupMandateV2, SubmitEvidenceData, SubmitEvidenceV2,
        ValidationTrait, WebhookDetailsResponse,
    },
    types::{
        CardSpecificFeatures, ConnectorInfo, FeatureStatus, PaymentConnectorCategory,
        PaymentMethodDataType, PaymentMethodDetails, PaymentMethodSpecificFeatures,
        SupportedPaymentMethods,
    },
};
use hyperswitch_api_models::enums::Connector;
use hyperswitch_common_enums::{
    AttemptStatus, CaptureMethod, CardNetwork, EventClass, PaymentMethod, PaymentMethodType,
};
use hyperswitch_common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    pii::SecretSerdeValue,
    request::{Method, RequestContent},
    types::{AmountConvertor, MinorUnit},
};
use std::sync::LazyLock;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use error_stack::{report, ResultExt};
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_request_types::SyncRequestType,
};
use hyperswitch_interfaces::{
    api::{self, CaptureSyncMethod, ConnectorCommon},
    configs::Connectors,
    connector_integration_v2::ConnectorIntegrationV2,
    errors,
    errors::ConnectorError,
    events::connector_api_logs::ConnectorEvent,
    types::Response,
};
use hyperswitch_masking::{Mask, Maskable, PeekInterface};
use transformers::{self as paypay};
use transformers::ForeignTryFrom;

#[derive(Clone)]
pub struct Paypay {
    #[allow(dead_code)]
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
}

impl ValidationTrait for Paypay {
    fn should_do_order_create(&self) -> bool {
        false
    }
}

impl ConnectorServiceTrait for Paypay {}
impl PaymentAuthorizeV2 for Paypay {}
impl PaymentSyncV2 for Paypay {}
impl PaymentOrderCreate for Paypay {}
impl PaymentVoidV2 for Paypay {}
impl RefundSyncV2 for Paypay {}
impl RefundV2 for Paypay {}
impl PaymentCapture for Paypay {}
impl SetupMandateV2 for Paypay {}
impl AcceptDispute for Paypay {}
impl SubmitEvidenceV2 for Paypay {}
impl DisputeDefend for Paypay {}
impl IncomingWebhook for Paypay {}

impl Paypay {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &hyperswitch_common_utils::types::MinorUnitForConnector,
        }
    }
}

impl ConnectorCommon for Paypay {
    fn id(&self) -> &'static str {
        "paypay"
    }
    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Minor
    }
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = paypay::PaypayAuthType::try_from(auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            "authorization".to_string(),
            format!("Bearer {}", auth.key_id.peek()).into_masked(),
        )])
    }
    fn base_url(&self, _connectors: &Connectors) -> &'static str {
        "https://stg-api.sandbox.paypay.ne.jp/"
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: paypay::PaypayErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error.code,
            message: response.error.description,
            reason: Some(response.error.reason),
            attempt_status: None,
            connector_transaction_id: None,
        })
    }
}

impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Paypay
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
    where
        Self: ConnectorIntegrationV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    {
        let mut header = vec![(
            "content-type".to_string(),
            "application/json".to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}v1/subscription/payments",
            req.resource_common_data.connectors.paypay.base_url
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let paypay_router_data = paypay::PaypayRouterData {
            amount: req.request.minor_amount,
            router_data: req,
        };
        let connector_req = paypay::PaypayPaymentRequest::try_from(&paypay_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: paypay::PaypayPaymentResponse = res
            .response
            .parse_struct("PaypayPaymentResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((
            response,
            data.clone(),
            res.status_code,
            data.request.capture_method,
            false,
            data.request.payment_method_type,
        ))
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Empty implementations for unimplemented flows
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Paypay {
    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            "content-type".to_string(),
            "application/json".to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let merchant_payment_id = req.request.connector_transaction_id.get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingRequiredField {
                field_name: "merchant_payment_id",
            })?;
        Ok(format!(
            "{}v2/payments/{}",
            req.resource_common_data.connectors.paypay.base_url,
            merchant_payment_id
        ))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        // PSync is a GET request, so no request body needed
        Ok(None)
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> {
        let response: paypay::PaypaySyncResponse = res
            .response
            .parse_struct("PaypaySyncResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((
            response,
            data.clone(),
            res.status_code,
            data.request.capture_method,
            false,
            data.request.payment_method_type,
        ))
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for Paypay {
    fn get_headers(
        &self,
        _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("CreateOrder not implemented".into())))
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("CreateOrder not implemented".into())))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("CreateOrder not implemented".into())))
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("CreateOrder not implemented".into())))
    }

    fn get_error_response_v2(
        &self,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("CreateOrder not implemented".into())))
    }
}

impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Paypay {
    fn get_headers(
        &self,
        _req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("Capture not implemented".into())))
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("Capture not implemented".into())))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("Capture not implemented".into())))
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("Capture not implemented".into())))
    }

    fn get_error_response_v2(
        &self,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("Capture not implemented".into())))
    }
}

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Paypay {
    fn get_headers(
        &self,
        _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("Void not implemented".into())))
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("Void not implemented".into())))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("Void not implemented".into())))
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("Void not implemented".into())))
    }

    fn get_error_response_v2(
        &self,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("Void not implemented".into())))
    }
}

impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Paypay {
    fn get_headers(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            "content-type".to_string(),
            "application/json".to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}v2/refunds",
            req.resource_common_data.connectors.paypay.base_url
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let paypay_router_data = paypay::PaypayRouterData {
            amount: req.request.minor_refund_amount,
            router_data: req,
        };
        let connector_req = paypay::PaypayRefundRequest::try_from(&paypay_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, errors::ConnectorError> {
        let response: paypay::PaypayRefundResponse = res
            .response
            .parse_struct("PaypayRefundResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((
            response,
            data.clone(),
        ))
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Paypay {
    fn get_headers(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            "content-type".to_string(),
            "application/json".to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let merchant_refund_id = if req.request.connector_refund_id.is_empty() {
            return Err(report!(errors::ConnectorError::MissingRequiredField {
                field_name: "merchant_refund_id",
            }));
        } else {
            req.request.connector_refund_id.clone()
        };
        
        Ok(format!(
            "{}v2/refunds/{}",
            req.resource_common_data.connectors.paypay.base_url,
            merchant_refund_id
        ))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        // RSync is a GET request, so no request body needed
        Ok(None)
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, errors::ConnectorError> {
        let response: paypay::PaypayRsyncResponse = res
            .response
            .parse_struct("PaypayRsyncResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((
            response,
            data.clone(),
        ))
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData> for Paypay {
    fn get_headers(
        &self,
        _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("SetupMandate not implemented".into())))
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("SetupMandate not implemented".into())))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("SetupMandate not implemented".into())))
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("SetupMandate not implemented".into())))
    }

    fn get_error_response_v2(
        &self,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("SetupMandate not implemented".into())))
    }
}

impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData> for Paypay {
    fn get_headers(
        &self,
        _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("Accept not implemented".into())))
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("Accept not implemented".into())))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("Accept not implemented".into())))
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("Accept not implemented".into())))
    }

    fn get_error_response_v2(
        &self,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("Accept not implemented".into())))
    }
}

impl ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData> for Paypay {
    fn get_headers(
        &self,
        _req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("SubmitEvidence not implemented".into())))
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("SubmitEvidence not implemented".into())))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("SubmitEvidence not implemented".into())))
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("SubmitEvidence not implemented".into())))
    }

    fn get_error_response_v2(
        &self,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("SubmitEvidence not implemented".into())))
    }
}

impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData> for Paypay {
    fn get_headers(
        &self,
        _req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("DefendDispute not implemented".into())))
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("DefendDispute not implemented".into())))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("DefendDispute not implemented".into())))
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("DefendDispute not implemented".into())))
    }

    fn get_error_response_v2(
        &self,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented("DefendDispute not implemented".into())))
    }
}
