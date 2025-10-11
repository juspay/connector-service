pub mod transformers;

use std::marker::PhantomData;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    consts,
    crypto::{self, OptionalEncryptable},
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{FloatMajorUnit, StringMinorUnit},
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, RSync,
        Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, ConnectorSpecifications, ConnectorWebhookSecrets, DisputeDefendData,
        DisputeFlowData, DisputeResponseData, EventType, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundWebhookDetailsResponse, RefundsData, RefundsResponseData,
        RepeatPaymentData, RequestDetails, ResponseId, SessionTokenRequestData,
        SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    router_request_types::ResponseIdType,
    types::{
        self, AccessToken, AmountConverter, AmountConverterTrait, ConnectorAuthType,
        ConnectorCommonData, ConnectorCommonV2, ConnectorConfig, ConnectorData,
        ConnectorIntegrationV2, ConnectorRedirectResponse, ConnectorRequestHeaders,
        ConnectorResponseData, ConnectorValidation, CurrencyUnit, PaymentAddress,
        PaymentMethodDataType, RedirectForm, RefundResponseData, RouterData,
    },
    webhooks::{IncomingWebhook, IncomingWebhookRequest},
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use masking::PeekInterface;
use serde::{Deserialize, Serialize};

use crate::{
    services,
    utils::{self, ConnectorErrorType},
};

// Create all prerequisites using the mandatory macro framework
macros::create_all_prerequisites!(
    connector_name: ZaakPay,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: transformers::ZaakPayPaymentsRequest,
            response_body: transformers::ZaakPayPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: transformers::ZaakPayPaymentsSyncRequest,
            response_body: transformers::ZaakPayPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: RSync,
            request_body: transformers::ZaakPayRefundSyncRequest,
            response_body: transformers::ZaakPayRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        // Stub types for unimplemented flows
        (
            flow: Void,
            request_body: transformers::ZaakPayVoidRequest,
            response_body: transformers::ZaakPayVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: transformers::ZaakPayCaptureRequest,
            response_body: transformers::ZaakPayCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: transformers::ZaakPayRefundRequest,
            response_body: transformers::ZaakPayRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: CreateOrder,
            request_body: transformers::ZaakPayCreateOrderRequest,
            response_body: transformers::ZaakPayCreateOrderResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: CreateSessionToken,
            request_body: transformers::ZaakPaySessionTokenRequest,
            response_body: transformers::ZaakPaySessionTokenResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: transformers::ZaakPaySetupMandateRequest,
            response_body: transformers::ZaakPaySetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: transformers::ZaakPayRepeatPaymentRequest,
            response_body: transformers::ZaakPayRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            request_body: transformers::ZaakPayAcceptDisputeRequest,
            response_body: transformers::ZaakPayAcceptDisputeResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ),
        (
            flow: DefendDispute,
            request_body: transformers::ZaakPayDefendDisputeRequest,
            response_body: transformers::ZaakPayDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ),
        (
            flow: SubmitEvidence,
            request_body: transformers::ZaakPaySubmitEvidenceRequest,
            response_body: transformers::ZaakPaySubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        fn get_auth_header(&self, auth_type: &ConnectorAuthType) -> CustomResult<ConnectorRequestHeaders, errors::ConnectorError> {
            match auth_type {
                ConnectorAuthType::HeaderKey { api_key } => {
                    Ok(vec![(
                        "Authorization".to_string(),
                        format!("Bearer {}", api_key.peek()),
                    )])
                }
                _ => Err(errors::ConnectorError::AuthenticationFailed.into()),
            }
        }

        fn build_checksum(&self, data: &str, salt: &str) -> String {
            use sha2::{Digest, Sha512};
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.update(salt);
            hex::encode(hasher.finalize())
        }
    }
);

// Implement connector common trait for custom logic
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommon for ZaakPay<T>
{
    fn get_connector_name(&self) -> &'static str {
        "zaakpay"
    }

    fn get_base_url(&self) -> &'static str {
        match self.connector_name {
            "zaakpay_test" => "https://zaakpay.com",
            _ => "https://zaakpay.com",
        }
    }

    fn get_api_tag(&self) -> &'static str {
        match self.flow_name {
            "Authorize" => "transact",
            "PSync" => "check",
            "RSync" => "check",
            _ => "default",
        }
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_error_response_v2(
        &self,
        response: &[u8],
    ) -> CustomResult<transformers::ZaakPayErrorResponse, errors::ConnectorError> {
        self.handle_error_response(response)
    }
}

// Implement Authorize flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: ZaakPay,
    curl_request: Json(transformers::ZaakPayPaymentsRequest),
    curl_response: transformers::ZaakPayPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
            let connector_request = transformers::ZaakPayPaymentsRequest::try_from(req)?;
            let auth_header = self.get_auth_header(&req.connector_auth_type)?;
            
            let request = services::RequestBuilder::new()
                .method(services::Method::Post)
                .url(&types::UrlType::get_url(
                    self.get_base_url(),
                    self.get_api_tag(),
                    &types::ConnectorAction::PaymentAuthorize,
                )?)
                .attach_default_headers()
                .headers(auth_header)
                .body(types::RequestBody::Json(connector_request))
                .build();

            Ok(Some(request))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            res: services::Response,
        ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, errors::ConnectorError> {
            let response: transformers::ZaakPayPaymentsResponse = res
                .response
                .parse_struct("ZaakPayPaymentsResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            let router_response = transformers::ZaakPayPaymentsResponse::try_from(response)?;

            Ok(RouterDataV2::from_response(
                router_response,
                req.request.clone(),
                req.resource_common_data.clone(),
                req.connector_meta_data.clone(),
            ))
        }
    }
);

// Implement PSync flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: ZaakPay,
    curl_request: Json(transformers::ZaakPayPaymentsSyncRequest),
    curl_response: transformers::ZaakPayPaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
            let connector_request = transformers::ZaakPayPaymentsSyncRequest::try_from(req)?;
            let auth_header = self.get_auth_header(&req.connector_auth_type)?;
            
            let request = services::RequestBuilder::new()
                .method(services::Method::Post)
                .url(&types::UrlType::get_url(
                    self.get_base_url(),
                    self.get_api_tag(),
                    &types::ConnectorAction::PaymentSync,
                )?)
                .attach_default_headers()
                .headers(auth_header)
                .body(types::RequestBody::Json(connector_request))
                .build();

            Ok(Some(request))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            res: services::Response,
        ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> {
            let response: transformers::ZaakPayPaymentsSyncResponse = res
                .response
                .parse_struct("ZaakPayPaymentsSyncResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            let router_response = transformers::ZaakPayPaymentsSyncResponse::try_from(response)?;

            Ok(RouterDataV2::from_response(
                router_response,
                req.request.clone(),
                req.resource_common_data.clone(),
                req.connector_meta_data.clone(),
            ))
        }
    }
);

// Implement RSync flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: ZaakPay,
    curl_request: Json(transformers::ZaakPayRefundSyncRequest),
    curl_response: transformers::ZaakPayRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
            let connector_request = transformers::ZaakPayRefundSyncRequest::try_from(req)?;
            let auth_header = self.get_auth_header(&req.connector_auth_type)?;
            
            let request = services::RequestBuilder::new()
                .method(services::Method::Post)
                .url(&types::UrlType::get_url(
                    self.get_base_url(),
                    self.get_api_tag(),
                    &types::ConnectorAction::RefundSync,
                )?)
                .attach_default_headers()
                .headers(auth_header)
                .body(types::RequestBody::Json(connector_request))
                .build();

            Ok(Some(request))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            res: services::Response,
        ) -> CustomResult<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, errors::ConnectorError> {
            let response: transformers::ZaakPayRefundSyncResponse = res
                .response
                .parse_struct("ZaakPayRefundSyncResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            let router_response = transformers::ZaakPayRefundSyncResponse::try_from(response)?;

            Ok(RouterDataV2::from_response(
                router_response,
                req.request.clone(),
                req.resource_common_data.clone(),
                req.connector_meta_data.clone(),
            ))
        }
    }
);

// Implement not-implemented flows with proper error handling
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for ZaakPay<T>
        {
            fn build_request_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
            ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
                let flow_name = stringify!($flow);
                Err(errors::ConnectorError::NotImplemented(flow_name.to_string()).into())
            }

            fn handle_response_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _res: services::Response,
            ) -> CustomResult<RouterDataV2<$flow, $common_data, $req, $resp>, errors::ConnectorError> {
                let flow_name = stringify!($flow);
                Err(errors::ConnectorError::NotImplemented(flow_name.to_string()).into())
            }
        }
    };
}

// Apply not-implemented macro to all unimplemented flows
impl_not_implemented_flow!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_not_implemented_flow!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_not_implemented_flow!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_not_implemented_flow!(SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData);
impl_not_implemented_flow!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_not_implemented_flow!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_not_implemented_flow!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_not_implemented_flow!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);

// Implement source verification stubs for all flows
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            ConnectorValidation<$flow, $common_data, $req, $resp> for ZaakPay<T>
        {
            fn validate_capture_method(
                &self,
                _capture_method: Option<common_enums::CaptureMethod>,
            ) -> CustomResult<(), errors::ConnectorError> {
                Ok(())
            }

            fn validate_mandate_payment(
                &self,
                _mandate_type: Option<common_enums::MandateType>,
            ) -> CustomResult<(), errors::ConnectorError> {
                Ok(())
            }

            fn validate_pmnt_refund(
                &self,
                _pmnt_ref: &str,
            ) -> CustomResult<(), errors::ConnectorError> {
                Ok(())
            }
        }
    };
}

// Apply source verification stubs to all flows
impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_source_verification_stub!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_source_verification_stub!(SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData);
impl_source_verification_stub!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_source_verification_stub!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_source_verification_stub!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_source_verification_stub!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);

// Implement all required connector traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentSessionToken for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentCaptureV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundExecuteV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundSyncV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::MandateSetupV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentRepeatV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::DisputeAcceptV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::DisputeDefendV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::DisputeSubmitEvidenceV2 for ZaakPay<T> {}

// Webhook implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    IncomingWebhook for ZaakPay<T>
{
    fn get_webhook_source_verification_algorithm(
        &self,
        _request: &IncomingWebhookRequest,
    ) -> CustomResult<Box<dyn crypto::VerifySignature>, errors::ConnectorError> {
        Ok(Box::new(crypto::HmacSha256))
    }

    fn get_webhook_source_verification_signature(
        &self,
        request: &IncomingWebhookRequest,
        _connector_webhook_secrets: &ConnectorWebhookSecrets,
    ) -> CustomResult<String, errors::ConnectorError> {
        let signature = request
            .headers
            .get("x-zaakpay-signature")
            .and_then(|header| header.to_str().ok())
            .ok_or(errors::ConnectorError::WebhookSignatureNotFound)?;
        Ok(signature.to_string())
    }

    fn get_webhook_source_verification_message(
        &self,
        request: &IncomingWebhookRequest,
        _connector_webhook_secrets: &ConnectorWebhookSecrets,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(request.body.clone())
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &IncomingWebhookRequest,
    ) -> CustomResult<String, errors::ConnectorError> {
        let webhook_response: transformers::ZaakPayWebhookResponse = request
            .body
            .parse_struct("ZaakPayWebhookResponse")
            .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;
        
        Ok(webhook_response.txnData)
    }

    fn get_webhook_event_type(
        &self,
        request: &IncomingWebhookRequest,
    ) -> CustomResult<IncomingWebhookEvent, errors::ConnectorError> {
        let webhook_response: transformers::ZaakPayWebhookResponse = request
            .body
            .parse_struct("ZaakPayWebhookResponse")
            .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;
        
        match webhook_response.txnData.as_str() {
            "success" => Ok(IncomingWebhookEvent::PaymentIntentSuccess),
            "failure" => Ok(IncomingWebhookEvent::PaymentIntentFailure),
            _ => Ok(IncomingWebhookEvent::UnknownEvent),
        }
    }

    fn get_webhook_api_type(
        &self,
        _request: &IncomingWebhookRequest,
    ) -> CustomResult<WebhookApiType, errors::ConnectorError> {
        Ok(WebhookApiType::PaymentIntent)
    }
}