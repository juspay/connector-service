pub mod transformers;

use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void, CreateOrder},
    connector_types::{
        ConnectorServiceTrait, EventType, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ConnectorWebhookSecrets, RequestDetails, WebhookDetailsResponse, RefundWebhookDetailsResponse
    },
};
use error_stack::{ResultExt, report};
use hyperswitch_api_models::enums::{self};
use hyperswitch_common_utils::{
    errors::CustomResult,
    request::{Method, RequestBuilder, RequestContent},
    types::MinorUnit, ext_traits::ByteSliceExt,
};
use hyperswitch_domain_models::{
    router_data::{ConnectorAuthType, ErrorResponse, RouterData},
    router_data_v2::RouterDataV2,
    router_request_types::{
        PaymentsAuthorizeData as DomainPaymentsAuthorizeData,
        ResponseId
    },
    router_response_types::{RedirectForm, MandateReference},
};
use hyperswitch_interfaces::{
    api::{self, ConnectorCommon, ConnectorCommonExt, ConnectorIntegration, ConnectorRedirectResponse, ConnectorValidation},
    configs::Connectors,
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    connector_integration_v2::ConnectorIntegrationV2,
    errors::{self, ConnectorError},
    events::connector_api_logs::ConnectorEvent,
    types::{Response, RefreshTokenRouterData, ResponseRouterData},
    webhooks::{IncomingWebhook, IncomingWebhookRequestDetails},
};

use masking::{Mask, PeekInterface, Maskable};
use router_env::logger;
use transformers as airwallex_transformer;
use crate::constants::headers;
use crate::types::ConnectorData; // Assuming ConnectorData might be needed for some operations or it's a common pattern.


#[derive(Debug, Clone)]
pub struct Airwallex;

impl Airwallex {
    pub fn new() -> Self {
        Self
    }
}

impl ConnectorServiceTrait for Airwallex {}

impl api::Payment for Airwallex {}
impl api::PaymentAuthorize for Airwallex {}
impl api::PaymentSync for Airwallex {}
impl api::PaymentVoid for Airwallex {}
impl api::PaymentCapture for Airwallex {}
impl api::PaymentSession for Airwallex {}
impl api::ConnectorAccessToken for Airwallex {}
impl api::MandateSetup for Airwallex {}
impl api::PaymentToken for Airwallex {}

impl api::Refund for Airwallex {}
impl api::RefundExecute for Airwallex {}
impl api::RefundSync for Airwallex {}

impl api::Dispute for Airwallex {}
impl api::DisputeEvidence for Airwallex {}

impl api::IncomingWebhookReceiver for Airwallex {}


//Marker traits from domain_types::connector_types
impl domain_types::connector_types::PaymentAuthorizeV2 for Airwallex {}
impl domain_types::connector_types::PaymentSyncV2 for Airwallex {}
impl domain_types::connector_types::PaymentOrderCreate for Airwallex {}
impl domain_types::connector_types::PaymentVoidV2 for Airwallex {}
impl domain_types::connector_types::RefundSyncV2 for Airwallex {}
impl domain_types::connector_types::RefundV2 for Airwallex {}
impl domain_types::connector_types::PaymentCapture for Airwallex {}


impl ConnectorCommon for Airwallex {
    fn id(&self) -> &'static str {
        "airwallex"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.airwallex.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        let response: Result<airwallex_transformer::AirwallexErrorResponse, _> =
            res.response.parse_struct("AirwallexErrorResponse");

        match response {
            Ok(airwallex_error) => {
                with_response_body!(event_builder, airwallex_error);
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: airwallex_error.code,
                    message: airwallex_error.message,
                    reason: airwallex_error.source,
                    attempt_status: None,
                    connector_transaction_id: None,
                })
            }
            Err(e) => {
                 logger::error!(deserialization_error =?e, error_response=?res.response);
                 with_response_body!(event_builder, res.response);
                 Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: NO_ERROR_CODE.to_string(),
                    message: NO_ERROR_MESSAGE.to_string(),
                    reason: Some(String::from_utf8_lossy(&res.response).into_owned()),
                    attempt_status: None,
                    connector_transaction_id: None,
                })
            }
        }
    }
}

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Airwallex
where
    Self: ConnectorIntegration<Flow, Request, Response>,
{
    fn build_headers(
        &self,
        req: &RouterData<Flow, Request, Response>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut headers = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.get_content_type().to_string().into(),
        )];
        let access_token = req
            .access_token
            .clone()
            .ok_or(errors::ConnectorError::FailedToObtainAuthType)?;
        let auth_header = (
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", access_token.token.peek()).into_masked(),
        );
        headers.push(auth_header);
        Ok(headers)
    }
}


impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Airwallex
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        _connectors: &Connectors, // Changed from req.connectors to _connectors
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
         let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        // Airwallex uses API Key and Client ID passed in auth_type for BodyKey, not Bearer token for this flow typically
        // The Hyperswitch example uses Bearer token which is obtained from a separate access_token call.
        // For now, assuming access token is already populated in RouterDataV2 similar to RouterData
        // This might need adjustment based on how access_token is managed in RouterDataV2
        // Or if direct API key usage is preferred for authorize.
        // The provided Hyperswitch `build_headers` uses `req.access_token`.
        // Let's assume `req.access_token` exists in `RouterDataV2` or is passed via `connector_auth_type`.
        // The guide uses `get_auth_header(&req.connector_auth_type)?` which is more aligned if it's not an OAuth style token.
        // Hyperswitch Airwallex `build_headers` uses `req.access_token`.

        // For Payments Authorize, Airwallex typically requires a client credential based access token.
        // This token should be fetched *before* this call and stored in `req.access_token`.
        // The `ConnectorAccessToken` trait implementation would handle fetching this token.

        let access_token = req.access_token.clone().ok_or_else(|| {
            report!(errors::ConnectorError::MissingRequiredField {
                field_name: "access_token"
            })
        })?;

        let auth_header = (
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", access_token.token.peek()).into_masked(),
        );
        header.push(auth_header);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        // From Hyperswitch: POST /api/v1/pa/payments/create
        // However, the intent creation seems to be a separate step in some Airwallex flows.
        // Let's assume for direct payment creation:
        Ok(format!(
            "{}/api/v1/pa/payments/create", // Path for creating a payment intent/payment
            self.base_url(connectors)
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data = airwallex_transformer::AirwallexRouterData::try_from((
            &self.get_currency_unit(), // Currency unit from ConnectorCommon
            req.request.currency,
            req.request.amount, // This is i64, transformers expect i64 for amount
            req,
        ))?;
        let connector_req = airwallex_transformer::AirwallexPaymentsRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response(
        &self,
        data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>, errors::ConnectorError> {
        logger::debug!(airwallex_payment_response=?res);
        let response: airwallex_transformer::AirwallexPaymentsResponse = res
            .response
            .parse_struct("AirwallexPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::try_from(hyperswitch_domain_models::router_data::RouterData {
            flow: std::marker::PhantomData,
            merchant_id: data.merchant_id.clone(),
            customer_id: data.customer_id.clone(),
            connector_customer: data.connector_customer.clone(),
            payment_id: data.payment_id.clone(),
            attempt_id: data.attempt_id.clone(),
            status: enums::AttemptStatus::try_from(response.status.clone()).unwrap_or(enums::AttemptStatus::Pending), // Assuming response.status can be mapped
            payment_method: data.payment_method,
            connector_auth_type: data.connector_auth_type.clone(),
            description: data.description.clone(),
            return_url: data.return_url.clone(),
            address: data.address.clone(),
            auth_type: data.auth_type,
            connector_meta_data: data.connector_meta_data.clone(),
            amount_captured: data.amount_captured,
            minor_amount_captured: data.minor_amount_captured,
            access_token: data.access_token.clone(),
            session_token: data.session_token.clone(),
            reference_id: data.reference_id.clone(),
            payment_method_token: data.payment_method_token.clone(),
            preprocessing_id: data.preprocessing_id.clone(),
            connector_request_reference_id: data.connector_request_reference_id.clone(),
            test_mode: data.test_mode,
            connector_http_status_code: Some(res.status_code),
            external_latency: data.external_latency,
            request: data.request.clone(), // Original request data
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                redirection_data: response.next_action.as_ref().map(|next_action| {
                    match next_action.action_type.as_str() {
                        "redirect" => next_action.url.as_ref().map(|url| Box::new(Some(RedirectForm::Html { html_data: format!("<script>window.location.href='{}';</script>", url) }))), // Or proper redirect form
                        _ => None,
                    }
                }).flatten().map_or(Box::new(None), |b| b), // Wrap in Box<Option<...>>
                connector_metadata: None, // Populate if needed
                network_txn_id: response.id.clone().into(), // Assuming id is the network_txn_id
                connector_response_reference_id: Some(response.request_id.clone()),
                incremental_authorization_allowed: None, // Populate if applicable
            }),
            #[cfg(feature = "payouts")]
            payout_data: None,
            #[cfg(feature = "payouts")]
            refund_id: None,
            #[cfg(feature = "payouts")]
            payout_method_data: None,
            quote_id: None,
            payment_method_balance: None,
            connector_api_version: None,
            payment_method_status: None,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

     fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}


// Implement other ConnectorIntegrationV2 traits for PSync, CreateOrder, RSync, Void, Refund, Capture as stubs for now
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Airwallex {
    // Implement methods or use default if provided by a blanket impl
}
impl ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for Airwallex {
    // Implement methods
}
impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Airwallex {
    // Implement methods
}

impl IncomingWebhook for Airwallex {
    fn get_webhook_source_verification_algorithm(
        &self,
        _request: &IncomingWebhookRequestDetails,
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, errors::ConnectorError> {
        Err(errors::ConnectorError::WebhooksNotImplemented.into())
    }

    fn get_webhook_source_verification_merchant_secret(
        &self,
        _merchant_account: &hyperswitch_domain_models::merchant_account::MerchantAccount,
        _connector_webhook_secrets: &ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<common_utils::pii::Secret<String>>, errors::ConnectorError> {
        Err(errors::ConnectorError::WebhooksNotImplemented.into())
    }

    fn get_webhook_object_reference_id(
        &self,
        _request: &IncomingWebhookRequestDetails,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::WebhooksNotImplemented.into())
    }

    fn get_webhook_event_type(
        &self,
        _request: &IncomingWebhookRequestDetails,
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {
        Err(errors::ConnectorError::WebhooksNotImplemented.into())
    }

    fn get_webhook_resource_object(
        &self,
        _request: &IncomingWebhookRequestDetails,
    ) -> CustomResult<Box<dyn masking::ErasedMaskSerialize>, errors::ConnectorError> {
        Err(errors::ConnectorError::WebhooksNotImplemented.into())
    }

     fn get_webhook_api_response(
        &self,
        _request: &IncomingWebhookRequestDetails,
    ) -> CustomResult<services::api::ApplicationResponse<serde_json::Value>, errors::ConnectorError>
    {
        Err(errors::ConnectorError::WebhooksNotImplemented.into())
    }

    fn get_dispute_details(
        &self,
        _request: &IncomingWebhookRequestDetails,
    ) -> CustomResult<api::disputes::DisputePayload, errors::ConnectorError> {
        Err(errors::ConnectorError::WebhooksNotImplemented.into())
    }
}

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Airwallex {
    // Implement methods
}
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Airwallex {
    // Implement methods
}
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Airwallex {
    // Implement methods
}

// For ConnectorValidation
impl ConnectorValidation for Airwallex {
    // Implement methods if needed, or rely on default if provided by a blanket implementation.
    // For example, if there's specific validation logic for Airwallex:
    fn validate_capture_method(
        &self,
        capture_method: Option<enums::CaptureMethod>,
        _pm_type: Option<enums::PaymentMethodType>,
    ) -> CustomResult<(), errors::ConnectorError> {
        // Airwallex default capture is automatic, manual capture is also supported.
        // No specific validation documented for capture method here, assume all valid Hyperswitch methods are fine.
        match capture_method {
            Some(enums::CaptureMethod::Manual) | Some(enums::CaptureMethod::Automatic) | Some(enums::CaptureMethod::Scheduled) | None => Ok(()),
            Some(val) => Err(report!(errors::ConnectorError::FlowNotSupported {
                flow: format!("{:?}", val),
                connector: "Airwallex".to_string(),
            })),
        }
    }

    fn validate_payment_method_fields(
        &self,
        payment_method_data: &hyperswitch_domain_models::payment_method_data::PaymentMethodData,
    ) -> CustomResult<(), errors::ConnectorError> {
        match payment_method_data {
            hyperswitch_domain_models::payment_method_data::PaymentMethodData::Card(_) => Ok(()),
            // Add other supported payment methods by Airwallex and their validations
            _ => Err(errors::ConnectorError::NotImplemented("Payment method validation".to_string()).into()),
        }
    }
}


// AccessToken trait
impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Airwallex {
    fn get_headers(
        &self,
        _req: &RouterData<AccessTokenAuth, AccessTokenRequestData, AccessToken>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/x-www-form-urlencoded".to_string().into(),
        )])
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        _req: &RouterData<AccessTokenAuth, AccessTokenRequestData, AccessToken>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/api/v1/authentication/login", // Airwallex token endpoint
            self.base_url(connectors)
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterData<AccessTokenAuth, AccessTokenRequestData, AccessToken>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let auth = airwallex_transformer::AirwallexAuthType::try_from(&req.connector_auth_type)?;
        let connector_req = airwallex_transformer::AirwallexAuthUpdateRequest {
            client_id: auth.x_client_id.peek().clone(),
            api_key: auth.x_api_key.peek().clone(),
        };
        Ok(Some(RequestContent::FormUrlEncoded(Box::new(
            connector_req,
        ))))
    }

    fn build_request(
        &self,
        req: &RouterData<AccessTokenAuth, AccessTokenRequestData, AccessToken>,
        connectors: &Connectors,
    ) -> CustomResult<Option<RequestBuilder>, errors::ConnectorError> {
        let request_body = self.get_request_body(req, connectors)?;
        let url = self.get_url(req, connectors)?;
        let headers = self.get_headers(req, connectors)?;

        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&url)
                .attach_optional_headers(Some(headers))
                .set_body(request_body),
        ))
    }
    fn handle_response(
        &self,
        data: &RouterData<AccessTokenAuth, AccessTokenRequestData, AccessToken>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterData<AccessTokenAuth, AccessTokenRequestData, AccessToken>, errors::ConnectorError> {
        let response: airwallex_transformer::AirwallexAuthUpdateResponse = res
            .response
            .parse_struct("AirwallexAuthUpdateResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        with_response_body!(event_builder, response.clone());

        Ok(data.clone().map(|_| {
            AccessToken {
                token: response.token,
                expires: response.expires_in, // expires_in is typically seconds
            }
        }))
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Stubs for other trait implementations from Hyperswitch example
// These would need to be filled out for other flows like PreProcessing, CompleteAuthorize, etc.
// based on the specific requirements of those flows in your system and Airwallex's API.

impl api::ConnectorPreProcessing for Airwallex {}
impl PreProcessing for Airwallex {
    // fn get_request_body ...
    // fn handle_response ...
}

impl api::ConnectorCompleteAuthorize for Airwallex {}
impl CompleteAuthorize for Airwallex {
     // fn get_request_body ...
    // fn handle_response ...
}


// Helper for building error response (already defined in ConnectorCommon)
// fn build_error_response ... 