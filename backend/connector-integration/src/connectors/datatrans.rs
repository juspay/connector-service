pub mod transformers;

use std::fmt::Debug;

use base64::Engine;
use common_enums::CurrencyUnit;
use common_utils::{
    errors::CustomResult, 
    ext_traits::ByteSliceExt, 
    types::{StringMinorUnit, AmountConvertor, MinorUnit}, 
    request::RequestBuilder
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateAccessToken, CreateOrder, CreateSessionToken,
        DefendDispute, PSync, PaymentMethodToken, RSync, Refund, RepeatPayment, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData,
        ConnectorWebhookSecrets, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        RequestDetails, SessionTokenRequestData, SessionTokenResponseData, SetupMandateRequestData,
        SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface, Secret};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;
use transformers::{self as datatrans, DatatransPaymentsRequest, DatatransResponse, DatatransSyncResponse};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

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
            + Serialize
            + Default,
    > connector_types::ConnectorServiceTrait<T> for Datatrans<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize
            + Default,
    > connector_types::PaymentAuthorizeV2<T> for Datatrans<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize
            + Default,
    > connector_types::PaymentSyncV2 for Datatrans<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentSessionToken for Datatrans<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Datatrans<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentVoidV2 for Datatrans<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RefundSyncV2 for Datatrans<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RefundV2 for Datatrans<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentCapture for Datatrans<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::SetupMandateV2<T> for Datatrans<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RepeatPaymentV2 for Datatrans<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentTokenV2<T> for Datatrans<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::AcceptDispute for Datatrans<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::DisputeDefend for Datatrans<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::SubmitEvidenceV2 for Datatrans<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentOrderCreate for Datatrans<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::IncomingWebhook for Datatrans<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ValidationTrait for Datatrans<T>
{
}

#[derive(Clone)]
pub struct Datatrans<T> {
    #[allow(dead_code)]
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
    #[allow(dead_code)]
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Datatrans<T> {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &common_utils::types::MinorUnitForConnector,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Datatrans<T>
{
    fn id(&self) -> &'static str {
        "datatrans"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.datatrans.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = datatrans::DatatransAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let auth_key = format!("{}:{}", auth.merchant_id.peek(), auth.passcode.peek());
        let auth_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(auth_key)
        );
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            auth_header.into_masked(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: Result<datatrans::DatatransErrorResponse, _> =
            res.response.parse_struct("Datatrans Error Response");

        match response {
            Ok(error_res) => {
                event_builder.map(|i| i.set_error_response_body(&error_res));
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: error_res.error.code.clone(),
                    message: error_res.error.message.clone(),
                    reason: Some(error_res.error.message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                })
            }
            Err(_) => {
                let error_message = match res.status_code {
                    401 => "Authentication failed",
                    403 => "Access forbidden",
                    404 => "Resource not found",
                    500 => "Internal server error",
                    _ => "Unknown error",
                };
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: res.status_code.to_string(),
                    message: error_message.to_string(),
                    reason: None,
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

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize + Default>
    ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for Datatrans<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        println!("datatrans: Getting headers for authorization request");
        let mut headers = self.get_auth_header(&req.connector_auth_type)?;
        headers.push((headers::CONTENT_TYPE.to_string(), "application/json".to_string().into()));
        println!("datatrans: Headers prepared successfully");
        Ok(headers)
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.base_url(&req.resource_common_data.connectors);
        println!("datatrans: Base URL from config: '{}'", base_url);
        println!("datatrans: Base URL ends with slash: {}", base_url.ends_with('/'));
        
        // Fix double slash issue by trimming trailing slash from base_url
        let clean_base_url = base_url.trim_end_matches('/');
        let url = format!("{}/v1/transactions", clean_base_url);
        println!("datatrans: Using URL: {}", url);
        Ok(url)
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::RequestContent>, errors::ConnectorError> {
        println!("datatrans: Creating request body for authorization");
        // Use the proper transformation logic
        let datatrans_router_data = transformers::DatatransRouterData {
            amount: common_utils::types::MinorUnit(req.request.amount),
            router_data: req.clone(),
            payment_method_data: std::marker::PhantomData,
        };
        let datatrans_req = transformers::DatatransPaymentsRequest::try_from(datatrans_router_data)?;
        // datatrans_req is already created above
        let body = common_utils::RequestContent::Json(Box::new(datatrans_req));
        println!("datatrans: Request body created successfully");
        Ok(Some(body))
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::Request>, errors::ConnectorError> {
        println!("datatrans: Building authorization request");
        Ok(Some(
            RequestBuilder::new()
                .method(common_utils::Method::Post)
                .url(&self.get_url(req)?)
                .attach_default_headers()
                .headers(self.get_headers(req)?)
                .set_body(self.get_request_body(req)?.unwrap_or(common_utils::RequestContent::Json(Box::new(serde_json::json!({})))))
                .build(),
        ))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, errors::ConnectorError> {
        println!("datatrans: Handling authorization response with status: {}", res.status_code);
        println!("datatrans: Response body: {}", String::from_utf8_lossy(&res.response));
        
        let response: DatatransResponse = res
            .response
            .parse_struct("DatatransPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        println!("datatrans: Response parsed successfully: {:?}", response);
        event_builder.map(|i| i.set_response_body(&response));
        
        // Create the response with proper capture method handling
        let (status, transaction_id) = match response {
            DatatransResponse::TransactionResponse(ref resp) => {
                println!("datatrans: TransactionResponse received - mapping to Charged");
                (
                    common_enums::AttemptStatus::Charged,
                    Some(resp.transaction_id.clone()),
                )
            },
            DatatransResponse::ThreeDSResponse(ref resp) => {
                println!("datatrans: ThreeDSResponse received - checking capture method");
                println!("datatrans: Capture method from request: {:?}", data.request.capture_method);
                
                // Handle capture method properly for 3DS responses
                let status = match data.request.capture_method {
                    Some(common_enums::CaptureMethod::Manual) => {
                        println!("datatrans: Manual capture - mapping to Authorized status");
                        common_enums::AttemptStatus::Authorized
                    },
                    Some(common_enums::CaptureMethod::Automatic) 
                    | Some(common_enums::CaptureMethod::SequentialAutomatic) 
                    | None => {
                        println!("datatrans: Automatic capture - mapping to AuthenticationPending status");
                        common_enums::AttemptStatus::AuthenticationPending
                    },
                    Some(common_enums::CaptureMethod::ManualMultiple) => {
                        println!("datatrans: Manual multiple capture - mapping to Authorized status");
                        common_enums::AttemptStatus::Authorized
                    },
                    Some(common_enums::CaptureMethod::Scheduled) => {
                        println!("datatrans: Scheduled capture - mapping to Authorized status");
                        common_enums::AttemptStatus::Authorized
                    },
                };
                
                (status, Some(resp.transaction_id.clone()))
            },
            DatatransResponse::ErrorResponse(_) => {
                println!("datatrans: ErrorResponse received - mapping to Failure");
                (
                    common_enums::AttemptStatus::Failure,
                    None,
                )
            },
        };
        
        let mut response_data = data.clone();
        response_data.response = Ok(domain_types::connector_types::PaymentsResponseData::TransactionResponse {
            resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
                transaction_id.unwrap_or_default()
            ),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: res.status_code,
        });
        response_data.resource_common_data.status = status;
        
        Ok(response_data)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize + Default>
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Datatrans<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        println!("datatrans: Getting headers for sync request");
        let headers = self.get_auth_header(&req.connector_auth_type)?;
        println!("datatrans: Headers prepared successfully for sync");
        Ok(headers)
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.base_url(&req.resource_common_data.connectors);
        let connector_payment_id = req.request.connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
        
        // Fix double slash issue by trimming trailing slash from base_url
        let clean_base_url = base_url.trim_end_matches('/');
        let url = format!("{}/v1/transactions/{}", clean_base_url, connector_payment_id);
        println!("datatrans: Using sync URL: {}", url);
        Ok(url)
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::RequestContent>, errors::ConnectorError> {
        println!("datatrans: Sync request uses GET method, no body needed");
        Ok(None)
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::Request>, errors::ConnectorError> {
        println!("datatrans: Building sync request");
        Ok(Some(
            RequestBuilder::new()
                .method(common_utils::Method::Get)
                .url(&self.get_url(req)?)
                .attach_default_headers()
                .headers(self.get_headers(req)?)
                .build(),
        ))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> {
        println!("datatrans: Handling sync response with status: {}", res.status_code);
        println!("datatrans: Sync response body: {}", String::from_utf8_lossy(&res.response));
        
        let response: DatatransSyncResponse = res
            .response
            .parse_struct("DatatransSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        println!("datatrans: Sync response parsed successfully: {:?}", response);
        // Skip setting response body for sync to avoid serialization issues
        
        // Return error for now - will implement proper response handling later
        Err(errors::ConnectorError::ResponseHandlingFailed.into())
    }
}

// Add empty implementations for all other flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Datatrans<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Datatrans<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Datatrans<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Datatrans<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
    for Datatrans<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Datatrans<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Datatrans<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Datatrans<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Datatrans<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>
    for Datatrans<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>
    for Datatrans<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>
    for Datatrans<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>
    for Datatrans<T>
{
}

// Add SourceVerification implementations for all flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for Datatrans<T>
{
    fn get_secrets(
        &self,
        _secrets: ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }
    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }
    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }
    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned())
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Datatrans<T>
{
    fn get_secrets(
        &self,
        _secrets: ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }
    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }
    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }
    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned())
    }
}

// Add stub SourceVerification implementations for other flows
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
            SourceVerification<$flow, $common_data, $req, $resp> for Datatrans<T>
        {
            fn get_secrets(
                &self,
                _secrets: ConnectorSourceVerificationSecrets,
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new())
            }
            fn get_algorithm(
                &self,
            ) -> CustomResult<
                Box<dyn common_utils::crypto::VerifySignature + Send>,
                errors::ConnectorError,
            > {
                Ok(Box::new(common_utils::crypto::NoAlgorithm))
            }
            fn get_signature(
                &self,
                _payload: &[u8],
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new())
            }
            fn get_message(
                &self,
                payload: &[u8],
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(payload.to_owned())
            }
        }
    };
}

// Apply to remaining flows
impl_source_verification_stub!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
impl_source_verification_stub!(SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData);
impl_source_verification_stub!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_source_verification_stub!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_source_verification_stub!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);
impl_source_verification_stub!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_source_verification_stub!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_source_verification_stub!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_source_verification_stub!(CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData);
impl_source_verification_stub!(PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse);