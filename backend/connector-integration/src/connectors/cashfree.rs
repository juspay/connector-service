//! Cashfree UPI Payment Connector
//!
//! This module implements the connector integration for Cashfree, focusing on UPI payment methods
//! in the Indian market.
//!
//! # UPI Payment Methods
//!
//! ## UPI Intent
//! UPI Intent allows users to select a UPI app for payment by providing deep links.
//! The flow involves redirecting the user to their chosen UPI app to complete the payment.
//!
//! ## UPI QR
//! UPI QR generates a QR code that customers can scan with their UPI apps for payment.
//!
//! ## UPI Collect
//! UPI Collect allows merchants to collect payments directly from a customer's UPI ID (VPA).
//! The customer receives a payment request in their UPI app and approves it.
//!
//! # Implementation Details
//!
//! This connector implements:
//! - Payment authorization for UPI Intent, UPI QR, and UPI Collect
//! - HMAC-SHA256 signature-based security verification
//! - Error handling for Cashfree-specific error codes
//! - Mobile deep linking for UPI apps
//! - Both new and legacy API flows as per Cashfree implementation guide

use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, RSync,
        Refund, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDispute, AcceptDisputeData, ConnectorServiceTrait, DisputeDefend, DisputeDefendData,
        DisputeFlowData, DisputeResponseData, PaymentAuthorizeV2, PaymentCapture,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentOrderCreate,
        PaymentSessionToken, PaymentSyncV2, PaymentVoidData, PaymentVoidV2, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundSyncV2, RefundV2, RefundsData, RefundsResponseData,
        SessionTokenRequestData, SessionTokenResponseData, SetupMandateRequestData, SetupMandateV2,
        SubmitEvidenceData, SubmitEvidenceV2, ValidationTrait,
    },
};
use hyperswitch_domain_models::router_data_v2::RouterDataV2;
use hyperswitch_interfaces::{
    api::{ConnectorCommon, CurrencyUnit},
    configs::Connectors,
    connector_integration_v2::ConnectorIntegrationV2,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::Response,
};

use common_enums::AttemptStatus;
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    request::RequestContent,
    types::{AmountConvertor, MinorUnit, MinorUnitForConnector},
};
use error_stack::ResultExt;
use hyperswitch_domain_models::router_data::ErrorResponse;
use masking::Maskable;

pub mod test;
pub mod transformers;

#[derive(Clone)]
pub struct Cashfree {
    #[allow(dead_code)]
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
}

impl ValidationTrait for Cashfree {
    fn should_do_session_token(&self) -> bool {
        true // Enable session token for both APIs
    }
}

impl ConnectorServiceTrait for Cashfree {}
impl PaymentAuthorizeV2 for Cashfree {}
impl PaymentSyncV2 for Cashfree {}
impl PaymentOrderCreate for Cashfree {}
impl PaymentSessionToken for Cashfree {}
impl PaymentVoidV2 for Cashfree {}
impl PaymentCapture for Cashfree {}
impl RefundV2 for Cashfree {}
impl RefundSyncV2 for Cashfree {}
impl SetupMandateV2 for Cashfree {}
impl AcceptDispute for Cashfree {}
impl SubmitEvidenceV2 for Cashfree {}
impl DisputeDefend for Cashfree {}

// Trait aliases implementation
impl domain_types::connector_types::IncomingWebhook for Cashfree {}

impl Cashfree {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &MinorUnitForConnector,
        }
    }
}

impl ConnectorCommon for Cashfree {
    fn id(&self) -> &'static str {
        "cashfree"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        // For now, use a placeholder since Cashfree may not be in hyperswitch_domain_models::configs::Connectors
        // URLs are handled directly in get_url methods
        "https://api.cashfree.com/"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn build_error_response(
        &self,
        res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: Result<transformers::CashfreePaymentResponse, _> =
            res.response.parse_struct("CashfreePaymentResponse");

        match response {
            Ok(cashfree_response) => Ok(ErrorResponse {
                status_code: res.status_code,
                code: cashfree_response.status,
                message: cashfree_response.message,
                reason: cashfree_response.tx_msg,
                attempt_status: Some(AttemptStatus::Failure),
                connector_transaction_id: cashfree_response.reference_id,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            }),
            Err(_) => Ok(ErrorResponse {
                status_code: res.status_code,
                code: "UNKNOWN_ERROR".to_string(),
                message: "Unknown error occurred".to_string(),
                reason: None,
                attempt_status: Some(AttemptStatus::Failure),
                connector_transaction_id: None,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            }),
        }
    }
}

// Stub implementations for unsupported flows
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Cashfree {}
impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Cashfree
{
}
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Cashfree
{
}
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Cashfree
{
}
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Cashfree
{
}
impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Cashfree
{
}
impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Cashfree
{
}
impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Cashfree
{
}
impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Cashfree
{
}
impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Cashfree
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let headers = vec![
            (
                "Content-Type".to_string(),
                "application/json".to_string().into(),
            ),
            ("Accept".to_string(), "application/json".to_string().into()),
            ("x-api-version".to_string(), "2023-08-01".to_string().into()),
        ];
        Ok(headers)
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        // Check connector_api_version to determine which CreateOrder API to use
        match req.resource_common_data.connector_api_version.as_ref().map(|v| v.as_str()) {
            Some("v2") => {
                // V2 flow uses createOrderV1 API endpoint
                Ok("https://api.cashfree.com/pg/orders".to_string())
            }
            Some("v3") => {
                // V3 flow uses createOrderV3 API endpoint  
                Ok("https://api.cashfree.com/pg/orders/v3".to_string())
            }
            Some("v1") | Some("legacy") | None => {
                // V1/Legacy doesn't use CreateOrder - this shouldn't be called
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "CreateOrder not used for v1/legacy flow",
                })?
            }
            Some(_unknown_version) => {
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "Unsupported version for CreateOrder",
                })?
            }
        }
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        // Check version to determine request structure
        match req.resource_common_data.connector_api_version.as_ref().map(|v| v.as_str()) {
            Some("v2") => {
                // V2 flow uses createOrderV1 request structure
                let connector_req = transformers::CashfreeOrderRequest::try_from(req)?;
                Ok(Some(RequestContent::Json(Box::new(connector_req))))
            }
            Some("v3") => {
                // V3 flow uses createOrderV3 request structure (may be different)
                let connector_req = transformers::CashfreeOrderRequest::try_from(req)?;
                Ok(Some(RequestContent::Json(Box::new(connector_req))))
            }
            Some("v1") | Some("legacy") | None => {
                // V1/Legacy doesn't use CreateOrder
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "CreateOrder not used for v1/legacy flow",
                })?
            }
            Some(_unknown_version) => {
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "Unsupported version for CreateOrder request",
                })?
            }
        }
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
        errors::ConnectorError,
    > {
        let response: transformers::CashfreeOrderResponse = res
            .response
            .parse_struct("Cashfree Order Creation Response")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(event_builder) = event_builder {
            event_builder.set_response_body(&response);
        }

        // Use the version from request to determine which field to extract
        let order_id = match data.resource_common_data.connector_api_version.as_ref().map(|v| v.as_str()) {
            Some("v3") => {
                // V3 flow uses payment_session_id from createOrderV3 
                response.payment_session_id.clone()
            }
            Some("v2") => {
                // V2 flow uses order_token from createOrderV1
                response.order_token.clone()
            }
            _ => {
                // Default to v2 behavior for backward compatibility
                response.order_token.clone()
            }
        };
        
        // Update resource_common_data to include session_token (order_id)
        let mut updated_resource_data = data.resource_common_data.clone();
        updated_resource_data.session_token = Some(order_id.clone());
        
        Ok(RouterDataV2 {
            flow: data.flow,
            tenant_id: data.tenant_id.clone(),
            resource_common_data: updated_resource_data,
            connector_auth_type: data.connector_auth_type.clone(),
            request: data.request.clone(),
            response: Ok(PaymentCreateOrderResponse {
                order_id,
            }),
        })
    }
}
impl
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Cashfree
{
    fn get_headers(
        &self,
        req: &RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // CreateSessionToken is only for Legacy API
        match req.resource_common_data.connector_api_version.as_ref().map(|v| v.as_str()) {
            Some("legacy") | Some("v1") | None => {
                // Legacy API - local session token creation, no actual API call
                let headers = vec![
                    ("Content-Type".to_string(), "application/json".to_string().into()),
                ];
                Ok(headers)
            }
            Some("v2") | Some("v3") => {
                // V2/V3 API should use CreateOrder, not CreateSessionToken
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "V2/V3 API should use CreateOrder flow, not CreateSessionToken",
                })?
            }
            Some(_) => {
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "Unsupported version for session token",
                })?
            }
        }
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        match req.resource_common_data.connector_api_version.as_ref().map(|v| v.as_str()) {
            Some("legacy") | Some("v1") | None => {
                // Legacy API - no actual URL needed, we handle locally
                // Return a placeholder since we don't make an actual call
                Ok("https://api.cashfree.com/legacy/session".to_string())
            }
            Some("v2") | Some("v3") => {
                // V2/V3 API should use CreateOrder, not CreateSessionToken
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "V2/V3 API should use CreateOrder flow, not CreateSessionToken",
                })?
            }
            Some(_) => {
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "Unsupported version for session token",
                })?
            }
        }
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        match req.resource_common_data.connector_api_version.as_ref().map(|v| v.as_str()) {
            Some("v1") | Some("legacy") | None => {
                // V1/Legacy API - prepare the payment request locally with signature
                let legacy_req = transformers::CashfreeLegacySessionRequest::try_from(req)?;
                // We don't actually send this, but we prepare it for the session token
                Ok(Some(RequestContent::Json(Box::new(legacy_req))))
            }
            Some("v2") | Some("v3") => {
                // V2/V3 API should use CreateOrder, not CreateSessionToken
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "V2/V3 API should use CreateOrder flow, not CreateSessionToken",
                })?
            }
            Some(_) => {
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "Unsupported version for session token",
                })?
            }
        }
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        _res: Response, // Unused in legacy flow since we handle locally
    ) -> CustomResult<
        RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        errors::ConnectorError,
    > {
        match data.resource_common_data.connector_api_version.as_ref().map(|v| v.as_str()) {
            Some("v1") | Some("legacy") | None => {
                // V1/Legacy API - we handle session token creation locally
                // Generate a session token from the prepared request
                let legacy_req = transformers::CashfreeLegacySessionRequest::try_from(data)?;
                
                // Serialize the prepared request as the session token
                let session_token = serde_json::to_string(&legacy_req)
                    .change_context(errors::ConnectorError::RequestEncodingFailed)?;

                // Encode as base64 to make it more token-like
                use base64::{engine::general_purpose, Engine as _};
                let encoded_token = general_purpose::STANDARD.encode(session_token.as_bytes());

                if let Some(event_builder) = event_builder {
                    event_builder.set_response_body(&serde_json::json!({
                        "status": "success",
                        "session_token": encoded_token,
                        "message": "V1/Legacy session token created locally with signature"
                    }));
                }

                Ok(RouterDataV2 {
                    flow: data.flow,
                    tenant_id: data.tenant_id.clone(),
                    resource_common_data: data.resource_common_data.clone(),
                    connector_auth_type: data.connector_auth_type.clone(),
                    request: data.request.clone(),
                    response: Ok(SessionTokenResponseData {
                        session_token: encoded_token,
                    }),
                })
            }
            Some("v2") | Some("v3") => {
                // V2/V3 API should use CreateOrder, not CreateSessionToken
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "V2/V3 API should use CreateOrder flow, not CreateSessionToken",
                })?
            }
            Some(_) => {
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "Unsupported version for session token",
                })?
            }
        }
    }
}

// Main Authorize flow implementation
impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Cashfree
{
    fn get_headers(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Check connector_api_version field to determine content type
        let content_type = match req.resource_common_data.connector_api_version.as_ref().map(|v| v.as_str()) {
            Some("v2") | Some("v3") => "application/json",
            Some("v1") | Some("legacy") | None => "application/x-www-form-urlencoded",
            Some(_) => "application/x-www-form-urlencoded", // Default fallback
        };

        let mut headers = vec![
            ("Content-Type".to_string(), content_type.to_string().into()),
            ("Cache-Control".to_string(), "no-cache".to_string().into()),
        ];

        // Add API version header for V2/V3 API
        if matches!(req.resource_common_data.connector_api_version.as_ref().map(|v| v.as_str()), Some("v2") | Some("v3")) {
            headers.push(("x-api-version".to_string(), "2023-08-01".to_string().into()));
            headers.push(("Accept".to_string(), "application/json".to_string().into()));
        }

        Ok(headers)
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        // Check connector_api_version to determine API endpoint and flow
        match req.resource_common_data.connector_api_version.as_ref().map(|v| v.as_str()) {
            Some("v2") => {
                // V2 API flow (createOrderV1 -> authorize V2)
                // Uses order_token from CreateOrder
                if let Some(order_id) = &req.resource_common_data.session_token {
                    Ok(format!("https://api.cashfree.com/pg/orders/{}/pay", order_id))
                } else {
                    Err(errors::ConnectorError::MissingRequiredField {
                        field_name: "order_token from CreateOrderV1",
                    })?
                }
            }
            Some("v3") => {
                // V3 API flow (createOrderV3 -> authorize V3)  
                // Uses payment_session_id from CreateOrder
                if let Some(session_id) = &req.resource_common_data.session_token {
                    Ok(format!("https://api.cashfree.com/pg/orders/{}/pay", session_id))
                } else {
                    Err(errors::ConnectorError::MissingRequiredField {
                        field_name: "payment_session_id from CreateOrderV3",
                    })?
                }
            }
            Some("v1") | Some("legacy") | None => {
                // V1/Legacy API endpoint for direct UPI transactions
                Ok("https://api.cashfree.com/order/pay".to_string())
            }
            Some(_unknown_version) => {
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "Unsupported version for URL determination",
                })?
            }
        }
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        // Check connector_api_version to determine request format
        match req.resource_common_data.connector_api_version.as_ref().map(|v| v.as_str()) {
            Some("v2") => {
                // V2 API flow (createOrderV1 -> authorize V2) uses JSON format
                let connector_req = transformers::CashfreeNewApiPaymentRequest::try_from(req)?;
                Ok(Some(RequestContent::Json(Box::new(connector_req))))
            }
            Some("v3") => {
                // V3 API flow (createOrderV3 -> authorize V3) uses JSON format
                // May have different request structure than V2
                let connector_req = transformers::CashfreeNewApiPaymentRequest::try_from(req)?;
                Ok(Some(RequestContent::Json(Box::new(connector_req))))
            }
            Some("v1") | Some("legacy") | None => {
                // V1/Legacy API uses form URL encoded format with session token containing prepared request
                // Decode the session token to get the prepared request with signature
                if let Some(session_token) = &req.request.session_token {
                    use base64::{engine::general_purpose, Engine as _};
                    let decoded = general_purpose::STANDARD.decode(session_token.as_bytes())
                        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
                    let decoded_str = String::from_utf8(decoded)
                        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
                    let prepared_req: transformers::CashfreeLegacySessionRequest = serde_json::from_str(&decoded_str)
                        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
                    
                    // Convert to final payment request format
                    let payment_req = transformers::CashfreePaymentRequest {
                        app_id: prepared_req.app_id,
                        order_id: prepared_req.order_id,
                        order_amount: prepared_req.order_amount,
                        order_currency: prepared_req.order_currency,
                        order_note: prepared_req.order_note,
                        customer_name: prepared_req.customer_name,
                        customer_phone: prepared_req.customer_phone,
                        customer_email: prepared_req.customer_email,
                        return_url: prepared_req.return_url,
                        notify_url: prepared_req.notify_url,
                        signature: prepared_req.signature,
                        payment_option: prepared_req.payment_option,
                        upi_mode: prepared_req.upi_mode,
                        upi_vpa: prepared_req.upi_vpa,
                        secret_key: prepared_req.secret_key,
                        response_type: prepared_req.response_type,
                    };
                    
                    Ok(Some(RequestContent::FormUrlEncoded(Box::new(payment_req))))
                } else {
                    Err(errors::ConnectorError::MissingRequiredField {
                        field_name: "session_token from CreateSessionToken",
                    })?
                }
            }
            Some(_unknown_version) => {
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "Unsupported version for request body determination",
                })?
            }
        }
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
        // Check connector_api_version field to determine response parsing
        match data.resource_common_data.connector_api_version.as_ref().map(|v| v.as_str()) {
            Some("v2") | Some("v3") => {
                // Parse new API response
                let response: transformers::CashfreeNewApiPaymentResponse = res
                    .response
                    .parse_struct("Cashfree New API Payment Response")
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

                if let Some(event_builder) = event_builder {
                    event_builder.set_response_body(&response);
                }

                let redirection_data = response.data.as_ref().and_then(|data| data.url.as_ref()).map(|url| {
                    use std::collections::HashMap;
                    let mut form_fields = HashMap::new();
                    form_fields.insert("upi_intent_url".to_string(), url.clone());

                    hyperswitch_domain_models::router_response_types::RedirectForm::Form {
                        endpoint: url.clone(),
                        method: common_utils::request::Method::Get,
                        form_fields,
                    }
                });

                Ok(RouterDataV2 {
                    flow: data.flow,
                    tenant_id: data.tenant_id.clone(),
                    resource_common_data: data.resource_common_data.clone(),
                    connector_auth_type: data.connector_auth_type.clone(),
                    request: data.request.clone(),
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
                            response.cf_payment_id.clone().unwrap_or_default(),
                        ),
                        redirection_data: Box::new(redirection_data),
                        mandate_reference: Box::new(None),
                        connector_metadata: Some(serde_json::json!({
                            "new_api_response": response
                        })),
                        network_txn_id: response.bank_reference.clone(),
                        connector_response_reference_id: response.auth_id.clone(),
                        incremental_authorization_allowed: Some(false),
                        raw_connector_response: None,
                        transaction_token: None,
                        transaction_amount: response.payment_amount.map(|amt| amt.to_string()),
                        merchant_name: None,
                        merchant_vpa: None,
                    }),
                })
            }
            Some("v1") | Some("legacy") | None => {
                // Parse V1/legacy API response
                let response: transformers::CashfreePaymentResponse = res
                    .response
                    .parse_struct("Cashfree Legacy Payment Response")
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

                if let Some(event_builder) = event_builder {
                    event_builder.set_response_body(&response);
                }

                let redirection_data = response.link.as_ref().map(|link| {
                    use std::collections::HashMap;
                    let mut form_fields = HashMap::new();
                    form_fields.insert("upi_intent_url".to_string(), link.clone());

                    hyperswitch_domain_models::router_response_types::RedirectForm::Form {
                        endpoint: link.clone(),
                        method: common_utils::request::Method::Get,
                        form_fields,
                    }
                });

                Ok(RouterDataV2 {
                    flow: data.flow,
                    tenant_id: data.tenant_id.clone(),
                    resource_common_data: data.resource_common_data.clone(),
                    connector_auth_type: data.connector_auth_type.clone(),
                    request: data.request.clone(),
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
                            response.reference_id.clone().unwrap_or_default(),
                        ),
                        redirection_data: Box::new(redirection_data),
                        mandate_reference: Box::new(None),
                        connector_metadata: Some(serde_json::json!({
                            "legacy_response": response
                        })),
                        network_txn_id: response.reference_id.clone(),
                        connector_response_reference_id: response.reference_id.clone(),
                        incremental_authorization_allowed: Some(false),
                        raw_connector_response: None,
                        transaction_token: None,
                        transaction_amount: response.order_amount.clone(),
                        merchant_name: None,
                        merchant_vpa: None,
                    }),
                })
            }
            Some(_unknown_version) => {
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "Unsupported version for URL determination",
                })?
            }
        }
    }
}
