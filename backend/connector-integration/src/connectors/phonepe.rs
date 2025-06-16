//! PhonePe UPI Payment Connector
//!
//! This module implements the connector integration for PhonePe, focusing on UPI payment methods
//! in the Indian market using PhonePe V2 API.
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
//! - Base64 JSON payload encoding
//! - SHA256 checksum-based security verification
//! - Error handling for PhonePe-specific error codes
//! - Mobile deep linking for UPI apps

use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, RSync,
        Refund, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, ConnectorServiceTrait, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentAuthorizeV2, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData, SessionTokenRequestData,
        SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
    },
};
use hyperswitch_interfaces::connector_integration_v2::ConnectorIntegrationV2;

use common_enums::AttemptStatus;
use common_utils::{errors::CustomResult, ext_traits::BytesExt, request::RequestContent};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use hyperswitch_interfaces::{
    api::{ConnectorCommon, CurrencyUnit},
    configs::Connectors,
    errors::{self, ConnectorError},
    events::connector_api_logs::ConnectorEvent,
    types::Response,
};

use base64::Engine;
use hex;
use masking::{ExposeInterface, Maskable};
use sha2::{Digest, Sha256};

mod transformers;
use super::macros;

use self::transformers::{
    PhonePeAuthType, PhonePeErrorResponse, PhonePePaymentRequest, PhonePePaymentResponse,
};
use crate::types::ResponseRouterData;

// Set up the connector with macros
macros::create_all_prerequisites!(
    connector_name: PhonePe,
    api: [
        (
            flow: Authorize,
            request_body: PhonePePaymentRequest,
            response_body: PhonePePaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
        )
    ],
    amount_converters: [],
    member_functions: {
        // Helper function to get product info from metadata or use default
        pub fn get_product_info(&self, router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>) -> String {
            router_data.request.metadata
                .as_ref()
                .and_then(|meta| meta.get("product_info").map(|v| v.to_string()))
                .unwrap_or_else(|| "Payment".to_string())
        }

        // Helper function to determine if a UPI payment needs redirection
        pub fn requires_redirection(&self, payment_method_data: &hyperswitch_domain_models::payment_method_data::PaymentMethodData) -> bool {
            match payment_method_data {
                hyperswitch_domain_models::payment_method_data::PaymentMethodData::Upi(upi_data) => {
                    match upi_data {
                        hyperswitch_domain_models::payment_method_data::UpiData::UpiIntent(_) => true,  // UPI Intent requires app redirection
                        hyperswitch_domain_models::payment_method_data::UpiData::UpiCollect(_) => false, // UPI Collect is direct debit
                        hyperswitch_domain_models::payment_method_data::UpiData::UpiQr(_) => false,     // UPI QR returns QR data
                    }
                },
                _ => false,
            }
        }

        // Generate PhonePe V2 API checksum
        pub fn generate_phonepe_checksum(
            &self,
            auth: &PhonePeAuthType,
            base64_payload: &str,
            api_path: &str,
        ) -> CustomResult<String, errors::ConnectorError> {
            // PhonePe checksum format:
            // sha256(base64EncodedPayload + apiPath + saltKey) + "###" + keyIndex

            let checksum_string = format!(
                "{}{}{}",
                base64_payload,
                api_path,
                auth.salt_key.clone().expose()
            );

            tracing::info!(
                "PhonePe checksum string: {}{}{}",
                base64_payload,
                api_path,
                auth.salt_key.clone().expose()
            );

            // Generate SHA256 hash
            let mut hasher = Sha256::new();
            hasher.update(checksum_string.as_bytes());
            let hash_result = hasher.finalize();


            // Convert to hex string and add key index
            let hash = hex::encode(hash_result);

            tracing::info!("PhonePe checksum hash: {}", hash);

            let checksum = format!("{}###{}", hash, auth.salt_index.clone().expose());
            tracing::info!("PhonePe checksum: {}", checksum);
            Ok(checksum)
        }

        // Generate webhook URL for PhonePe callbacks
        pub fn get_webhook_url(&self, router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>) -> CustomResult<String, errors::ConnectorError> {
            router_data.request.webhook_url.clone().ok_or(
                errors::ConnectorError::MissingRequiredField {
                    field_name: "webhook_url",
                }.into()
            )
        }

        // Get device OS from request headers/metadata
        pub fn get_device_os(&self, router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>) -> Option<String> {
            router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|info| info.user_agent.as_ref())
                .and_then(|ua| {
                    let ua_lower = ua.to_lowercase();
                    if ua_lower.contains("android") {
                        Some("ANDROID".to_string())
                    } else if ua_lower.contains("iphone") || ua_lower.contains("ipad") || ua_lower.contains("ios") {
                        Some("IOS".to_string())
                    } else {
                        Some("WEB".to_string())
                    }
                })
        }
    }
);

// Implement the ConnectorIntegrationV2 trait for Authorize flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: PhonePe,
    curl_request: Json(PhonePePaymentRequest),
    curl_response: PhonePePaymentResponse,
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
            let auth = PhonePeAuthType::try_from(&req.connector_auth_type)?;

            // Generate the base64 payload to create checksum
            let phonepe_req = PhonePePaymentRequest::try_from(req.clone())?;


            let base64_payload = phonepe_req.request;

            // Generate checksum
            let api_path = "/pg/v1/pay";
            let checksum = self.generate_phonepe_checksum(&auth, &base64_payload, api_path)?;

            let headers = vec![
                ("Content-Type".to_string(), ("application/json".to_string().into())),
                ("X-VERIFY".to_string(), (checksum.into())),
                ("Accept".to_string(), ("application/json".to_string().into())),
            ];

            tracing::info!(
                "PhonePe headers: {:?}",
                headers.iter().map(|(k, v): &(String, Maskable<String>)| (k, v)).collect::<Vec<_>>()
            );

            Ok(headers)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = &req.resource_common_data.connectors.phonepe.base_url;
            let url = format!("{}/pg/v1/pay", base_url);
            Ok(url)
        }
    }
);

impl ConnectorCommon for PhonePe {
    fn id(&self) -> &'static str {
        "phonepe"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // PhonePe uses X-VERIFY header for authentication, not Authorization header
        Ok(vec![])
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.phonepe.base_url
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: PhonePeErrorResponse = res
            .response
            .parse_struct("PhonePeErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(_event_builder) = event_builder {
            // TODO: Add event logging when the correct methods are available
        }

        // Map PhonePe error codes to appropriate attempt status
        let attempt_status = match response.code.as_str() {
            "PAYMENT_ERROR" => AttemptStatus::Failure,
            "AUTHENTICATION_FAILED" => AttemptStatus::AuthenticationFailed,
            "INVALID_REQUEST" => AttemptStatus::Failure,
            "PAYMENT_DECLINED" => AttemptStatus::Failure,
            "INSUFFICIENT_FUNDS" => AttemptStatus::Failure,
            "TRANSACTION_NOT_FOUND" => AttemptStatus::Failure,
            "PAYMENT_PENDING" => AttemptStatus::Pending,
            _ => AttemptStatus::Failure,
        };

        Ok(ErrorResponse {
            code: response.code.clone(),
            message: response
                .message
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string()),
            reason: response.message.clone(),
            status_code: res.status_code,
            attempt_status: Some(attempt_status),
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// Implement required trait markers and stubs for unsupported features
impl ConnectorServiceTrait for PhonePe {}
impl PaymentAuthorizeV2 for PhonePe {}

// PhonePe doesn't support these features yet, but we need to implement them for the trait

// Stub implementations for unsupported flows - these will return NotImplemented errors
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for PhonePe {}

impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for PhonePe
{
}

impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for PhonePe
{
}

impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for PhonePe
{
}

impl
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for PhonePe
{
}

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for PhonePe
{
}

impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for PhonePe
{
}

impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for PhonePe
{
}

impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for PhonePe
{
}

impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for PhonePe
{
}

impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for PhonePe
{
}

// Now implement the trait aliases
impl domain_types::connector_types::RefundV2 for PhonePe {}
impl domain_types::connector_types::RefundSyncV2 for PhonePe {}
impl domain_types::connector_types::PaymentSyncV2 for PhonePe {}
impl domain_types::connector_types::PaymentOrderCreate for PhonePe {}
impl domain_types::connector_types::PaymentSessionToken for PhonePe {}
impl domain_types::connector_types::PaymentVoidV2 for PhonePe {}
impl domain_types::connector_types::IncomingWebhook for PhonePe {}
impl domain_types::connector_types::PaymentCapture for PhonePe {}
impl domain_types::connector_types::SetupMandateV2 for PhonePe {}
impl domain_types::connector_types::AcceptDispute for PhonePe {}
impl domain_types::connector_types::SubmitEvidenceV2 for PhonePe {}
impl domain_types::connector_types::DisputeDefend for PhonePe {}
impl domain_types::connector_types::ValidationTrait for PhonePe {}
