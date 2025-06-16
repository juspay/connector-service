//! PayU UPI Payment Connector
//!
//! This module implements the connector integration for PayU, focusing on UPI payment methods
//! in the Indian market.
//!
//! # UPI Payment Methods
//!
//! ## UPI Intent
//! UPI Intent allows users to select a UPI app (Google Pay, PhonePe, etc.) for payment.
//! The flow involves redirecting the user to their chosen UPI app to complete the payment.
//!
//! ## UPI Collect
//! UPI Collect allows merchants to collect payments directly from a customer's UPI ID (VPA).
//! The customer receives a payment request in their UPI app and approves it.
//!
//! # Implementation Details
//!
//! This connector implements:
//! - Payment authorization for UPI Intent and UPI Collect
//! - Hash-based security verification
//! - Error handling for UPI-specific error codes
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
use common_utils::{errors::CustomResult, ext_traits::BytesExt};
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
use masking::{ExposeInterface, Maskable, Secret};
use sha2::{Digest, Sha512};

mod transformers;
use super::macros;

use self::transformers::{
    PayuAuthType, PayuErrorResponse, PayuPaymentRequest, PayuPaymentResponse,
};
use crate::types::ResponseRouterData;

// Set up the connector with macros
macros::create_all_prerequisites!(
    connector_name: Payu,
    api: [
        (
            flow: Authorize,
            request_body: PayuPaymentRequest,
            response_body: PayuPaymentResponse,
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
                        hyperswitch_domain_models::payment_method_data::UpiData::UpiQr(_) => false,
                    }
                },
                _ => false,
            }
        }

        // Hash generation function for PayU
        pub fn generate_payu_hash(
            &self,
            auth: &PayuAuthType,
            txn_id: &str,
            amount: &str,
            product_info: &str,
            first_name: &str,
            email: &str,
        ) -> CustomResult<Secret<String>, errors::ConnectorError> {
            // PayU hash format:
            // sha512(key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5||||||salt)
            // Note the 6 empty fields between udf5 and salt (represented by 6 consecutive pipes)

            let hash_string = format!(
                "{}|{}|{}|{}|{}|{}|||||||||||{}",
                auth.key.clone().expose(),
                txn_id,
                amount,
                product_info,
                first_name,
                email,
                auth.salt.clone().expose()
            );

            // Generate SHA512 hash
            let mut hasher = Sha512::new();
            hasher.update(hash_string.as_bytes());
            let hash_result = hasher.finalize();

            // Convert to hex string
            let hash = hex::encode(hash_result);

            Ok(Secret::new(hash))
        }
    }
);

// Implement the ConnectorIntegrationV2 trait for Authorize flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Payu,
    curl_request: FormData(PayuPaymentRequest),
    curl_response: PayuPaymentResponse,
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

            // Check if this is UPI Collect flow which returns base64 response
            let is_base64_response = matches!(
                &req.request.payment_method_data,
                hyperswitch_domain_models::payment_method_data::PaymentMethodData::Upi(
                    hyperswitch_domain_models::payment_method_data::UpiData::UpiCollect(_)
                )
            );

            // Check if this is UPI QR flow
            let is_upi_qr = matches!(
                &req.request.payment_method_data,
                hyperswitch_domain_models::payment_method_data::PaymentMethodData::Upi(
                    hyperswitch_domain_models::payment_method_data::UpiData::UpiQr(_)
                )
            );

            // Basic headers for PayU requests
            let mut headers = vec![
                ("Content-Type".to_string(), ("application/x-www-form-urlencoded".to_string().into())),
                ("Accept".to_string(), ("application/json".to_string().into())),
            ];

            // Add UPI Collect specific headers (base64 response)
            if is_base64_response {
                headers.push(("X-PayU-Flow".to_string(), ("upi_collect".to_string().into())));
                headers.push(("Accept".to_string(), ("text/plain".to_string().into()))); // Expect base64 response
            }

            // Add UPI QR specific headers (JSON response)
            if is_upi_qr {
                headers.push(("X-PayU-Flow".to_string(), ("upi_qr".to_string().into())));
                // UPI QR returns JSON response like UPI Intent, so keep default Accept header
            }

            // Add mobile-specific headers if this is a UPI request from a mobile device
            if let Some(is_mobile) = req.request.metadata.as_ref()
                .and_then(|meta| meta.get("is_mobile_device").map(|v| v == "true"))
            {
                if is_mobile {
                    headers.push(("User-Agent".to_string(), "Mozilla/5.0 (Linux; Android 10)".to_string().into()));
                    headers.push(("X-Mobile-Request".to_string(), ("true".to_string().into())));
                }
            }

            Ok(headers)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            // Get base URL from the connectors configuration
            let base_url = &req.resource_common_data.connectors.payu.base_url;

            // Check payment method to determine the endpoint
            let payment_path = match &req.request.payment_method_data {
                hyperswitch_domain_models::payment_method_data::PaymentMethodData::Upi(upi_data) => {
                    match upi_data {
                        hyperswitch_domain_models::payment_method_data::UpiData::UpiCollect(_) => {
                            "/_payment" // UPI Collect endpoint (returns base64)
                        },
                        hyperswitch_domain_models::payment_method_data::UpiData::UpiIntent(_) => {
                            "/_payment" // UPI Intent endpoint (returns JSON)
                        },
                        hyperswitch_domain_models::payment_method_data::UpiData::UpiQr(_) => {
                            "/_payment" // UPI QR endpoint (returns JSON)
                        }
                    }
                },
                _ => "/_payment" // Default endpoint
            };

            let url = format!("{}{}", base_url, payment_path);

            tracing::info!("PayU URL for payment method: {}", url);
            Ok(url)
        }

        fn preprocess_response(
            &self,
            data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
            res: Response,
        ) -> CustomResult<Response, errors::ConnectorError> {
            // Check if this is UPI Collect flow which returns base64 response
            let is_base64_response = matches!(
                &data.request.payment_method_data,
                hyperswitch_domain_models::payment_method_data::PaymentMethodData::Upi(
                    hyperswitch_domain_models::payment_method_data::UpiData::UpiCollect(_)
                )
            );

            if is_base64_response {
                // For UPI Collect, PayU returns base64 encoded JSON
                // We need to decode it before parsing
                let response_str = String::from_utf8(res.response.to_vec())
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

                tracing::info!("PayU UPI Collect raw response: {}", response_str);

                // Try to decode from base64
                match base64::engine::general_purpose::STANDARD.decode(response_str.trim()) {
                    Ok(decoded_bytes) => {
                        tracing::info!("Successfully decoded base64 response for UPI Collect");
                        Ok(Response {
                            headers: res.headers,
                            response: bytes::Bytes::from(decoded_bytes),
                            status_code: res.status_code,
                        })
                    },
                    Err(_) => {
                        // If base64 decoding fails, assume it's already JSON and return as-is
                        tracing::info!("Base64 decoding failed, treating as regular JSON response");
                        Ok(res)
                    }
                }
            } else {
                // For UPI Intent and other flows, return response as-is
                Ok(res)
            }
        }

    }
);

impl ConnectorCommon for Payu {
    fn id(&self) -> &'static str {
        "payu"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // PayU primarily uses form-based authentication, not headers
        Ok(vec![])
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.payu.base_url
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: PayuErrorResponse = res
            .response
            .parse_struct("PayuErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Log the error with event builder if available
        if let Some(_event_builder) = event_builder {
            // TODO: Add event logging when the correct methods are available
            // event_builder.add_data("payu_error_code", response.error_code.as_ref());
            // event_builder.add_data("payu_error_message", &response.error_message);
        }

        // Map PayU error codes to appropriate attempt status
        let attempt_status = match response.error.as_str() {
            "E108" | "EX108" => AttemptStatus::Failure, // Duplicate transaction
            "E400" => AttemptStatus::Failure,           // Invalid parameters
            "E401" => AttemptStatus::AuthenticationFailed, // Authentication failed
            "E402" => AttemptStatus::Failure,           // Invalid hash
            "E403" => AttemptStatus::Failure,           // Insufficient funds
            "E404" => AttemptStatus::Failure,           // Invalid VPA
            "E408" => AttemptStatus::Pending,           // Timeout
            _ => AttemptStatus::Failure,
        };

        Ok(ErrorResponse {
            code: response.error.clone(),
            message: response.message.clone(),
            reason: Some(response.message.clone()),
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
impl ConnectorServiceTrait for Payu {}
impl PaymentAuthorizeV2 for Payu {}

// PayU doesn't support these features yet, but we need to implement them for the trait

// Stub implementations for unsupported flows - these will return NotImplemented errors
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Payu {}

impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Payu {}

impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Payu
{
}

impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Payu
{
}

impl
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Payu
{
}

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Payu {}

impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Payu
{
}

impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Payu
{
}

impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Payu
{
}

impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Payu
{
}

impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Payu
{
}

// Now implement the trait aliases
impl domain_types::connector_types::RefundV2 for Payu {}
impl domain_types::connector_types::RefundSyncV2 for Payu {}
impl domain_types::connector_types::PaymentSyncV2 for Payu {}
impl domain_types::connector_types::PaymentOrderCreate for Payu {}
impl domain_types::connector_types::PaymentSessionToken for Payu {}
impl domain_types::connector_types::PaymentVoidV2 for Payu {}
impl domain_types::connector_types::IncomingWebhook for Payu {}
impl domain_types::connector_types::PaymentCapture for Payu {}
impl domain_types::connector_types::SetupMandateV2 for Payu {}
impl domain_types::connector_types::AcceptDispute for Payu {}
impl domain_types::connector_types::SubmitEvidenceV2 for Payu {}
impl domain_types::connector_types::DisputeDefend for Payu {}
impl domain_types::connector_types::ValidationTrait for Payu {}
