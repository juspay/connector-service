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
    connector_flow::{Authorize, Accept, Capture, DefendDispute, PSync, RSync, Refund, SetupMandate, SubmitEvidence, Void, CreateOrder}, 
    connector_types::{
        ConnectorServiceTrait, PaymentAuthorizeV2, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
        DisputeFlowData, AcceptDisputeData, DisputeResponseData, SubmitEvidenceData, DisputeDefendData,
        RefundFlowData, RefundsData, RefundsResponseData, RefundSyncData, PaymentVoidData, PaymentsSyncData,
        PaymentsCaptureData, SetupMandateRequestData, PaymentCreateOrderData, PaymentCreateOrderResponse
    },
};
use hyperswitch_interfaces::connector_integration_v2::ConnectorIntegrationV2;

use common_enums::AttemptStatus;
use common_utils::{errors::CustomResult, ext_traits::BytesExt};
use hyperswitch_domain_models::{router_data::{ ConnectorAuthType, ErrorResponse}, router_data_v2::RouterDataV2};
use hyperswitch_interfaces::{
    api::{ConnectorCommon, CurrencyUnit}, configs::Connectors, errors::{self, ConnectorError}, events::connector_api_logs::ConnectorEvent, types::Response
};
use error_stack::ResultExt;

use hex;
use masking::{Maskable, Secret, ExposeInterface};
use sha2::{Sha512, Digest};

mod transformers;
use super::macros;

use self::transformers::{PayuPaymentRequest, PayuPaymentResponse, PayuErrorResponse, PayuErrorCode, PayuAuthType};
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
            
            // Basic headers for PayU requests
            let mut headers = vec![
                ("Content-Type".to_string(), ("application/x-www-form-urlencoded".to_string().into())),
                ("Accept".to_string(), ("application/json".to_string().into())),
            ];
            
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
            let payment_path = "/_payment"; // PayU standard payment endpoint
            let url = format!("{}{}", base_url, payment_path);
            
            
            Ok(url)
        }
        
    }
);

/*
# PayU UPI Integration Guide

PayU in India supports two main UPI payment flows:

## 1. UPI Intent (App-Based)

In UPI Intent flow, the customer selects a UPI app (Google Pay, PhonePe, etc.) and completes the payment within that app.

### Flow:
1. Customer selects "Pay with UPI app" and chooses an app
2. PayU generates a redirect URL or deep link to the chosen app
3. Customer completes payment in the UPI app
4. App redirects back to merchant's success/failure URL
5. Merchant verifies payment status using PSync

### Implementation Details:
- Use `PaymentMethodData::UpiIntent` with appropriate app name
- PayU requires the `upi_app_name` parameter
- Response will contain redirect_url for web or deep_link_url for mobile
- Set AttemptStatus to AuthenticationPending for redirect

### Supported Apps:
- Google Pay (GPAY)
- PhonePe (PHONEPE)
- Paytm (PAYTM)
- BHIM (BHIM)
- Amazon Pay (AMAZONPAY)
- And others supported by PayU

## 2. UPI Collect (VPA-Based)

In UPI Collect flow, the merchant collects the customer's UPI ID (VPA) and initiates a payment request.

### Flow:
1. Customer provides their UPI ID (e.g., "customer@okbank")
2. Merchant sends request to PayU with the VPA
3. PayU sends collect request to customer's UPI ID
4. Customer receives notification in their UPI app to approve
5. Customer approves or rejects payment in their app
6. PayU updates merchant about status via webhooks

### Implementation Details:
- Use `PaymentMethodData::UpiCollect` with customer's VPA
- PayU requires the `vpa` parameter
- Set `enforce_pay_method` to "upi_collect"
- Initial status may be "pending" until customer approves
- No redirection is needed, but status tracking is required

## Important Integration Notes:

1. Hash Generation:
   - Critical for security verification
   - Format: sha512(key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5||||||salt)
   - Even empty fields must be included in the hash calculation

2. Payment Status:
   - success: Payment completed successfully
   - failure: Payment failed
   - pending: Payment initiated but not yet completed

3. Error Handling:
   - InvalidVpa: The UPI ID format is invalid
   - UpiTimeout: The UPI request timed out
   - UpiAppNotInstalled: Selected app not installed on customer's device
   - UpiAppError: Error in the UPI app

4. Mobile Optimizations:
   - For mobile devices, use deep_link_url or intent_url when available
   - Add appropriate headers for mobile requests
   - Consider device-specific behavior for app selection

5. Testing:
   - Use PayU sandbox credentials for testing
   - PayU provides test VPAs for simulating different responses
   - Test both web and mobile flows for completeness

6. Production Checklist:
   - Verify hash calculation in production environment
   - Implement proper status sync using PSync
   - Set up webhook handling for asynchronous updates
   - Ensure proper error messaging for customers
*/

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
        let response: PayuErrorResponse = res.response
            .parse_struct("PayuErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            
        // Log the error with event builder if available
        if let Some(_event_builder) = event_builder {
            // TODO: Add event logging when the correct methods are available
            // event_builder.add_data("payu_error_code", response.error_code.as_ref());
            // event_builder.add_data("payu_error_message", &response.error_message);
        }
        
        // Map PayU error code to connector error
        let _connector_error = response.error_code.to_connector_error();
        
        // Map PayU error codes to appropriate attempt status
        let attempt_status = match response.error_code {
            PayuErrorCode::InvalidVpa => AttemptStatus::Failure,
            PayuErrorCode::UpiTimeout => AttemptStatus::Pending,
            PayuErrorCode::UpiAppNotInstalled => AttemptStatus::AuthenticationFailed,
            PayuErrorCode::UpiAppError => AttemptStatus::AuthenticationFailed,
            PayuErrorCode::PaymentFailed => AttemptStatus::Failure,
            _ => AttemptStatus::Failure,
        };
        
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.as_ref().to_string(),
            message: response.error_message.clone(),
            reason: Some(response.error_message),
            attempt_status: Some(attempt_status),
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
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

impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Payu {}

impl ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for Payu {}

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Payu {}

impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Payu {}

impl ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData> for Payu {}

impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData> for Payu {}

impl ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData> for Payu {}

impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData> for Payu {}

// Now implement the trait aliases
impl domain_types::connector_types::RefundV2 for Payu {}
impl domain_types::connector_types::RefundSyncV2 for Payu {}
impl domain_types::connector_types::PaymentSyncV2 for Payu {}
impl domain_types::connector_types::PaymentOrderCreate for Payu {}
impl domain_types::connector_types::PaymentVoidV2 for Payu {}
impl domain_types::connector_types::IncomingWebhook for Payu {}
impl domain_types::connector_types::PaymentCapture for Payu {}
impl domain_types::connector_types::SetupMandateV2 for Payu {}
impl domain_types::connector_types::AcceptDispute for Payu {}
impl domain_types::connector_types::SubmitEvidenceV2 for Payu {}
impl domain_types::connector_types::DisputeDefend for Payu {}
impl domain_types::connector_types::ValidationTrait for Payu {}
