// AUTO-GENERATED — do not edit by hand.
// Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate

use std::collections::HashMap;

use crate::error::SdkError;
use crate::http_client::{
    HttpClient, HttpOptions as NativeHttpOptions, HttpRequest as ClientHttpRequest,
};
use connector_service_ffi::types::{FfiMetadataPayload, FfiRequestData};
use connector_service_ffi::utils::ffi_headers_to_masked_metadata;
use domain_types::router_data::ConnectorSpecificConfig;
use domain_types::router_response_types::Response;
use domain_types::utils::ForeignTryFrom;
use grpc_api_types::payments::{ConnectorConfig, FfiOptions, RequestConfig};
use grpc_api_types::payments::{
    CustomerServiceCreateRequest, CustomerServiceCreateResponse, DisputeServiceAcceptRequest,
    DisputeServiceAcceptResponse, DisputeServiceDefendRequest, DisputeServiceDefendResponse,
    DisputeServiceSubmitEvidenceRequest, DisputeServiceSubmitEvidenceResponse,
    MerchantAuthenticationServiceCreateClientAuthenticationTokenRequest,
    MerchantAuthenticationServiceCreateClientAuthenticationTokenResponse,
    MerchantAuthenticationServiceCreateServerAuthenticationTokenRequest,
    MerchantAuthenticationServiceCreateServerAuthenticationTokenResponse,
    MerchantAuthenticationServiceCreateServerSessionAuthenticationTokenRequest,
    MerchantAuthenticationServiceCreateServerSessionAuthenticationTokenResponse,
    PaymentMethodAuthenticationServiceAuthenticateRequest,
    PaymentMethodAuthenticationServiceAuthenticateResponse,
    PaymentMethodAuthenticationServicePostAuthenticateRequest,
    PaymentMethodAuthenticationServicePostAuthenticateResponse,
    PaymentMethodAuthenticationServicePreAuthenticateRequest,
    PaymentMethodAuthenticationServicePreAuthenticateResponse, PaymentMethodServiceTokenizeRequest,
    PaymentMethodServiceTokenizeResponse, PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest, PaymentServiceCaptureResponse,
    PaymentServiceCreateOrderRequest, PaymentServiceCreateOrderResponse, PaymentServiceGetRequest,
    PaymentServiceGetResponse, PaymentServiceIncrementalAuthorizationRequest,
    PaymentServiceIncrementalAuthorizationResponse, PaymentServiceProxyAuthorizeRequest,
    PaymentServiceProxySetupRecurringRequest, PaymentServiceRefundRequest,
    PaymentServiceReverseRequest, PaymentServiceReverseResponse,
    PaymentServiceSetupRecurringRequest, PaymentServiceSetupRecurringResponse,
    PaymentServiceTokenAuthorizeRequest, PaymentServiceTokenSetupRecurringRequest,
    PaymentServiceVoidRequest, PaymentServiceVoidResponse, RecurringPaymentServiceChargeRequest,
    RecurringPaymentServiceChargeResponse, RecurringPaymentServiceRevokeRequest,
    RecurringPaymentServiceRevokeResponse, RefundResponse, RefundServiceGetRequest,
};
use grpc_api_types::payouts::{
    PayoutServiceCreateLinkRequest, PayoutServiceCreateLinkResponse,
    PayoutServiceCreateRecipientRequest, PayoutServiceCreateRecipientResponse,
    PayoutServiceCreateRequest, PayoutServiceCreateResponse,
    PayoutServiceEnrollDisburseAccountRequest, PayoutServiceEnrollDisburseAccountResponse,
    PayoutServiceGetRequest, PayoutServiceGetResponse, PayoutServiceStageRequest,
    PayoutServiceStageResponse, PayoutServiceTransferRequest, PayoutServiceTransferResponse,
    PayoutServiceVoidRequest, PayoutServiceVoidResponse,
};

/// ConnectorClient — high-level Rust wrapper for the Connector Service.
///
/// Handles the full round-trip for any payment flow:
///   1. Build connector HTTP request via Rust core handlers
///   2. Execute the HTTP request via our standardized HttpClient (reqwest)
///   3. Parse the connector response via Rust core handlers
///
/// This client owns its primary connection pool (http_client).
pub struct ConnectorClient {
    http_client: HttpClient,
    config: ConnectorConfig,
}

// ── Internal macro: generate a ConnectorClient method for a payment flow ──────
//
// Each generated method follows the same round-trip pattern:
//   1. Build FfiRequestData from caller inputs
//   2. Call the flow-specific req_handler to build the connector HTTP request
//   3. Execute HTTP via the shared HttpClient
//   4. Call the flow-specific res_handler to parse the response
//
// Usage: impl_flow_method!(method_name, ReqType, ResType, req_handler_fn, res_handler_fn);
macro_rules! impl_flow_method {
    ($method:ident, $req_type:ty, $res_type:ty, $req_handler:ident, $res_handler:ident) => {
        pub async fn $method(
            &self,
            request: $req_type,
            metadata: &HashMap<String, String>,
            options: Option<RequestConfig>,
        ) -> Result<$res_type, SdkError> {
            use connector_service_ffi::handlers::payments::{$req_handler, $res_handler};

            let ffi_options = self.resolve_ffi_options(&options);
            let override_opts = options
                .as_ref()
                .and_then(|o| o.http.as_ref())
                .map(NativeHttpOptions::from);

            let ffi_request =
                build_ffi_request(request.clone(), metadata, &ffi_options).map_err(|e| {
                    SdkError::IntegrationError {
                        error_code: "SDK_INTERNAL_ERROR".to_string(),
                        error_message: format!("{:?}", e),
                        suggested_action: None,
                        doc_url: None,
                    }
                })?;
            let environment = Some(
                grpc_api_types::payments::Environment::try_from(ffi_options.environment).map_err(
                    |e| SdkError::IntegrationError {
                        error_code: "INVALID_ENVIRONMENT".to_string(),
                        error_message: format!("{:?}", e),
                        suggested_action: None,
                        doc_url: None,
                    },
                )?,
            );

            let connector_request = $req_handler(ffi_request, environment)
                .map_err(SdkError::from)?
                .ok_or_else(|| SdkError::IntegrationError {
                    error_code: "NO_REQUEST_GENERATED".to_string(),
                    error_message: "No connector request was generated".to_string(),
                    suggested_action: None,
                    doc_url: None,
                })?;

            let (body, boundary) = connector_request
                .body
                .as_ref()
                .map(|b| b.get_body_bytes())
                .transpose()
                .map_err(|e| SdkError::IntegrationError {
                    error_code: "BODY_EXTRACTION_FAILED".to_string(),
                    error_message: format!("{e}"),
                    suggested_action: None,
                    doc_url: None,
                })?
                .unwrap_or((None, None));
            let mut headers = connector_request.get_headers_map();
            if let Some(boundary) = boundary {
                headers.insert(
                    "content-type".to_string(),
                    format!("multipart/form-data; boundary={}", boundary),
                );
            }
            let http_req = ClientHttpRequest {
                url: connector_request.url.clone(),
                method: connector_request.method,
                headers,
                body,
            };
            let http_response = self
                .http_client
                .execute(http_req, override_opts)
                .await
                .map_err(SdkError::from)?;

            let mut header_map = http::HeaderMap::new();
            for (key, value) in &http_response.headers {
                if let Ok(name) = http::header::HeaderName::from_bytes(key.as_bytes()) {
                    if let Ok(val) = http::header::HeaderValue::from_bytes(value.as_bytes()) {
                        header_map.insert(name, val);
                    }
                }
            }
            let response = Response {
                headers: Some(header_map),
                response: bytes::Bytes::from(http_response.body),
                status_code: http_response.status_code,
            };

            let ffi_request_for_res =
                build_ffi_request(request, metadata, &ffi_options).map_err(|e| {
                    SdkError::IntegrationError {
                        error_code: "SDK_INTERNAL_ERROR".to_string(),
                        error_message: format!("{:?}", e),
                        suggested_action: None,
                        doc_url: None,
                    }
                })?;
            $res_handler(ffi_request_for_res, response, environment).map_err(SdkError::from)
        }
    };
}

impl ConnectorClient {
    /// Initialize a new ConnectorClient.
    ///
    /// Returns `Err(SdkError::NetworkError)` if the HTTP client cannot be constructed
    /// (e.g. invalid proxy URL or CA certificate).
    ///
    /// # Arguments
    /// * `config` - The ConnectorConfig (connector_config with typed auth, options with environment).
    /// * `options` - Optional RequestConfig for default http/vault settings.
    pub fn new(config: ConnectorConfig, options: Option<RequestConfig>) -> Result<Self, SdkError> {
        let defaults = options.unwrap_or_default();

        let native_opts = match defaults.http.as_ref() {
            Some(http_proto) => NativeHttpOptions::from(http_proto),
            None => NativeHttpOptions::default(),
        };

        Ok(Self {
            http_client: HttpClient::new(native_opts).map_err(SdkError::from)?,
            config,
        })
    }

    /// Builds FfiOptions from config. Environment comes from SdkOptions (immutable).
    fn resolve_ffi_options(&self, _options: &Option<RequestConfig>) -> FfiOptions {
        let environment = self
            .config
            .options
            .as_ref()
            .map(|o| o.environment)
            .unwrap_or(0);
        FfiOptions {
            environment,
            connector_config: self.config.connector_config.clone(),
        }
    }

    // ── CustomerService flows ───────────────────────────────────────────────────
    impl_flow_method!(
        create_customer,
        CustomerServiceCreateRequest,
        CustomerServiceCreateResponse,
        create_req_handler,
        create_res_handler
    );
    // ── DisputeService flows ───────────────────────────────────────────────────
    impl_flow_method!(
        accept,
        DisputeServiceAcceptRequest,
        DisputeServiceAcceptResponse,
        accept_req_handler,
        accept_res_handler
    );
    impl_flow_method!(
        defend,
        DisputeServiceDefendRequest,
        DisputeServiceDefendResponse,
        defend_req_handler,
        defend_res_handler
    );
    impl_flow_method!(
        submit_evidence,
        DisputeServiceSubmitEvidenceRequest,
        DisputeServiceSubmitEvidenceResponse,
        submit_evidence_req_handler,
        submit_evidence_res_handler
    );
    // ── EventService flows ───────────────────────────────────────────────────
    // TODO: Single-step flow handle_event needs different macro/implementation
    // ── MerchantAuthenticationService flows ───────────────────────────────────────────────────
    impl_flow_method!(
        create_client_authentication_token,
        MerchantAuthenticationServiceCreateClientAuthenticationTokenRequest,
        MerchantAuthenticationServiceCreateClientAuthenticationTokenResponse,
        create_client_authentication_token_req_handler,
        create_client_authentication_token_res_handler
    );
    impl_flow_method!(
        create_server_authentication_token,
        MerchantAuthenticationServiceCreateServerAuthenticationTokenRequest,
        MerchantAuthenticationServiceCreateServerAuthenticationTokenResponse,
        create_server_authentication_token_req_handler,
        create_server_authentication_token_res_handler
    );
    impl_flow_method!(
        create_server_session_authentication_token,
        MerchantAuthenticationServiceCreateServerSessionAuthenticationTokenRequest,
        MerchantAuthenticationServiceCreateServerSessionAuthenticationTokenResponse,
        create_server_session_authentication_token_req_handler,
        create_server_session_authentication_token_res_handler
    );
    // ── PaymentMethodAuthenticationService flows ───────────────────────────────────────────────────
    impl_flow_method!(
        authenticate,
        PaymentMethodAuthenticationServiceAuthenticateRequest,
        PaymentMethodAuthenticationServiceAuthenticateResponse,
        authenticate_req_handler,
        authenticate_res_handler
    );
    impl_flow_method!(
        post_authenticate,
        PaymentMethodAuthenticationServicePostAuthenticateRequest,
        PaymentMethodAuthenticationServicePostAuthenticateResponse,
        post_authenticate_req_handler,
        post_authenticate_res_handler
    );
    impl_flow_method!(
        pre_authenticate,
        PaymentMethodAuthenticationServicePreAuthenticateRequest,
        PaymentMethodAuthenticationServicePreAuthenticateResponse,
        pre_authenticate_req_handler,
        pre_authenticate_res_handler
    );
    // ── PaymentMethodService flows ───────────────────────────────────────────────────
    impl_flow_method!(
        tokenize,
        PaymentMethodServiceTokenizeRequest,
        PaymentMethodServiceTokenizeResponse,
        tokenize_req_handler,
        tokenize_res_handler
    );
    // ── PaymentService flows ───────────────────────────────────────────────────
    impl_flow_method!(
        authorize,
        PaymentServiceAuthorizeRequest,
        PaymentServiceAuthorizeResponse,
        authorize_req_handler,
        authorize_res_handler
    );
    impl_flow_method!(
        capture,
        PaymentServiceCaptureRequest,
        PaymentServiceCaptureResponse,
        capture_req_handler,
        capture_res_handler
    );
    impl_flow_method!(
        create_order,
        PaymentServiceCreateOrderRequest,
        PaymentServiceCreateOrderResponse,
        create_order_req_handler,
        create_order_res_handler
    );
    impl_flow_method!(
        get,
        PaymentServiceGetRequest,
        PaymentServiceGetResponse,
        get_req_handler,
        get_res_handler
    );
    impl_flow_method!(
        incremental_authorization,
        PaymentServiceIncrementalAuthorizationRequest,
        PaymentServiceIncrementalAuthorizationResponse,
        incremental_authorization_req_handler,
        incremental_authorization_res_handler
    );
    impl_flow_method!(
        proxy_authorize,
        PaymentServiceProxyAuthorizeRequest,
        PaymentServiceAuthorizeResponse,
        proxy_authorize_req_handler,
        proxy_authorize_res_handler
    );
    impl_flow_method!(
        proxy_setup_recurring,
        PaymentServiceProxySetupRecurringRequest,
        PaymentServiceSetupRecurringResponse,
        proxy_setup_recurring_req_handler,
        proxy_setup_recurring_res_handler
    );
    impl_flow_method!(
        refund,
        PaymentServiceRefundRequest,
        RefundResponse,
        refund_req_handler,
        refund_res_handler
    );
    impl_flow_method!(
        reverse,
        PaymentServiceReverseRequest,
        PaymentServiceReverseResponse,
        reverse_req_handler,
        reverse_res_handler
    );
    impl_flow_method!(
        setup_recurring,
        PaymentServiceSetupRecurringRequest,
        PaymentServiceSetupRecurringResponse,
        setup_recurring_req_handler,
        setup_recurring_res_handler
    );
    impl_flow_method!(
        token_authorize,
        PaymentServiceTokenAuthorizeRequest,
        PaymentServiceAuthorizeResponse,
        token_authorize_req_handler,
        token_authorize_res_handler
    );
    impl_flow_method!(
        token_setup_recurring,
        PaymentServiceTokenSetupRecurringRequest,
        PaymentServiceSetupRecurringResponse,
        token_setup_recurring_req_handler,
        token_setup_recurring_res_handler
    );
    impl_flow_method!(
        void,
        PaymentServiceVoidRequest,
        PaymentServiceVoidResponse,
        void_req_handler,
        void_res_handler
    );
    // TODO: Single-step flow verify_redirect_response needs different macro/implementation
    // ── PayoutService flows ───────────────────────────────────────────────────
    impl_flow_method!(
        payout_create,
        PayoutServiceCreateRequest,
        PayoutServiceCreateResponse,
        payout_create_req_handler,
        payout_create_res_handler
    );
    impl_flow_method!(
        create_link,
        PayoutServiceCreateLinkRequest,
        PayoutServiceCreateLinkResponse,
        payout_create_link_req_handler,
        payout_create_link_res_handler
    );
    impl_flow_method!(
        create_recipient,
        PayoutServiceCreateRecipientRequest,
        PayoutServiceCreateRecipientResponse,
        payout_create_recipient_req_handler,
        payout_create_recipient_res_handler
    );
    impl_flow_method!(
        enroll_disburse_account,
        PayoutServiceEnrollDisburseAccountRequest,
        PayoutServiceEnrollDisburseAccountResponse,
        payout_enroll_disburse_account_req_handler,
        payout_enroll_disburse_account_res_handler
    );
    impl_flow_method!(
        payout_get,
        PayoutServiceGetRequest,
        PayoutServiceGetResponse,
        payout_get_req_handler,
        payout_get_res_handler
    );
    impl_flow_method!(
        stage,
        PayoutServiceStageRequest,
        PayoutServiceStageResponse,
        payout_stage_req_handler,
        payout_stage_res_handler
    );
    impl_flow_method!(
        transfer,
        PayoutServiceTransferRequest,
        PayoutServiceTransferResponse,
        payout_transfer_req_handler,
        payout_transfer_res_handler
    );
    impl_flow_method!(
        payout_void,
        PayoutServiceVoidRequest,
        PayoutServiceVoidResponse,
        payout_void_req_handler,
        payout_void_res_handler
    );
    // ── RecurringPaymentService flows ───────────────────────────────────────────────────
    impl_flow_method!(
        recurring_charge,
        RecurringPaymentServiceChargeRequest,
        RecurringPaymentServiceChargeResponse,
        charge_req_handler,
        charge_res_handler
    );
    impl_flow_method!(
        recurring_revoke,
        RecurringPaymentServiceRevokeRequest,
        RecurringPaymentServiceRevokeResponse,
        recurring_revoke_req_handler,
        recurring_revoke_res_handler
    );
    // ── RefundService flows ───────────────────────────────────────────────────
    impl_flow_method!(
        refund_get,
        RefundServiceGetRequest,
        RefundResponse,
        refund_get_req_handler,
        refund_get_res_handler
    );
}

/// Internal helper to build the context-heavy FfiRequestData from raw inputs.
pub fn build_ffi_request<T>(
    payload: T,
    metadata: &HashMap<String, String>,
    options: &FfiOptions,
) -> Result<FfiRequestData<T>, SdkError> {
    let proto_config =
        options
            .connector_config
            .as_ref()
            .ok_or_else(|| SdkError::IntegrationError {
                error_code: "MISSING_CONNECTOR_CONFIG".to_string(),
                error_message: "Missing connector_config in FfiOptions".to_string(),
                suggested_action: Some(
                    "Provide connector_config when constructing ConnectorClient".to_string(),
                ),
                doc_url: None,
            })?;

    let config_variant =
        proto_config
            .config
            .as_ref()
            .ok_or_else(|| SdkError::IntegrationError {
                error_code: "MISSING_CONFIG_VARIANT".to_string(),
                error_message: "Missing config variant in ConnectorSpecificConfig".to_string(),
                suggested_action: Some(
                    "Set the connector-specific config (e.g. stripe.api_key)".to_string(),
                ),
                doc_url: None,
            })?;

    let connector =
        domain_types::connector_types::ConnectorEnum::foreign_try_from(config_variant.clone())
            .map_err(|e| SdkError::IntegrationError {
                error_code: "CONNECTOR_MAPPING_FAILED".to_string(),
                error_message: format!("Connector mapping failed: {e}"),
                suggested_action: None,
                doc_url: None,
            })?;

    let connector_config = ConnectorSpecificConfig::foreign_try_from(proto_config.clone())
        .map_err(|e| SdkError::IntegrationError {
            error_code: "CONNECTOR_CONFIG_MAPPING_FAILED".to_string(),
            error_message: format!("Connector config mapping failed: {e}"),
            suggested_action: None,
            doc_url: None,
        })?;

    let masked_metadata =
        ffi_headers_to_masked_metadata(metadata).map_err(|e| SdkError::IntegrationError {
            error_code: "METADATA_MAPPING_FAILED".to_string(),
            error_message: format!("Metadata mapping failed: {:?}", e),
            suggested_action: None,
            doc_url: None,
        })?;

    Ok(FfiRequestData {
        payload,
        extracted_metadata: FfiMetadataPayload {
            connector,
            connector_config,
        },
        masked_metadata: Some(masked_metadata),
    })
}
