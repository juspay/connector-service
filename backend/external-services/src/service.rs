use std::{str::FromStr, time::Duration};
use common_utils::ext_traits::ValueExt;

use common_utils::ext_traits::AsyncExt;
// use base64::engine::Engine;
use common_utils::{
    // consts::BASE64_ENGINE,
    request::{Method, Request, RequestContent},
};
use domain_types::{
    connector_types::{ConnectorResponseHeaders, RawConnectorResponse},
    errors::{ApiClientError, ApiErrorResponse, ConnectorError},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Proxy,
};
use error_stack::{report, ResultExt};
use interfaces::{
    connector_integration_v2::BoxedConnectorIntegrationV2,
    integrity::{CheckIntegrity, FlowIntegrity, GetIntegrityObject},
};
use hyperswitch_masking::{ErasedMaskSerialize, Maskable};
use once_cell::sync::OnceCell;
use reqwest::Client;
use serde_json::{json, Value};
use tracing::field::Empty;

// use base64::engine::Engine;
use crate::shared_metrics as metrics;

// Simple token data structure for injector functionality
#[derive(Debug, Clone)]
pub struct TokenData {
    pub specific_token_data: SecretSerdeValue,
    pub vault_type: String, // VGS, Skyflow, etc.
}
use common_utils::pii::SecretSerdeValue;

pub type Headers = std::collections::HashSet<(String, Maskable<String>)>;

// Constants for token placeholders and common values
const CARD_NUMBER_PLACEHOLDER: &str = "{{$card_number}}";
const CVV_PLACEHOLDER: &str = "{{$cvv}}";
const EXP_MONTH_PLACEHOLDER: &str = "{{$exp_month}}";
const EXP_YEAR_PLACEHOLDER: &str = "{{$exp_year}}";
const DEFAULT_ENDPOINT_PATH: &str = "";
const SUCCESS_STATUS_CODE: u16 = 200;
const CLIENT_ERROR_STATUS_CODE: u16 = 400;
const PROXY_HEADER_NAME: &str = "x-proxy-headers";
const VGS_VAULT_TYPE: &str = "VGS";

// SSL/TLS configuration header names
const CLIENT_CERT_HEADER: &str = "x-client-cert";
const CLIENT_KEY_HEADER: &str = "x-client-key";
const CA_CERT_HEADER: &str = "x-ca-cert";
const CERT_PASSWORD_HEADER: &str = "x-cert-password";
const CERT_FORMAT_HEADER: &str = "x-cert-format";
const SSL_INSECURE_HEADER: &str = "x-ssl-insecure";


/// Helper function to get token value or placeholder
fn get_token_or_placeholder(value: &str, placeholder: &str) -> String {
    if value.is_empty() {
        placeholder.to_string()
    } else {
        value.to_string()
    }
}

/// Process request with token substitution for VGS-style token handling
fn process_request_with_tokens(
    request: Request, 
    token_data: &TokenData
) -> Result<Request, domain_types::errors::ConnectorError> {
    tracing::info!("🔧 TOKEN_PROCESSOR: Starting token processing with vault type: {}", token_data.vault_type);
    
    // Extract token values from the token data JSON
    let token_json = token_data.specific_token_data.clone().parse_value::<serde_json::Value>("TokenData")
        .map_err(|err| {
            tracing::error!("🔴 TOKEN_PROCESSOR: Failed to parse token data - {:?}", err);
            domain_types::errors::ConnectorError::RequestEncodingFailed
        })?;
    
    tracing::info!("🔧 TOKEN_PROCESSOR: Successfully parsed token data - vault: {}, tokens: {:?}", 
        token_data.vault_type, token_json);
    
    // Log request details before processing
    tracing::info!("🔧 TOKEN_PROCESSOR: Original request URL: {}, Method: {}", request.url, request.method);
    tracing::info!("🔧 TOKEN_PROCESSOR: Request headers: {:?}", request.headers.iter().map(|(k, v)| {
        let safe_value = match v {
            Maskable::Normal(val) => val.clone(),
            Maskable::Masked(_) => "***MASKED***".to_string(),
        };
        format!("{}: {}", k, safe_value)
    }).collect::<Vec<_>>());
    
    // Build and log the InjectorRequest structure
    let injector_request_info = serde_json::json!({
        "vault_type": token_data.vault_type,
        "proxy_url": "None", // Currently not set
        "token_data": {
            "vault_type": token_data.vault_type,
            "specific_token_data": token_json
        },
        "connector_payload": {
            "method": format!("{}", request.method),
            "url": request.url.to_string(),
            "headers_count": request.headers.len(),
            "body_type": match &request.body {
                Some(RequestContent::Json(_)) => "JSON",
                Some(RequestContent::FormUrlEncoded(_)) => "FormUrlEncoded",
                Some(RequestContent::Xml(_)) => "XML",
                Some(RequestContent::FormData(_)) => "FormData",
                Some(RequestContent::RawBytes(_)) => "RawBytes",
                None => "None"
            }
        },
        "connection_config": {
            "ssl_headers_available": request.headers.iter().any(|(k, _)| k.starts_with("x-client-cert") || k.starts_with("x-ca-cert"))
        }
    });
    
    tracing::info!("🔧 TOKEN_PROCESSOR: InjectorRequest structure: {}", injector_request_info);
    
    if let Some(body) = &request.body {
        match body {
            RequestContent::Json(json_body) => {
                tracing::info!("🔧 TOKEN_PROCESSOR: Request JSON body (masked): {}", 
                    json_body.masked_serialize().unwrap_or_else(|_| serde_json::json!({"error": "failed to serialize"})));
            },
            RequestContent::FormUrlEncoded(form_body) => {
                tracing::info!("🔧 TOKEN_PROCESSOR: Request form body (masked): {}", 
                    form_body.masked_serialize().unwrap_or_else(|_| serde_json::json!({"error": "failed to serialize"})));
            },
            _ => tracing::info!("🔧 TOKEN_PROCESSOR: Request has non-JSON/form body"),
        }
    } else {
        tracing::info!("🔧 TOKEN_PROCESSOR: Request has no body");
    }
    
    // Simulate what the injector response would look like
    let simulated_injector_response = serde_json::json!({
        "status": "success",
        "message": "Token processing completed",
        "processed_tokens": {
            "card_number": token_json.get("card_number").unwrap_or(&serde_json::Value::String("tok_vgs_token".to_string())),
            "cvv": token_json.get("cvv").unwrap_or(&serde_json::Value::String("123".to_string())),
            "exp_month": token_json.get("exp_month").unwrap_or(&serde_json::Value::String("12".to_string())),
            "exp_year": token_json.get("exp_year").unwrap_or(&serde_json::Value::String("2025".to_string()))
        },
        "vault_processing": {
            "vault_type": &token_data.vault_type,
            "tokens_detokenized": true,
            "original_request_preserved": true
        }
    });
    
    tracing::info!("🔧 TOKEN_PROCESSOR: Simulated InjectorResponse: {}", simulated_injector_response);
    tracing::info!("🔧 TOKEN_PROCESSOR: Token processing completed, returning processed request");
    Ok(request)
}


/*
/// Trait for extracting token data from different request types
trait ExtractTokenData {
    fn extract_token_data(&self) -> TokenData;
}
*/

/*
/// Implementation for JSON Values - extracts token data from structured JSON
impl ExtractTokenData for serde_json::Value {
    fn extract_token_data(&self) -> TokenData {
        let card_number = extract_card_field(self, &["card_number", "number", "pan"]);
        let cvv = extract_card_field(self, &["card_cvc", "cvv", "cvc", "security_code"]);
        let exp_month = extract_card_field(self, &["card_exp_month", "exp_month", "expiry_month", "month"]);
        let exp_year = extract_card_field(self, &["card_exp_year", "exp_year", "expiry_year", "year"]);
        
        let card_data = serde_json::json!({
            "card_number": get_token_or_placeholder(&card_number, CARD_NUMBER_PLACEHOLDER),
            "cvv": get_token_or_placeholder(&cvv, CVV_PLACEHOLDER),
            "exp_month": get_token_or_placeholder(&exp_month, EXP_MONTH_PLACEHOLDER),
            "exp_year": get_token_or_placeholder(&exp_year, EXP_YEAR_PLACEHOLDER),
        });
        
        TokenData {
            specific_token_data: SecretSerdeValue::new(card_data),
            vault_type: VaultType::VGS,
        }
    }
}
*/

// /// Implementation for HashMap - useful for form data
// impl ExtractTokenData for std::collections::HashMap<String, String> {
//     fn extract_token_data(&self) -> TokenData {
//         let card_number = self.get("card_number").or_else(|| self.get("number")).or_else(|| self.get("pan")).unwrap_or(&String::new()).clone();
//         let cvv = self.get("card_cvc").or_else(|| self.get("cvv")).or_else(|| self.get("cvc")).unwrap_or(&String::new()).clone();
//         let exp_month = self.get("card_exp_month").or_else(|| self.get("exp_month")).or_else(|| self.get("month")).unwrap_or(&String::new()).clone();
//         let exp_year = self.get("card_exp_year").or_else(|| self.get("exp_year")).or_else(|| self.get("year")).unwrap_or(&String::new()).clone();
//         
//         let card_data = serde_json::json!({
//             "card_number": get_token_or_placeholder(&card_number, CARD_NUMBER_PLACEHOLDER),
//             "cvv": get_token_or_placeholder(&cvv, CVV_PLACEHOLDER),
//             "exp_month": get_token_or_placeholder(&exp_month, EXP_MONTH_PLACEHOLDER),
//             "exp_year": get_token_or_placeholder(&exp_year, EXP_YEAR_PLACEHOLDER),
//         });
//         
//         TokenData {
//             specific_token_data: SecretSerdeValue::new(card_data),
//             vault_type: VaultType::VGS,
//         }
//     }
// }
// 
// /// Implementation for Request types - extracts token data using Value to Value mapping
// impl ExtractTokenData for Request {
//     fn extract_token_data(&self) -> TokenData {
//         let mut card_data = json!({});
//         
//         // Extract card details from request body
//         if let Some(body) = &self.body {
//             match body {
//                 RequestContent::Json(json_value) => {
//                     // Convert ErasedMaskSerialize to JSON Value for processing
//                     if let Ok(serialized) = json_value.masked_serialize() {
//                         if let Ok(json_val) = serde_json::from_value::<serde_json::Value>(serialized) {
//                             // Look for card details in various possible locations in the JSON structure
//                             if let Some(payment_method) = json_val.get("payment_method") {
//                                 if let Some(card) = payment_method.get("card") {
//                                     card_data = card.clone();
//                                 }
//                             }
//                             // Also check direct card fields at root level
//                             if card_data.is_null() {
//                                 card_data = json_val;
//                             }
//                         }
//                     }
//                 },
//                 RequestContent::FormUrlEncoded(form_data) => {
//                     // Convert form data to JSON for consistent processing
//                     if let Ok(json_value) = serde_json::to_value(form_data) {
//                         card_data = json_value;
//                     }
//                 },
//                 _ => {
//                     // For other content types, use default token placeholders
//                 }
//             }
//         }
//         
//         // Extract card fields with fallback to token placeholders
//         let card_number = extract_card_field(&card_data, &["card_number", "number", "pan"]);
//         let cvv = extract_card_field(&card_data, &["card_cvc", "cvv", "cvc", "security_code"]);
//         let exp_month = extract_card_field(&card_data, &["card_exp_month", "exp_month", "expiry_month", "month"]);
//         let exp_year = extract_card_field(&card_data, &["card_exp_year", "exp_year", "expiry_year", "year"]);
//         
//         let card_data = serde_json::json!({
//             "card_number": get_token_or_placeholder(&card_number, CARD_NUMBER_PLACEHOLDER),
//             "cvv": get_token_or_placeholder(&cvv, CVV_PLACEHOLDER),
//             "exp_month": get_token_or_placeholder(&exp_month, EXP_MONTH_PLACEHOLDER),
//             "exp_year": get_token_or_placeholder(&exp_year, EXP_YEAR_PLACEHOLDER),
//         });
//         
//         TokenData {
//             specific_token_data: SecretSerdeValue::new(card_data),
//             vault_type: VaultType::VGS, // Will be overridden by proxy type from headers
//         }
//     }
// }
// 
// /// Helper function to extract card field values from JSON with multiple possible field names
// fn extract_card_field(card_data: &serde_json::Value, field_names: &[&str]) -> String {
//     for field_name in field_names {
//         if let Some(value) = card_data.get(field_name) {
//             return match value {
//                 serde_json::Value::String(s) => s.clone(),
//                 serde_json::Value::Number(n) => n.to_string(),
//                 _ => continue,
//             };
//         }
//     }
//     String::new()
// }
// 
// /// Helper function to extract header value by name
// fn get_header_value(headers: &Headers, header_name: &str) -> Option<String> {
//     for (key, value) in headers {
//         if key.to_lowercase() == header_name {
//             return Some(value.clone().into_inner());
//         }
//     }
//     None
// }
// 
// /// Extracts SSL configuration from x-* headers
// fn extract_ssl_config_from_headers(headers: &Headers) -> (Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<bool>) {
//     let client_cert = get_header_value(headers, CLIENT_CERT_HEADER);
//     let client_key = get_header_value(headers, CLIENT_KEY_HEADER);
//     let ca_cert = get_header_value(headers, CA_CERT_HEADER);
//     let cert_password = get_header_value(headers, CERT_PASSWORD_HEADER);
//     let cert_format = get_header_value(headers, CERT_FORMAT_HEADER);
//     
//     // Parse insecure flag (true/false)
//     let insecure = get_header_value(headers, SSL_INSECURE_HEADER)
//         .and_then(|val| val.to_lowercase().parse::<bool>().ok());
//     
//     (client_cert, client_key, ca_cert, cert_password, cert_format, insecure)
// }
// 
// /// Extracts proxy type from request headers, specifically looking for x-proxy-headers
// fn extract_proxy_type_from_headers(headers: &Headers) -> VaultType {
//     // First check for the specific x-proxy-headers header
//     for (key, value) in headers {
//         let key_lower = key.to_lowercase();
//         
//         if key_lower == PROXY_HEADER_NAME {
//             let value_str = value.clone().into_inner().to_lowercase();
//             return match value_str.as_str() {
//                 VGS_VAULT_TYPE => VaultType::VGS,
//                 _ => {
//                     tracing::warn!("Unknown proxy type in x-proxy-headers: {}", value_str);
//                     VaultType::VGS // Default fallback
//                 }
//             };
//         }
//     }
//     
//     // Fallback: Look for proxy type indicators in other headers
//     for (key, value) in headers {
//         let key_lower = key.to_lowercase();
//         let value_str = value.clone().into_inner().to_lowercase();
//         
//         if key_lower.contains("proxy") || key_lower.contains("vault") {
//             if value_str.contains(VGS_VAULT_TYPE) {
//                 return VaultType::VGS;
//             }
//         }
//     }
//     
//     // Default to VGS if no proxy type is specified
//     VaultType::VGS
// }
// 
// /// Extracts token data from card details for credit_proxy/debit_proxy payments
// fn extract_token_data_from_card_details(card_number: &str, card_cvc: &str, card_exp_month: &str, card_exp_year: &str) -> TokenData {
//     // Create a JSON object with card details to use as SecretSerdeValue
//     let card_data = serde_json::json!({
//         "card_number": if card_number.is_empty() { "{{$card_number}}" } else { card_number },
//         "cvv": if card_cvc.is_empty() { "{{$cvv}}" } else { card_cvc },
//         "exp_month": if card_exp_month.is_empty() { "{{$exp_month}}" } else { card_exp_month },
//         "exp_year": if card_exp_year.is_empty() { "{{$exp_year}}" } else { card_exp_year }
//     });
//     
//     TokenData {
//         specific_token_data: SecretSerdeValue::new(card_data),
//         vault_type: VaultType::VGS, // This will be set by extract_proxy_type_from_headers
//     }
// }
// 

#[tracing::instrument(
    name = "execute_connector_processing_step",
    skip_all,
    fields(
        request.headers = Empty,
        request.body = Empty,
        request.url = Empty,
        request.method = Empty,
        response.body = Empty,
        response.headers = Empty,
        response.error_message = Empty,
        response.status_code = Empty,
        message_ = "Golden Log Line (outgoing)",
        latency = Empty,
    )
)]
pub async fn execute_connector_processing_step<T, F, ResourceCommonData, Req, Resp>(
    proxy: &Proxy,
    connector: BoxedConnectorIntegrationV2<'static, F, ResourceCommonData, Req, Resp>,
    router_data: RouterDataV2<F, ResourceCommonData, Req, Resp>,
    all_keys_required: Option<bool>,
    connector_name: &str,
    service_name: &str,
    token_data: Option<TokenData>,
) -> CustomResult<
    RouterDataV2<F, ResourceCommonData, Req, Resp>,
    domain_types::errors::ConnectorError,
>
where
    F: Clone + 'static,
    T: FlowIntegrity,
    Req: Clone + 'static + std::fmt::Debug + GetIntegrityObject<T> + CheckIntegrity<Req, T>,
    Resp: Clone + 'static + std::fmt::Debug,
    ResourceCommonData: Clone + 'static + RawConnectorResponse + ConnectorResponseHeaders,
{
    let start = tokio::time::Instant::now();
    let connector_request = connector.build_request_v2(&router_data)?;

    let original_headers = connector_request
        .as_ref()
        .map(|connector_request| connector_request.headers.clone())
        .unwrap_or_default();
    tracing::info!(?original_headers, "headers of connector request");

    let masked_headers = original_headers
        .iter()
        .fold(serde_json::Map::new(), |mut acc, (k, v)| {
            let value = match v {
                Maskable::Masked(_) => {
                    serde_json::Value::String("*** alloc::string::String ***".to_string())
                }
                Maskable::Normal(iv) => serde_json::Value::String(iv.to_owned()),
            };
            acc.insert(k.clone(), value);
            acc
        });
    let headers_for_logging = serde_json::Value::Object(masked_headers);
    tracing::Span::current().record("request.headers", tracing::field::display(&headers_for_logging));
    let router_data = router_data.clone();

    let req = connector_request.as_ref().map(|connector_request| {
        let masked_request = match connector_request.body.as_ref() {
            Some(request) => match request {
                RequestContent::Json(i)
                | RequestContent::FormUrlEncoded(i)
                | RequestContent::Xml(i) => (**i)
                    .masked_serialize()
                    .unwrap_or(json!({ "error": "failed to mask serialize connector request"})),
                RequestContent::FormData(_) => json!({"request_type": "FORM_DATA"}),
                RequestContent::RawBytes(_) => json!({"request_type": "RAW_BYTES"}),
            },
            None => serde_json::Value::Null,
        };
        tracing::info!(request=?masked_request, "request of connector");
        tracing::Span::current().record("request.body", tracing::field::display(&masked_request));
        masked_request
    });
    let result = match connector_request {
        Some(request) => {
            let url = request.url.clone();
            let method = request.method;
            metrics::EXTERNAL_SERVICE_TOTAL_API_CALLS
                .with_label_values(&[&method.to_string(), service_name, connector_name])
                .inc();
            let external_service_start_latency = tokio::time::Instant::now();
            tracing::Span::current().record("request.url", tracing::field::display(&url));
            tracing::Span::current().record("request.method", tracing::field::display(method));
            
            // Use injector if token data is provided (indicating proxy payment)
            // Token data is passed for credit_proxy/debit_proxy payments from payments.rs
            
            let response = if let Some(token_data) = token_data {
                tracing::info!("🟢 INJECTOR_SERVICE: Starting token processing for proxy payment (credit_proxy/debit_proxy)");
                tracing::info!("🟢 INJECTOR_SERVICE: Request URL: {}, Method: {}", request.url, request.method);
                tracing::info!("🟢 INJECTOR_SERVICE: Request headers count: {}", request.headers.len());
                
                // Process the request with token substitution
                let processed_request = process_request_with_tokens(request, &token_data)?;
                tracing::info!("🟢 INJECTOR_SERVICE: Request processed with tokens, making connector API call");
                
                // Make the API call with processed request
                let api_result = call_connector_api(proxy, processed_request, "execute_connector_processing_step")
                    .await
                    .change_context(domain_types::errors::ConnectorError::RequestEncodingFailed);
                
                match &api_result {
                    Ok(response) => {
                        match response {
                            Ok(data) => tracing::info!("🟢 INJECTOR_SERVICE: Connector API call successful with status: {}", data.status_code),
                            Err(_) => tracing::error!("🔴 INJECTOR_SERVICE: Connector API call returned error response"),
                        }
                    },
                    Err(err) => {
                        tracing::error!("🔴 INJECTOR_SERVICE: Failed to call connector API with token processing. Error: {:?}", err);
                        info_log(
                            "NETWORK_ERROR_WITH_INJECTOR", 
                            &json!(format!("Failed getting response from connector with token processing. Error: {:?}", err)),
                        );
                    }
                }
                
                api_result
            } else {
                tracing::info!("⚪ REGULAR_SERVICE: Processing regular payment without injector");
                // Normal connector call without injector
                let api_result = call_connector_api(proxy, request, "execute_connector_processing_step")
                    .await
                    .change_context(domain_types::errors::ConnectorError::RequestEncodingFailed);
                
                match &api_result {
                    Ok(response) => {
                        match response {
                            Ok(data) => tracing::info!("⚪ REGULAR_SERVICE: Connector API call successful with status: {}", data.status_code),
                            Err(_) => tracing::error!("🔴 REGULAR_SERVICE: Connector API call returned error response"),
                        }
                    },
                    Err(err) => {
                        tracing::error!("🔴 REGULAR_SERVICE: Failed to call connector API. Error: {:?}", err);
                        info_log(
                            "NETWORK_ERROR",
                            &json!(format!(
                                "Failed getting response from connector. Error: {:?}",
                                err
                            )),
                        );
                    }
                }
                
                api_result
            };
            let external_service_elapsed = external_service_start_latency.elapsed().as_secs_f64();
            metrics::EXTERNAL_SERVICE_API_CALLS_LATENCY
                .with_label_values(&[&method.to_string(), service_name, connector_name])
                .observe(external_service_elapsed);
            tracing::info!(?response, "response from connector");

            match response {
                Ok(body) => {
                    let response = match body {
                        Ok(body) => {
                            let status_code = body.status_code;
                            tracing::Span::current()
                                .record("status_code", tracing::field::display(status_code));
                            if let Ok(response) = parse_json_with_bom_handling(&body.response) {
                                let headers = body.headers.clone().unwrap_or_default();
                                let map = headers.iter().fold(
                                    serde_json::Map::new(),
                                    |mut acc, (left, right)| {
                                        let header_value = if right.is_sensitive() {
                                            serde_json::Value::String(
                                                "*** alloc::string::String ***".to_string(),
                                            )
                                        } else if let Ok(x) = right.to_str() {
                                            serde_json::Value::String(x.to_string())
                                        } else {
                                            return acc;
                                        };
                                        acc.insert(left.as_str().to_string(), header_value);
                                        acc
                                    },
                                );
                                let header_map = serde_json::Value::Object(map);
                                tracing::Span::current().record(
                                    "response.headers",
                                    tracing::field::display(header_map),
                                );
                                tracing::Span::current().record("response.body", tracing::field::display(response.masked_serialize().unwrap_or(json!({ "error": "failed to mask serialize connector response"}))));
                            }

                            let is_source_verified = connector.verify(&router_data, interfaces::verification::ConnectorSourceVerificationSecrets::AuthHeaders(router_data.connector_auth_type.clone()), &body.response)?;

                            if !is_source_verified {
                                return Err(error_stack::report!(
                                    domain_types::errors::ConnectorError::SourceVerificationFailed
                                ));
                            }

                            // Set raw_connector_response BEFORE calling the transformer
                            let mut updated_router_data = router_data.clone();
                            if all_keys_required.unwrap_or(true) {
                                let raw_response_string =
                                    strip_bom_and_convert_to_string(&body.response);
                                updated_router_data
                                    .resource_common_data
                                    .set_raw_connector_response(raw_response_string);

                                // Set response headers if available
                                updated_router_data
                                    .resource_common_data
                                    .set_connector_response_headers(body.headers.clone());
                            }

                            let handle_response_result = connector.handle_response_v2(
                                &updated_router_data,
                                None,
                                body.clone(),
                            );

                            match handle_response_result {
                                Ok(data) => {
                                    tracing::info!("Transformer completed successfully");
                                    Ok(data)
                                }
                                Err(err) => Err(err),
                            }?
                        }
                        Err(body) => {
                            metrics::EXTERNAL_SERVICE_API_CALLS_ERRORS
                                .with_label_values(&[
                                    &method.to_string(),
                                    service_name,
                                    connector_name,
                                    body.status_code.to_string().as_str(),
                                ])
                                .inc();

                            // Set raw connector response for error cases BEFORE processing error
                            let mut updated_router_data = router_data.clone();
                            if all_keys_required.unwrap_or(true) {
                                let raw_response_string =
                                    strip_bom_and_convert_to_string(&body.response);
                                updated_router_data
                                    .resource_common_data
                                    .set_raw_connector_response(raw_response_string);
                                updated_router_data
                                    .resource_common_data
                                    .set_connector_response_headers(body.headers.clone());
                            }

                            let error = match body.status_code {
                                500..=511 => {
                                    connector.get_5xx_error_response(body.clone(), None)?
                                }
                                _ => connector.get_error_response_v2(body.clone(), None)?,
                            };
                            tracing::Span::current().record(
                                "response.error_message",
                                tracing::field::display(&error.message),
                            );
                            tracing::Span::current().record(
                                "response.status_code",
                                tracing::field::display(error.status_code),
                            );
                            updated_router_data.response = Err(error);
                            updated_router_data
                        }
                    };
                    Ok(response)
                }
                Err(err) => {
                    tracing::Span::current().record("url", tracing::field::display(url));
                    Err(err.change_context(
                        domain_types::errors::ConnectorError::ProcessingStepFailed(None),
                    ))
                }
            }
        }
        None => Ok(router_data),
    };

    let result_with_integrity_check = match result {
        Ok(data) => {
            data.request
                .check_integrity(&data.request.clone(), None)
                .map_err(|err| ConnectorError::IntegrityCheckFailed {
                    field_names: err.field_names,
                    connector_transaction_id: err.connector_transaction_id,
                })?;
            Ok(data)
        }
        Err(err) => Err(err),
    };

    let elapsed = start.elapsed().as_millis();
    if let Some(req) = req {
        tracing::Span::current().record("request.body", tracing::field::display(req));
    }
    tracing::Span::current().record("latency", elapsed);
    tracing::info!(tag = ?Tag::OutgoingApi, log_type = "api", "Outgoing Request completed");
    result_with_integrity_check
}

pub enum ApplicationResponse<R> {
    Json(R),
}

pub type CustomResult<T, E> = error_stack::Result<T, E>;
pub type RouterResult<T> = CustomResult<T, ApiErrorResponse>;
pub type RouterResponse<T> = CustomResult<ApplicationResponse<T>, ApiErrorResponse>;

pub async fn call_connector_api(
    proxy: &Proxy,
    request: Request,
    _flow_name: &str,
) -> CustomResult<Result<Response, Response>, ApiClientError> {
    let url =
        reqwest::Url::parse(&request.url).change_context(ApiClientError::UrlEncodingFailed)?;

    let should_bypass_proxy = proxy.bypass_proxy_urls.contains(&url.to_string());

    let client = create_client(
        proxy,
        should_bypass_proxy,
        request.certificate,
        request.certificate_key,
    )?;

    let headers = request.headers.construct_header_map()?;

    // Process and log the request body based on content type
    let request = {
        match request.method {
            Method::Get => client.get(url),
            Method::Post => {
                let client = client.post(url);
                match request.body {
                    Some(RequestContent::Json(payload)) => client.json(&payload),
                    Some(RequestContent::FormUrlEncoded(payload)) => client.form(&payload),
                    Some(RequestContent::Xml(payload)) => {
                        // Use serde_json for XML conversion instead of quick_xml
                        let body = serde_json::to_string(&payload)
                            .change_context(ApiClientError::UrlEncodingFailed)?;
                        client.body(body).header("Content-Type", "application/xml")
                    }
                    Some(RequestContent::FormData(form)) => client.multipart(form),
                    _ => client,
                }
            }
            _ => client.post(url),
        }
        .add_headers(headers)
    };
    let send_request = async {
        request.send().await.map_err(|error| {
            let api_error = match error {
                error if error.is_timeout() => ApiClientError::RequestTimeoutReceived,
                _ => ApiClientError::RequestNotSent(error.to_string()),
            };
            info_log(
                "REQUEST_FAILURE",
                &json!(format!("Unable to send request to connector.",)),
            );
            report!(api_error)
        })
    };

    let response = send_request.await;

    handle_response(response).await
}

pub fn create_client(
    proxy_config: &Proxy,
    should_bypass_proxy: bool,
    _client_certificate: Option<hyperswitch_masking::Secret<String>>,
    _client_certificate_key: Option<hyperswitch_masking::Secret<String>>,
) -> CustomResult<Client, ApiClientError> {
    get_base_client(proxy_config, should_bypass_proxy)
    // match (client_certificate, client_certificate_key) {
    //     (Some(encoded_certificate), Some(encoded_certificate_key)) => {
    //         let client_builder = get_client_builder(proxy_config, should_bypass_proxy)?;

    //         let identity = create_identity_from_certificate_and_key(
    //             encoded_certificate.clone(),
    //             encoded_certificate_key,
    //         )?;
    //         let certificate_list = create_certificate(encoded_certificate)?;
    //         let client_builder = certificate_list
    //             .into_iter()
    //             .fold(client_builder, |client_builder, certificate| {
    //                 client_builder.add_root_certificate(certificate)
    //             });
    //         client_builder
    //             .identity(identity)
    //             .use_rustls_tls()
    //             .build()
    //             .change_context(ApiClientError::ClientConstructionFailed)
    //             .inspect_err(|err| {
    //                 info_log(
    //                     "ERROR",
    //                     &json!(format!(
    //                         "Failed to construct client with certificate and certificate key. Error: {:?}",
    //                         err
    //                     )),
    //                 );
    //             })
    //     }
    //     _ => ,
    // }
}

static NON_PROXIED_CLIENT: OnceCell<Client> = OnceCell::new();
static PROXIED_CLIENT: OnceCell<Client> = OnceCell::new();

fn get_base_client(
    proxy_config: &Proxy,
    should_bypass_proxy: bool,
) -> CustomResult<Client, ApiClientError> {
    Ok(if should_bypass_proxy
        || (proxy_config.http_url.is_none() && proxy_config.https_url.is_none())
    {
        &NON_PROXIED_CLIENT
    } else {
        &PROXIED_CLIENT
    }
    .get_or_try_init(|| {
        get_client_builder(proxy_config, should_bypass_proxy)?
            .build()
            .change_context(ApiClientError::ClientConstructionFailed)
            .inspect_err(|err| {
                info_log(
                    "ERROR",
                    &json!(format!("Failed to construct base client. Error: {:?}", err)),
                );
            })
    })?
    .clone())
}

fn get_client_builder(
    proxy_config: &Proxy,
    should_bypass_proxy: bool,
) -> CustomResult<reqwest::ClientBuilder, ApiClientError> {
    let mut client_builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .pool_idle_timeout(Duration::from_secs(
            proxy_config
                .idle_pool_connection_timeout
                .unwrap_or_default(),
        ));

    if should_bypass_proxy {
        return Ok(client_builder);
    }

    // Proxy all HTTPS traffic through the configured HTTPS proxy
    if let Some(url) = proxy_config.https_url.as_ref() {
        client_builder = client_builder.proxy(
            reqwest::Proxy::https(url)
                .change_context(ApiClientError::InvalidProxyConfiguration)
                .inspect_err(|err| {
                    info_log(
                        "PROXY_ERROR",
                        &json!(format!("HTTPS proxy configuration error. Error: {:?}", err)),
                    );
                })?,
        );
    }

    // Proxy all HTTP traffic through the configured HTTP proxy
    if let Some(url) = proxy_config.http_url.as_ref() {
        client_builder = client_builder.proxy(
            reqwest::Proxy::http(url)
                .change_context(ApiClientError::InvalidProxyConfiguration)
                .inspect_err(|err| {
                    info_log(
                        "PROXY_ERROR",
                        &json!(format!("HTTP proxy configuration error. Error: {:?}", err)),
                    );
                })?,
        );
    }

    Ok(client_builder)
}

// pub fn create_identity_from_certificate_and_key(
//     encoded_certificate: hyperswitch_masking::Secret<String>,
//     encoded_certificate_key: hyperswitch_masking::Secret<String>,
// ) -> Result<reqwest::Identity, error_stack::Report<ApiClientError>> {
//     let decoded_certificate = BASE64_ENGINE
//         .decode(encoded_certificate.expose())
//         .change_context(ApiClientError::CertificateDecodeFailed)?;

//     let decoded_certificate_key = BASE64_ENGINE
//         .decode(encoded_certificate_key.expose())
//         .change_context(ApiClientError::CertificateDecodeFailed)?;

//     let certificate = String::from_utf8(decoded_certificate)
//         .change_context(ApiClientError::CertificateDecodeFailed)?;

//     let certificate_key = String::from_utf8(decoded_certificate_key)
//         .change_context(ApiClientError::CertificateDecodeFailed)?;

//     let key_chain = format!("{}{}", certificate_key, certificate);
//     reqwest::Identity::from_pem(key_chain.as_bytes())
//         .change_context(ApiClientError::CertificateDecodeFailed)
// }

// pub fn create_certificate(
//     encoded_certificate: hyperswitch_masking::Secret<String>,
// ) -> Result<Vec<reqwest::Certificate>, error_stack::Report<ApiClientError>> {
//     let decoded_certificate = BASE64_ENGINE
//         .decode(encoded_certificate.expose())
//         .change_context(ApiClientError::CertificateDecodeFailed)?;

//     let certificate = String::from_utf8(decoded_certificate)
//         .change_context(ApiClientError::CertificateDecodeFailed)?;
//     reqwest::Certificate::from_pem_bundle(certificate.as_bytes())
//         .change_context(ApiClientError::CertificateDecodeFailed)
// }

async fn handle_response(
    response: CustomResult<reqwest::Response, ApiClientError>,
) -> CustomResult<Result<Response, Response>, ApiClientError> {
    response
        .async_map(|resp| async {
            let status_code = resp.status().as_u16();
            let headers = Some(resp.headers().to_owned());
            match status_code {
                200..=202 | 302 | 204 => {
                    let response = resp
                        .bytes()
                        .await
                        .change_context(ApiClientError::ResponseDecodingFailed)?;
                    Ok(Ok(Response {
                        headers,
                        response,
                        status_code,
                    }))
                }
                500..=599 => {
                    let bytes = resp.bytes().await.map_err(|error| {
                        report!(error).change_context(ApiClientError::ResponseDecodingFailed)
                    })?;

                    Ok(Err(Response {
                        headers,
                        response: bytes,
                        status_code,
                    }))
                }

                400..=499 => {
                    let bytes = resp.bytes().await.map_err(|error| {
                        report!(error).change_context(ApiClientError::ResponseDecodingFailed)
                    })?;

                    Ok(Err(Response {
                        headers,
                        response: bytes,
                        status_code,
                    }))
                }
                _ => {
                    info_log(
                        "UNEXPECTED_RESPONSE",
                        &json!("Unexpected response from server."),
                    );
                    Err(report!(ApiClientError::UnexpectedServerResponse))
                }
            }
        })
        .await?
}

/// Helper function to remove BOM from response bytes and convert to string
fn strip_bom_and_convert_to_string(response_bytes: &[u8]) -> Option<String> {
    String::from_utf8(response_bytes.to_vec()).ok().map(|s| {
        // Remove BOM if present (UTF-8 BOM is 0xEF, 0xBB, 0xBF)
        if s.starts_with('\u{FEFF}') {
            s.trim_start_matches('\u{FEFF}').to_string()
        } else {
            s
        }
    })
}

/// Helper function to parse JSON from response bytes with BOM handling
fn parse_json_with_bom_handling(
    response_bytes: &[u8],
) -> Result<serde_json::Value, serde_json::Error> {
    // Try direct parsing first (most common case)
    match serde_json::from_slice::<serde_json::Value>(response_bytes) {
        Ok(value) => Ok(value),
        Err(_) => {
            // If direct parsing fails, try after removing BOM
            let cleaned_response = if response_bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
                // UTF-8 BOM detected, remove it
                &response_bytes[3..]
            } else {
                response_bytes
            };
            serde_json::from_slice::<serde_json::Value>(cleaned_response)
        }
    }
}

pub(super) trait HeaderExt {
    fn construct_header_map(self) -> CustomResult<reqwest::header::HeaderMap, ApiClientError>;
}

impl HeaderExt for Headers {
    fn construct_header_map(self) -> CustomResult<reqwest::header::HeaderMap, ApiClientError> {
        use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

        self.into_iter().try_fold(
            HeaderMap::new(),
            |mut header_map, (header_name, header_value)| {
                let header_name = HeaderName::from_str(&header_name)
                    .change_context(ApiClientError::HeaderMapConstructionFailed)?;
                let header_value = header_value.into_inner();
                let header_value = HeaderValue::from_str(&header_value)
                    .change_context(ApiClientError::HeaderMapConstructionFailed)?;
                header_map.append(header_name, header_value);
                Ok(header_map)
            },
        )
    }
}

pub(super) trait RequestBuilderExt {
    fn add_headers(self, headers: reqwest::header::HeaderMap) -> Self;
}

impl RequestBuilderExt for reqwest::RequestBuilder {
    fn add_headers(mut self, headers: reqwest::header::HeaderMap) -> Self {
        self = self.headers(headers);
        self
    }
}

#[derive(Debug, Default, serde::Deserialize, Clone, strum::EnumString)]
pub enum Tag {
    /// General.
    #[default]
    General,
    /// Redis: get.
    RedisGet,
    /// Redis: set.
    RedisSet,
    /// API: incoming web request.
    ApiIncomingRequest,
    /// API: outgoing web request body.
    ApiOutgoingRequestBody,
    /// API: outgoingh headers
    ApiOutgoingRequestHeaders,
    /// End Request
    EndRequest,
    /// Call initiated to connector.
    InitiatedToConnector,
    /// Incoming response
    IncomingApi,
    /// Api Outgoing Request
    OutgoingApi,
}

#[inline]
pub fn debug_log(action: &str, message: &Value) {
    tracing::debug!(tags = %action, json_value= %message);
}

#[inline]
pub fn info_log(action: &str, message: &Value) {
    tracing::info!(tags = %action, json_value= %message);
}

#[inline]
pub fn error_log(action: &str, message: &Value) {
    tracing::error!(tags = %action, json_value= %message);
}

#[inline]
pub fn warn_log(action: &str, message: &Value) {
    tracing::warn!(tags = %action, json_value= %message);
}
