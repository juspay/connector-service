//! Flow metadata extraction from services.proto
//!
//! This module parses the gRPC service definitions from services.proto and
//! generates flow metadata that maps probe flow keys to their canonical
//! gRPC service.rpc names and human-readable descriptions.
//!
//! NO HARDCODED DATA - All metadata is parsed from services.proto at runtime.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Flow metadata extracted from services.proto
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FlowMetadata {
    /// Flow key used in probe (e.g., "authorize", "capture")
    pub flow_key: String,
    /// Full gRPC service.rpc name (e.g., "PaymentService.Authorize")
    pub service_rpc: String,
    /// Human-readable description from proto comments
    pub description: String,
    /// Service name (e.g., "PaymentService")
    pub service_name: String,
    /// RPC/method name (e.g., "Authorize")
    pub rpc_name: String,
    /// Category for grouping in documentation (e.g., "Payments", "Refunds")
    pub category: String,
    /// gRPC request message name (e.g., "PaymentServiceAuthorizeRequest")
    pub grpc_request: String,
    /// gRPC response message name (e.g., "PaymentServiceAuthorizeResponse")
    pub grpc_response: String,
}

impl FlowMetadata {
    /// Create a new flow metadata entry
    pub fn new(
        flow_key: String,
        service_name: String,
        rpc_name: String,
        description: String,
        grpc_request: String,
        grpc_response: String,
    ) -> Self {
        let category = get_category_for_service(&service_name);
        Self {
            flow_key,
            service_rpc: format!("{}.{}", service_name, rpc_name),
            description,
            service_name,
            rpc_name,
            category,
            grpc_request,
            grpc_response,
        }
    }
}

/// Get category for a service name
fn get_category_for_service(service_name: &str) -> String {
    match service_name {
        "PaymentService" => "Payments".to_string(),
        "RecurringPaymentService" => "Mandates".to_string(),
        "RefundService" => "Refunds".to_string(),
        "CustomerService" => "Customers".to_string(),
        "PaymentMethodService" => "Payments".to_string(),
        "MerchantAuthenticationService" => "Authentication".to_string(),
        "PaymentMethodAuthenticationService" => "Authentication".to_string(),
        "DisputeService" => "Disputes".to_string(),
        "EventService" => "Events".to_string(),
        _ => "Other".to_string(),
    }
}

/// Mapping from (service_name, rpc_name) to probe flow key
/// This is the only configuration needed - everything else comes from proto
fn get_flow_key_mapping() -> HashMap<(&'static str, &'static str), &'static str> {
    [
        // PaymentService
        (("PaymentService", "Authorize"), "authorize"),
        (("PaymentService", "Capture"), "capture"),
        (("PaymentService", "Get"), "get"),
        (("PaymentService", "Void"), "void"),
        (("PaymentService", "Reverse"), "reverse"),
        (("PaymentService", "Refund"), "refund"),
        (("PaymentService", "CreateOrder"), "create_order"),
        (("PaymentService", "SetupRecurring"), "setup_recurring"),
        (("PaymentService", "IncrementalAuthorization"), "incremental_auth"),
        (("PaymentService", "VerifyRedirectResponse"), "verify_redirect"),
        // RecurringPaymentService
        (("RecurringPaymentService", "Charge"), "recurring_charge"),
        (("RecurringPaymentService", "Revoke"), "mandate_revoke"),
        // RefundService
        (("RefundService", "Get"), "rsync"),
        // CustomerService
        (("CustomerService", "Create"), "create_customer"),
        // PaymentMethodService
        (("PaymentMethodService", "Tokenize"), "tokenize"),
        // MerchantAuthenticationService
        (("MerchantAuthenticationService", "CreateAccessToken"), "create_access_token"),
        (("MerchantAuthenticationService", "CreateSessionToken"), "create_session_token"),
        (("MerchantAuthenticationService", "CreateSdkSessionToken"), "sdk_session_token"),
        // PaymentMethodAuthenticationService
        (("PaymentMethodAuthenticationService", "PreAuthenticate"), "pre_authenticate"),
        (("PaymentMethodAuthenticationService", "Authenticate"), "authenticate"),
        (("PaymentMethodAuthenticationService", "PostAuthenticate"), "post_authenticate"),
        // DisputeService
        (("DisputeService", "SubmitEvidence"), "dispute_submit_evidence"),
        (("DisputeService", "Get"), "dispute_get"),
        (("DisputeService", "Defend"), "dispute_defend"),
        (("DisputeService", "Accept"), "dispute_accept"),
        // EventService
        (("EventService", "HandleEvent"), "handle_event"),
    ]
    .iter()
    .cloned()
    .collect()
}

/// Parse services.proto and extract flow metadata.
/// Maps probe flow keys to their gRPC service.rpc names and descriptions.
/// 
/// # Panics
/// Panics if services.proto cannot be found or parsed.
pub fn parse_services_proto() -> Vec<FlowMetadata> {
    // Try to find services.proto
    let proto_paths = [
        "backend/grpc-api-types/proto/services.proto",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../grpc-api-types/proto/services.proto"),
    ];
    
    let proto_content = proto_paths
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok());
    
    match proto_content {
        Some(content) => parse_proto_content(&content),
        None => {
            panic!(
                "Could not find services.proto. Searched paths:\n  {}",
                proto_paths.join("\n  ")
            );
        }
    }
}

/// Parse proto file content and extract service/RPC definitions with comments
fn parse_proto_content(content: &str) -> Vec<FlowMetadata> {
    let mut metadata: Vec<FlowMetadata> = Vec::new();
    let mut current_service: Option<String> = None;
    let mut pending_comment: String = String::new();
    
    let flow_key_mapping = get_flow_key_mapping();
    
    for line in content.lines() {
        let trimmed = line.trim();
        
        // Track service declarations
        if trimmed.starts_with("service ") && trimmed.ends_with("{") {
            let service_name = trimmed
                .strip_prefix("service ")
                .unwrap_or("")
                .trim()
                .trim_end_matches('{')
                .trim()
                .to_string();
            current_service = Some(service_name);
            pending_comment.clear();
            continue;
        }
        
        // Track closing braces (end of service)
        if trimmed == "}" {
            current_service = None;
            pending_comment.clear();
            continue;
        }
        
        // Collect comment lines (description) - must be directly above the RPC
        if trimmed.starts_with("//") {
            let comment = trimmed.trim_start_matches('/').trim();
            if !comment.is_empty() {
                // Check if this is a standalone line comment (not inline)
                if !line.starts_with("rpc") {
                    if !pending_comment.is_empty() {
                        pending_comment.push(' ');
                    }
                    pending_comment.push_str(comment);
                }
            }
            continue;
        }
        
        // Parse RPC definitions
        if let Some(ref service_name) = current_service {
            if trimmed.starts_with("rpc ") {
                // Extract RPC name
                let rpc_part = trimmed
                    .strip_prefix("rpc ")
                    .unwrap_or("")
                    .trim();
                let rpc_name = rpc_part
                    .split('(')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                
                // Extract request and response message names
                let (grpc_request, grpc_response) = extract_message_names(trimmed);
                
                // Look up flow key using (service, rpc) tuple
                if let Some(&flow_key) = flow_key_mapping.get(&(service_name.as_str(), rpc_name.as_str())) {
                    let description = clean_description(&pending_comment);
                    metadata.push(FlowMetadata::new(
                        flow_key.to_string(),
                        service_name.clone(),
                        rpc_name,
                        description,
                        grpc_request,
                        grpc_response,
                    ));
                }
                
                // Clear pending comment after processing an RPC
                pending_comment.clear();
            }
        }
    }
    
    if metadata.is_empty() {
        panic!(
            "No flows extracted from services.proto. Check that the proto file contains RPC definitions."
        );
    }
    
    eprintln!("Extracted {} flow metadata entries from services.proto", metadata.len());
    metadata
}

/// Extract request and response message names from RPC definition
/// Example: "rpc Authorize(PaymentServiceAuthorizeRequest) returns (PaymentServiceAuthorizeResponse);"
fn extract_message_names(rpc_line: &str) -> (String, String) {
    // Find the request message between first pair of parentheses
    let request = rpc_line
        .split('(')
        .nth(1)
        .and_then(|s| s.split(')').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    
    // Find the response message after "returns"
    let response = rpc_line
        .split("returns")
        .nth(1)
        .and_then(|s| s.split('(').nth(1))
        .and_then(|s| s.split(')').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    
    (request, response)
}

/// Clean up description text extracted from comments
fn clean_description(desc: &str) -> String {
    // Remove " // " patterns that might have been captured
    let cleaned = desc
        .replace(" // ", " ")
        .replace("  ", " ")
        .trim()
        .to_string();
    
    // Ensure it ends with a period for consistency
    if !cleaned.is_empty() 
        && !cleaned.ends_with('.') 
        && !cleaned.ends_with('!') 
        && !cleaned.ends_with('?') 
    {
        format!("{}.", cleaned)
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_extract_message_names() {
        let rpc_line = "rpc Authorize(PaymentServiceAuthorizeRequest) returns (PaymentServiceAuthorizeResponse);";
        let (req, resp) = extract_message_names(rpc_line);
        assert_eq!(req, "PaymentServiceAuthorizeRequest");
        assert_eq!(resp, "PaymentServiceAuthorizeResponse");
    }
    
    #[test]
    fn test_clean_description() {
        assert_eq!(clean_description("Test description"), "Test description.");
        assert_eq!(clean_description("Test description."), "Test description.");
        assert_eq!(clean_description("Test // description"), "Test description.");
    }
    
    #[test]
    fn test_get_category_for_service() {
        assert_eq!(get_category_for_service("PaymentService"), "Payments");
        assert_eq!(get_category_for_service("RefundService"), "Refunds");
        assert_eq!(get_category_for_service("UnknownService"), "Other");
    }
    
    #[test]
    fn test_flow_key_mapping_exists() {
        let mapping = get_flow_key_mapping();
        // Verify essential mappings exist
        assert!(mapping.contains_key(&("PaymentService", "Authorize")));
        assert!(mapping.contains_key(&("PaymentService", "Capture")));
        assert!(mapping.contains_key(&("PaymentService", "Get")));
        assert!(mapping.contains_key(&("RefundService", "Get")));
    }
}