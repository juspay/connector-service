use std::collections::HashSet;

use serde::Serialize;

use crate::config::max_iterations;
use crate::error_parsing::{is_not_implemented, is_not_supported, parse_missing_field, parse_missing_field_alt};
use crate::json_utils::{clean_proto_request, convert_rust_to_proto_json};
use crate::normalizer::extract_sample;
use crate::types::FlowResult;

pub(crate) type PciFfi = domain_types::payment_method_data::DefaultPCIHolder;

pub(crate) fn run_probe<Req, F>(mut req: Req, mut call: F, mut patch: impl FnMut(&mut Req, &str)) -> FlowResult
where
    Req: Clone + Serialize,
    F: FnMut(
        Req,
    ) -> Result<
        Option<common_utils::request::Request>,
        grpc_api_types::payments::RequestError,
    >,
{
    let mut required_fields: Vec<String> = Vec::new();
    let mut seen_fields: HashSet<String> = HashSet::new();

    for _i in 0..max_iterations() {
        match call(req.clone()) {
            Ok(Some(connector_req)) => {
                // If the connector returned a request with no URL, treat it as not_implemented.
                // This happens when ConnectorIntegrationV2 is implemented as an empty default
                // impl (no get_url override), so the default build_request_v2 produces a
                // Request with an empty URL string.
                if connector_req.url.is_empty() {
                    return FlowResult {
                        status: "not_implemented".to_string(),
                        required_fields,
                        proto_request: None,
                        sample: None,
                        error: None,
                        service_rpc: None,
                        description: None,
                    };
                }

                // Convert Rust serde JSON to proper proto JSON format, then clean it
                let proto_json = serde_json::to_value(&req)
                    .ok()
                    .map(|v| convert_rust_to_proto_json(&v))
                    .map(|v| clean_proto_request(&v));
                return FlowResult {
                    status: "supported".to_string(),
                    required_fields,
                    proto_request: proto_json,
                    sample: Some(extract_sample(&connector_req)),
                    error: None,
                    service_rpc: None,
                    description: None,
                };
            }
            Ok(None) => {
                return FlowResult {
                    status: "not_implemented".to_string(),
                    required_fields,
                    proto_request: None,
                    sample: None,
                    error: None,
                    service_rpc: None,
                    description: None,
                };
            }
            Err(ref e) => {
                let msg = e.error_message.as_deref().unwrap_or("");
                if is_not_implemented(msg) {
                    return FlowResult {
                        status: "not_implemented".to_string(),
                        required_fields,
                        proto_request: None,
                        sample: None,
                        error: Some(msg.to_string()),
                        service_rpc: None,
                        description: None,
                    };
                } else if is_not_supported(msg) {
                    return FlowResult {
                        status: "not_supported".to_string(),
                        required_fields,
                        proto_request: None,
                        sample: None,
                        error: Some(msg.to_string()),
                        service_rpc: None,
                        description: None,
                    };
                } else if let Some(field) =
                    parse_missing_field(msg).or_else(|| parse_missing_field_alt(msg))
                {
                    if seen_fields.contains(&field) {
                        return FlowResult {
                            status: "error".to_string(),
                            required_fields,
                            proto_request: None,
                            sample: None,
                            error: Some(format!("Stuck on field: {field} — {msg}")),
                            service_rpc: None,
                            description: None,
                        };
                    }
                    seen_fields.insert(field.clone());
                    required_fields.push(field.clone());
                    patch(&mut req, &field);
                } else {
                    return FlowResult {
                        status: "error".to_string(),
                        required_fields,
                        proto_request: None,
                        sample: None,
                        error: Some(msg.to_string()),
                        service_rpc: None,
                        description: None,
                    };
                }
            }
        }
    }

    FlowResult {
        status: "error".to_string(),
        required_fields,
        proto_request: None,
        sample: None,
        error: Some("Max iterations reached".to_string()),
        service_rpc: None,
        description: None,
    }
}
