use std::collections::HashMap;

use connector_service_ffi::bindings::uniffi as ffi_bindings;
use connector_service_ffi::errors::UniffiError;
use grpc_api_types::payments::{
    self, connector_specific_config, ConnectorSpecificConfig, Environment, FfiConnectorHttpRequest,
    FfiConnectorHttpResponse, FfiOptions, RequestError, ResponseError,
};
use prost::Message;
use reqwest::{blocking::Client, Method};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

use crate::harness::{
    credentials::{load_connector_auth, ConnectorAuth},
    scenario_api::parse_tonic_payload,
    scenario_types::ScenarioError,
};

type RequestTransformer = fn(Vec<u8>, Vec<u8>) -> Result<Vec<u8>, UniffiError>;
type ResponseTransformer = fn(Vec<u8>, Vec<u8>, Vec<u8>) -> Result<Vec<u8>, UniffiError>;

/// Returns whether a suite is currently wired for SDK/FFI execution.
pub fn supports_sdk_suite(suite: &str) -> bool {
    matches!(
        suite,
        "create_access_token"
            | "create_customer"
            | "authorize"
            | "capture"
            | "void"
            | "refund"
            | "get"
            | "setup_recurring"
            | "recurring_charge"
    )
}

/// Returns whether a connector has SDK transformer/auth support in this harness.
pub fn supports_sdk_connector(connector: &str) -> bool {
    matches!(connector, "stripe" | "authorizedotnet" | "paypal")
}

/// Executes one scenario via SDK FFI request/response transformers.
pub fn execute_sdk_request_from_payload(
    suite: &str,
    scenario: &str,
    grpc_req: &Value,
    connector: &str,
) -> Result<String, ScenarioError> {
    // SDK path still uses the same credential loader as grpcurl/tonic paths.
    let auth = load_connector_auth(connector).map_err(|error| ScenarioError::CredentialLoad {
        connector: connector.to_string(),
        message: error.to_string(),
    })?;

    let options = build_ffi_options(connector, &auth)?;
    let options_bytes = options.encode_to_vec();

    match suite {
        "create_access_token" => execute_sdk_flow::<
            payments::MerchantAuthenticationServiceCreateAccessTokenRequest,
            payments::MerchantAuthenticationServiceCreateAccessTokenResponse,
        >(
            suite,
            scenario,
            connector,
            grpc_req,
            &options_bytes,
            ffi_bindings::create_access_token_req_transformer,
            ffi_bindings::create_access_token_res_transformer,
        ),
        "create_customer" => execute_sdk_flow::<
            payments::CustomerServiceCreateRequest,
            payments::CustomerServiceCreateResponse,
        >(
            suite,
            scenario,
            connector,
            grpc_req,
            &options_bytes,
            ffi_bindings::create_req_transformer,
            ffi_bindings::create_res_transformer,
        ),
        "authorize" => execute_sdk_flow::<
            payments::PaymentServiceAuthorizeRequest,
            payments::PaymentServiceAuthorizeResponse,
        >(
            suite,
            scenario,
            connector,
            grpc_req,
            &options_bytes,
            ffi_bindings::authorize_req_transformer,
            ffi_bindings::authorize_res_transformer,
        ),
        "capture" => execute_sdk_flow::<
            payments::PaymentServiceCaptureRequest,
            payments::PaymentServiceCaptureResponse,
        >(
            suite,
            scenario,
            connector,
            grpc_req,
            &options_bytes,
            ffi_bindings::capture_req_transformer,
            ffi_bindings::capture_res_transformer,
        ),
        "void" => execute_sdk_flow::<
            payments::PaymentServiceVoidRequest,
            payments::PaymentServiceVoidResponse,
        >(
            suite,
            scenario,
            connector,
            grpc_req,
            &options_bytes,
            ffi_bindings::void_req_transformer,
            ffi_bindings::void_res_transformer,
        ),
        "refund" => {
            execute_sdk_flow::<payments::PaymentServiceRefundRequest, payments::RefundResponse>(
                suite,
                scenario,
                connector,
                grpc_req,
                &options_bytes,
                ffi_bindings::refund_req_transformer,
                ffi_bindings::refund_res_transformer,
            )
        }
        "get" => execute_sdk_flow::<
            payments::PaymentServiceGetRequest,
            payments::PaymentServiceGetResponse,
        >(
            suite,
            scenario,
            connector,
            grpc_req,
            &options_bytes,
            ffi_bindings::get_req_transformer,
            ffi_bindings::get_res_transformer,
        ),
        "setup_recurring" => execute_sdk_flow::<
            payments::PaymentServiceSetupRecurringRequest,
            payments::PaymentServiceSetupRecurringResponse,
        >(
            suite,
            scenario,
            connector,
            grpc_req,
            &options_bytes,
            ffi_bindings::setup_recurring_req_transformer,
            ffi_bindings::setup_recurring_res_transformer,
        ),
        "recurring_charge" => execute_sdk_flow::<
            payments::RecurringPaymentServiceChargeRequest,
            payments::RecurringPaymentServiceChargeResponse,
        >(
            suite,
            scenario,
            connector,
            grpc_req,
            &options_bytes,
            ffi_bindings::charge_req_transformer,
            ffi_bindings::charge_res_transformer,
        ),
        _ => Err(ScenarioError::UnsupportedSuite {
            suite: suite.to_string(),
        }),
    }
}

/// Generic SDK execution pipeline:
/// 1. parse JSON payload into protobuf request
/// 2. run request transformer (proto -> connector HTTP request)
/// 3. execute HTTP call
/// 4. run response transformer (HTTP response -> proto)
/// 5. serialize proto response to pretty JSON
fn execute_sdk_flow<Req, Res>(
    suite: &str,
    scenario: &str,
    connector: &str,
    grpc_req: &Value,
    options_bytes: &[u8],
    req_transformer: RequestTransformer,
    res_transformer: ResponseTransformer,
) -> Result<String, ScenarioError>
where
    Req: Message + Default + DeserializeOwned,
    Res: Message + Default + Serialize,
{
    let request_payload: Req = parse_sdk_payload(suite, scenario, connector, grpc_req)?;
    let request_bytes = request_payload.encode_to_vec();

    let ffi_http_request_bytes = req_transformer(request_bytes.clone(), options_bytes.to_vec())
        .map_err(|error| ScenarioError::SdkExecution {
            message: format!(
                "sdk request transformer invocation failed for '{}/{}': {:?}",
                suite, scenario, error
            ),
        })?;

    let ffi_http_request = FfiConnectorHttpRequest::decode(ffi_http_request_bytes.as_slice())
        .map_err(|decode_error| {
            if let Ok(request_error) = RequestError::decode(ffi_http_request_bytes.as_slice()) {
                return map_request_error("request transformer", suite, scenario, request_error);
            }

            ScenarioError::SdkExecution {
                message: format!(
                    "sdk decode failed for '{}'/'{}' request bytes: {}",
                    suite, scenario, decode_error
                ),
            }
        })?;

    let ffi_http_response = execute_connector_http_request(ffi_http_request, suite, scenario)?;
    let ffi_http_response_bytes = ffi_http_response.encode_to_vec();

    let proto_response_bytes = res_transformer(
        ffi_http_response_bytes,
        request_bytes,
        options_bytes.to_vec(),
    )
    .map_err(|error| ScenarioError::SdkExecution {
        message: format!(
            "sdk response transformer invocation failed for '{}/{}': {:?}",
            suite, scenario, error
        ),
    })?;

    let proto_response = Res::decode(proto_response_bytes.as_slice()).map_err(|decode_error| {
        if let Ok(response_error) = ResponseError::decode(proto_response_bytes.as_slice()) {
            return map_response_error("response transformer", suite, scenario, response_error);
        }

        ScenarioError::SdkExecution {
            message: format!(
                "sdk decode failed for '{}'/'{}' response bytes: {}",
                suite, scenario, decode_error
            ),
        }
    })?;

    serde_json::to_string_pretty(&proto_response)
        .map_err(|source| ScenarioError::JsonSerialize { source })
}

/// Performs the raw HTTP call described by FFI transformed request.
fn execute_connector_http_request(
    request: FfiConnectorHttpRequest,
    suite: &str,
    scenario: &str,
) -> Result<FfiConnectorHttpResponse, ScenarioError> {
    let method = Method::from_bytes(request.method.as_bytes()).map_err(|error| {
        ScenarioError::SdkExecution {
            message: format!(
                "sdk invalid HTTP method for '{}'/'{}': {}",
                suite, scenario, error
            ),
        }
    })?;

    let client = Client::builder()
        .build()
        .map_err(|error| ScenarioError::SdkExecution {
            message: format!(
                "sdk HTTP client initialization failed for '{}'/'{}': {}",
                suite, scenario, error
            ),
        })?;

    let mut builder = client.request(method, &request.url);
    // Preserve connector headers exactly as produced by the transformer.
    for (key, value) in &request.headers {
        builder = builder.header(key, value);
    }

    if let Some(body) = request.body {
        builder = builder.body(body);
    }

    let response = builder
        .send()
        .map_err(|error| ScenarioError::SdkExecution {
            message: format!(
                "sdk HTTP request failed for '{}'/'{}': {}",
                suite, scenario, error
            ),
        })?;

    let status_code = u32::from(response.status().as_u16());
    let mut headers = HashMap::new();
    for (name, value) in response.headers() {
        if let Ok(value) = value.to_str() {
            headers.insert(name.to_string(), value.to_string());
        }
    }

    let body = response
        .bytes()
        .map_err(|error| ScenarioError::SdkExecution {
            message: format!(
                "sdk HTTP response read failed for '{}'/'{}': {}",
                suite, scenario, error
            ),
        })?
        .to_vec();

    Ok(FfiConnectorHttpResponse {
        status_code,
        headers,
        body,
    })
}

/// Parses scenario JSON payload into a strongly typed protobuf request.
pub fn parse_sdk_payload<T: DeserializeOwned>(
    suite: &str,
    scenario: &str,
    connector: &str,
    grpc_req: &Value,
) -> Result<T, ScenarioError> {
    parse_tonic_payload(suite, scenario, connector, grpc_req).map_err(convert_sdk_error_label)
}

/// Builds FFI options bundle used by all request/response transformers.
fn build_ffi_options(
    connector: &str,
    connector_auth: &ConnectorAuth,
) -> Result<FfiOptions, ScenarioError> {
    let connector_config = build_proto_connector_config(connector, connector_auth)?;

    Ok(FfiOptions {
        environment: environment_discriminant(ffi_environment()),
        connector_config: Some(connector_config),
    })
}

fn environment_discriminant(environment: Environment) -> i32 {
    match environment {
        Environment::Sandbox => 0,
        Environment::Production => 1,
    }
}

/// Converts harness credential shape into connector-specific protobuf config oneof.
pub fn build_proto_connector_config(
    connector: &str,
    connector_auth: &ConnectorAuth,
) -> Result<ConnectorSpecificConfig, ScenarioError> {
    match (connector, connector_auth) {
        ("stripe", ConnectorAuth::HeaderKey { api_key }) => Ok(ConnectorSpecificConfig {
            config: Some(connector_specific_config::Config::Stripe(
                payments::StripeConfig {
                    api_key: Some(api_key.to_string().into()),
                    base_url: None,
                },
            )),
        }),
        ("authorizedotnet", ConnectorAuth::BodyKey { api_key, key1 }) => {
            Ok(ConnectorSpecificConfig {
                config: Some(connector_specific_config::Config::Authorizedotnet(
                    payments::AuthorizedotnetConfig {
                        name: Some(api_key.to_string().into()),
                        transaction_key: Some(key1.to_string().into()),
                        base_url: None,
                    },
                )),
            })
        }
        ("paypal", ConnectorAuth::BodyKey { api_key, key1 }) => Ok(ConnectorSpecificConfig {
            config: Some(connector_specific_config::Config::Paypal(
                payments::PaypalConfig {
                    client_id: Some(key1.to_string().into()),
                    client_secret: Some(api_key.to_string().into()),
                    payer_id: None,
                    base_url: None,
                },
            )),
        }),
        (
            "paypal",
            ConnectorAuth::SignatureKey {
                api_key,
                key1,
                api_secret,
            },
        ) => Ok(ConnectorSpecificConfig {
            config: Some(connector_specific_config::Config::Paypal(
                payments::PaypalConfig {
                    client_id: Some(key1.to_string().into()),
                    client_secret: Some(api_key.to_string().into()),
                    payer_id: Some(api_secret.to_string().into()),
                    base_url: None,
                },
            )),
        }),
        _ => Err(ScenarioError::CredentialLoad {
            connector: connector.to_string(),
            message: "unsupported connector auth shape for SDK harness".to_string(),
        }),
    }
}

/// SDK environment selector (defaults to sandbox for safety).
fn ffi_environment() -> Environment {
    let env = std::env::var("UCS_SDK_ENVIRONMENT")
        .unwrap_or_default()
        .to_ascii_lowercase();

    if env == "production" || env == "prod" {
        Environment::Production
    } else {
        Environment::Sandbox
    }
}

fn map_request_error(
    stage: &str,
    suite: &str,
    scenario: &str,
    error: RequestError,
) -> ScenarioError {
    let mut details = Vec::new();
    if let Some(message) = error.error_message.filter(|msg| !msg.is_empty()) {
        details.push(message);
    }
    if let Some(code) = error.error_code.filter(|code| !code.is_empty()) {
        details.push(format!("code={code}"));
    }
    if let Some(status_code) = error.status_code {
        details.push(format!("status_code={status_code}"));
    }

    let detail_text = if details.is_empty() {
        "unknown ffi request error".to_string()
    } else {
        details.join(", ")
    };

    ScenarioError::SdkExecution {
        message: format!(
            "sdk {} failed for '{}/{}': {}",
            stage, suite, scenario, detail_text
        ),
    }
}

fn map_response_error(
    stage: &str,
    suite: &str,
    scenario: &str,
    error: ResponseError,
) -> ScenarioError {
    let mut details = Vec::new();
    if let Some(message) = error.error_message.filter(|msg| !msg.is_empty()) {
        details.push(message);
    }
    if let Some(code) = error.error_code.filter(|code| !code.is_empty()) {
        details.push(format!("code={code}"));
    }
    if let Some(status_code) = error.status_code {
        details.push(format!("status_code={status_code}"));
    }

    let detail_text = if details.is_empty() {
        "unknown ffi response error".to_string()
    } else {
        details.join(", ")
    };

    ScenarioError::SdkExecution {
        message: format!(
            "sdk {} failed for '{}/{}': {}",
            stage, suite, scenario, detail_text
        ),
    }
}

/// Re-labels generic execution errors into SDK-specific error variant.
fn convert_sdk_error_label(error: ScenarioError) -> ScenarioError {
    match error {
        ScenarioError::GrpcurlExecution { message } => ScenarioError::SdkExecution { message },
        other => other,
    }
}
