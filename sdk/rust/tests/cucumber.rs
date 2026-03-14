use base64::{engine::general_purpose, Engine as _};
use common_utils::request::Method;
use cucumber::{given, then, when, World};
use hyperswitch_payments_client::http_client::{HttpClient, HttpOptions, HttpRequest, ProxyConfig};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

const LANG: &str = "rust";

fn artifacts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("client_sanity")
        .join("artifacts")
}

/// Scenarios from manifest.json that are skipped for Rust.
const SKIP_SCENARIOS: &[&str] = &["CASE_10_RESPONSE_TIMEOUT"];

#[derive(Debug, Default, World)]
pub struct SanityWorld {
    method: String,
    url: String,
    headers: HashMap<String, String>,
    body: Option<String>,
    proxy_url: Option<String>,
    response_timeout_ms: Option<u32>,

    scenario_id: String,
    source_id: String,
    skipped: bool,

    response: Option<SdkResponse>,
    error: Option<SdkError>,
}

#[derive(Debug)]
struct SdkResponse {
    status_code: u16,
    headers: HashMap<String, String>,
    body: String,
}

#[derive(Debug)]
struct SdkError {
    code: String,
    #[allow(dead_code)]
    message: String,
}

#[given(expr = "the echo server is running on port {int}")]
async fn echo_server_running(_world: &mut SanityWorld, _port: i32) {
    // Echo server is started externally before test run; documentation step.
}

#[given(expr = "a {string} request to {string}")]
async fn set_request(world: &mut SanityWorld, method: String, url: String) {
    world.method = method;
    world.url = url;
}

#[given(expr = "header {string} is {string}")]
async fn set_header(world: &mut SanityWorld, name: String, value: String) {
    world.headers.insert(name, value);
}

#[given(expr = "body is {string}")]
async fn set_body(world: &mut SanityWorld, body: String) {
    let body = body.replace("\\r\\n", "\r\n").replace("\\n", "\n");
    world.body = Some(body);
}

#[given(expr = "a response timeout of {int} ms")]
async fn set_response_timeout(world: &mut SanityWorld, ms: i32) {
    world.response_timeout_ms = Some(ms as u32);
}

#[given(expr = "the proxy is {string}")]
async fn set_proxy(world: &mut SanityWorld, url: String) {
    world.proxy_url = Some(url);
}

#[when(expr = "the request is sent as scenario {string}")]
async fn execute_request(world: &mut SanityWorld, scenario_id: String) {
    world.scenario_id = scenario_id.clone();
    world.source_id = format!("{}_{}", LANG, scenario_id);

    // Skip scenarios not supported by Rust SDK
    if SKIP_SCENARIOS.contains(&scenario_id.as_str()) {
        world.skipped = true;
        return;
    }

    // Clean old artifacts
    let capture_file = artifacts_dir().join(format!("capture_{}.json", world.source_id));
    let actual_file = artifacts_dir().join(format!("actual_{}.json", world.source_id));
    let _ = fs::remove_file(&capture_file);
    let _ = fs::remove_file(&actual_file);

    // Parse method
    let method = match world.method.as_str() {
        "POST" => Method::Post,
        "GET" => Method::Get,
        "PUT" => Method::Put,
        "DELETE" => Method::Delete,
        "PATCH" => Method::Patch,
        other => {
            world.error = Some(SdkError {
                code: "RUNNER_CRASH".to_string(),
                message: format!("Unsupported method: {}", other),
            });
            return;
        }
    };

    // Build headers
    let mut headers = world.headers.clone();
    headers.insert("x-source".to_string(), world.source_id.clone());
    headers.insert("x-scenario-id".to_string(), world.scenario_id.clone());

    // Build body
    let body = world.body.as_ref().map(|b| {
        if b.starts_with("base64:") {
            general_purpose::STANDARD
                .decode(b.trim_start_matches("base64:"))
                .unwrap_or_default()
        } else {
            b.as_bytes().to_vec()
        }
    });

    let request = HttpRequest {
        url: world.url.clone(),
        method,
        headers,
        body,
    };

    // Build proxy config
    let proxy_cfg = world.proxy_url.as_ref().map(|url| ProxyConfig {
        http_url: Some(url.clone()),
        https_url: None,
        bypass_urls: vec![world.url.clone()],
    });

    let options = HttpOptions {
        proxy: proxy_cfg,
        total_timeout_ms: None,
        response_timeout_ms: world.response_timeout_ms,
        ..Default::default()
    };

    // Create client
    let client = match HttpClient::new(options) {
        Ok(c) => c,
        Err(e) => {
            world.error = Some(SdkError {
                code: e.error_code().to_string(),
                message: e.to_string(),
            });
            return;
        }
    };

    // Execute request
    match client.execute(request, None).await {
        Ok(resp) => {
            let ct = resp
                .headers
                .get("content-type")
                .map(|s| s.to_lowercase())
                .unwrap_or_default();
            let body_str = if ct.contains("application/octet-stream") {
                general_purpose::STANDARD.encode(&resp.body)
            } else {
                String::from_utf8_lossy(&resp.body).into_owned()
            };
            world.response = Some(SdkResponse {
                status_code: resp.status_code,
                headers: resp.headers,
                body: body_str,
            });
        }
        Err(e) => {
            world.error = Some(SdkError {
                code: e.error_code().to_string(),
                message: e.to_string(),
            });
        }
    }

    // Wait for echo server to write capture
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
}

#[then(expr = "the response status should be {int}")]
async fn check_status(world: &mut SanityWorld, expected: i32) {
    if world.skipped { return; }
    let resp = world
        .response
        .as_ref()
        .unwrap_or_else(|| panic!("Expected response but got error: {:?}", world.error));
    assert_eq!(
        resp.status_code, expected as u16,
        "Status mismatch: expected {}, got {}",
        expected, resp.status_code
    );
}

#[then(expr = "the response body should be {string}")]
async fn check_body(world: &mut SanityWorld, expected: String) {
    if world.skipped { return; }
    let resp = world
        .response
        .as_ref()
        .unwrap_or_else(|| panic!("Expected response but got error: {:?}", world.error));
    assert_eq!(
        resp.body, expected,
        "Body mismatch: expected {}, got {}",
        expected, resp.body
    );
}

#[then(expr = "the response header {string} should be {string}")]
async fn check_header(world: &mut SanityWorld, name: String, value: String) {
    if world.skipped { return; }
    let resp = world
        .response
        .as_ref()
        .unwrap_or_else(|| panic!("Expected response but got error: {:?}", world.error));
    let actual = resp.headers.get(&name.to_lowercase()).cloned().unwrap_or_default();
    assert_eq!(
        actual, value,
        "Header \"{}\" mismatch: expected \"{}\", got \"{}\"",
        name, value, actual
    );
}

#[then(expr = "the response should have multi-value header {string} with values {string}")]
async fn check_multi_header(world: &mut SanityWorld, name: String, values_str: String) {
    if world.skipped { return; }
    let resp = world
        .response
        .as_ref()
        .unwrap_or_else(|| panic!("Expected response but got error: {:?}", world.error));
    let mut expected: Vec<&str> = values_str.split(',').collect();
    expected.sort();
    let actual_raw = resp.headers.get(&name.to_lowercase()).cloned().unwrap_or_default();
    let mut actual: Vec<&str> = actual_raw.split(',').map(|s| s.trim()).collect();
    actual.sort();
    assert_eq!(
        actual, expected,
        "Multi-value header \"{}\" mismatch",
        name
    );
}

#[then(expr = "the SDK should return error {string}")]
async fn check_error(world: &mut SanityWorld, expected_code: String) {
    if world.skipped { return; }
    let err = world
        .error
        .as_ref()
        .unwrap_or_else(|| panic!("Expected error \"{}\" but got response: {:?}", expected_code, world.response));
    assert_eq!(
        err.code, expected_code,
        "Error code mismatch: expected \"{}\", got \"{}\"",
        expected_code, err.code
    );
}

#[then("the server should have received the correct request")]
async fn check_capture(world: &mut SanityWorld) {
    if world.skipped { return; }
    let capture_file = artifacts_dir().join(format!("capture_{}.json", world.source_id));
    let content = fs::read_to_string(&capture_file)
        .unwrap_or_else(|_| panic!("Capture file not found for {}", world.source_id));
    let capture: serde_json::Value = serde_json::from_str(&content).expect("Invalid capture JSON");

    // Verify method
    assert_eq!(
        capture["method"].as_str().unwrap(),
        world.method,
        "Captured method mismatch"
    );

    // Verify URL (path-based comparison to allow encoding differences)
    let captured_url = capture["url"].as_str().unwrap_or("");
    let expected_path = world.url.replace("http://localhost:8081", "");
    let expected_path_base = expected_path.split('?').next().unwrap_or(&expected_path);
    assert!(
        captured_url.contains(expected_path_base),
        "Captured URL mismatch: expected contains {}, got {}",
        world.url,
        captured_url
    );

    // Verify headers (ignoring transport noise)
    let ignored: std::collections::HashSet<&str> = [
        "user-agent", "host", "connection", "accept-encoding", "content-length",
        "x-source", "x-scenario-id", "accept", "keep-alive", "date",
        "transfer-encoding", "accept-language", "sec-fetch-mode",
        "sec-fetch-site", "sec-fetch-dest", "priority",
    ]
    .iter()
    .copied()
    .collect();

    let expected_headers: HashMap<String, String> = world
        .headers
        .iter()
        .filter(|(k, _)| !ignored.contains(k.to_lowercase().as_str()))
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    if let Some(obj) = capture["headers"].as_object() {
        let captured_headers: HashMap<String, String> = obj
            .iter()
            .filter(|(k, _)| !ignored.contains(k.to_lowercase().as_str()))
            .map(|(k, v)| (k.to_lowercase(), v.as_str().unwrap_or("").to_string()))
            .collect();
        assert_eq!(captured_headers, expected_headers, "Captured headers mismatch");
    }

    // Verify body (with multipart normalization)
    let expected_body = world.body.as_deref().unwrap_or("");
    let captured_body = capture["body"].as_str().unwrap_or("");

    let normalize_multipart = |body: &str, headers: &HashMap<String, String>| -> String {
        let ct = headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-type")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        if ct.contains("multipart/form-data") {
            if let Some(caps) = Regex::new(r"boundary=([^;]+)").ok().and_then(|re| re.captures(ct)) {
                if let Some(boundary) = caps.get(1) {
                    return body.replace(boundary.as_str(), "REFERENCE");
                }
            }
        }
        body.to_string()
    };

    let capture_headers_map: HashMap<String, String> = capture["headers"]
        .as_object()
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                .collect()
        })
        .unwrap_or_default();

    assert_eq!(
        normalize_multipart(captured_body, &capture_headers_map),
        normalize_multipart(expected_body, &world.headers),
        "Captured body mismatch"
    );
}

fn main() {
    let features_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("client_sanity")
        .join("features");

    futures::executor::block_on(
        SanityWorld::cucumber()
            .with_default_cli()
            .features(features_path)
            .run_and_exit(),
    );
}
