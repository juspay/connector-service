use common_utils::request::Method;
use base64::{engine::general_purpose, Engine as _};
use hyperswitch_payments_client::http_client::{
    HttpClient, HttpOptions, HttpRequest, ProxyConfig,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Read};

#[derive(Deserialize)]
struct RunnerInput {
    scenario_id: String,
    source_id: String,
    request: RequestDetails,
    client_timeout_ms: Option<u64>,
    proxy: Option<ScenarioProxy>,
}

#[derive(Deserialize)]
struct ScenarioProxy {
    http_url: Option<String>,
    https_url: Option<String>,
}

#[derive(Deserialize)]
struct RequestDetails {
    url: String,
    method: String,
    headers: HashMap<String, String>,
    body: Option<String>,
}

#[derive(Serialize)]
struct RunnerOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<SdkResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<SdkError>,
}

#[derive(Serialize)]
struct SdkResponse {
    #[serde(rename = "statusCode")]
    status_code: u16,
    headers: HashMap<String, String>,
    body: String,
}

#[derive(Serialize)]
struct SdkError {
    code: String,
    message: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    let input: RunnerInput = serde_json::from_str(&buffer)?;

    let method = match input.request.method.as_str() {
        "POST" => Method::Post,
        "GET" => Method::Get,
        "PUT" => Method::Put,
        "DELETE" => Method::Delete,
        "PATCH" => Method::Patch,
        _ => panic!("Unsupported method"),
    };

    let mut headers = input.request.headers.clone();
    headers.insert("x-source".to_string(), input.source_id);
    headers.insert("x-scenario-id".to_string(), input.scenario_id);

    let body = input.request.body.map(|b| {
        if b.starts_with("base64:") {
            general_purpose::STANDARD
                .decode(b.trim_start_matches("base64:"))
                .unwrap_or_default()
        } else {
            b.into_bytes()
        }
    });

    let request = HttpRequest {
        url: input.request.url.clone(),
        method,
        headers,
        body,
    };

    let proxy_cfg = input.proxy.as_ref().map(|p| ProxyConfig {
        http_url: p.http_url.clone(),
        https_url: p.https_url.clone(),
        bypass_urls: vec![input.request.url.clone()],
    });

    let options = HttpOptions {
        proxy: proxy_cfg,
        total_timeout_ms: input.client_timeout_ms.map(|ms| ms as u32),
        ..Default::default()
    };

    let client = match HttpClient::new(options) {
        Ok(c) => c,
        Err(e) => {
            let out = RunnerOutput {
                response: None,
                error: Some(SdkError {
                    code: e.error_code().to_string(),
                    message: e.to_string(),
                }),
            };
            println!("{}", serde_json::to_string(&out)?);
            return Ok(());
        }
    };

    let sdk_result = client.execute(request, None).await;

    let out = match sdk_result {
        Ok(resp) => {
            let ct = resp.headers.get("content-type").map(|s| s.to_lowercase()).unwrap_or_default();
            let body_str = if ct.contains("application/octet-stream") {
                general_purpose::STANDARD.encode(&resp.body)
            } else {
                String::from_utf8_lossy(&resp.body).into_owned()
            };
            RunnerOutput {
                response: Some(SdkResponse {
                    status_code: resp.status_code,
                    headers: resp.headers,
                    body: body_str,
                }),
                error: None,
            }
        }
        Err(e) => RunnerOutput {
            response: None,
            error: Some(SdkError {
                code: e.error_code().to_string(),
                message: e.to_string(),
            }),
        },
    };

    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}
