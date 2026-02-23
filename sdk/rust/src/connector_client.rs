use std::collections::HashMap;
use std::error::Error;

use connector_service_ffi::handlers::payments::{authorize_req_handler, authorize_res_handler};
use connector_service_ffi::types::{FfiConnectorConfig, FfiRequestData};
use connector_service_ffi::utils::ffi_headers_to_masked_metadata;
use domain_types::router_response_types::Response;
use domain_types::utils::ForeignTryFrom;
use grpc_api_types::payments::{
    ConnectorConfig, PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse,
};

pub struct ConnectorClient {
    config: ConnectorConfig,
}

impl ConnectorClient {
    pub fn new(config: ConnectorConfig) -> Self {
        Self { config }
    }

    pub async fn authorize(
        &self,
        request: PaymentServiceAuthorizeRequest,
    ) -> Result<PaymentServiceAuthorizeResponse, Box<dyn Error>> {
        let ffi_request = self.build_ffi_request(request.clone())?;

        let connector_request = authorize_req_handler(ffi_request)
            .map_err(|e| format!("authorize_req_handler failed: {:?}", e))?
            .ok_or("No connector request generated")?;

        let raw_json =
            external_services::service::extract_raw_connector_request(&connector_request);
        let raw: serde_json::Value = serde_json::from_str(&raw_json)?;

        let url = raw["url"]
            .as_str()
            .ok_or("Missing url in connector request")?;
        let method = raw["method"]
            .as_str()
            .ok_or("Missing method in connector request")?;

        let client = reqwest::Client::new();
        let mut req_builder = match method.to_uppercase().as_str() {
            "GET" => client.get(url),
            "POST" => client.post(url),
            "PUT" => client.put(url),
            "DELETE" => client.delete(url),
            "PATCH" => client.patch(url),
            other => return Err(format!("Unsupported HTTP method: {}", other).into()),
        };

        if let Some(headers) = raw["headers"].as_object() {
            for (key, value) in headers {
                if let Some(val) = value.as_str() {
                    req_builder = req_builder.header(key.as_str(), val);
                }
            }
        }

        if !raw["body"].is_null() {
            let body_str = if raw["body"].is_string() {
                raw["body"].as_str().unwrap_or("").to_string()
            } else {
                raw["body"].to_string()
            };
            req_builder = req_builder.body(body_str);
        }

        let http_response = req_builder.send().await?;

        let status_code = http_response.status().as_u16();
        let mut header_map = http::HeaderMap::new();
        for (key, value) in http_response.headers() {
            if let Ok(name) = http::header::HeaderName::from_bytes(key.as_str().as_bytes()) {
                if let Ok(val) = http::header::HeaderValue::from_bytes(value.as_bytes()) {
                    header_map.insert(name, val);
                }
            }
        }
        let response_bytes: bytes::Bytes = http_response.bytes().await?;

        let response = Response {
            headers: if header_map.is_empty() {
                None
            } else {
                Some(header_map)
            },
            response: response_bytes,
            status_code,
        };

        let ffi_request_for_res = self.build_ffi_request(request)?;
        match authorize_res_handler(ffi_request_for_res, response) {
            Ok(auth_response) => Ok(auth_response),
            Err(error_response) => {
                Err(format!("Authorization failed: {:?}", error_response).into())
            }
        }
    }

    fn build_ffi_request(
        &self,
        payload: PaymentServiceAuthorizeRequest,
    ) -> Result<FfiRequestData<PaymentServiceAuthorizeRequest>, Box<dyn Error>> {
        let metadata = FfiConnectorConfig::foreign_try_from(self.config.clone())
            .map_err(|e| format!("config conversion failed: {e}"))?;

        let masked_metadata = {
            let mut headers = HashMap::new();
            headers.insert(
                common_utils::consts::X_MERCHANT_ID.to_string(),
                "dummy_merchant".to_string(),
            );
            headers.insert(
                common_utils::consts::X_TENANT_ID.to_string(),
                "dummy_tenant".to_string(),
            );
            headers.insert(
                common_utils::consts::X_CONNECTOR_NAME.to_string(),
                "stripe".to_string(),
            );
            headers.insert(
                common_utils::consts::X_REQUEST_ID.to_string(),
                "dummy_request_id".to_string(),
            );
            headers.insert(
                common_utils::consts::X_AUTH.to_string(),
                "dummy_auth".to_string(),
            );
            ffi_headers_to_masked_metadata(&headers).ok()
        };

        Ok(FfiRequestData {
            payload,
            extracted_metadata: metadata,
            masked_metadata,
        })
    }
}
