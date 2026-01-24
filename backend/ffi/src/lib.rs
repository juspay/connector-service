//! FFI layer for connector-service transformation logic.
//!
//! This crate exposes the core transformation logic via C-compatible FFI,
//! allowing foreign languages (JS, Java, Python, etc.) to:
//!
//! 1. Transform payment requests into connector-specific HTTP requests
//! 2. Transform connector HTTP responses back into standardized payment responses
//!
//! The foreign language is responsible for executing the actual HTTP request
//! using its native HTTP client.
//!
//! # Example Usage (pseudocode)
//!
//! ```text
//! // 1. Build the HTTP request components
//! let result = connector_transform_request(
//!     connector_name: "stripe",
//!     flow_name: "authorize",
//!     request_json: "{ ... payment data ... }",
//! );
//!
//! // Result contains:
//! // - url: "https://api.stripe.com/v1/charges"
//! // - method: "POST"
//! // - headers: [("Authorization", "Bearer sk_..."), ("Content-Type", "application/json")]
//! // - body: "{ ... stripe-specific request ... }"
//!
//! // 2. Foreign language executes HTTP request with native client
//! let response = http_client.request(result.method, result.url)
//!     .headers(result.headers)
//!     .body(result.body)
//!     .send();
//!
//! // 3. Transform the response back
//! let payment_response = connector_transform_response(
//!     connector_name: "stripe",
//!     flow_name: "authorize",
//!     status_code: response.status,
//!     response_body: response.body,
//!     original_request_json: "{ ... original payment data ... }",
//! );
//!
//! // payment_response contains standardized PaymentsResponseData
//! ```

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

/// FFI-safe HTTP method enum
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiHttpMethod {
    Get = 0,
    Post = 1,
    Put = 2,
    Delete = 3,
    Patch = 4,
}

/// FFI-safe header (key-value pair)
#[repr(C)]
pub struct FfiHeader {
    pub key: *const c_char,
    pub value: *const c_char,
    /// If true, value is sensitive and should be masked in logs
    pub is_sensitive: bool,
}

/// FFI-safe HTTP request result
#[repr(C)]
pub struct FfiHttpRequest {
    /// The URL to send the request to
    pub url: *const c_char,
    /// HTTP method (GET, POST, etc.)
    pub method: FfiHttpMethod,
    /// Content-Type header value
    pub content_type: *const c_char,
    /// Array of headers
    pub headers: *const FfiHeader,
    /// Number of headers
    pub headers_count: usize,
    /// Request body (JSON/XML/Form-encoded string)
    pub body: *const c_char,
    /// Body format: "json", "form", "xml", "raw"
    pub body_format: *const c_char,
}

/// FFI-safe error information
#[repr(C)]
pub struct FfiError {
    pub code: *const c_char,
    pub message: *const c_char,
}

/// Result of transform_request operation
#[repr(C)]
pub struct FfiTransformRequestResult {
    /// 0 = success, non-zero = error
    pub status: i32,
    /// On success: the HTTP request to execute
    pub request: FfiHttpRequest,
    /// On error: error details
    pub error: FfiError,
}

/// FFI-safe payment response
#[repr(C)]
pub struct FfiPaymentResponse {
    /// Connector's transaction ID
    pub connector_transaction_id: *const c_char,
    /// Payment status: "succeeded", "failed", "pending", "requires_action", etc.
    pub status: *const c_char,
    /// Amount in minor units (cents)
    pub amount: i64,
    /// 3-letter currency code
    pub currency: *const c_char,
    /// Redirect URL if payment requires action
    pub redirect_url: *const c_char,
    /// Full response as JSON for additional fields
    pub response_json: *const c_char,
}

/// Result of transform_response operation
#[repr(C)]
pub struct FfiTransformResponseResult {
    /// 0 = success, non-zero = error
    pub status: i32,
    /// On success: the parsed payment response
    pub response: FfiPaymentResponse,
    /// On error: error details
    pub error: FfiError,
}

/// Opaque handle to connector context
/// This holds pre-loaded connector configurations
pub struct FfiConnectorContext {
    // Internal Rust structures
    _private: (),
}

// =============================================================================
// Core FFI Functions
// =============================================================================

/// Initialize the FFI library. Must be called once before any other functions.
///
/// # Arguments
/// * `config_json` - JSON string containing connector configurations
///
/// # Returns
/// * Pointer to FfiConnectorContext on success, null on failure
///
/// # Safety
/// Caller must eventually call `connector_context_free` to release resources.
#[no_mangle]
pub unsafe extern "C" fn connector_context_init(
    config_json: *const c_char,
) -> *mut FfiConnectorContext {
    if config_json.is_null() {
        return ptr::null_mut();
    }

    // TODO: Parse config and initialize connectors
    // For now, return a placeholder
    Box::into_raw(Box::new(FfiConnectorContext { _private: () }))
}

/// Free the connector context
///
/// # Safety
/// Must only be called with a valid pointer from `connector_context_init`.
/// Must not be called more than once for the same pointer.
#[no_mangle]
pub unsafe extern "C" fn connector_context_free(ctx: *mut FfiConnectorContext) {
    if !ctx.is_null() {
        drop(Box::from_raw(ctx));
    }
}

/// Transform a payment request into connector-specific HTTP request components.
///
/// # Arguments
/// * `ctx` - Connector context from `connector_context_init`
/// * `connector_name` - Name of the connector (e.g., "stripe", "adyen", "phonepe")
/// * `flow_name` - Payment flow (e.g., "authorize", "capture", "refund", "sync")
/// * `request_json` - JSON string containing the payment request data
/// * `auth_json` - JSON string containing connector authentication credentials
///
/// # Returns
/// * FfiTransformRequestResult with either the HTTP request or an error
///
/// # Safety
/// All string pointers must be valid null-terminated UTF-8 strings.
/// The returned result must be freed with `transform_request_result_free`.
#[no_mangle]
pub unsafe extern "C" fn connector_transform_request(
    _ctx: *const FfiConnectorContext,
    connector_name: *const c_char,
    flow_name: *const c_char,
    request_json: *const c_char,
    auth_json: *const c_char,
) -> FfiTransformRequestResult {
    // Validate inputs
    if connector_name.is_null() || flow_name.is_null() || request_json.is_null() || auth_json.is_null() {
        return create_error_result("INVALID_INPUT", "Null pointer provided");
    }

    let _connector = match CStr::from_ptr(connector_name).to_str() {
        Ok(s) => s,
        Err(_) => return create_error_result("INVALID_UTF8", "Invalid UTF-8 in connector_name"),
    };

    let _flow = match CStr::from_ptr(flow_name).to_str() {
        Ok(s) => s,
        Err(_) => return create_error_result("INVALID_UTF8", "Invalid UTF-8 in flow_name"),
    };

    let _request = match CStr::from_ptr(request_json).to_str() {
        Ok(s) => s,
        Err(_) => return create_error_result("INVALID_UTF8", "Invalid UTF-8 in request_json"),
    };

    let _auth = match CStr::from_ptr(auth_json).to_str() {
        Ok(s) => s,
        Err(_) => return create_error_result("INVALID_UTF8", "Invalid UTF-8 in auth_json"),
    };

    // TODO: Implement actual transformation logic
    // 1. Parse request_json into RouterDataV2
    // 2. Look up connector by name
    // 3. Call connector.build_request_v2()
    // 4. Extract URL, headers, method, body
    // 5. Return as FfiHttpRequest

    // Placeholder implementation
    create_error_result("NOT_IMPLEMENTED", "Transformation not yet implemented")
}

/// Transform a connector HTTP response into a standardized payment response.
///
/// # Arguments
/// * `ctx` - Connector context from `connector_context_init`
/// * `connector_name` - Name of the connector
/// * `flow_name` - Payment flow
/// * `status_code` - HTTP status code from the response
/// * `response_body` - Response body bytes
/// * `original_request_json` - The original request (needed for context)
///
/// # Returns
/// * FfiTransformResponseResult with either the payment response or an error
///
/// # Safety
/// All string pointers must be valid null-terminated UTF-8 strings.
/// The returned result must be freed with `transform_response_result_free`.
#[no_mangle]
pub unsafe extern "C" fn connector_transform_response(
    _ctx: *const FfiConnectorContext,
    connector_name: *const c_char,
    flow_name: *const c_char,
    status_code: u16,
    response_body: *const c_char,
    original_request_json: *const c_char,
) -> FfiTransformResponseResult {
    // Validate inputs
    if connector_name.is_null() || flow_name.is_null() || response_body.is_null() {
        return create_response_error_result("INVALID_INPUT", "Null pointer provided");
    }

    let _connector = match CStr::from_ptr(connector_name).to_str() {
        Ok(s) => s,
        Err(_) => return create_response_error_result("INVALID_UTF8", "Invalid UTF-8 in connector_name"),
    };

    let _flow = match CStr::from_ptr(flow_name).to_str() {
        Ok(s) => s,
        Err(_) => return create_response_error_result("INVALID_UTF8", "Invalid UTF-8 in flow_name"),
    };

    let _response = match CStr::from_ptr(response_body).to_str() {
        Ok(s) => s,
        Err(_) => return create_response_error_result("INVALID_UTF8", "Invalid UTF-8 in response_body"),
    };

    let _original = if !original_request_json.is_null() {
        CStr::from_ptr(original_request_json).to_str().ok()
    } else {
        None
    };

    let _ = status_code; // Will be used in actual implementation

    // TODO: Implement actual transformation logic
    // 1. Parse response_body
    // 2. Look up connector by name
    // 3. Reconstruct RouterDataV2 from original_request_json
    // 4. Call connector.handle_response_v2()
    // 5. Extract payment status, transaction ID, etc.
    // 6. Return as FfiPaymentResponse

    create_response_error_result("NOT_IMPLEMENTED", "Response transformation not yet implemented")
}

/// Get list of supported connectors
///
/// # Returns
/// * JSON array of connector names: ["stripe", "adyen", "phonepe", ...]
///
/// # Safety
/// The returned string must be freed with `ffi_string_free`.
#[no_mangle]
pub unsafe extern "C" fn connector_list_supported() -> *const c_char {
    // TODO: Generate from actual connector registry
    let connectors = r#"["stripe","adyen","phonepe","checkout","braintree","paypal","razorpay","mollie"]"#;

    match CString::new(connectors) {
        Ok(s) => s.into_raw(),
        Err(_) => ptr::null(),
    }
}

/// Get supported flows for a connector
///
/// # Arguments
/// * `connector_name` - Name of the connector
///
/// # Returns
/// * JSON array of flow names: ["authorize", "capture", "refund", "sync", ...]
///
/// # Safety
/// The returned string must be freed with `ffi_string_free`.
#[no_mangle]
pub unsafe extern "C" fn connector_list_flows(
    connector_name: *const c_char,
) -> *const c_char {
    if connector_name.is_null() {
        return ptr::null();
    }

    let _connector = match CStr::from_ptr(connector_name).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null(),
    };

    // TODO: Look up connector and return actual supported flows
    let flows = r#"["authorize","capture","void","refund","sync","setup_mandate"]"#;

    match CString::new(flows) {
        Ok(s) => s.into_raw(),
        Err(_) => ptr::null(),
    }
}

// =============================================================================
// Memory Management
// =============================================================================

/// Free a string returned by the FFI layer
///
/// # Safety
/// Must only be called with pointers returned by FFI functions.
#[no_mangle]
pub unsafe extern "C" fn ffi_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Free the headers array in an FfiHttpRequest
///
/// # Safety
/// Must only be called with valid FfiHttpRequest from transform_request.
#[no_mangle]
pub unsafe extern "C" fn ffi_headers_free(headers: *mut FfiHeader, count: usize) {
    if !headers.is_null() && count > 0 {
        let headers_vec = Vec::from_raw_parts(headers, count, count);
        for header in headers_vec {
            if !header.key.is_null() {
                drop(CString::from_raw(header.key as *mut c_char));
            }
            if !header.value.is_null() {
                drop(CString::from_raw(header.value as *mut c_char));
            }
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

fn create_error_result(code: &str, message: &str) -> FfiTransformRequestResult {
    FfiTransformRequestResult {
        status: -1,
        request: FfiHttpRequest {
            url: ptr::null(),
            method: FfiHttpMethod::Get,
            content_type: ptr::null(),
            headers: ptr::null(),
            headers_count: 0,
            body: ptr::null(),
            body_format: ptr::null(),
        },
        error: FfiError {
            code: CString::new(code).map(|s| s.into_raw()).unwrap_or(ptr::null_mut()),
            message: CString::new(message).map(|s| s.into_raw()).unwrap_or(ptr::null_mut()),
        },
    }
}

fn create_response_error_result(code: &str, message: &str) -> FfiTransformResponseResult {
    FfiTransformResponseResult {
        status: -1,
        response: FfiPaymentResponse {
            connector_transaction_id: ptr::null(),
            status: ptr::null(),
            amount: 0,
            currency: ptr::null(),
            redirect_url: ptr::null(),
            response_json: ptr::null(),
        },
        error: FfiError {
            code: CString::new(code).map(|s| s.into_raw()).unwrap_or(ptr::null_mut()),
            message: CString::new(message).map(|s| s.into_raw()).unwrap_or(ptr::null_mut()),
        },
    }
}

// =============================================================================
// High-Level JSON API (Alternative to raw C FFI)
// =============================================================================

/// Transform request using JSON input/output (simpler for dynamic languages)
///
/// # Arguments
/// * `request_json` - JSON object with fields:
///   - connector: string (e.g., "stripe")
///   - flow: string (e.g., "authorize")
///   - auth: object (connector credentials)
///   - data: object (payment data)
///
/// # Returns
/// * JSON object with fields:
///   - success: boolean
///   - request: { url, method, headers, body, body_format } on success
///   - error: { code, message } on failure
///
/// # Safety
/// Input must be valid null-terminated UTF-8 JSON string.
/// Output must be freed with `ffi_string_free`.
#[no_mangle]
pub unsafe extern "C" fn connector_transform_request_json(
    request_json: *const c_char,
) -> *const c_char {
    if request_json.is_null() {
        return json_error("INVALID_INPUT", "Null input");
    }

    let _input = match CStr::from_ptr(request_json).to_str() {
        Ok(s) => s,
        Err(_) => return json_error("INVALID_UTF8", "Invalid UTF-8 input"),
    };

    // TODO: Parse JSON, call transformation, return JSON result
    json_error("NOT_IMPLEMENTED", "JSON API not yet implemented")
}

/// Transform response using JSON input/output
///
/// # Arguments
/// * `response_json` - JSON object with fields:
///   - connector: string
///   - flow: string
///   - status_code: number
///   - body: string (response body)
///   - original_request: object (optional, for context)
///
/// # Returns
/// * JSON object with standardized payment response
///
/// # Safety
/// Input must be valid null-terminated UTF-8 JSON string.
/// Output must be freed with `ffi_string_free`.
#[no_mangle]
pub unsafe extern "C" fn connector_transform_response_json(
    response_json: *const c_char,
) -> *const c_char {
    if response_json.is_null() {
        return json_error("INVALID_INPUT", "Null input");
    }

    let _input = match CStr::from_ptr(response_json).to_str() {
        Ok(s) => s,
        Err(_) => return json_error("INVALID_UTF8", "Invalid UTF-8 input"),
    };

    // TODO: Parse JSON, call transformation, return JSON result
    json_error("NOT_IMPLEMENTED", "JSON API not yet implemented")
}

fn json_error(code: &str, message: &str) -> *const c_char {
    let error = format!(r#"{{"success":false,"error":{{"code":"{}","message":"{}"}}}}"#, code, message);
    CString::new(error).map(|s| s.into_raw()).unwrap_or(ptr::null_mut())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_connector_list_supported() {
        unsafe {
            let result = connector_list_supported();
            assert!(!result.is_null());
            let s = CStr::from_ptr(result).to_str().unwrap();
            assert!(s.contains("stripe"));
            ffi_string_free(result as *mut c_char);
        }
    }

    #[test]
    fn test_null_input_handling() {
        unsafe {
            let result = connector_transform_request(
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            );
            assert_eq!(result.status, -1);
        }
    }
}
