# FFI Usage Examples

This document shows how to use the connector-service FFI from different programming languages.

## Concept

The FFI exposes two main operations:

1. **Transform Request**: Convert a standardized payment request into connector-specific HTTP request components
2. **Transform Response**: Convert a connector HTTP response back into a standardized payment response

Your application handles the actual HTTP execution using its native HTTP client.

## Python Example

```python
import ctypes
import json
from ctypes import c_char_p, c_int, c_void_p, POINTER, Structure

# Load the library
lib = ctypes.CDLL("./libconnector_ffi.so")

# Define function signatures
lib.connector_context_init.argtypes = [c_char_p]
lib.connector_context_init.restype = c_void_p

lib.connector_transform_request_json.argtypes = [c_char_p]
lib.connector_transform_request_json.restype = c_char_p

lib.connector_transform_response_json.argtypes = [c_char_p]
lib.connector_transform_response_json.restype = c_char_p

lib.ffi_string_free.argtypes = [c_char_p]
lib.ffi_string_free.restype = None

def transform_request(connector: str, flow: str, auth: dict, data: dict) -> dict:
    """Transform a payment request into HTTP request components."""
    request = json.dumps({
        "connector": connector,
        "flow": flow,
        "auth": auth,
        "data": data
    }).encode('utf-8')

    result_ptr = lib.connector_transform_request_json(request)
    result = json.loads(ctypes.string_at(result_ptr).decode('utf-8'))
    lib.ffi_string_free(result_ptr)

    return result

def transform_response(connector: str, flow: str, status_code: int,
                       body: str, original_request: dict = None) -> dict:
    """Transform an HTTP response into a standardized payment response."""
    request = json.dumps({
        "connector": connector,
        "flow": flow,
        "status_code": status_code,
        "body": body,
        "original_request": original_request
    }).encode('utf-8')

    result_ptr = lib.connector_transform_response_json(request)
    result = json.loads(ctypes.string_at(result_ptr).decode('utf-8'))
    lib.ffi_string_free(result_ptr)

    return result

# Usage
import requests

# Step 1: Transform the request
http_request = transform_request(
    connector="stripe",
    flow="authorize",
    auth={"api_key": "sk_test_xxx"},
    data={
        "amount": 1000,
        "currency": "USD",
        "payment_method": {
            "type": "card",
            "card": {
                "number": "4242424242424242",
                "exp_month": 12,
                "exp_year": 2025,
                "cvc": "123"
            }
        }
    }
)

if http_request["success"]:
    req = http_request["request"]

    # Step 2: Execute HTTP request with native client
    response = requests.request(
        method=req["method"],
        url=req["url"],
        headers=req["headers"],
        data=req["body"]
    )

    # Step 3: Transform the response
    payment_response = transform_response(
        connector="stripe",
        flow="authorize",
        status_code=response.status_code,
        body=response.text
    )

    print(payment_response)
```

## JavaScript/Node.js Example

```javascript
const ffi = require('ffi-napi');
const ref = require('ref-napi');

// Load the library
const lib = ffi.Library('./libconnector_ffi', {
    'connector_transform_request_json': ['string', ['string']],
    'connector_transform_response_json': ['string', ['string']],
    'ffi_string_free': ['void', ['string']],
});

async function processPayment(connector, flow, auth, paymentData) {
    // Step 1: Transform request
    const requestInput = JSON.stringify({
        connector,
        flow,
        auth,
        data: paymentData
    });

    const httpRequestJson = lib.connector_transform_request_json(requestInput);
    const httpRequest = JSON.parse(httpRequestJson);

    if (!httpRequest.success) {
        throw new Error(`Transform failed: ${httpRequest.error.message}`);
    }

    const req = httpRequest.request;

    // Step 2: Execute HTTP request with native fetch
    const response = await fetch(req.url, {
        method: req.method,
        headers: req.headers,
        body: req.body
    });

    const responseBody = await response.text();

    // Step 3: Transform response
    const responseInput = JSON.stringify({
        connector,
        flow,
        status_code: response.status,
        body: responseBody
    });

    const paymentResponseJson = lib.connector_transform_response_json(responseInput);
    const paymentResponse = JSON.parse(paymentResponseJson);

    return paymentResponse;
}

// Usage
processPayment('stripe', 'authorize',
    { api_key: 'sk_test_xxx' },
    { amount: 1000, currency: 'USD', /* ... */ }
).then(console.log);
```

## Java Example

```java
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;

public interface ConnectorFFI extends Library {
    ConnectorFFI INSTANCE = Native.load("connector_ffi", ConnectorFFI.class);

    String connector_transform_request_json(String request);
    String connector_transform_response_json(String response);
    void ffi_string_free(Pointer ptr);
}

public class PaymentProcessor {
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final HttpClient httpClient = HttpClient.newHttpClient();

    public PaymentResponse processPayment(String connector, String flow,
                                          Map<String, Object> auth,
                                          Map<String, Object> paymentData) throws Exception {
        // Step 1: Transform request
        Map<String, Object> transformInput = Map.of(
            "connector", connector,
            "flow", flow,
            "auth", auth,
            "data", paymentData
        );

        String httpRequestJson = ConnectorFFI.INSTANCE
            .connector_transform_request_json(mapper.writeValueAsString(transformInput));

        TransformResult result = mapper.readValue(httpRequestJson, TransformResult.class);

        if (!result.success) {
            throw new PaymentException(result.error.code, result.error.message);
        }

        // Step 2: Execute HTTP request
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(result.request.url))
            .method(result.request.method,
                    HttpRequest.BodyPublishers.ofString(result.request.body));

        for (Map.Entry<String, String> header : result.request.headers.entrySet()) {
            requestBuilder.header(header.getKey(), header.getValue());
        }

        HttpResponse<String> response = httpClient.send(
            requestBuilder.build(),
            HttpResponse.BodyHandlers.ofString()
        );

        // Step 3: Transform response
        Map<String, Object> responseInput = Map.of(
            "connector", connector,
            "flow", flow,
            "status_code", response.statusCode(),
            "body", response.body()
        );

        String paymentResponseJson = ConnectorFFI.INSTANCE
            .connector_transform_response_json(mapper.writeValueAsString(responseInput));

        return mapper.readValue(paymentResponseJson, PaymentResponse.class);
    }
}
```

## Go Example

```go
package main

/*
#cgo LDFLAGS: -L. -lconnector_ffi
#include <stdlib.h>

extern char* connector_transform_request_json(char* request);
extern char* connector_transform_response_json(char* response);
extern void ffi_string_free(char* s);
*/
import "C"
import (
    "encoding/json"
    "io"
    "net/http"
    "strings"
    "unsafe"
)

type TransformInput struct {
    Connector string                 `json:"connector"`
    Flow      string                 `json:"flow"`
    Auth      map[string]interface{} `json:"auth"`
    Data      map[string]interface{} `json:"data"`
}

type HttpRequestResult struct {
    Success bool `json:"success"`
    Request struct {
        URL     string            `json:"url"`
        Method  string            `json:"method"`
        Headers map[string]string `json:"headers"`
        Body    string            `json:"body"`
    } `json:"request"`
    Error struct {
        Code    string `json:"code"`
        Message string `json:"message"`
    } `json:"error"`
}

func ProcessPayment(connector, flow string, auth, data map[string]interface{}) (map[string]interface{}, error) {
    // Step 1: Transform request
    input := TransformInput{
        Connector: connector,
        Flow:      flow,
        Auth:      auth,
        Data:      data,
    }

    inputJson, _ := json.Marshal(input)
    cInput := C.CString(string(inputJson))
    defer C.free(unsafe.Pointer(cInput))

    cResult := C.connector_transform_request_json(cInput)
    resultJson := C.GoString(cResult)
    C.ffi_string_free(cResult)

    var httpReq HttpRequestResult
    json.Unmarshal([]byte(resultJson), &httpReq)

    if !httpReq.Success {
        return nil, fmt.Errorf("%s: %s", httpReq.Error.Code, httpReq.Error.Message)
    }

    // Step 2: Execute HTTP request
    req, _ := http.NewRequest(
        httpReq.Request.Method,
        httpReq.Request.URL,
        strings.NewReader(httpReq.Request.Body),
    )

    for k, v := range httpReq.Request.Headers {
        req.Header.Set(k, v)
    }

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)

    // Step 3: Transform response
    respInput := map[string]interface{}{
        "connector":   connector,
        "flow":        flow,
        "status_code": resp.StatusCode,
        "body":        string(body),
    }

    respInputJson, _ := json.Marshal(respInput)
    cRespInput := C.CString(string(respInputJson))
    defer C.free(unsafe.Pointer(cRespInput))

    cPaymentResp := C.connector_transform_response_json(cRespInput)
    paymentRespJson := C.GoString(cPaymentResp)
    C.ffi_string_free(cPaymentResp)

    var result map[string]interface{}
    json.Unmarshal([]byte(paymentRespJson), &result)

    return result, nil
}
```

## Building the Library

```bash
# Build for your platform
cargo build --release -p connector-ffi

# Output locations:
# Linux:   target/release/libconnector_ffi.so
# macOS:   target/release/libconnector_ffi.dylib
# Windows: target/release/connector_ffi.dll

# Generate C header (optional, using cbindgen)
cbindgen --config cbindgen.toml --crate connector-ffi --output connector_ffi.h
```

## Thread Safety

The FFI functions are thread-safe. Multiple threads can call transformation functions concurrently. The `FfiConnectorContext` is read-only after initialization.

## Memory Management

- Strings returned by FFI functions must be freed with `ffi_string_free()`
- The JSON API handles this internally when using language bindings
- Do not free strings more than once
- Do not use freed strings
