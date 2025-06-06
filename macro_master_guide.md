# Macro Implementation Guide: From Old Structure to New Framework

This comprehensive guide outlines the process of migrating a connector from the old code structure to the new macro-based framework. We'll use the Adyen implementation as our reference model, focusing specifically on implementing Fiserv in the macro framework.

## Table of Contents

1. [Understanding the Macro Framework](#understanding-the-macro-framework)
2. [Project Structure](#project-structure)
3. [Implementation Roadmap](#implementation-roadmap)
4. [Detailed Implementation Steps](#detailed-implementation-steps)
5. [Data Structure Migration](#data-structure-migration)
6. [Flow-Specific Implementations](#flow-specific-implementations)
7. [Common Challenges and Solutions](#common-challenges-and-solutions)
8. [Testing and Validation](#testing-and-validation)
9. [Best Practices](#best-practices)
10. [Real-World Implementation: Fiserv Case Study](#real-world-implementation-fiserv-case-study)

## Understanding the Macro Framework

The macro framework in this connector service was designed to standardize connector implementations, reduce boilerplate code, and provide a consistent approach to handling payment flows. It centralizes common functionality and allows developers to focus on connector-specific logic.

### Key Benefits

- **Reduced Redundancy**: Common patterns are abstracted into macros
- **Consistent Implementation**: Standardized approach across connectors
- **Better Maintainability**: Clear separation of concerns
- **Simplified Testing**: Standardized testing approach

### Core Macros Overview

The framework uses several key macros:

1. **`create_all_prerequisites!`**: Defines connector structure, bridges for request/response handling, and common member functions
2. **`macro_connector_implementation!`**: Implements a specific payment flow for a connector
3. **`expand_connector_input_data!`**: Creates router data structures for the connector
4. **`impl_templating!`**: Sets up templating for request and response types

## Project Structure

A typical connector implementation using the macro framework consists of:

```
backend/connector-integration/src/connectors/
├── fiserv.rs                   # Main connector implementation
└── fiserv/
    ├── transformers.rs         # Data transformation logic
    └── test.rs                 # Tests for the connector
```

### File Responsibilities

1. **Main Connector File (`fiserv.rs`)**:
   - Connector trait implementations
   - Macro calls for connector setup
   - Flow-specific implementations
   - Authentication and header construction
   - URL building logic
   - Error handling

2. **Transformers File (`transformers.rs`)**:
   - Request/response data structures
   - Type conversion implementations (RouterData ↔ Connector types)
   - Helper functions for data transformation
   - Status mapping and response parsing

3. **Test File (`test.rs`)**:
   - Unit tests for request building
   - Response parsing tests
   - Integration tests

## Implementation Roadmap

### Step 1: Analyze the Reference Implementation (Adyen)

Start by understanding how Adyen is implemented in the macro framework:

- Study the structure of `adyen.rs` and `adyen/transformers.rs`
- Identify the flows implemented (Authorize, Capture, Refund, etc.)
- Understand how request/response structures are defined
- Note how error handling and authentication are managed

### Step 2: Understand the Fiserv API

Before implementation:

- Review Fiserv API documentation
- Identify required endpoints for each payment flow
- Note authentication requirements
- Document request/response formats

### Step 3: Create Basic Structures

- Set up basic file structure
- Define request/response data types
- Implement basic trait requirements

### Step 4: Implement Core Functionality

- Define and implement the core macros
- Set up authentication
- Create flow-specific implementations

### Step 5: Test and Validate

- Write unit tests
- Perform integration testing
- Validate against real API endpoints

## Detailed Implementation Steps

### 1. Create Basic Structure

Start by setting up the main connector file and transformer file:

#### 1.1 Main Connector File (`fiserv.rs`)

```rust
mod test;
pub mod transformers;

use crate::types::ResponseRouterData;
use crate::with_error_response_body;
use domain_types::{
    connector_types::{ConnectorValidation, SupportedPaymentMethodsExt},
    types::{
        self, CardSpecificFeatures, ConnectorInfo, FeatureStatus, PaymentMethodDataType,
        PaymentMethodDetails, PaymentMethodSpecificFeatures, SupportedPaymentMethods,
    },
};
use hyperswitch_common_enums::{
    AttemptStatus, CaptureMethod, CardNetwork, EventClass, PaymentMethod, PaymentMethodType,
};
use hyperswitch_common_utils::{
    errors::CustomResult, ext_traits::ByteSliceExt, pii::SecretSerdeValue, request::RequestContent,
};
use std::sync::LazyLock;

use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};

use error_stack::report;
use hyperswitch_interfaces::errors::ConnectorError;
use hyperswitch_interfaces::{
    api::{self, ConnectorCommon},
    configs::Connectors,
    connector_integration_v2::ConnectorIntegrationV2,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::Response,
};
use hyperswitch_masking::{Mask, Maskable};

use super::macros;
use domain_types::{
    connector_flow::{
        Authorize, Capture, PSync, Refund, Void,
    },
    connector_types::{
        ConnectorServiceTrait, PaymentAuthorizeV2, PaymentCapture, PaymentFlowData, PaymentSyncV2,
        PaymentVoidData, PaymentVoidV2, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncV2, RefundV2,
        RefundsData, RefundsResponseData, ResponseId, ValidationTrait,
    },
};
use transformers::{
    self as fiserv, FiservPaymentRequest, FiservPaymentResponse, FiservPSyncRequest,
    FiservPSyncResponse, FiservCaptureRequest, FiservCaptureResponse, FiservVoidRequest,
    FiservVoidResponse, FiservRefundRequest, FiservRefundResponse,
};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const API_KEY: &str = "apikey";
    pub(crate) const CLIENT_REQUEST_ID: &str = "Client-Request-Id";
    pub(crate) const TIMESTAMP: &str = "Timestamp";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

impl ConnectorServiceTrait for Fiserv {}
impl PaymentAuthorizeV2 for Fiserv {}
impl PaymentSyncV2 for Fiserv {}
impl PaymentVoidV2 for Fiserv {}
impl RefundSyncV2 for Fiserv {}
impl RefundV2 for Fiserv {}
impl PaymentCapture for Fiserv {}
impl ValidationTrait for Fiserv {}
```

#### 1.2 Transformers File (`transformers.rs`)

Start by defining the basic structures needed for the Fiserv implementation:

```rust
use domain_types::{
    connector_flow::{
        Authorize, Capture, PSync, Refund, Void,
    },
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData,
        RefundsResponseData, ResponseId,
    },
};
use error_stack::{Report, ResultExt};
use hyperswitch_api_models::enums::{self, AttemptStatus, RefundStatus};
use hyperswitch_common_utils::{
    errors::CustomResult,
    ext_traits::{ByteSliceExt, OptionExt},
    request::Method,
    types::MinorUnit,
};
use hyperswitch_domain_models::{
    payment_method_data::{Card, PaymentMethodData},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use hyperswitch_interfaces::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors,
};
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::types::ResponseRouterData;

use super::FiservRouterData;

// Define common structures

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Amount {
    pub currency: enums::Currency,
    pub value: MinorUnit,
}

type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;

// Define payment request/response structures

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservPaymentRequest {
    // Define fields based on Fiserv API docs
    amount: Amount,
    reference_id: String,
    // Add other fields as needed
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservPaymentResponse {
    // Define fields based on Fiserv API docs
    transaction_id: String,
    status: String,
    // Add other fields as needed
}

// Define other request/response structures for different flows
// (PSync, Capture, Void, Refund, etc.)
```

### 2. Implement Core Macros

The next step is to implement the core macros in the main connector file:

#### 2.1 `create_all_prerequisites!` Macro

This macro sets up the connector structure and basic functionality:

```rust
macros::create_all_prerequisites!(
    connector_name: Fiserv,
    api: [
        (
            flow: Authorize,
            request_body: FiservPaymentRequest,
            response_body: FiservPaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
        ),
        (
            flow: PSync,
            request_body: FiservPSyncRequest,
            response_body: FiservPSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
        ),
        (
            flow: Capture,
            request_body: FiservCaptureRequest,
            response_body: FiservCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        ),
        (
            flow: Void,
            request_body: FiservVoidRequest,
            response_body: FiservVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
        ),
        (
            flow: Refund,
            request_body: FiservRefundRequest,
            response_body: FiservRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
        )
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];
            
            // Add Fiserv-specific headers
            let timestamp = OffsetDateTime::now_utc().unix_timestamp().to_string();
            header.push((headers::TIMESTAMP.to_string(), timestamp.into()));
            
            // Get authentication headers
            let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut auth_header);
            
            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.fiserv.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.fiserv.base_url
        }
    }
);
```

### 3. Implement Flow-Specific Functionality

Next, implement each payment flow using the `macro_connector_implementation!` macro:

#### 3.1 Authorization Flow

```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiserv,
    curl_request: Json(FiservPaymentRequest),
    curl_response: FiservPaymentResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            // Construct URL for authorization endpoint
            Ok(format!("{}/payments/v1/charges", self.connector_base_url_payments(req)))
        }
    }
);
```

#### 3.2 Payment Sync Flow

```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiserv,
    curl_request: Json(FiservPSyncRequest),
    curl_response: FiservPSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            // Extract transaction ID from the request
            let connector_tx_id = req.request.connector_transaction_id.clone();
            
            // Construct URL for payment status endpoint
            Ok(format!("{}/payments/v1/charges/{}", self.connector_base_url_payments(req), connector_tx_id))
        }
    }
);
```

#### 3.3 Capture Flow

```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiserv,
    curl_request: Json(FiservCaptureRequest),
    curl_response: FiservCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let connector_tx_id = req.request.connector_transaction_id.clone();
            Ok(format!("{}/payments/v1/charges/{}/capture", self.connector_base_url_payments(req), connector_tx_id))
        }
    }
);
```

#### 3.4 Implement Other Flows

Follow the same pattern to implement the remaining flows (Void, Refund, etc.) following the Adyen examples.

### 4. Implement Error Handling and Common Functionality

Add the common connector implementation:

```rust
impl ConnectorCommon for Fiserv {
    fn id(&self) -> &'static str {
        "fiserv"
    }
    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Minor
    }
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = fiserv::FiservAuthType::try_from(auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        
        // Implement Fiserv-specific authentication
        // This might include HMAC signatures or other auth mechanisms
        
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            auth.api_key.into_masked(),
        )])
    }
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.fiserv.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: fiserv::FiservErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message: response.error_message.clone().unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
            reason: response.error_message,
            attempt_status: None,
            connector_transaction_id: response.transaction_id,
        })
    }
}
```

## Common Challenges and Solutions

During the implementation of connectors using the macro framework, several common challenges may arise. Here are the most common issues and their solutions:

### 1. Duplicate Trait Implementations

**Challenge**: You may run into errors about duplicate trait implementations, especially for traits like `ConnectorSpecifications`.

**Example Error**:
```
conflicting implementations of trait `ConnectorSpecifications` for type `connectors::fiserv::Fiserv`
```

**Solution**: Ensure you have only one implementation of each trait. If you've implemented traits in multiple places, consolidate them into a single implementation:

```rust
// WRONG: Multiple implementations
impl ConnectorSpecifications for Fiserv {}
// ...later in the code...
impl ConnectorSpecifications for Fiserv {
    // methods...
}

// RIGHT: Single implementation
impl ConnectorSpecifications for Fiserv {
    // All methods here
}
```

### 2. Misplaced Validation Methods

**Challenge**: Methods like `validate_mandate_payment` and `is_webhook_source_verification_mandatory` might be implemented on the wrong trait.

**Solution**: Ensure validation methods are implemented on `ConnectorValidation` rather than `ConnectorSpecifications`:

```rust
// WRONG: Implementing validation methods on ConnectorSpecifications
impl ConnectorSpecifications for Fiserv {
    fn validate_mandate_payment(&self, /* params */) -> CustomResult<(), errors::ConnectorError> {
        // Implementation
    }
}

// RIGHT: Implementing validation methods on ConnectorValidation
impl ConnectorValidation for Fiserv {
    fn validate_mandate_payment(&self, /* params */) -> CustomResult<(), errors::ConnectorError> {
        // Implementation
    }
}
```

### 3. Type Mismatches in TryFrom Implementations

**Challenge**: The macro expects certain TryFrom implementations that might not match the way you've defined your types.

**Example Error**:
```
the trait bound `connectors::fiserv::transformers::FiservPaymentRequest: TryFrom<connectors::fiserv::FiservRouterData<RouterDataV2<...>>>` is not satisfied
```

**Solution**: Ensure your type implementations match what the macro expects. You may need to add more specific TryFrom implementations:

```rust
// If macro expects:
impl TryFrom<FiservRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>>
    for FiservPaymentRequest 
{
    type Error = Error;
    fn try_from(
        item: FiservRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        // Implementation
    }
}
```

### 4. Authentication and Header Building

**Challenge**: For connectors with complex authentication (like HMAC signing), the standard header building might not be sufficient.

**Solution**: Modify the `build_headers` function to accept additional parameters, like the serialized payload string for signature generation:

```rust
pub fn build_headers<F, FCD, Req, Res>(
    &self,
    req: &RouterDataV2<F, FCD, Req, Res>,
    payload_string_for_sig: &str, // Add parameter for payload
) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
    // Generate headers with signature based on payload
}
```

Then in flow implementations, serialize the request body before calling `build_headers`:

```rust
fn get_headers(
    &self,
    req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
    // Get the request body string for signature
    let temp_request_body_for_sig = self.get_request_body(req)?;
    let payload_string_for_sig = match temp_request_body_for_sig {
        Some(RequestContent::Json(json_body)) => serde_json::to_string(&json_body)?,
        // Handle other cases
    };
    
    self.build_headers(req, &payload_string_for_sig)
}
```

### 5. Handling Special Router Data Types

**Challenge**: For connectors that require specialized router data types (like for capturing with session information), the macro might not handle it properly.

**Solution**: Define custom router data types for specific flows:

```rust
#[derive(Debug)]
pub struct FiservCaptureRouterData<'a> {
    pub amount: FloatMajorUnit,
    pub router_data: &'a RouterDataV2<CaptureFlow, PaymentFlowData, PaymentsCaptureData, ConnectorPaymentsResponseData>,
}

impl<'a> TryFrom<(FloatMajorUnit, &'a RouterDataV2<CaptureFlow, PaymentFlowData, PaymentsCaptureData, ConnectorPaymentsResponseData>)> for FiservCaptureRouterData<'a> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from((amount, router_data): (FloatMajorUnit, &'a RouterDataV2<CaptureFlow, PaymentFlowData, PaymentsCaptureData, ConnectorPaymentsResponseData>)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data,
        })
    }
}
```

### 6. Handling Amount Conversion and Formatting

**Challenge**: When working with payment amounts, you need to properly convert between minor and major units (e.g., cents to dollars) and format them correctly for the API. Different connectors may expect different data types for amount values.

**Example Error**:
```
Unknown field data in object: expected Number but found String for field 'total'
```

**Solution**: Adapt the Amount struct to match connector expectations:

```rust
// Solution 1: For connectors expecting string amounts
#[derive(Default, Debug, Serialize)]
pub struct Amount {
    pub total: String,  // Use String for connectors expecting string values
    pub currency: String,
}

// Helper function to convert FloatMajorUnit to String (when needed)
fn float_major_to_string(amount: FloatMajorUnit) -> String {
    // Use the debug representation and convert to f64 string with 2 decimal places
    let debug_str = format!("{:?}", amount);
    // Extract the numeric value from debug representation
    let value_str = debug_str.trim_start_matches("FloatMajorUnit(").trim_end_matches(')');
    
    // Try to parse as f64 and format with 2 decimal places
    if let Ok(value) = value_str.parse::<f64>() {
        return format!("{:.2}", value);
    }
    
    // Fallback to the original debug string if parsing fails
    debug_str
}

// Solution 2: For connectors expecting numeric amounts (preferred when supported)
#[derive(Default, Debug, Serialize)]
pub struct Amount {
    pub total: FloatMajorUnit,  // Use FloatMajorUnit directly for numeric values
    pub currency: String,
}

// In request building code for either solution
let converter = FloatMajorUnitForConnector;
let amount_major = converter.convert(router_data.request.minor_amount, router_data.request.currency)?;

let amount = Amount {
    total: amount_major,  // Use directly for numeric APIs
    // OR total: float_major_to_string(amount_major),  // Convert for string APIs
    currency: router_data.request.currency.to_string(),
};
```

**Important Note**: When possible, prefer using the numeric type directly (Solution 2) as it avoids unnecessary string conversion and properly serializes as a JSON number. Only use string conversion when the connector API specifically requires string-formatted amounts.

### 7. Extracting Metadata from Different Sources

**Challenge**: Some connectors need to extract additional metadata (like session information) from different sources, depending on the flow.

**Solution**: Implement flexible extraction that checks multiple possible sources:

```rust
// Try to get session string from different sources
let session_str = if let Some(meta) = router_data.resource_common_data.connector_meta_data.as_ref() {
    // Use connector_meta_data from resource_common_data
    match meta.peek() {
        serde_json::Value::String(s) => s.to_string(),
        _ => return Err(errors::ConnectorError::InvalidConnectorConfig {
            config: "connector_meta_data was not a JSON string",
        }),
    }
} else if let Some(connector_meta) = router_data.request.connector_metadata.as_ref() {
    // Use connector_metadata from request
    match connector_meta {
        serde_json::Value::String(s) => s.clone(),
        _ => return Err(errors::ConnectorError::InvalidConnectorConfig {
            config: "connector_metadata was not a JSON string",
        }),
    }
} else {
    // No metadata available
    return Err(errors::ConnectorError::MissingRequiredField { 
        field_name: "connector_metadata or connector_meta_data"
    })
}
```

## Real-World Implementation: Fiserv Case Study

This section demonstrates the practical application of the macro framework through our implementation of the Fiserv connector. This case study highlights key challenges, solutions, and lessons learned.

### Implementation Overview

The Fiserv connector implementation required supporting six key payment flows:

1. **Authorize**: For card payment authorization
2. **Capture**: To capture pre-authorized funds
3. **Payment Sync (PSync)**: To check payment status
4. **Void**: To cancel authorized payments
5. **Refund**: To refund completed payments
6. **Refund Sync (RSync)**: To check refund status

### Challenge: HMAC Authentication

Fiserv required HMAC-SHA256 signatures for each API request, with the signature calculated from:
- API Key
- Client Request ID
- Timestamp
- Request body payload

**Solution**: We enhanced the `build_headers` function to accept the serialized request payload:

```rust
pub fn build_headers<F, FCD, Req, Res>(
    &self,
    req: &RouterDataV2<F, FCD, Req, Res>,
    payload_string_for_sig: &str,
) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
    let timestamp_ms = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let client_request_id = Uuid::new_v4().to_string();
    
    let auth_type = self::transformers::FiservAuthType::try_from(&req.connector_auth_type)?;
    let signature = self.generate_authorization_signature(
        &auth_type,
        &client_request_id,
        payload_string_for_sig,
        timestamp_ms,
    )?;

    // Create headers with the generated signature
    let headers = vec![
        (headers::CONTENT_TYPE.to_string(), "application/json".to_string().into()),
        (headers::CLIENT_REQUEST_ID.to_string(), client_request_id.into()),
        (headers::TIMESTAMP.to_string(), timestamp_ms.to_string().into()),
        (headers::AUTH_TOKEN_TYPE.to_string(), "HMAC".to_string().into()),
        (headers::AUTHORIZATION.to_string(), signature.into_masked()),
    ];
    
    Ok(headers)
}
```

In each flow implementation, we first generated the request body and then calculated the signature:

```rust
fn get_headers(
    &self,
    req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
    let request_body = self.get_request_body(req)?;
    let payload_string = match request_body {
        Some(RequestContent::Json(json_body)) => serde_json::to_string(&json_body)?,
        // Handle other cases
        _ => "".to_string(),
    };
    
    self.build_headers(req, &payload_string)
}
```

### Challenge: Custom Router Data Types

The standard router data types weren't sufficient for our complex request building needs, especially for the capture flow which required session information.

**Solution**: We created specialized router data types for each flow:

```rust
// Regular router data for standard flows
#[derive(Debug)]
pub struct FiservRouterData<'a, F, ReqBody, Resp> {
    pub amount: FloatMajorUnit,
    pub router_data: &'a RouterDataV2<F, ReqBody, PaymentsAuthorizeData, Resp>,
}

// Specific router data for capture flow
#[derive(Debug)]
pub struct FiservCaptureRouterData<'a> {
    pub amount: FloatMajorUnit,
    pub router_data: &'a RouterDataV2<CaptureFlow, PaymentFlowData, PaymentsCaptureData, ConnectorPaymentsResponseData>,
}

// Specific router data for refund flow
#[derive(Debug)]
pub struct FiservRefundRouterData<'a> {
    pub amount: FloatMajorUnit,
    pub router_data: &'a RouterDataV2<RefundFlowMarker, RefundFlowData, RefundsData, ConnectorRefundsResponseData>,
}
```

### Challenge: Metadata Extraction

Fiserv required a terminal ID from session metadata, but the metadata could be stored in different locations depending on the flow.

**Solution**: We implemented flexible metadata extraction:

```rust
// For Capture flow
let session_str = if let Some(meta) = router_data.resource_common_data.connector_meta_data.as_ref() {
    // Use connector_meta_data from resource_common_data
    match meta.peek() {
        serde_json::Value::String(s) => s.to_string(),
        _ => return Err(errors::ConnectorError::InvalidConnectorConfig { 
            config: "connector_meta_data was not a JSON string" 
        }),
    }
} else if let Some(connector_meta) = router_data.request.connector_metadata.as_ref() {
    // Use connector_metadata from request
    match connector_meta {
        serde_json::Value::String(s) => s.clone(),
        _ => return Err(errors::ConnectorError::InvalidConnectorConfig { 
            config: "connector_metadata was not a JSON string"
        }),
    }
} else {
    // No metadata available
    return Err(errors::ConnectorError::MissingRequiredField { 
        field_name: "connector_metadata or connector_meta_data" 
    });
};

let session: FiservSessionObject = serde_json::from_str(&session_str)?;
```

### Complete Flow Implementation

We extended our implementation to support all six payment flows by updating the `create_all_prerequisites!` macro:

```rust
macros::create_all_prerequisites!(
    connector_name: Fiserv,
    api: [
        (
            flow: Authorize,
            request_body: FiservPaymentsRequest,
            response_body: FiservPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
        ),
        (
            flow: PSync,
            request_body: FiservSyncRequest,
            response_body: FiservSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
        ),
        (
            flow: Capture,
            request_body: FiservCaptureRequest,
            response_body: FiservCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        ),
        (
            flow: Void, 
            request_body: FiservVoidRequest,
            response_body: FiservVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
        ),
        (
            flow: Refund,
            request_body: FiservRefundRequest,
            response_body: FiservRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
        ),
        (
            flow: RSync,
            request_body: FiservSyncRequest,
            response_body: FiservSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
        )
    ],
    // Other configuration...
);
```

### Key Lessons

1. **Customized Headers**: For connectors with complex authentication requirements like HMAC, extend the header building function to accommodate signature generation.

2. **Specialized Router Data Types**: Create specialized router data types for different payment flows when standard types aren't sufficient.

3. **Flexible Metadata Handling**: Implement robust checks for metadata from multiple sources, as different flows may store metadata in different locations.

4. **Consistent Pattern Application**: Apply the same patterns across all payment flows to ensure consistency and maintainability.

5. **Flow-Specific Endpoints**: While maintaining a consistent pattern, be sure to adapt URLs and HTTP methods as needed for each flow.

By following the macro framework approach and addressing these challenges, we successfully implemented all the required payment flows for the Fiserv connector, resulting in clean, maintainable code that follows a consistent pattern across flows.

## Additional Lessons From Implementation

### Challenge: Templating Conflicts Between Similar Flows

When implementing multiple similar flows (like Payment Sync and Refund Sync) that share similar request/response structures, you may encounter templating conflicts due to how the macro system generates code. This is especially common with flows that serve similar purposes but for different payment actions.

**Error Example**:
```
error[E0428]: the name `FiservSyncRequestTemplating` is defined multiple times
   --> backend/connector-integration/src/connectors/macros.rs:367:27
    |
367 |               paste::paste!{pub struct [<$connector_type_name Templating>]; }
    |                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |                             |
    |                             `FiservSyncRequestTemplating` redefined here
    |                             previous definition of the type `FiservSyncRequestTemplating` here
```

**Problem Analysis**:
The error occurs because the macro generates templating types with names based on the request/response type names. When multiple flows use the same request/response struct names, the macro tries to define the same templating type multiple times, leading to conflicts.

**Solution**:
1. Create distinct type names for each flow, even if they have identical structures
2. Update the macro calls to use these distinct types

**Example Implementation**:
```rust
// Original problematic structure
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservSyncRequest {
    pub merchant_details: MerchantDetails,
    pub reference_transaction_details: ReferenceTransactionDetails,
}

// Create a distinct type for RefundSync to avoid templating conflicts
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservRefundSyncRequest {
    pub merchant_details: MerchantDetails,
    pub reference_transaction_details: ReferenceTransactionDetails,
}
```

Then update the macros in the main connector file to use the appropriate type for each flow:

```rust
macros::create_all_prerequisites!(
    connector_name: Fiserv,
    api: [
        // Other flows...
        (
            flow: PSync,
            request_body: FiservSyncRequest,
            response_body: FiservSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
        ),
        (
            flow: RSync,
            request_body: FiservRefundSyncRequest,
            response_body: FiservRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
        )
    ],
    // Rest of the macro...
);
```

### Challenge: Different Resource Data Structures

Different flow types (like `PaymentFlowData` vs `RefundFlowData`) may have different field structures. This can cause errors when trying to access fields that don't exist in a particular flow.

**Error Example**:
```
error[E0609]: no field `connector_meta_data` on type `domain_types::connector_types::RefundFlowData`
   --> backend/connector-integration/src/connectors/fiserv/transformers.rs:538:80
    |
538 |         let session_str = if let Some(meta) = router_data.resource_common_data.connector_meta_data.as_ref() {
    |                                                                                ^^^^^^^^^^^^^^^^^^^ unknown field
```

**Problem Analysis**:
The code tries to access `connector_meta_data` from `resource_common_data`, but `RefundFlowData` doesn't have this field available, while `PaymentFlowData` does.

**Solution**:
1. Check which fields are available in each flow data structure
2. Modify code to use alternative sources for the data (like `connector_metadata` from request)
3. Create flow-specific implementations that account for these differences

**Example Implementation**:
```rust
// For PaymentFlowData which has connector_meta_data
let session_str = if let Some(meta) = router_data.resource_common_data.connector_meta_data.as_ref() {
    // Use connector_meta_data from resource_common_data
    match meta.peek() {
        serde_json::Value::String(s) => s.to_string(),
        _ => return Err(report!(ConnectorError::InvalidConnectorConfig {
            config: "connector_meta_data was not a JSON string",
        })),
    }
} else if let Some(connector_meta) = router_data.request.connector_metadata.as_ref() {
    // Use connector_metadata from request as fallback
    // ...
};

// For RefundFlowData which does NOT have connector_meta_data
let session_str = if let Some(connector_meta) = router_data.request.connector_metadata.as_ref() {
    // Use connector_metadata from request only
    match connector_meta {
        serde_json::Value::String(s) => s.clone(),
        _ => return Err(report!(ConnectorError::InvalidConnectorConfig {
            config: "connector_metadata was not a JSON string",
        })),
    }
} else {
    // No metadata available
    return Err(report!(ConnectorError::MissingRequiredField { 
        field_name: "connector_metadata" 
    }));
};
```

### Challenge: Missing Methods on Different Types

Sometimes similar flows might have different methods available on their types, leading to compilation errors.

**Error Example**:
```
error[E0599]: no method named `get_connector_transaction_id` found for struct `std::string::String` in the current scope
   --> backend/connector-integration/src/connectors/fiserv/transformers.rs:602:22
    |
599 |                   reference_transaction_id: router_data
    |  ___________________________________________-
600 | |                     .request
601 | |                     .connector_transaction_id
602 | |                     .get_connector_transaction_id()
    | |                     -^^^^^^^^^^^^^^^^^^^^^^^^^^^^ method not found in `String`
```

**Problem Analysis**:
While `PaymentsSyncData` might have a `connector_transaction_id` that provides a `get_connector_transaction_id()` method, `RefundSyncData` might simply have a `String` that doesn't provide this method.

**Solution**:
Adapt the code to handle the specific type by either:
1. Using the appropriate method for the specific type
2. Converting to a common type that both can use

**Example Implementation**:
```rust
// In PaymentsSync flow, using the method:
reference_transaction_id: router_data
    .request
    .connector_transaction_id
    .get_connector_transaction_id()
    .change_context(ConnectorError::MissingConnectorTransactionID)?,

// In RefundSync flow, using simple clone instead:
reference_transaction_id: router_data
    .request
    .connector_transaction_id
    .clone(),
```

These additional patterns demonstrate how to handle common issues that arise when implementing multiple flows in the macro framework, especially when dealing with similar but distinct flows like Payment Sync vs Refund Sync.
