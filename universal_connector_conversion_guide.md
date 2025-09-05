# Universal Connector Conversion Guide: Hyperswitch to Connector Service

## ⚠️ CRITICAL UPDATES - CORRECTED ARCHITECTURAL PATTERNS

This guide provides a systematic approach to converting Hyperswitch connector implementations to the Connector Service architecture based on analysis of existing successful implementations (Adyen, Razorpay, Checkout). **This guide has been updated to fix critical architectural discrepancies identified in the codebase.**

## Table of Contents

1. [🚨 Critical Fixes Applied](#critical-fixes-applied)
2. [Architecture Overview](#architecture-overview)
3. [Core Patterns](#core-patterns)
4. [Step-by-Step Conversion Process](#step-by-step-conversion-process)
5. [Implementation Templates](#implementation-templates)
6. [Common Patterns and Best Practices](#common-patterns-and-best-practices)
7. [Error Handling Patterns](#error-handling-patterns)
8. [Testing and Validation](#testing-and-validation)
9. [🔧 Test Implementation Guide](#test-implementation-guide)

## 🚨 Critical Fixes Applied

### **ARCHITECTURAL CORRECTION: File Structure Pattern**

❌ **PREVIOUS INCORRECT GUIDANCE:**
```
backend/connector-integration/src/connectors/connector_name/
├── mod.rs          # WRONG - Only Forte uses this pattern
└── transformers.rs
```

✅ **CORRECTED PATTERN (Used by ALL other connectors):**
```
backend/connector-integration/src/connectors/
├── connector_name.rs          # Main implementation file
└── connector_name/
    └── transformers.rs         # Data transformers only
```

**Evidence from Actual Implementations:**
- [`adyen.rs`](backend/connector-integration/src/connectors/adyen.rs) + [`adyen/transformers.rs`](backend/connector-integration/src/connectors/adyen/transformers.rs)
- [`checkout.rs`](backend/connector-integration/src/connectors/checkout.rs) + [`checkout/transformers.rs`](backend/connector-integration/src/connectors/checkout/transformers.rs)
- [`razorpay.rs`](backend/connector-integration/src/connectors/razorpay.rs) + [`razorpay/transformers.rs`](backend/connector-integration/src/connectors/razorpay/transformers.rs)

### **MISSING CRITICAL COMPONENTS ADDED:**
1. **Connector Struct Definition** patterns
2. **Connector Specifications** implementation
3. **Webhook Implementation** detailed patterns
4. **Validation Trait** implementation
5. **Source Verification** implementations
6. **Domain Type Integration** steps
7. **Complete Testing** implementation guide with correct API types

## Architecture Overview

### Connector Service Architecture

The Connector Service uses a modern, generic-based architecture with the following key components:

```rust
// Core structure
pub struct ConnectorName<T: PaymentMethodDataTypes> {
    // Generic type parameter for payment method data
}

// RouterDataV2 with flow-specific typing
RouterDataV2<Flow, FlowCommonData, FlowRequest, FlowResponse>

// Macro-based implementation
macros::create_all_prerequisites!()
macros::macro_connector_implementation!()
```

### Key Architectural Differences from Hyperswitch

| Aspect | Hyperswitch | Connector Service |
|--------|-------------|-------------------|
| **Type System** | Basic structs | Generic type parameters with bounds |
| **Flow Architecture** | Simple flow handling | Flow-specific RouterDataV2 with typed flows |
| **Code Generation** | Manual implementation | Macro-based code generation |
| **Authentication** | Simple auth types | Structured auth with TryFrom patterns |
| **Error Handling** | Basic error mapping | Comprehensive error transformation |
| **Status Mapping** | Direct enum mapping | Context-aware status determination |

## Core Patterns

### 1. Generic Type System

**Pattern**: All connector implementations use generic type parameters with specific bounds:

```rust
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorTrait for ConnectorName<T>
```

### 2. Flow-Specific RouterData

**Pattern**: Each flow uses typed RouterDataV2:

```rust
RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
```

### 3. Macro-Based Implementation

**Pattern**: Use macros for boilerplate code generation:

```rust
macros::create_all_prerequisites!(
    connector_name: ConnectorName,
    generic_type: T,
    api: [
        (flow: Authorize, request_body: RequestType, response_body: ResponseType, router_data: RouterDataType),
        // ... other flows
    ]
);
```

### 4. Authentication Patterns

**Pattern**: Structured authentication with TryFrom implementations:

```rust
pub struct ConnectorAuthType {
    pub api_key: Secret<String>,
    pub additional_field: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for ConnectorAuthType {
    type Error = domain_types::errors::ConnectorError;
    // Implementation
}
```

## Step-by-Step Conversion Process

### Step 1: Project Structure Setup (CORRECTED)

1. **Create connector files using CORRECT pattern**:
   ```
   backend/connector-integration/src/connectors/
   ├── connector_name.rs          # Main implementation
   └── connector_name/
       └── transformers.rs         # Data transformers only
   ```

2. **Update parent connectors.rs**:
   ```rust
   pub mod connector_name;
   ```

3. **Register in domain types** (CRITICAL - Often missed):
   ```rust
   // In backend/domain_types/src/connector_types.rs
   pub enum ConnectorEnum {
       // ... existing connectors
       ConnectorName,
   }
   
   // In backend/domain_types/src/types.rs
   pub struct Connectors {
       // ... existing connectors
       pub connector_name: ConnectorSettings,
   }
   ```

### Step 2: Define Core Connector Structure (ENHANCED)

1. **Create generic connector struct with proper instantiation**:
   ```rust
   // In connector_name.rs
   #[derive(Clone)]
   pub struct ConnectorName<T> {
       #[allow(dead_code)]
       _phantom: std::marker::PhantomData<T>,
   }
   
   impl<T> ConnectorName<T> {
       pub const fn new() -> &'static Self {
           &Self {
               _phantom: std::marker::PhantomData,
           }
       }
   }
   ```

2. **Implement ALL required trait bounds** (COMPLETE LIST):
   ```rust
   // Service trait
   impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
       connector_types::ConnectorServiceTrait<T> for ConnectorName<T> {}
   
   // Flow-specific traits (implement only what's actually supported)
   impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
       connector_types::PaymentAuthorizeV2<T> for ConnectorName<T> {}
   
   impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
       connector_types::PaymentSyncV2 for ConnectorName<T> {}
   
   impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
       connector_types::PaymentCapture for ConnectorName<T> {}
   
   impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
       connector_types::PaymentVoidV2 for ConnectorName<T> {}
   
   impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
       connector_types::RefundV2 for ConnectorName<T> {}
   
   impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
       connector_types::RefundSyncV2 for ConnectorName<T> {}
   
   // Validation trait
   impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
       connector_types::ValidationTrait for ConnectorName<T> {}
   ```

### Step 2.5: Implement ConnectorCommon (CRITICAL - Often missed)

```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorCommon for ConnectorName<T>
{
    fn id(&self) -> &'static str {
        "connector_name"
    }
    
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }
    
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = transformers::ConnectorAuthType::try_from(auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            "Authorization".to_string(),
            format!("Bearer {}", auth.api_key.peek()).into_masked(),
        )])
    }
    
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.connector_name.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        // Implement error response building
        let response: transformers::ConnectorErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.unwrap_or_else(|| "UNKNOWN_ERROR".to_string()),
            message: response.error_message.unwrap_or_else(|| "Unknown error".to_string()),
            reason: response.error_message,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}
```

### Step 3: Authentication Implementation

1. **Define auth structure**:
   ```rust
   pub struct ConnectorAuthType {
       pub api_key: Secret<String>,
       // Add connector-specific auth fields
   }
   ```

2. **Implement TryFrom for ConnectorAuthType**:
   ```rust
   impl TryFrom<&domain_types::router_data::ConnectorAuthType> for ConnectorAuthType {
       type Error = domain_types::errors::ConnectorError;
       fn try_from(auth_type: &domain_types::router_data::ConnectorAuthType) -> Result<Self, Self::Error> {
           match auth_type {
               domain_types::router_data::ConnectorAuthType::HeaderKey { api_key } => {
                   Ok(Self { api_key: api_key.to_owned() })
               }
               _ => Err(domain_types::errors::ConnectorError::FailedToObtainAuthType),
           }
       }
   }
   ```

### Step 4: Request/Response Structures

1. **Define request structures with generics**:
   ```rust
   #[derive(Debug, Serialize)]
   pub struct ConnectorPaymentRequest<T: PaymentMethodDataTypes + Serialize> {
       pub amount: MinorUnit,
       pub currency: String,
       pub payment_method: PaymentMethodData<T>,
       // Add connector-specific fields
   }
   ```

2. **Define response structures**:
   ```rust
   #[derive(Debug, Deserialize)]
   pub struct ConnectorPaymentResponse {
       pub id: String,
       pub status: ConnectorStatus,
       // Add connector-specific fields
   }
   ```

### Step 5: Status Mapping

1. **Define connector status enum**:
   ```rust
   #[derive(Debug, Deserialize)]
   pub enum ConnectorStatus {
       Success,
       Pending,
       Failed,
       // Add connector-specific statuses
   }
   ```

2. **Implement status conversion**:
   ```rust
   impl From<ConnectorStatus> for common_enums::AttemptStatus {
       fn from(status: ConnectorStatus) -> Self {
           match status {
               ConnectorStatus::Success => Self::Charged,
               ConnectorStatus::Pending => Self::Pending,
               ConnectorStatus::Failed => Self::Failure,
           }
       }
   }
   ```

### Step 6: Transformer Implementations

1. **Request transformation**:
   ```rust
   impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
       TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
       for ConnectorPaymentRequest<T>
   {
       type Error = error_stack::Report<domain_types::errors::ConnectorError>;
       fn try_from(item: &RouterDataV2<...>) -> Result<Self, Self::Error> {
           // Implementation
       }
   }
   ```

2. **Response transformation**:
   ```rust
   impl<F> TryFrom<ResponseRouterData<ConnectorPaymentResponse, RouterDataV2<F, ...>>>
       for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
   {
       type Error = error_stack::Report<domain_types::errors::ConnectorError>;
       fn try_from(item: ResponseRouterData<...>) -> Result<Self, Self::Error> {
           // Implementation
       }
   }
   ```

### Step 7: Macro Implementation

1. **Use create_all_prerequisites macro**:
   ```rust
   macros::create_all_prerequisites!(
       connector_name: ConnectorName,
       generic_type: T,
       api: [
           (
               flow: Authorize,
               request_body: ConnectorPaymentRequest<T>,
               response_body: ConnectorPaymentResponse,
               router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
           ),
           // Add other flows
       ],
       amount_converters: [],
       member_functions: {
           // Add connector-specific helper functions
       }
   );
   ```

2. **Use macro_connector_implementation for each flow**:
   ```rust
   macros::macro_connector_implementation!(
       connector_default_implementations: [get_content_type, get_error_response_v2],
       connector: ConnectorName,
       curl_request: Json(ConnectorPaymentRequest),
       curl_response: ConnectorPaymentResponse,
       flow_name: Authorize,
       resource_common_data: PaymentFlowData,
       flow_request: PaymentsAuthorizeData<T>,
       flow_response: PaymentsResponseData,
       http_method: Post,
       generic_type: T,
       [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
       other_functions: {
           fn get_url(&self, req: &RouterDataV2<...>) -> CustomResult<String, errors::ConnectorError> {
               Ok(format!("{}payments", self.base_url(&req.resource_common_data.connectors)))
           }
       }
   );
   ```

## Implementation Templates

### Basic Connector Template

```rust
// mod.rs
pub mod transformers;

use domain_types::{
    connector_flow::{Authorize, Capture, PSync, Refund, Void},
    connector_types::*,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
};
use serde::Serialize;
use transformers::*;

pub struct ConnectorName<T: PaymentMethodDataTypes> {
    _phantom: std::marker::PhantomData<T>,
}

// Trait implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for ConnectorName<T> {}

// Macro implementations
macros::create_all_prerequisites!(
    connector_name: ConnectorName,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: ConnectorPaymentRequest<T>,
            response_body: ConnectorPaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
    ],
    amount_converters: [],
    member_functions: {}
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: ConnectorName,
    curl_request: Json(ConnectorPaymentRequest),
    curl_response: ConnectorPaymentResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<...>) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}payments", self.base_url(&req.resource_common_data.connectors)))
        }
    }
);
```

### Transformers Template

```rust
// transformers.rs
use common_enums::AttemptStatus;
use common_utils::types::MinorUnit;
use domain_types::{
    connector_flow::Authorize,
    connector_types::*,
    errors::ConnectorError,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

// Auth type
pub struct ConnectorAuthType {
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for ConnectorAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => {
                Ok(Self { api_key: api_key.to_owned() })
            }
            _ => Err(ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Request structures
#[derive(Debug, Serialize)]
pub struct ConnectorPaymentRequest<T: PaymentMethodDataTypes + Serialize> {
    pub amount: MinorUnit,
    pub currency: String,
    // Add connector-specific fields
}

// Response structures
#[derive(Debug, Deserialize)]
pub struct ConnectorPaymentResponse {
    pub id: String,
    pub status: ConnectorStatus,
}

#[derive(Debug, Deserialize)]
pub enum ConnectorStatus {
    Success,
    Pending,
    Failed,
}

impl From<ConnectorStatus> for AttemptStatus {
    fn from(status: ConnectorStatus) -> Self {
        match status {
            ConnectorStatus::Success => Self::Charged,
            ConnectorStatus::Pending => Self::Pending,
            ConnectorStatus::Failed => Self::Failure,
        }
    }
}

// Request transformation
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for ConnectorPaymentRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.request.minor_amount,
            currency: item.request.currency.to_string(),
        })
    }
}

// Response transformation
impl<F> TryFrom<ResponseRouterData<ConnectorPaymentResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<ConnectorPaymentResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code } = item;
        
        let status = AttemptStatus::from(response.status);
        
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id),
                redirection_data: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                mandate_reference: None,
                status_code: http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}
```

## Common Patterns and Best Practices

### 1. Payment Method Handling

**Pattern**: Use generic payment method data with type bounds:

```rust
// In request structures
pub struct PaymentRequest<T: PaymentMethodDataTypes + Serialize> {
    pub payment_method: PaymentMethodSpecificData<T>,
}

// Extract payment method data
match &router_data.request.payment_method_data {
    PaymentMethodData::Card(card) => {
        // Handle card data
    }
    PaymentMethodData::Wallet(wallet) => {
        // Handle wallet data
    }
    _ => Err(ConnectorError::NotImplemented("Payment method not supported".into()))?,
}
```

### 2. Amount Handling

**Pattern**: Use MinorUnit consistently:

```rust
// In transformers
pub amount: MinorUnit,

// From router data
amount: item.request.minor_amount,

// For refunds
amount: item.request.minor_refund_amount,
```

### 3. Error Handling

**Pattern**: Comprehensive error transformation:

```rust
// Error response structure
#[derive(Debug, Deserialize)]
pub struct ConnectorErrorResponse {
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

// Error transformation
if status == AttemptStatus::Failure {
    router_data.response = Err(ErrorResponse {
        status_code: http_code,
        code: response.error_code.unwrap_or_else(|| NO_ERROR_CODE.to_string()),
        message: response.error_message.unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
        reason: response.error_message,
        attempt_status: Some(AttemptStatus::Failure),
        connector_transaction_id: Some(response.id),
        network_decline_code: None,
        network_advice_code: None,
        network_error_message: None,
    });
}
```

### 4. Status Mapping

**Pattern**: Context-aware status determination:

```rust
// Consider capture method for status mapping
fn get_attempt_status(status: ConnectorStatus, capture_method: Option<CaptureMethod>) -> AttemptStatus {
    match status {
        ConnectorStatus::Authorized => {
            match capture_method {
                Some(CaptureMethod::Manual) => AttemptStatus::Authorized,
                _ => AttemptStatus::Charged,
            }
        }
        ConnectorStatus::Captured => AttemptStatus::Charged,
        ConnectorStatus::Failed => AttemptStatus::Failure,
    }
}
```

### 5. URL Construction

**Pattern**: Dynamic URL construction based on flow:

```rust
// In macro implementation
other_functions: {
    fn get_url(&self, req: &RouterDataV2<...>) -> CustomResult<String, ConnectorError> {
        match F {
            Authorize => Ok(format!("{}payments", self.base_url(...))),
            Capture => {
                let tx_id = req.request.connector_transaction_id;
                Ok(format!("{}payments/{}/capture", self.base_url(...), tx_id))
            }
            Refund => {
                let tx_id = req.request.connector_transaction_id;
                Ok(format!("{}payments/{}/refund", self.base_url(...), tx_id))
            }
        }
    }
}
```

## Error Handling Patterns

### 1. Authentication Errors

```rust
impl TryFrom<&ConnectorAuthType> for ConnectorAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => {
                Ok(Self { api_key: api_key.to_owned() })
            }
            _ => Err(ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}
```

### 2. Payment Method Errors

```rust
// In request transformation
match &router_data.request.payment_method_data {
    PaymentMethodData::Card(card) => {
        // Handle card
    }
    _ => Err(ConnectorError::NotImplemented(
        "Payment method not supported".into()
    ).into())?,
}
```

### 3. Response Parsing Errors

```rust
// Use change_context for error propagation
let response: ConnectorResponse = res.response
    .parse_struct("ConnectorResponse")
    .change_context(ConnectorError::ResponseDeserializationFailed)?;
```

## Testing and Validation

### 1. Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_payment_request_transformation() {
        // Test request transformation
    }
    
    #[test]
    fn test_status_mapping() {
        // Test status mapping logic
    }
}
```

### 2. Integration Tests

```rust
// Test with actual RouterDataV2 structures
#[test]
fn test_authorize_flow() {
    let router_data = RouterDataV2 {
        // Construct test data
    };
    
    let request = ConnectorPaymentRequest::try_from(&router_data).unwrap();
    // Validate request structure
}
```

## Migration Checklist

- [ ] Create connector directory structure
- [ ] Define generic connector struct with type bounds
- [ ] Implement authentication structure and TryFrom
- [ ] Define request/response structures with generics
- [ ] Implement status mapping with context awareness
- [ ] Create transformer implementations for all flows
- [ ] Use macros for boilerplate code generation
- [ ] Implement error handling patterns
- [ ] Add comprehensive tests
- [ ] Validate with actual API calls

## 🔧 Test Implementation Guide

### Critical API Type Corrections

❌ **INCORRECT API Types (from ai_generate_test.md):**
```rust
use grpc_api_types::{
    payments::{
        PaymentsAuthorizeRequest, PaymentsAuthorizeResponse, // WRONG
        PaymentsCaptureRequest, PaymentsSyncRequest,         // WRONG
        RefundsRequest, RefundsSyncRequest,                  // WRONG
    },
};
```

✅ **CORRECT API Types (from actual implementations):**
```rust
use grpc_api_types::{
    payments::{
        PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse,
        PaymentServiceCaptureRequest, PaymentServiceGetRequest,
        PaymentServiceRefundRequest, PaymentServiceVoidRequest,
        RefundServiceGetRequest, // Note: Different service for refund sync
    },
};
```

### Required Imports for Test Files

```rust
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use cards::CardNumber;
use grpc_server::{app, configs};
use hyperswitch_masking::Secret;
mod common;

use std::{
    env,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use grpc_api_types::{
    health_check::{health_client::HealthClient, HealthCheckRequest},
    payments::{
        card_payment_method_type, identifier::IdType, payment_method,
        payment_service_client::PaymentServiceClient,
        refund_service_client::RefundServiceClient,
        AuthenticationType, CaptureMethod, CardDetails, CardPaymentMethodType,
        Currency, Identifier, PaymentMethod, PaymentServiceAuthorizeRequest,
        PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest,
        PaymentServiceGetRequest, PaymentServiceRefundRequest,
        PaymentServiceVoidRequest, PaymentStatus, RefundServiceGetRequest,
        RefundStatus, Address, PaymentAddress, CountryAlpha2,
    },
};
use tonic::{transport::Channel, Request};
```

### Correct Request Creation Patterns

#### Payment Authorization Request
```rust
fn create_payment_authorize_request(capture_method: CaptureMethod) -> PaymentServiceAuthorizeRequest {
    let card_details = card_payment_method_type::CardType::Credit(CardDetails {
        card_number: Some(CardNumber::from_str(TEST_CARD_NUMBER).unwrap()),
        card_exp_month: Some(Secret::new(TEST_CARD_EXP_MONTH.to_string())),
        card_exp_year: Some(Secret::new(TEST_CARD_EXP_YEAR.to_string())),
        card_cvc: Some(Secret::new(TEST_CARD_CVC.to_string())),
        card_holder_name: Some(Secret::new(TEST_CARD_HOLDER.to_string())),
        card_issuer: None,
        card_network: None,
        card_type: None,
        card_issuing_country_alpha2: None,
        bank_code: None,
        nick_name: None,
    });

    PaymentServiceAuthorizeRequest {
        amount: TEST_AMOUNT,
        minor_amount: TEST_AMOUNT,
        currency: i32::from(Currency::Usd),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Card(CardPaymentMethodType {
                card_type: Some(card_details),
            })),
        }),
        email: Some(TEST_EMAIL.to_string().into()),
        address: Some(PaymentAddress {
            billing_address: Some(Address {
                first_name: Some("Test".to_string()),
                last_name: Some("User".to_string()),
                line1: Some("123 Test St".to_string().into()),
                city: Some("Test City".to_string().into()),
                state: Some("NY".to_string().into()),
                zip_code: Some("10001".to_string().into()),
                country_alpha2_code: Some(i32::from(CountryAlpha2::Us)),
                phone_number: None,
                phone_country_code: None,
                email: None,
            }),
            shipping_address: None,
        }),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("connector_test_{}", get_timestamp()))),
        }),
        enrolled_for_3ds: false,
        request_incremental_authorization: false,
        capture_method: Some(i32::from(capture_method)),
        metadata: std::collections::HashMap::new(),
        ..Default::default()
    }
}
```

#### Payment Sync Request
```rust
fn create_payment_sync_request(transaction_id: &str) -> PaymentServiceGetRequest {
    PaymentServiceGetRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("sync_{}", get_timestamp()))),
        }),
    }
}
```

#### Correct Transaction ID Extraction
```rust
fn extract_transaction_id(response: &PaymentServiceAuthorizeResponse) -> String {
    match &response.transaction_id {
        Some(id) => match &id.id_type {
            Some(id_type) => match id_type {
                IdType::Id(id) => id.clone(),
                IdType::EncodedData(id) => id.clone(),
                _ => format!("unknown_id_type_{}", get_timestamp()),
            },
            None => format!("no_id_type_{}", get_timestamp()),
        },
        None => format!("no_transaction_id_{}", get_timestamp()),
    }
}
```

### Correct Metadata Headers Implementation

```rust
fn add_connector_metadata<T>(request: &mut Request<T>) {
    // Get credentials from environment
    let api_key = env::var(CONNECTOR_API_KEY_ENV)
        .expect("API key environment variable must be set");
    
    // Add required headers
    request.metadata_mut().append(
        "x-connector",
        CONNECTOR_NAME.parse().expect("Failed to parse x-connector"),
    );
    request.metadata_mut().append(
        "x-auth",
        AUTH_TYPE.parse().expect("Failed to parse x-auth"),
    );
    request.metadata_mut().append(
        "x-api-key",
        api_key.parse().expect("Failed to parse x-api-key"),
    );
    
    // Add required system headers
    request.metadata_mut().append(
        "x-merchant-id",
        "test_merchant".parse().expect("Failed to parse x-merchant-id"),
    );
    request.metadata_mut().append(
        "x-tenant-id",
        "default".parse().expect("Failed to parse x-tenant-id"),
    );
    
    // Add auth-specific headers based on AUTH_TYPE
    if AUTH_TYPE == "body-key" || AUTH_TYPE == "signature-key" {
        let key1 = env::var(CONNECTOR_KEY1_ENV)
            .expect("Key1 environment variable must be set");
        request.metadata_mut().append(
            "x-key1",
            key1.parse().expect("Failed to parse x-key1"),
        );
    }
    
    if AUTH_TYPE == "signature-key" {
        let api_secret = env::var(CONNECTOR_API_SECRET_ENV)
            .expect("API secret environment variable must be set");
        request.metadata_mut().append(
            "x-api-secret",
            api_secret.parse().expect("Failed to parse x-api-secret"),
        );
    }
}
```

### Flow Implementation Detection

Before implementing tests, analyze the connector to determine which flows are actually implemented:

```rust
// Check for actual implementations vs placeholders
// DO NOT TEST empty implementations like:
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for ConnectorName<T> {}

// ONLY TEST implementations with actual methods like:
impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for ConnectorName<T>
{
    fn get_headers(&self, req: &RouterDataV2<...>) -> CustomResult<...> {
        // Actual implementation
    }
    fn get_url(&self, req: &RouterDataV2<...>) -> CustomResult<String, ...> {
        // Actual implementation
    }
    // Other implemented methods
}
```

### Complete Test Template

```rust
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use cards::CardNumber;
use grpc_server::{app, configs};
use hyperswitch_masking::Secret;
mod common;

use std::{
    env,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use grpc_api_types::{
    health_check::{health_client::HealthClient, HealthCheckRequest},
    payments::{
        card_payment_method_type, identifier::IdType, payment_method,
        payment_service_client::PaymentServiceClient,
        AuthenticationType, CaptureMethod, CardDetails, CardPaymentMethodType,
        Currency, Identifier, PaymentMethod, PaymentServiceAuthorizeRequest,
        PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest,
        PaymentServiceGetRequest, PaymentStatus, Address, PaymentAddress,
        CountryAlpha2,
    },
};
use tonic::{transport::Channel, Request};

// Constants
const CONNECTOR_NAME: &str = "connector_name";
const AUTH_TYPE: &str = "header-key"; // or "body-key", "signature-key"

// Environment variables
const CONNECTOR_API_KEY_ENV: &str = "TEST_CONNECTOR_API_KEY";
// Add other env vars based on auth type

// Test data
const TEST_AMOUNT: i64 = 1000;
const TEST_CARD_NUMBER: &str = "4242424242424242";
const TEST_CARD_EXP_MONTH: &str = "12";
const TEST_CARD_EXP_YEAR: &str = "2025";
const TEST_CARD_CVC: &str = "123";
const TEST_CARD_HOLDER: &str = "Test User";
const TEST_EMAIL: &str = "customer@example.com";

// Helper functions
fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Test implementations
#[tokio::test]
async fn test_health() {
    grpc_test!(client, HealthClient<Channel>, {
        let response = client
            .check(Request::new(HealthCheckRequest {
                service: "connector_service".to_string(),
            }))
            .await
            .expect("Failed to call health check")
            .into_inner();

        assert_eq!(
            response.status(),
            grpc_api_types::health_check::health_check_response::ServingStatus::Serving
        );
    });
}

#[tokio::test]
async fn test_payment_authorization_auto_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_payment_authorize_request(CaptureMethod::Automatic);
        let mut grpc_request = Request::new(request);
        add_connector_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Verify response with proper error handling for sandbox
        let acceptable_statuses = [
            i32::from(PaymentStatus::Charged),
            i32::from(PaymentStatus::Pending),
            i32::from(PaymentStatus::Authorized),
        ];
        
        assert!(
            acceptable_statuses.contains(&response.status),
            "Payment should be in acceptable state but was: {}",
            response.status
        );

        if response.transaction_id.is_some() {
            let _transaction_id = extract_transaction_id(&response);
            // Use transaction_id for further operations
        }
    });
}

// Add other test functions following the same pattern
```

### Missing Components to Add

1. **Connector Specifications Implementation**:
```rust
impl ConnectorSpecifications for ConnectorName<DefaultPCIHolder> {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&CONNECTOR_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [EventClass]> {
        Some(CONNECTOR_SUPPORTED_WEBHOOK_FLOWS)
    }
}
```

2. **Webhook Implementation**:
```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for ConnectorName<T>
{
    fn get_event_type(&self, request: RequestDetails, ...) -> Result<EventType, ...> {
        // Implementation
    }
    
    fn process_payment_webhook(&self, ...) -> Result<WebhookDetailsResponse, ...> {
        // Implementation
    }
}
```

3. **Validation Implementation**:
```rust
impl ConnectorValidation for ConnectorName<DefaultPCIHolder> {
    fn validate_mandate_payment(&self, ...) -> CustomResult<(), ConnectorError> {
        // Implementation
    }
    
    fn is_webhook_source_verification_mandatory(&self) -> bool {
        false
    }
}
```

## Conclusion

This guide provides a systematic approach to converting Hyperswitch connectors to the Connector Service architecture. The key is to follow the established patterns from existing implementations while adapting to the specific requirements of each connector.

**CRITICAL UPDATES APPLIED:**
1. **Fixed file structure pattern** - Use `connector_name.rs` not `mod.rs`
2. **Added missing components** - ConnectorCommon, Specifications, Webhooks, Validation
3. **Corrected test implementation** - Fixed API types, request structures, metadata handling
4. **Enhanced error handling** - Added comprehensive error patterns
5. **Added domain integration** - ConnectorEnum and Connectors struct registration

The macro-based approach significantly reduces boilerplate code while maintaining type safety and flexibility. The generic type system ensures that payment method data is handled consistently across all flows.

Remember to test thoroughly using the corrected test patterns and follow the error handling patterns to ensure robust connector implementations.