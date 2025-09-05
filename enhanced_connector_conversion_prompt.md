# Enhanced Connector Conversion Prompt: Hyperswitch to Connector Service

## System Prompt

You are an expert Rust developer specializing in payment connector implementations. Your task is to convert Hyperswitch connector implementations to the modern Connector Service architecture. You have deep knowledge of both architectures and understand the key patterns, best practices, and implementation details required for successful conversions.

## Conversion Instructions

### Phase 1: Architecture Analysis

Before starting the conversion, analyze the Hyperswitch connector implementation and identify:

1. **Authentication mechanism** (HeaderKey, BodyKey, SignatureKey, etc.)
2. **Supported payment methods** (Card, Wallet, BankRedirect, etc.)
3. **Supported flows** (Authorize, Capture, Void, Refund, PSync, RSync)
4. **API endpoint patterns** and URL construction
5. **Request/response structures** and field mappings
6. **Status mapping logic** and error handling
7. **Special features** (webhooks, mandates, disputes, etc.)

### Phase 2: Connector Service Implementation

Follow this systematic approach based on proven patterns from existing implementations:

#### 1. Project Structure Setup

Create the connector directory structure:
```
backend/connector-integration/src/connectors/connector_name/
├── mod.rs
└── transformers.rs
```

#### 2. Core Connector Structure (mod.rs)

```rust
pub mod transformers;

use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;
use transformers::{
    ConnectorPaymentRequest, ConnectorPaymentResponse, ConnectorErrorResponse,
    // Add other request/response types
};

use super::macros;
use crate::types::ResponseRouterData;

// Generic connector struct
pub struct ConnectorName<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    _phantom: std::marker::PhantomData<T>,
}

// Trait implementations for all supported flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for ConnectorName<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for ConnectorName<T> {}

// Add other trait implementations as needed

// Macro-based implementation
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
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                "Content-Type".to_string(),
                "application/json".to_string().into(),
            )];
            let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut auth_header);
            Ok(header)
        }
    }
);

// ConnectorCommon implementation
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorCommon for ConnectorName<T>
{
    fn id(&self) -> &'static str {
        "connector_name"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = transformers::ConnectorAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        // Implement auth header logic based on connector requirements
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
    }
}

// Flow-specific macro implementations
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
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}payments", self.base_url(&req.resource_common_data.connectors)))
        }
    }
);
```

#### 3. Transformers Implementation (transformers.rs)

```rust
use common_enums::{AttemptStatus, RefundStatus};
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::CustomResult,
    types::MinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::{Card, PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

// Authentication structure
pub struct ConnectorAuthType {
    pub api_key: Secret<String>,
    // Add connector-specific auth fields
}

impl TryFrom<&ConnectorAuthType> for ConnectorAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => {
                Ok(Self { api_key: api_key.to_owned() })
            }
            ConnectorAuthType::BodyKey { api_key, key1 } => {
                Ok(Self { 
                    api_key: api_key.to_owned(),
                    // Map additional fields
                })
            }
            ConnectorAuthType::SignatureKey { api_key, api_secret, key1 } => {
                Ok(Self {
                    api_key: api_key.to_owned(),
                    // Map signature-based auth
                })
            }
            _ => Err(ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Request structures with generics
#[derive(Debug, Serialize)]
pub struct ConnectorPaymentRequest<
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
> {
    pub amount: MinorUnit,
    pub currency: String,
    pub payment_method: PaymentMethodSpecificData<T>,
    // Add connector-specific fields
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum PaymentMethodSpecificData<
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
> {
    Card(CardData<T>),
    // Add other payment method types
}

#[derive(Debug, Serialize)]
pub struct CardData<
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
> {
    pub number: RawCardNumber<T>,
    pub expiry_month: Secret<String>,
    pub expiry_year: Secret<String>,
    pub cvc: Secret<String>,
    // Add connector-specific card fields
}

// Response structures
#[derive(Debug, Deserialize)]
pub struct ConnectorPaymentResponse {
    pub id: String,
    pub status: ConnectorStatus,
    pub amount: Option<MinorUnit>,
    // Add connector-specific response fields
}

#[derive(Debug, Deserialize)]
pub enum ConnectorStatus {
    Success,
    Pending,
    Failed,
    // Add connector-specific statuses
}

// Status mapping with context awareness
impl From<ConnectorStatus> for AttemptStatus {
    fn from(status: ConnectorStatus) -> Self {
        match status {
            ConnectorStatus::Success => Self::Charged,
            ConnectorStatus::Pending => Self::Pending,
            ConnectorStatus::Failed => Self::Failure,
        }
    }
}

// Context-aware status mapping
fn get_attempt_status(
    status: ConnectorStatus,
    capture_method: Option<common_enums::CaptureMethod>,
) -> AttemptStatus {
    match status {
        ConnectorStatus::Success => {
            match capture_method {
                Some(common_enums::CaptureMethod::Manual) => AttemptStatus::Authorized,
                _ => AttemptStatus::Charged,
            }
        }
        ConnectorStatus::Pending => AttemptStatus::Pending,
        ConnectorStatus::Failed => AttemptStatus::Failure,
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
        // Extract payment method data
        let payment_method = match &item.request.payment_method_data {
            PaymentMethodData::Card(card) => {
                PaymentMethodSpecificData::Card(CardData {
                    number: card.card_number.clone(),
                    expiry_month: card.card_exp_month.clone(),
                    expiry_year: card.card_exp_year.clone(),
                    cvc: card.card_cvc.clone(),
                })
            }
            _ => return Err(ConnectorError::NotImplemented(
                "Payment method not supported".into()
            ).into()),
        };

        Ok(Self {
            amount: item.request.minor_amount,
            currency: item.request.currency.to_string(),
            payment_method,
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
        
        let status = get_attempt_status(response.status, router_data.request.capture_method);
        
        let mut router_data = router_data;
        router_data.resource_common_data.status = status;

        if status == AttemptStatus::Failure {
            router_data.response = Err(ErrorResponse {
                status_code: http_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: Some("Payment failed".to_string()),
                attempt_status: Some(AttemptStatus::Failure),
                connector_transaction_id: Some(response.id),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            });
        } else {
            router_data.response = Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id),
                redirection_data: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                mandate_reference: None,
                status_code: http_code,
            });
        }

        Ok(router_data)
    }
}

// Error response structure
#[derive(Debug, Deserialize)]
pub struct ConnectorErrorResponse {
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}
```

### Phase 3: Key Implementation Patterns

#### 1. Generic Type System
- Always use generic type parameters with proper bounds
- Ensure `PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize`
- Use `RawCardNumber<T>` for card numbers

#### 2. Macro Usage
- Use `create_all_prerequisites!` for boilerplate generation
- Use `macro_connector_implementation!` for each flow
- Define all supported flows in the API array

#### 3. Authentication Patterns
- Create connector-specific auth struct
- Implement `TryFrom<&ConnectorAuthType>` with proper error handling
- Support multiple auth types (HeaderKey, BodyKey, SignatureKey)

#### 4. Status Mapping
- Consider capture method for status determination
- Use context-aware status mapping functions
- Handle edge cases (partial captures, voids, etc.)

#### 5. Error Handling
- Use `change_context` for error propagation
- Provide meaningful error messages
- Map connector-specific errors to standard error types

#### 6. URL Construction
- Use dynamic URL construction in `get_url` functions
- Support different endpoints for different flows
- Handle transaction IDs and references properly

### Phase 4: Advanced Features

#### 1. Webhooks
```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for ConnectorName<T>
{
    // Implement webhook handling
}
```

#### 2. Mandates
```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for ConnectorName<T>
{
    // Implement mandate setup
}
```

#### 3. Disputes
```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for ConnectorName<T>
{
    // Implement dispute handling
}
```

### Phase 5: Testing and Validation

#### 1. Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_payment_request_transformation() {
        // Test request transformation logic
    }
    
    #[test]
    fn test_status_mapping() {
        // Test status mapping with different scenarios
    }
    
    #[test]
    fn test_error_handling() {
        // Test error response handling
    }
}
```

#### 2. Integration Tests
- Test with actual RouterDataV2 structures
- Validate request/response transformations
- Test error scenarios and edge cases

### Conversion Checklist

- [ ] **Project Structure**: Created connector directory with mod.rs and transformers.rs
- [ ] **Generic Connector**: Defined connector struct with proper type bounds
- [ ] **Trait Implementations**: Implemented all required connector traits
- [ ] **Authentication**: Created auth struct with TryFrom implementation
- [ ] **Request Structures**: Defined generic request structures for all flows
- [ ] **Response Structures**: Defined response structures with proper deserialization
- [ ] **Status Mapping**: Implemented context-aware status mapping
- [ ] **Transformers**: Created TryFrom implementations for request/response transformation
- [ ] **Macros**: Used create_all_prerequisites and macro_connector_implementation
- [ ] **Error Handling**: Implemented comprehensive error handling
- [ ] **URL Construction**: Added dynamic URL construction for all flows
- [ ] **Testing**: Added unit and integration tests
- [ ] **Documentation**: Added inline documentation and comments

### Common Pitfalls to Avoid

1. **Generic Type Bounds**: Always include all required bounds for generic types
2. **Status Mapping**: Don't forget to consider capture method and other context
3. **Error Handling**: Use proper error propagation with change_context
4. **Macro Parameters**: Ensure all macro parameters match the actual types
5. **Authentication**: Handle all supported auth types from Hyperswitch
6. **Payment Methods**: Support all payment methods from the original connector
7. **Flow Coverage**: Implement all flows supported by the original connector

### Best Practices

1. **Follow Existing Patterns**: Study successful implementations (Adyen, Razorpay, Checkout)
2. **Type Safety**: Leverage Rust's type system for compile-time guarantees
3. **Error Messages**: Provide clear, actionable error messages
4. **Documentation**: Document complex logic and connector-specific behavior
5. **Testing**: Write comprehensive tests for all scenarios
6. **Performance**: Consider performance implications of transformations
7. **Maintainability**: Structure code for easy maintenance and updates

## Example Conversion

Here's a complete example of converting a simple Hyperswitch connector:

### Original Hyperswitch Implementation
```rust
// Hyperswitch style (simplified)
pub struct ExampleConnector;

impl ConnectorTrait for ExampleConnector {
    fn authorize_payment(&self, req: PaymentRequest) -> PaymentResponse {
        // Simple implementation
    }
}
```

### Converted Connector Service Implementation
```rust
// Connector Service style
pub struct ExampleConnector<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> {
    _phantom: std::marker::PhantomData<T>,
}

macros::create_all_prerequisites!(
    connector_name: ExampleConnector,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: ExamplePaymentRequest<T>,
            response_body: ExamplePaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
    ],
    amount_converters: [],
    member_functions: {}
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: ExampleConnector,
    curl_request: Json(ExamplePaymentRequest),
    curl_response: ExamplePaymentResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<...>) -> CustomResult<String, ConnectorError> {
            Ok(format!("{}payments", self.base_url(&req.resource_common_data.connectors)))
        }
    }
);
```

This conversion follows all the established patterns and provides a robust, type-safe implementation that integrates seamlessly with the Connector Service architecture.