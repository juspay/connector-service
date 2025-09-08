# Comprehensive UCS Connector Error Fix Guide

## Overview
This guide provides systematic solutions for common errors encountered when converting Hyperswitch connectors to UCS (Universal Connector Service) format.

## Common Build Errors and Solutions

### 1. Generic Type Parameter Errors

#### Error: `the trait bound 'T: PaymentMethodDataTypes' is not satisfied`
**Cause**: Missing or incorrect generic type constraints

**Solution**:
```rust
// Correct constraint format
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for NewConnector<T>
{
    // implementation
}
```

#### Error: `cannot find type 'RouterData' in this scope`
**Cause**: Using old Hyperswitch RouterData instead of UCS RouterDataV2

**Solution**:
```rust
// Replace this:
RouterData<F, T, Req, Res>

// With this:
RouterDataV2<F, FCD, Req, Res>
```

### 2. Macro-Related Errors

#### Error: `macro 'create_connector_impl_struct' not found`
**Cause**: Using old Hyperswitch macro patterns

**Solution**:
```rust
// Replace old macro:
create_connector_impl_struct!(NewConnector);

// With UCS macro:
macros::create_all_prerequisites!(
    connector_name: NewConnector,
    generic_type: T,
    api: [
        // flow definitions
    ],
    amount_converters: [],
    member_functions: {
        // helper functions
    }
);
```

#### Error: `macro 'impl_connector_auth_type' not found`
**Cause**: Auth type implementation pattern changed

**Solution**:
```rust
// Manual implementation instead of macro:
pub struct NewConnectorAuthType {
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for NewConnectorAuthType {
    type Error = domain_types::errors::ConnectorError;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(domain_types::errors::ConnectorError::FailedToObtainAuthType),
        }
    }
}
```

### 3. Import and Module Errors

#### Error: `unresolved import 'crate::connector::utils'`
**Cause**: UCS has different module structure

**Solution**:
```rust
// Remove old imports:
use crate::connector::utils;

// Add correct UCS imports:
use common_utils::{
    errors::CustomResult, ext_traits::ByteSliceExt, types::StringMinorUnit,
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{PaymentFlowData, RefundFlowData, /* other types */},
    router_data_v2::RouterDataV2,
};
```

#### Error: `cannot find function 'get_error_response_v2' in this scope`
**Cause**: Missing error response implementation

**Solution**:
```rust
// Add to macro implementation:
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    // ... rest of macro
);
```

### 4. Data Access Pattern Errors

#### Error: `no field 'connector_meta' on type 'RouterDataV2'`
**Cause**: UCS uses different data access patterns

**Solution**:
```rust
// Replace old pattern:
item.connector_meta

// With UCS pattern:
item.resource_common_data.connectors.new_connector
```

#### Error: `no method named 'get_amount' found`
**Cause**: Amount access pattern changed

**Solution**:
```rust
// Replace:
item.get_amount()

// With:
item.request.minor_amount
```

### 5. Response Handling Errors

#### Error: `missing field 'status_code' in PaymentsResponseData`
**Cause**: UCS requires additional response fields

**Solution**:
```rust
// Ensure response includes all required fields:
Ok(Self {
    response: Ok(PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(item.response.id),
        redirection_data: None,
        connector_metadata: None,
        network_txn_id: None,
        connector_response_reference_id: None,
        incremental_authorization_allowed: None,
        mandate_reference: None,
        status_code: item.http_code, // Required field
    }),
    resource_common_data: PaymentFlowData {
        status,
        ..item.router_data.resource_common_data
    },
    ..item.router_data
})
```

### 6. Trait Implementation Errors

#### Error: `trait 'ConnectorIntegration' is not implemented`
**Cause**: Using old trait instead of ConnectorIntegrationV2

**Solution**:
```rust
// Replace:
impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData>

// With:
impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
```

### 7. Serialization/Deserialization Errors

#### Error: `the trait 'Serialize' is not implemented for 'T'`
**Cause**: Missing Serialize constraint on generic type

**Solution**:
```rust
// Add Serialize to all generic constraints:
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
```

#### Error: `cannot serialize field with generic type`
**Cause**: Incorrect generic handling in request structs

**Solution**:
```rust
// Use proper generic constraints in request structs:
#[derive(Debug, Serialize)]
pub struct NewConnectorPaymentsRequest<
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
> {
    // fields
}
```

## Systematic Debugging Process

### Step 1: Identify Error Category
1. **Compilation Errors**: Missing imports, type mismatches, trait bounds
2. **Runtime Errors**: Serialization issues, data access problems
3. **Logic Errors**: Incorrect flow implementations, wrong response handling

### Step 2: Common Fix Patterns

#### For Missing Trait Implementations:
```rust
// Add all required trait implementations:
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for NewConnector<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for NewConnector<T> {}

// Continue for all flows...
```

#### For Router Data Wrapper Issues:
```rust
// Create proper wrapper struct:
#[derive(Debug, Serialize)]
pub struct NewConnectorRouterData<T, U> {
    pub amount: MinorUnit,
    pub router_data: T,
    pub payment_method_data: std::marker::PhantomData<U>,
}

impl<T, U> TryFrom<(MinorUnit, T)> for NewConnectorRouterData<T, U> {
    type Error = domain_types::errors::ConnectorError;
    fn try_from((amount, item): (MinorUnit, T)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data: item,
            payment_method_data: std::marker::PhantomData,
        })
    }
}
```

### Step 3: Validation Checklist

#### Before Building:
- [ ] All imports are UCS-compatible
- [ ] Generic type constraints include all required traits
- [ ] RouterDataV2 is used instead of RouterData
- [ ] Proper macro patterns are implemented
- [ ] All flows have corresponding trait implementations

#### After Build Errors:
- [ ] Check error messages for missing trait bounds
- [ ] Verify macro syntax and parameters
- [ ] Ensure all required fields are present in responses
- [ ] Validate data access patterns

#### For Runtime Issues:
- [ ] Test serialization/deserialization with sample data
- [ ] Verify authentication header construction
- [ ] Check URL building logic
- [ ] Validate response status mapping

## Error-Specific Solutions

### Authentication Errors
```rust
// Ensure proper auth header construction:
pub fn get_auth_header(
    &self,
    auth_type: &ConnectorAuthType,
) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
    let auth = new_connector::NewConnectorAuthType::try_from(auth_type)
        .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
    Ok(vec![(
        headers::AUTHORIZATION.to_string(),
        format!("Bearer {}", auth.api_key.peek()).into_masked(),
    )])
}
```

### URL Building Errors
```rust
// Implement proper URL building:
fn get_url(
    &self,
    req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
) -> CustomResult<String, errors::ConnectorError> {
    Ok(format!("{}payments", self.connector_base_url_payments(req)))
}
```

### Response Transformation Errors
```rust
// Ensure complete response transformation:
impl TryFrom<ResponseRouterData<NewConnectorPaymentsResponse, RouterDataV2<...>>> 
    for RouterDataV2<...>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<...>) -> Result<Self, Self::Error> {
        // Map connector status to UCS status
        let status = match item.response.status.as_str() {
            "succeeded" | "completed" => common_enums::AttemptStatus::Charged,
            "pending" | "processing" => common_enums::AttemptStatus::Pending,
            "failed" | "declined" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                mandate_reference: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}
```

## Testing and Validation

### Unit Test Errors
```rust
// Ensure test structure matches UCS patterns:
#[tokio::test]
async fn test_authorize_payment() {
    let connector = NewConnector::new();
    let router_data = RouterDataV2 {
        // proper test data structure
    };
    
    let result = connector.execute_pretasks(router_data, &state).await;
    assert!(result.is_ok());
}
```

### Integration Test Issues
- Verify test data matches UCS RouterDataV2 structure
- Ensure proper flow data initialization
- Check authentication setup in tests

## Prevention Strategies

1. **Use Reference Implementation**: Always compare against working UCS connectors (Adyen, Checkout)
2. **Incremental Development**: Implement one flow at a time and test before proceeding
3. **Type-Driven Development**: Let the compiler guide implementation through type errors
4. **Macro Understanding**: Study existing macro usage patterns before implementing
5. **Documentation Review**: Keep UCS documentation and examples handy during development

## Quick Reference Commands

### Build and Test
```bash
# Build specific connector
cargo build --bin connector-integration

# Run connector tests
cargo test --test new_connector_payment_flows_test

# Check for unused imports
cargo clippy -- -W unused-imports

# Format code
cargo fmt
```

### Common File Locations
- Main connector: `backend/connector-integration/src/connectors/new_connector.rs`
- Transformers: `backend/connector-integration/src/connectors/new_connector/transformers.rs`
- Tests: `backend/grpc-server/tests/new_connector_payment_flows_test.rs`
- Types: `backend/domain_types/src/connector_types.rs`
- Config: `config/development.toml`

This guide should resolve most common issues encountered during UCS connector conversion. For complex issues, compare your implementation against working UCS connectors and ensure all patterns match the UCS architecture.