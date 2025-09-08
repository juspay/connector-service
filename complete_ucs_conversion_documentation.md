# Complete UCS Connector Conversion Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture Comparison](#architecture-comparison)
3. [Conversion Process](#conversion-process)
4. [Implementation Guide](#implementation-guide)
5. [Error Resolution](#error-resolution)
6. [Testing Strategy](#testing-strategy)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

## Overview

This documentation provides a complete guide for converting Hyperswitch connectors to UCS (Universal Connector Service) format. The conversion involves fundamental architectural changes that require careful attention to patterns, types, and implementation details.

### Key Differences: Hyperswitch vs UCS

| Aspect | Hyperswitch | UCS |
|--------|-------------|-----|
| Router Data | `RouterData<F, T, Req, Res>` | `RouterDataV2<F, FCD, Req, Res>` |
| Generic Constraints | Simple type parameters | `PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize` |
| Data Access | `item.connector_meta` | `item.resource_common_data.connectors` |
| Macros | `create_connector_impl_struct!` | `macros::create_all_prerequisites!` |
| Flow Data | Direct access | Wrapped in `PaymentFlowData`/`RefundFlowData` |
| Auth Handling | Built-in patterns | Manual implementation required |
| Error Responses | Simple mapping | `with_error_response_body!` macro |

## Architecture Comparison

### Hyperswitch Pattern (Old)
```rust
pub struct Connector;

impl<Flow, Request, Response> ConnectorIntegration<Flow, Request, Response> for Connector {
    // Simple implementation
}

// Direct RouterData usage
RouterData<Flow, Request, Response>
```

### UCS Pattern (New)
```rust
pub struct Connector<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Flow, FlowData, Request, Response> for Connector<T> {
    // Complex generic implementation
}

// RouterDataV2 with flow-specific data
RouterDataV2<Flow, PaymentFlowData, Request, Response>
```

## Conversion Process

### Phase 1: Project Setup

#### 1.1 Update Domain Types
**File**: `backend/domain_types/src/connector_types.rs`

Add connector to enum:
```rust
#[derive(Clone, Copy, Debug, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ConnectorEnum {
    // ... existing connectors
    NewConnector,
}
```

Add to conversion implementation:
```rust
impl ForeignTryFrom<grpc_api_types::payments::Connector> for ConnectorEnum {
    type Error = String;
    fn foreign_try_from(value: grpc_api_types::payments::Connector) -> Result<Self, Self::Error> {
        match value {
            // ... existing mappings
            grpc_api_types::payments::Connector::NewConnector => Ok(Self::NewConnector),
        }
    }
}
```

#### 1.2 Register Connector
**File**: `backend/connector-integration/src/types.rs`

Add import:
```rust
use crate::connectors::NewConnector;
```

Add to converter:
```rust
pub fn convert_connector(connector: ConnectorEnum) -> Box<dyn ConnectorData> {
    match connector {
        // ... existing connectors
        ConnectorEnum::NewConnector => Box::new(NewConnector::new()),
    }
}
```

#### 1.3 Update Configuration
**File**: `config/development.toml`

```toml
[connectors]
new_connector.base_url = "https://api.newconnector.com/"
```

### Phase 2: Core Implementation

#### 2.1 Module Declaration
**File**: `backend/connector-integration/src/connectors.rs`

```rust
pub mod new_connector;
pub use self::new_connector::NewConnector;
```

#### 2.2 Main Connector Structure
**File**: `backend/connector-integration/src/connectors/new_connector.rs`

```rust
pub mod transformers;

use base64::Engine;
use common_enums::CurrencyUnit;
use common_utils::{
    errors::CustomResult, ext_traits::ByteSliceExt, types::StringMinorUnit,
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund,
        RepeatPayment, SetupMandate, SubmitEvidence, Void, CreateSessionToken,
    },
    connector_types::{
        AcceptDisputeData, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        SetupMandateRequestData, SubmitEvidenceData, SessionTokenRequestData, SessionTokenResponseData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use serde::Serialize;
use std::fmt::Debug;
use hyperswitch_masking::{ExposeInterface, Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use transformers::{
    self as new_connector,
    // Import request/response types
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

use error_stack::ResultExt;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

// Trait implementations for all required traits
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for NewConnector<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for NewConnector<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for NewConnector<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for NewConnector<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for NewConnector<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for NewConnector<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for NewConnector<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for NewConnector<T> {}

// Additional trait implementations...

// Macro for creating prerequisites
macros::create_all_prerequisites!(
    connector_name: NewConnector,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: NewConnectorPaymentsRequest<T>,
            response_body: NewConnectorPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: NewConnectorSyncRequest,
            response_body: NewConnectorSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        // ... other flows
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.new_connector.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.new_connector.base_url
        }
    }
);

// ConnectorCommon implementation
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for NewConnector<T>
{
    fn id(&self) -> &'static str {
        "new_connector"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn get_auth_header(
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

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.new_connector.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: new_connector::NewConnectorErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message: response.message.unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
            reason: response.message,
            attempt_status: None,
            connector_transaction_id: response.transaction_id,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// Macro implementations for each flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: NewConnector,
    curl_request: Json(NewConnectorPaymentsRequest),
    curl_response: NewConnectorPaymentsResponse,
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
            Ok(format!("{}payments", self.connector_base_url_payments(req)))
        }
    }
);

// Repeat macro_connector_implementation for other flows...

// Stub implementations for unsupported flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>
    for NewConnector<T> {}

// SourceVerification implementations for all flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for NewConnector<T> {}

// Repeat for all flows...
```

### Phase 3: Transformers Implementation

#### 3.1 Transformers Structure
**File**: `backend/connector-integration/src/connectors/new_connector/transformers.rs`

```rust
use std::collections::HashMap;

use cards::CardNumber;
use common_utils::{
    ext_traits::OptionExt,
    pii,
    request::Method,
    types::{MinorUnit, StringMinorUnit},
};
use domain_types::{
    connector_flow::{self, Authorize, PSync, RSync, RepeatPayment, SetupMandate, Void, Capture},
    connector_types::{
        MandateReference, MandateReferenceId, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        ResponseId, SetupMandateRequestData,
    },
    errors::{self, ConnectorError},
    payment_method_data::{
        PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
        WalletData as WalletDataPaymentMethod,
    },
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret, PeekInterface};
use serde::{Deserialize, Serialize};
use strum::Display;

use crate::{connectors::new_connector::NewConnectorRouterData, types::ResponseRouterData};

// Auth Type Implementation
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

// Request/Response Structures
#[derive(Debug, Serialize)]
pub struct NewConnectorPaymentsRequest<
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
> {
    pub amount: MinorUnit,
    pub currency: String,
    pub payment_method: NewConnectorPaymentMethod<T>,
    pub reference: String,
}

#[derive(Debug, Serialize)]
pub struct NewConnectorPaymentMethod<
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
> {
    #[serde(flatten)]
    pub method_data: NewConnectorMethodData<T>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum NewConnectorMethodData<
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
> {
    #[serde(rename = "card")]
    Card(NewConnectorCard<T>),
}

#[derive(Debug, Serialize)]
pub struct NewConnectorCard<
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
> {
    pub number: RawCardNumber<T>,
    pub expiry_month: Secret<String>,
    pub expiry_year: Secret<String>,
    pub cvc: Secret<String>,
    pub holder_name: Option<Secret<String>>,
}

#[derive(Debug, Deserialize)]
pub struct NewConnectorPaymentsResponse {
    pub id: String,
    pub status: String,
    pub amount: MinorUnit,
}

#[derive(Debug, Deserialize)]
pub struct NewConnectorErrorResponse {
    pub error_code: Option<String>,
    pub message: Option<String>,
    pub transaction_id: Option<String>,
}

// Router Data Wrapper
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

// TryFrom Implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        NewConnectorRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for NewConnectorPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: NewConnectorRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let payment_method = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => NewConnectorPaymentMethod {
                method_data: NewConnectorMethodData::Card(NewConnectorCard {
                    number: card.card_number.clone(),
                    expiry_month: card.card_exp_month.clone(),
                    expiry_year: card.card_exp_year.clone(),
                    cvc: card.card_cvc.clone(),
                    holder_name: item.router_data.request.customer_name.clone().map(Secret::new),
                }),
            },
            _ => return Err(ConnectorError::NotImplemented("payment method".into()).into()),
        };

        Ok(Self {
            amount: item.router_data.request.minor_amount,
            currency: item.router_data.request.currency.to_string(),
            payment_method,
            reference: item.router_data.resource_common_data.connector_request_reference_id.clone(),
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        ResponseRouterData<
            NewConnectorPaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            NewConnectorPaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_str() {
            "succeeded" => common_enums::AttemptStatus::Charged,
            "pending" => common_enums::AttemptStatus::Pending,
            "failed" => common_enums::AttemptStatus::Failure,
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

// Implement similar patterns for other flows (PSync, Capture, Void, Refund, RSync)
```

## Error Resolution

### Common Build Errors

1. **Generic Type Constraint Errors**
   - **Error**: `the trait bound 'T: PaymentMethodDataTypes' is not satisfied`
   - **Solution**: Add complete constraint: `T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize`

2. **RouterData Type Errors**
   - **Error**: `cannot find type 'RouterData' in this scope`
   - **Solution**: Use `RouterDataV2<F, FCD, Req, Res>` instead

3. **Macro Expansion Errors**
   - **Error**: `macro 'create_connector_impl_struct' not found`
   - **Solution**: Use `macros::create_all_prerequisites!` pattern

4. **Data Access Errors**
   - **Error**: `no field 'connector_meta' on type 'RouterDataV2'`
   - **Solution**: Use `item.resource_common_data.connectors.connector_name`

## Testing Strategy

### Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_request_transformation() {
        // Test request transformation logic
    }

    #[test]
    fn test_payment_response_transformation() {
        // Test response transformation logic
    }
}
```

### Integration Tests
**File**: `backend/grpc-server/tests/new_connector_payment_flows_test.rs`

Follow the patterns in [`ai_generate_test.md`](ai_generate_test.md) for comprehensive flow testing.

## Best Practices

### 1. **Type Safety**
- Always use complete generic constraints
- Leverage the type system to catch errors early
- Use proper error types and propagation

### 2. **Code Organization**
- Separate concerns between main connector and transformers
- Use consistent naming patterns
- Group related functionality together

### 3. **Error Handling**
- Implement comprehensive error responses
- Use proper error codes and messages
- Include debugging information

### 4. **Testing**
- Test all supported flows
- Include error scenarios
- Validate edge cases

### 5. **Documentation**
- Document complex transformations
- Include examples for common patterns
- Maintain up-to-date API documentation

## Troubleshooting

### Build Issues
1. Check generic type constraints
2. Verify import statements
3. Validate macro syntax
4. Ensure all required traits are implemented

### Runtime Issues
1. Test serialization/deserialization
2. Verify authentication headers
3. Check URL construction
4. Validate response mapping

### Test Failures
1. Review test data structure
2. Check flow implementations
3. Verify error handling
4. Validate response transformations

## Conclusion

Converting Hyperswitch connectors to UCS requires understanding fundamental architectural differences and following specific patterns. This documentation provides the complete framework for successful conversion, including:

- ✅ **Enhanced Conversion Prompt**: [`enhanced_connector_conversion_prompt.md`](enhanced_connector_conversion_prompt.md)
- ✅ **Error Fix Guide**: [`comprehensive_connector_error_fix_guide.md`](comprehensive_connector_error_fix_guide.md)
- ✅ **Specific Recommendations**: [`connector_conversion_recommendations.md`](connector_conversion_recommendations.md)
- ✅ **Complete Documentation**: This document

The key to success is following UCS patterns exactly, using proper generic type constraints, and implementing all required traits and transformations correctly.