# Forte Connector Transformation Plan: Hyperswitch to UCS

## Overview
This document outlines the step-by-step transformation of the Forte connector from Hyperswitch architecture to Universal Connector Service (UCS) architecture.

## Transformation Strategy

### Phase 1: Project Structure Setup
1. **Create UCS file structure** (following corrected pattern from guide):
   ```
   backend/connector-integration/src/connectors/
   ├── forte.rs                    # Main implementation file
   └── forte/
       └── transformers.rs         # Data transformers only
   ```

2. **Update parent module registration**:
   - Add `pub mod forte;` to `backend/connector-integration/src/connectors/mod.rs`

3. **Register in domain types**:
   - Add `Forte` to `ConnectorEnum` in `backend/domain_types/src/connector_types.rs`
   - Add `forte: ConnectorSettings` to `Connectors` struct in `backend/domain_types/src/types.rs`

### Phase 2: Core Connector Structure Transformation

#### 2.1 Generic Connector Struct
**From (Hyperswitch)**:
```rust
#[derive(Clone)]
pub struct Forte {
    amount_converter: &'static (dyn AmountConvertor<Output = FloatMajorUnit> + Sync),
}
```

**To (UCS)**:
```rust
#[derive(Clone)]
pub struct Forte<T: PaymentMethodDataTypes> {
    #[allow(dead_code)]
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Forte<T> {
    pub const fn new() -> &'static Self {
        &Self {
            _phantom: std::marker::PhantomData,
        }
    }
}
```

#### 2.2 Trait Implementation Updates
**Replace simple trait implementations with generic bounds**:
```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Forte<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Forte<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Forte<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Forte<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Forte<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Forte<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Forte<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Forte<T> {}
```

### Phase 3: Authentication Transformation

#### 3.1 Update Auth Structure
**From (Hyperswitch)**:
```rust
pub struct ForteAuthType {
    pub(super) api_access_id: Secret<String>,
    pub(super) organization_id: Secret<String>,
    pub(super) location_id: Secret<String>,
    pub(super) api_secret_key: Secret<String>,
}
```

**To (UCS)**:
```rust
pub struct ForteAuthType {
    pub api_access_id: Secret<String>,
    pub organization_id: Secret<String>,
    pub location_id: Secret<String>,
    pub api_secret_key: Secret<String>,
}

impl TryFrom<&domain_types::router_data::ConnectorAuthType> for ForteAuthType {
    type Error = domain_types::errors::ConnectorError;
    fn try_from(auth_type: &domain_types::router_data::ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            domain_types::router_data::ConnectorAuthType::MultiAuthKey {
                api_key,
                key1,
                api_secret,
                key2,
            } => Ok(Self {
                api_access_id: api_key.to_owned(),
                organization_id: Secret::new(format!("org_{}", key1.peek())),
                location_id: Secret::new(format!("loc_{}", key2.peek())),
                api_secret_key: api_secret.to_owned(),
            }),
            _ => Err(domain_types::errors::ConnectorError::FailedToObtainAuthType),
        }
    }
}
```

### Phase 4: Request/Response Structure Updates

#### 4.1 Add Generic Type Parameters
**Update all request structures to include generic type parameter**:
```rust
#[derive(Debug, Serialize)]
pub struct FortePaymentsRequest<T: PaymentMethodDataTypes + Serialize> {
    action: ForteAction,
    authorization_amount: MinorUnit,  // Changed from FloatMajorUnit
    billing_address: BillingAddress,
    card: Card,
    payment_method: PaymentMethodData<T>,  // Added generic payment method
}
```

#### 4.2 Amount Conversion Strategy
**Critical Change**: Convert from FloatMajorUnit to MinorUnit
- Hyperswitch Forte uses FloatMajorUnit (e.g., 10.00 for $10)
- UCS uses MinorUnit (e.g., 1000 for $10)
- Need conversion logic in transformers

### Phase 5: RouterData to RouterDataV2 Migration

#### 5.1 Flow-Specific RouterDataV2 Types
**Replace generic RouterData with flow-specific RouterDataV2**:

**Authorize Flow**:
```rust
RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
```

**Capture Flow**:
```rust
RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
```

**Sync Flow**:
```rust
RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
```

**Void Flow**:
```rust
RouterDataV2<Void, PaymentFlowData, PaymentsCancelData, PaymentsResponseData>
```

**Refund Flow**:
```rust
RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
```

**Refund Sync Flow**:
```rust
RouterDataV2<RSync, RefundFlowData, RefundsData, RefundsResponseData>
```

### Phase 6: Macro Implementation Strategy

#### 6.1 Create All Prerequisites Macro
```rust
macros::create_all_prerequisites!(
    connector_name: Forte,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: FortePaymentsRequest<T>,
            response_body: FortePaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: ForteCaptureRequest,
            response_body: ForteCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: (),
            response_body: FortePaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: ForteCancelRequest,
            response_body: ForteCancelResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentsCancelData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: ForteRefundRequest,
            response_body: RefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: (),
            response_body: RefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
    ],
    amount_converters: [],
    member_functions: {
        fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
            common_enums::CurrencyUnit::Minor
        }
    }
);
```

#### 6.2 Individual Flow Macro Implementations
**For each flow, implement macro_connector_implementation**:

**Example for Authorize Flow**:
```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Forte,
    curl_request: Json(FortePaymentsRequest),
    curl_response: FortePaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>) -> CustomResult<String, errors::ConnectorError> {
            let auth = transformers::ForteAuthType::try_from(&req.connector_auth_type)?;
            Ok(format!(
                "{}/organizations/{}/locations/{}/transactions",
                self.base_url(&req.resource_common_data.connectors),
                auth.organization_id.peek(),
                auth.location_id.peek()
            ))
        }
    }
);
```

### Phase 7: Transformer Implementation Updates

#### 7.1 Request Transformation Pattern
```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for FortePaymentsRequest<T>
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    ) -> Result<Self, Self::Error> {
        // Implementation with MinorUnit conversion
        let amount = item.request.minor_amount; // Use minor_amount directly
        
        // Rest of implementation...
    }
}
```

#### 7.2 Response Transformation Pattern
```rust
impl<F> TryFrom<ResponseRouterData<FortePaymentsResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<FortePaymentsResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code } = item;
        
        let status = get_status(response.response.response_code, response.action);
        
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transaction_id),
                redirection_data: None,
                connector_metadata: Some(serde_json::json!(ForteMeta {
                    auth_id: response.authorization_code,
                })),
                network_txn_id: None,
                connector_response_reference_id: Some(response.transaction_id),
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

### Phase 8: ConnectorCommon Implementation

```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorCommon for Forte<T>
{
    fn id(&self) -> &'static str {
        "forte"
    }
    
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }
    
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = transformers::ForteAuthType::try_from(auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        
        let raw_basic_token = format!(
            "{}:{}",
            auth.api_access_id.peek(),
            auth.api_secret_key.peek()
        );
        let basic_token = format!("Basic {}", BASE64_ENGINE.encode(raw_basic_token));
        
        Ok(vec![
            ("Authorization".to_string(), basic_token.into_masked()),
            ("X-Forte-Auth-Organization-Id".to_string(), auth.organization_id.into_masked()),
        ])
    }
    
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.forte.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: transformers::ForteErrorResponse = res
            .response
            .parse_struct("Forte ErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.response.response_code.unwrap_or_else(|| "UNKNOWN_ERROR".to_string()),
            message: response.response.response_desc,
            reason: Some(response.response.response_desc),
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}
```

### Phase 9: Implementation Order

1. **Setup Phase**:
   - Create file structure
   - Update module registrations
   - Register in domain types

2. **Core Implementation**:
   - Implement generic connector struct
   - Add trait implementations with bounds
   - Implement ConnectorCommon

3. **Authentication**:
   - Update auth structure
   - Implement TryFrom for ConnectorAuthType

4. **Data Structures**:
   - Update request/response structures with generics
   - Add amount conversion logic
   - Update status mappings

5. **Transformers**:
   - Implement request transformations with RouterDataV2
   - Implement response transformations
   - Handle all 6 flows (Authorize, Capture, Void, PSync, Refund, RSync)

6. **Macro Implementation**:
   - Add create_all_prerequisites macro
   - Add macro_connector_implementation for each flow

7. **Testing**:
   - Create comprehensive test suite
   - Test all supported flows
   - Validate error handling

### Phase 10: Critical Considerations

#### 10.1 Amount Handling
- **Challenge**: Hyperswitch uses FloatMajorUnit, UCS uses MinorUnit
- **Solution**: Convert amounts in transformers (multiply by 100 for USD)

#### 10.2 Metadata Handling
- **Challenge**: Authorization codes needed between flows (authorize → capture)
- **Solution**: Maintain ForteMeta structure for connector_metadata

#### 10.3 URL Construction
- **Challenge**: Dynamic URLs with organization_id and location_id
- **Solution**: Extract from auth in each flow's get_url implementation

#### 10.4 Error Handling
- **Challenge**: Complex error response structure
- **Solution**: Maintain existing error parsing logic in build_error_response

#### 10.5 Currency Restriction
- **Challenge**: Forte only supports USD
- **Solution**: Maintain currency validation in request transformers

### Phase 11: Testing Strategy

1. **Unit Tests**: Test each transformer individually
2. **Integration Tests**: Test complete flows end-to-end
3. **Error Handling Tests**: Test error scenarios
4. **Authentication Tests**: Test auth header generation
5. **Amount Conversion Tests**: Test FloatMajorUnit to MinorUnit conversion

### Success Criteria

1. All 6 flows (Authorize, Capture, Void, PSync, Refund, RSync) working
2. Proper error handling and status mapping
3. Correct amount conversion between systems
4. Authentication working with MultiAuthKey pattern
5. Comprehensive test coverage
6. Code follows UCS architectural patterns

---

This transformation plan provides a systematic approach to converting the Forte connector from Hyperswitch to UCS architecture while maintaining all existing functionality and adding the benefits of the UCS generic type system and macro-based implementation.