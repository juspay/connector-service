# Hyperswitch to UCS Connector Conversion Prompt

## Context Setup
Create NotesByXyne.md file to track conversion progress and context for future LLMs.

## Prerequisites and Reference Materials
1. **Read UCS Implementation Guide**: `connectorImplementationGuide.md`
2. **Read Test Generation Guide**: `ai_generate_test.md`
3. **Reference UCS Connector Examples**: Adyen or Checkout connectors in UCS codebase
4. **Source Hyperswitch Connector**: Use the GitHub Hyperswitch implementation as the base

## Step 1: Analyze Hyperswitch Source Connector

### 1.1 Fetch Hyperswitch Connector Implementation
**Task**: Retrieve the complete Hyperswitch connector implementation from GitHub
- **Main Connector File**: `https://github.com/juspay/hyperswitch/blob/main/crates/router/src/connector/{connector_name}.rs`
- **Transformers File**: `https://github.com/juspay/hyperswitch/blob/main/crates/router/src/connector/{connector_name}/transformers.rs`
- **Types File**: `https://github.com/juspay/hyperswitch/blob/main/crates/router/src/types/api/{connector_name}.rs` (if exists)

### 1.2 Extract Key Information from Hyperswitch Implementation
Analyze the Hyperswitch connector and extract:

#### Authentication Pattern
```rust
// From Hyperswitch - identify auth type
impl ConnectorCommon for ConnectorName {
    fn get_auth_header(&self, auth_type: &types::ConnectorAuthType) -> CustomResult<Vec<(String, request::Maskable<String>)>, errors::ConnectorError> {
        // Extract auth pattern
    }
}
```

#### API Endpoints and Methods
```rust
// From Hyperswitch - identify endpoints
fn get_url(&self, req: &types::PaymentsAuthorizeRouterData, connectors: &settings::Connectors) -> CustomResult<String, errors::ConnectorError> {
    // Extract URL patterns
}
```

#### Request/Response Structures
```rust
// From Hyperswitch transformers - identify data structures
#[derive(Debug, Serialize)]
pub struct ConnectorPaymentsRequest {
    // Extract request fields
}

#[derive(Debug, Deserialize)]
pub struct ConnectorPaymentsResponse {
    // Extract response fields
}
```

#### Payment Method Support
```rust
// From Hyperswitch - identify supported payment methods
impl TryFrom<&types::PaymentsAuthorizeRouterData> for ConnectorPaymentsRequest {
    fn try_from(item: &types::PaymentsAuthorizeRouterData) -> Result<Self, Self::Error> {
        match item.request.payment_method_data {
            // Extract payment method handling
        }
    }
}
```

#### Flow Implementations
Identify which flows are implemented in Hyperswitch:
- ✅ Authorize (payments)
- ✅ PSync (payment status)
- ✅ Capture
- ✅ Void/Cancel
- ✅ Refund
- ✅ RSync (refund status)
- ❓ SetupMandate
- ❓ RepeatPayment

## Step 2: UCS Project Setup

### 2.1 Update Domain Types
**File: `backend/domain_types/src/connector_types.rs`**

Add connector to enum (use exact name from Hyperswitch):
```rust
#[derive(Clone, Copy, Debug, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ConnectorEnum {
    // ... existing connectors
    {ConnectorName}, // Use exact Hyperswitch connector name
}
```

Add to ForeignTryFrom implementation:
```rust
impl ForeignTryFrom<grpc_api_types::payments::Connector> for ConnectorEnum {
    type Error = String;
    fn foreign_try_from(value: grpc_api_types::payments::Connector) -> Result<Self, Self::Error> {
        match value {
            // ... existing mappings
            grpc_api_types::payments::Connector::{ConnectorName} => Ok(Self::{ConnectorName}),
        }
    }
}
```

### 2.2 Register Connector in UCS
**File: `backend/connector-integration/src/types.rs`**

Add import:
```rust
use crate::connectors::{ConnectorName};
```

Add to convert_connector function:
```rust
pub fn convert_connector(connector: ConnectorEnum) -> Box<dyn ConnectorData> {
    match connector {
        // ... existing connectors
        ConnectorEnum::{ConnectorName} => Box::new({ConnectorName}::new()),
    }
}
```

### 2.3 Update Configuration
**File: `config/development.toml`**

```toml
[connectors]
{connector_name}.base_url = "{base_url_from_hyperswitch}"
```

## Step 3: Convert Hyperswitch Patterns to UCS

### 3.1 Module Declaration
**File: `backend/connector-integration/src/connectors.rs`**

```rust
pub mod {connector_name};
pub use self::{connector_name}::{ConnectorName};
```

### 3.2 Main Connector File Conversion
**File: `backend/connector-integration/src/connectors/{connector_name}.rs`**

#### Convert Hyperswitch Imports to UCS Imports
```rust
// Hyperswitch imports (REMOVE):
use crate::{
    connector::utils as connector_utils,
    core::errors::{self, CustomResult},
    types::{self, api, storage::enums},
};

// UCS imports (ADD):
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
    self as {connector_name},
    // Import request/response types from transformers
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};
```

#### Convert Hyperswitch Struct to UCS Generic Struct
```rust
// Hyperswitch pattern (REMOVE):
#[derive(Debug, Clone)]
pub struct ConnectorName;

// UCS pattern (ADD):
#[derive(Debug, Clone)]
pub struct {ConnectorName}<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> {ConnectorName}<T> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}
```

#### Convert Hyperswitch Trait Implementations to UCS
```rust
// Add all required UCS trait implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for {ConnectorName}<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for {ConnectorName}<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for {ConnectorName}<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for {ConnectorName}<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for {ConnectorName}<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for {ConnectorName}<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for {ConnectorName}<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for {ConnectorName}<T> {}

// Add other trait implementations based on Hyperswitch flows
```

#### Convert Hyperswitch Macros to UCS Macros
```rust
// Replace Hyperswitch macro patterns with UCS macros
macros::create_all_prerequisites!(
    connector_name: {ConnectorName},
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: {ConnectorName}PaymentsRequest<T>,
            response_body: {ConnectorName}PaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: {ConnectorName}SyncRequest,
            response_body: {ConnectorName}SyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        // Add other flows based on Hyperswitch implementation
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
            &req.resource_common_data.connectors.{connector_name}.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.{connector_name}.base_url
        }
    }
);
```

#### Convert Hyperswitch ConnectorCommon to UCS
```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for {ConnectorName}<T>
{
    fn id(&self) -> &'static str {
        "{connector_name}" // Use exact Hyperswitch connector ID
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        // Copy from Hyperswitch implementation
        common_enums::CurrencyUnit::Minor // or Base, depending on Hyperswitch
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Convert Hyperswitch auth pattern to UCS
        let auth = {connector_name}::{ConnectorName}AuthType::try_from(auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        
        // Use exact auth pattern from Hyperswitch
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", auth.api_key.peek()).into_masked(),
        )])
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.{connector_name}.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        // Convert Hyperswitch error response pattern
        let response: {connector_name}::{ConnectorName}ErrorResponse = res
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
```

#### Convert Hyperswitch Flow Implementations to UCS Macros
For each flow implemented in Hyperswitch, add corresponding UCS macro:

```rust
// For Authorize flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: {ConnectorName},
    curl_request: Json({ConnectorName}PaymentsRequest),
    curl_response: {ConnectorName}PaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post, // Use HTTP method from Hyperswitch
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
            // Convert Hyperswitch URL pattern
            Ok(format!("{}payments", self.connector_base_url_payments(req)))
        }
    }
);

// Repeat for PSync, Capture, Void, Refund, RSync based on Hyperswitch implementation
```

### 3.3 Convert Transformers
**File: `backend/connector-integration/src/connectors/{connector_name}/transformers.rs`**

#### Convert Hyperswitch Auth Type
```rust
// Convert Hyperswitch auth pattern to UCS
pub struct {ConnectorName}AuthType {
    pub(super) api_key: Secret<String>,
    // Add other auth fields from Hyperswitch
}

impl TryFrom<&ConnectorAuthType> for {ConnectorName}AuthType {
    type Error = domain_types::errors::ConnectorError;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        // Copy exact auth logic from Hyperswitch
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            // Add other auth types from Hyperswitch
            _ => Err(domain_types::errors::ConnectorError::FailedToObtainAuthType),
        }
    }
}
```

#### Convert Hyperswitch Request/Response Structures
```rust
// Convert Hyperswitch request structures to UCS with generics
#[derive(Debug, Serialize)]
pub struct {ConnectorName}PaymentsRequest<
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
> {
    // Copy exact fields from Hyperswitch request
    pub amount: MinorUnit,
    pub currency: String,
    pub payment_method: {ConnectorName}PaymentMethod<T>,
    // Add all other fields from Hyperswitch
}

// Convert Hyperswitch payment method structures
#[derive(Debug, Serialize)]
pub struct {ConnectorName}PaymentMethod<
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
> {
    // Copy exact structure from Hyperswitch
    #[serde(flatten)]
    pub method_data: {ConnectorName}MethodData<T>,
}

// Convert Hyperswitch response structures
#[derive(Debug, Deserialize)]
pub struct {ConnectorName}PaymentsResponse {
    // Copy exact fields from Hyperswitch response
    pub id: String,
    pub status: String,
    pub amount: MinorUnit,
    // Add all other fields from Hyperswitch
}

#[derive(Debug, Deserialize)]
pub struct {ConnectorName}ErrorResponse {
    // Copy exact error structure from Hyperswitch
    pub error_code: Option<String>,
    pub message: Option<String>,
    pub transaction_id: Option<String>,
}
```

#### Convert Hyperswitch Router Data Wrapper
```rust
#[derive(Debug, Serialize)]
pub struct {ConnectorName}RouterData<T, U> {
    pub amount: MinorUnit,
    pub router_data: T,
    pub payment_method_data: std::marker::PhantomData<U>,
}

impl<T, U> TryFrom<(MinorUnit, T)> for {ConnectorName}RouterData<T, U> {
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

#### Convert Hyperswitch TryFrom Implementations
```rust
// Convert Hyperswitch request transformation to UCS
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        {ConnectorName}RouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for {ConnectorName}PaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: {ConnectorName}RouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // Convert Hyperswitch transformation logic to UCS patterns
        // Replace item.request with item.router_data.request
        // Replace item.connector_request_reference_id with item.router_data.resource_common_data.connector_request_reference_id
        
        let payment_method = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => {
                // Copy exact card handling from Hyperswitch
                {ConnectorName}PaymentMethod {
                    method_data: {ConnectorName}MethodData::Card({ConnectorName}Card {
                        number: card.card_number.clone(),
                        expiry_month: card.card_exp_month.clone(),
                        expiry_year: card.card_exp_year.clone(),
                        cvc: card.card_cvc.clone(),
                        holder_name: item.router_data.request.customer_name.clone().map(Secret::new),
                    }),
                }
            },
            // Add other payment methods from Hyperswitch
            _ => return Err(ConnectorError::NotImplemented("payment method".into()).into()),
        };

        Ok(Self {
            amount: item.router_data.request.minor_amount,
            currency: item.router_data.request.currency.to_string(),
            payment_method,
            // Copy all other field mappings from Hyperswitch
        })
    }
}

// Convert Hyperswitch response transformation to UCS
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        ResponseRouterData<
            {ConnectorName}PaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            {ConnectorName}PaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Convert Hyperswitch status mapping to UCS
        let status = match item.response.status.as_str() {
            // Copy exact status mapping from Hyperswitch
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
                status_code: item.http_code, // Required in UCS
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// Repeat for all other flows implemented in Hyperswitch
```

## Step 4: Testing and Validation

### 4.1 Generate Tests Based on Hyperswitch
Follow the `ai_generate_test.md` guide to create tests that match the Hyperswitch connector's capabilities.

### 4.2 Build and Debug
```bash
cargo build
```

Fix any compilation errors using the [`comprehensive_connector_error_fix_guide.md`](comprehensive_connector_error_fix_guide.md).

### 4.3 Run Tests
```bash
cargo test --test {connector_name}_payment_flows_test
```

## Key Conversion Rules

### Data Access Pattern Conversion
```rust
// Hyperswitch pattern → UCS pattern
item.connector_meta → item.router_data.resource_common_data.connectors.{connector_name}
item.request → item.router_data.request
item.connector_request_reference_id → item.router_data.resource_common_data.connector_request_reference_id
```

### Type Conversion
```rust
// Hyperswitch → UCS
RouterData<F, T, Req, Res> → RouterDataV2<F, FCD, Req, Res>
types::PaymentsAuthorizeRouterData → RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
```

### Macro Conversion
```rust
// Hyperswitch → UCS
impl_connector_auth_type! → Manual TryFrom implementation
create_connector_impl_struct! → macros::create_all_prerequisites!
```

## Success Criteria
- ✅ All Hyperswitch flows are converted to UCS
- ✅ All Hyperswitch request/response structures are preserved
- ✅ All Hyperswitch authentication patterns work in UCS
- ✅ All Hyperswitch API endpoints and methods are maintained
- ✅ Build completes without errors
- ✅ Tests pass for all converted flows

This prompt ensures that the UCS connector maintains 100% functional compatibility with the original Hyperswitch implementation while following UCS architectural patterns.