# Enhanced Connector Conversion Prompt: Hyperswitch to Connector Service (v2)

## System Prompt

You are an expert Rust developer specializing in payment connector implementations. Your task is to convert Hyperswitch connector implementations to the modern Connector Service architecture following the official implementation guide. You have deep knowledge of both architectures and understand the key patterns, best practices, and implementation details required for successful conversions.

## Conversion Instructions

### Phase 1: Project Setup and Configuration

#### Step 1: Update Domain Types Configuration

**File: `backend/domain_types/src/connector_types.rs`**

1. Add the new connector variant to ConnectorEnum:
```rust
#[derive(Clone, Debug, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ConnectorEnum {
    Adyen,
    Razorpay,
    NewConnectorName, // Add your connector here
}
```

2. Add match arm in ForeignTryFrom implementation:
```rust
impl ForeignTryFrom<grpc_api_types::payments::Connector> for ConnectorEnum {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        connector: grpc_api_types::payments::Connector,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match connector {
            grpc_api_types::payments::Connector::Adyen => Ok(Self::Adyen),
            grpc_api_types::payments::Connector::Razorpay => Ok(Self::Razorpay),
            grpc_api_types::payments::Connector::NEW_CONNECTOR => Ok(Self::NEW_CONNECTOR), // Add your connector here
            // ... other cases
        }
    }
}
```

**File: `backend/domain_types/src/types.rs`**

3. Add connector to Connectors struct:
```rust
#[derive(Clone, serde::Deserialize, Debug)]
pub struct Connectors {
    pub adyen: ConnectorParams,
    pub razorpay: ConnectorParams,
    pub new_connector: ConnectorParams, // Add your connector params
}
```

#### Step 2: Update Connector Integration Configuration

**File: `backend/connector-integration/src/types.rs`**

4. Add connector to use statement:
```rust
use crate::connectors::{Adyen, Razorpay, NewConnectorName}; // Add your connector here
```

5. Add connector match arm in convert_connector function:
```rust
fn convert_connector(connector_name: ConnectorEnum) -> BoxedConnector {
    match connector_name {
        ConnectorEnum::Adyen => Box::new(Adyen::new()),
        ConnectorEnum::Razorpay => Box::new(Razorpay::new()),
        ConnectorEnum::NewConnectorName => Box::new(NewConnectorName::new()), // Add your connector here
    }
}
```

**File: `backend/connector-integration/src/connectors.rs`**

6. Add module declaration:
```rust
pub mod new_connector_name;
pub use self::new_connector_name::NewConnectorName;
```

**File: `config/development.toml`**

7. Add connector configuration (reference from hyperswitch development.toml for base_url context)

#### Step 3: Generate Connector Files

8. Export connector name and run scripts:
```sh
export CONNECTOR_NAME=new_connector
./fetch_connector_file.sh
./fetch_connector_transformers.sh
```

### Phase 2: Main Connector File Implementation

**File: `backend/connector-integration/src/connectors/new_connector.rs`**

#### Step 4: Clean and Setup Imports

9. Remove all existing use statements at the top of the file

10. Add the standardized import block:
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
    self as new_connector_name,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

use error_stack::ResultExt;
```

#### Step 5: Replace Connector Structure

11. Remove existing connector struct and impl
12. Remove all `impl api::` trait implementations

13. Add generic trait implementations:
```rust
// Trait implementations with generic type parameters
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2 for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for New_connector_name<T>
{
}
```

#### Step 6: Add Macro Prerequisites

14. Add the macro prerequisites structure:
```rust
macros::create_all_prerequisites!(
    connector_name: New_connector_name,
    generic_type: T,
    api: [
       
    ],
    amount_converters: [],
    member_functions: {
        
    }
);
```

#### Step 7: Add Stub Implementations

15. Add stub implementations at the bottom of the file:
```rust
// Stub implementations for unsupported flows
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for New_connector_name<T>
{
}

// SourceVerification implementations for all flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData,
        PaymentsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for New_connector_name<T>
{
}
```

#### Step 8: Setup Headers and Helper Functions

16. Locate the build_headers function from the original implementation and copy it to the member_functions block

17. Update build_headers function parameters:
```rust
pub fn build_headers<F, FCD, Req, Res>(
    &self,
    req: &RouterDataV2<F, FCD, Req, Res>,
) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
where
    Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
{
    // Original function body
}
```

18. Remove the whole ConnectorCommonExt trait

19. Add headers module:
```rust
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}
```

20. Update ConnectorCommon impl:
```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for New_connector_name<T>
{
```

21. Update build_error_response function:
Replace:
```rust
event_builder.map(|i| i.set_error_response_body(&response));
router_env::logger::info!(connector_response=?response);
```
With:
```rust
with_error_response_body!(event_builder, response);
```

22. Add base URL helper functions to member_functions:
```rust
pub fn connector_base_url_payments<'a, F, Req, Res>(
    &self,
    req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
) -> &'a str {
    &req.resource_common_data.connectors.new_connector_name.base_url
}

pub fn connector_base_url_refunds<'a, F, Req, Res>(
    &self,
    req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
) -> &'a str {
    &req.resource_common_data.connectors.new_connector_name.base_url
}
```

### Phase 3: Flow Implementation

#### Step 9: Implement Authorize Flow

23. Add Authorize flow to api array:
```rust
(
    flow: Authorize,
    request_body: <T>,
    response_body: ,
    router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
)
```

24. Add macro implementation for Authorize:
```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: New_connector_name,
    curl_request: ,
    curl_response: ,
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
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
        }
    }
);
```

25. Locate the original ConnectorIntegration<Authorize, ...> trait implementation
26. Copy get_headers and get_url function bodies to the macro
27. Identify request and response struct names from get_request_body and handle_response functions
28. Add struct names to transformers import
29. Update api array and macro with struct names
30. Remove the original ConnectorIntegration trait implementation

#### Step 10: Implement PSync Flow

31-35. Repeat steps 23-30 for PSync flow with appropriate struct names and parameters

#### Step 11: Implement Refund Flow

36-42. Repeat steps 23-30 for Refund flow with appropriate struct names and parameters

#### Step 12: Implement RSync Flow

43-48. Repeat steps 23-30 for RSync flow with appropriate struct names and parameters

#### Step 13: Implement Capture Flow

49-54. Repeat steps 23-30 for Capture flow with appropriate struct names and parameters

#### Step 14: Implement Void Flow

55-60. Repeat steps 23-30 for Void flow with appropriate struct names and parameters

### Phase 4: Transformers Implementation

**File: `backend/connector-integration/src/connectors/new_connector/transformers.rs`**

#### Step 15: Setup Transformers Imports

61. Remove all existing use statements

62. Add standardized import block:
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
```

63. Add router data import:
```rust
use crate::{connectors::new_connector_name::New_connector_nameRouterData, types::ResponseRouterData};
```

#### Step 16: Update Request Structures

64. Remove New_connector_nameRouterData struct and its impl

65-70. For each request struct:
- Add generic type parameters with proper bounds
- Update payment method fields to use generics
- Replace CardNumber with RawCardNumber<T>
- Follow the pattern through nested structs until CardNumber is reached

#### Step 17: Update TryFrom Implementations

71-119. For each flow (Authorize, PSync, Refund, RSync, Capture, Void):

**Request TryFrom:**
- Update TryFrom signature to use RouterDataV2 with proper generic bounds
- Change item access from `item.field` to `item.resource_common_data.field`
- Update error handling and field mappings

**Response TryFrom:**
- Update TryFrom signature to use RouterDataV2 with proper generic bounds
- Remove charges field from PaymentsResponseData::TransactionResponse
- Add raw_connector_response field
- Add status_code field
- Change item.data to item.router_data
- Wrap status in resource_common_data for proper flow data structure

### Phase 5: Final Steps

#### Step 18: Cleanup and Build

120. Remove unused implementations:
- ConnectorValidation
- ConnectorIntegration
- IncomingWebhook
- ConnectorSpecifications

121. Build using `cargo build` and fix compilation errors

122. Follow error fix guide: `./connectorErrorFixGuide.md`

123. Create test file following: `./ai_generate_test.md`

## Key Implementation Patterns

### 1. Generic Type System
- Always use `PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize` bounds
- Use `RawCardNumber<T>` for card numbers
- Apply generics consistently through nested structures

### 2. RouterDataV2 Usage
- Use flow-specific RouterDataV2 types
- Access fields through `resource_common_data`
- Maintain proper flow data structures

### 3. Macro-Based Implementation
- Use `create_all_prerequisites!` for boilerplate
- Use `macro_connector_implementation!` for each flow
- Define all flows in the api array

### 4. Error Handling
- Use `with_error_response_body!` macro
- Implement proper error propagation
- Handle connector-specific error responses

### 5. Response Transformation
- Remove deprecated fields (charges)
- Add required fields (raw_connector_response, status_code)
- Wrap status in appropriate flow data structures

## Validation Checklist

- [ ] All domain type configurations updated
- [ ] Connector integration configurations added
- [ ] Main connector file properly structured with generics
- [ ] All flows implemented with macro patterns
- [ ] Transformers updated with RouterDataV2 patterns
- [ ] Generic type parameters applied consistently
- [ ] Error handling updated to new patterns
- [ ] Build succeeds without errors
- [ ] Tests created and passing

This enhanced guide now incorporates the specific step-by-step instructions from the official implementation guide while maintaining the architectural insights from the connector service analysis.