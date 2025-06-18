# Gateway Integration Instruction Prompt

## Task Overview
Integrate a payment gateway with UPI Intent, UPI Collect, and UPI QR payment methods into the connector-service following the existing architecture and patterns. This prompt is designed to be reusable across different payment gateways by changing only the gateway name and reference documentation.

## Prerequisites
- Gateway analysis document has been generated using the Gateway Analysis Instruction Prompt
- Functional dependencies are available in `~/Downloads/fndep` directory  
- Use `mcp-fdep` tools to load and traverse the codebase for implementation details
- Access to the complete connector-service project structure

## Implementation Scope

### Primary Focus: UPI Payment Methods Only
1. **UPI Intent Flow**: Deep-link based payments for mobile app redirections
2. **UPI QR Flow**: QR code based payments for scanning with UPI apps
3. **UPI Collect Flow**: VPA-based collect requests for direct debit

### Exclusions
- Card payments, net banking, wallets, or any other payment methods
- Complex flows like disputes, mandates, or recurring payments beyond basic structure
- Advanced features not specifically mentioned in the reference documentation

## Architecture Understanding

### Core Components
The connector-service uses a trait-based system with the following key components:

1. **gRPC Server** (`backend/grpc-server`): Entry point handling `PaymentService/payment_authorize`
2. **Connector Integration** (`backend/connector-integration`): Payment processor implementations
3. **Domain Types** (`backend/domain_types`): Common data structures and flow definitions
4. **Macro Framework**: Reduces boilerplate in connector implementations

### Payment Flow Pattern
```
payment_authorize() → [CreateOrder] → [CreateSessionToken] → Authorize
```

Where:
- `CreateOrder`: Optional order creation step (if `should_do_order_create()` returns true)
- `CreateSessionToken`: Optional token generation step (if `should_do_session_token()` returns true) 
- `Authorize`: Main payment processing step

### Connector Registration Flow
```
gRPC Request (x-connector: "gateway_name") 
→ ConnectorEnum::from_str("gateway_name")
→ ConnectorData::get_connector_by_name() 
→ Factory pattern matches enum 
→ Instantiated connector handles request
```

## Step-by-Step Implementation Process

### Phase 1: Environment Setup and Analysis

#### Step 1.1: Load Dependencies and Analyze Reference Documentation
```bash
# Use mcp-fdep to load functional dependencies
```
1. Load fdep data from `~/Downloads/fndep`
2. Read and understand the gateway-specific reference documentation
3. Identify the key API endpoints, request/response structures, and authentication methods
4. Map the UPI flow differentiation logic from the reference documentation

#### Step 1.2: Study Existing Implementations
Use mcp-fdep to examine existing UPI implementations:
- Study `payu.rs`, `phonepe.rs`, and `paytm.rs` for UPI patterns
- Understand the macro framework usage in `connectors/macros.rs`
- Review the transformer patterns for request/response handling

### Phase 2: Register Gateway in System

#### Step 2.1: Add Gateway to ConnectorEnum
**File**: `backend/domain_types/src/connector_types.rs`

**Lines 35-42**: Add the new gateway to the enum:
```rust
#[derive(Clone, Debug, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ConnectorEnum {
    Adyen,
    Razorpay,
    RazorpayV2,
    Payu,
    PhonePe,
    Paytm,
    {GatewayName}, // Add new gateway here
}
```

#### Step 2.2: Add Integer Mapping for gRPC
**File**: `backend/domain_types/src/connector_types.rs`

**Lines 47-62**: Add integer ID mapping:
```rust
fn foreign_try_from(connector: i32) -> Result<Self, error_stack::Report<Self::Error>> {
    match connector {
        2 => Ok(Self::Adyen),
        68 => Ok(Self::Razorpay),
        69 => Ok(Self::RazorpayV2),
        72 => Ok(Self::Payu),
        73 => Ok(Self::PhonePe),
        74 => Ok(Self::Paytm),
        75 => Ok(Self::{GatewayName}), // Add with unique ID
        _ => Err(ApplicationErrorResponse::BadRequest(ApiError {
            // ... error handling
        }))
    }
}
```

#### Step 2.3: Register Module Export
**File**: `backend/connector-integration/src/connectors.rs`

Add module declaration and export:
```rust
pub mod {gateway_name};
pub use self::{gateway_name}::{GatewayName};
```

#### Step 2.4: Add to Connector Factory
**File**: `backend/connector-integration/src/types.rs`

**Lines 3**: Add import:
```rust
use crate::connectors::{Adyen, Paytm, Payu, PhonePe, Razorpay, RazorpayV2, {GatewayName}};
```

**Lines 20-29**: Add to factory pattern:
```rust
fn convert_connector(connector_name: ConnectorEnum) -> BoxedConnector {
    match connector_name {
        ConnectorEnum::Adyen => Box::new(Adyen::new()),
        ConnectorEnum::Razorpay => Box::new(Razorpay::new()),
        ConnectorEnum::RazorpayV2 => Box::new(RazorpayV2::new()),
        ConnectorEnum::Payu => Box::new(Payu::new()),
        ConnectorEnum::PhonePe => Box::new(PhonePe::new()),
        ConnectorEnum::Paytm => Box::new(Paytm::new()),
        ConnectorEnum::{GatewayName} => Box::new({GatewayName}::new()), // Add here
    }
}
```

#### Step 2.5: Add Configuration Structure
**File**: `backend/domain_types/src/types.rs`

**Lines 38-45**: Add to Connectors struct:
```rust
#[derive(Clone, serde::Deserialize, Debug)]
pub struct Connectors {
    pub adyen: ConnectorParams,
    pub razorpay: ConnectorParams,
    pub razorpayv2: ConnectorParams,
    pub payu: ConnectorParams,
    pub phonepe: ConnectorParams,
    pub paytm: ConnectorParams,
    pub {gateway_name}: ConnectorParams, // Add new gateway config
}
```

#### Step 2.6: Add Base URL Configuration
**File**: `config/development.toml`

**Lines 22-32**: Add connector configuration:
```toml
[connectors]
adyen.base_url = "https://checkout-test.adyen.com/"
razorpay.base_url = "https://api.razorpay.com/"
razorpayv2.base_url = "https://api.razorpay.com/"
payu.base_url = "https://secure.payu.in"
phonepe.base_url = "https://api.phonepe.com/apis/hermes"
paytm.base_url = "https://securestage.paytmpayments.com"
{gateway_name}.base_url = "https://api.{gateway_name}.com/"  # Add gateway URLs
# Add additional endpoints as needed from reference doc
```

#### Step 2.7: Compile and Test Registration
```bash
cargo build
```
Fix any compilation errors in the registration before proceeding to implementation.

### Phase 3: Create Connector Structure

#### Step 3.1: Create Connector Directory Structure
Create the following directory structure in `backend/connector-integration/src/connectors/`:
```
├── {gateway_name}/
│   ├── transformers.rs    # Request/Response structs and TryFrom implementations
│   └── test.rs           # Tests (initially empty)
└── {gateway_name}.rs     # Main connector logic
```

#### Step 3.2: Implement Base Connector Structure
In `{gateway_name}.rs`, implement:

1. **Import necessary modules and traits**
2. **Create authentication type struct** based on the gateway's auth requirements
3. **Set up connector using macros**:
   ```rust
   macros::create_all_prerequisites!(
       connector_name: {GatewayName},
       api: [
           (
               flow: Authorize,
               request_body: {GatewayName}PaymentRequest,
               response_body: {GatewayName}PaymentResponse,
               router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
           )
       ],
       amount_converters: [],
       member_functions: {
           // Gateway-specific helper functions based on reference doc
       }
   );
   ```

#### Step 3.3: Compile and Test Basic Structure
```bash
cargo build
```
Ensure the basic structure compiles before proceeding.

### Phase 4: Implement Authentication and Request Transformers

#### Step 4.1: Create Authentication Type
In `{gateway_name}/transformers.rs`:

1. **Define authentication struct** based on reference documentation:
   ```rust
   #[derive(Debug, Clone)]
   pub struct {GatewayName}AuthType {
       // Fields based on gateway requirements (API key, secret, etc.)
   }
   
   impl TryFrom<&ConnectorAuthType> for {GatewayName}AuthType {
       // Implementation based on gateway auth pattern
   }
   ```

#### Step 4.2: Implement UPI Request Structures
Based on the reference documentation, create:

1. **Base request structure** for the gateway API
2. **UPI-specific request fields** for Intent, Collect, and QR flows
3. **Helper structs** for UPI app configurations, device context, etc.

Example structure:
```rust
#[derive(Debug, Serialize)]
pub struct {GatewayName}PaymentRequest {
    // Common fields for all UPI flows
    pub amount: i64,
    pub currency: String,
    pub transaction_id: String,
    
    // UPI-specific fields based on reference doc
    pub upi_flow_type: String,  // Intent/Collect/QR differentiator
    // ... other fields from reference doc
}
```

#### Step 4.3: Implement TryFrom for Request Conversion
```rust
impl TryFrom<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>> 
    for {GatewayName}PaymentRequest {
    // Convert domain types to gateway-specific request format
    // Implement UPI flow differentiation logic from reference doc
}
```

Use mcp-fdep to extract exact transformation logic from the reference documentation, particularly:
- How UPI flows are differentiated (sourceObject mapping, request types, etc.)
- Required field mappings and transformations
- Authentication and signature generation logic

#### Step 4.4: Compile and Test Request Structures
```bash
cargo build
```
Fix any compilation errors before proceeding.

### Phase 5: Implement Response Handling

#### Step 5.1: Create Response Structures
Based on reference documentation:

1. **Success response structure** for UPI flows
2. **Error response structure** for failure cases
3. **UPI-specific response fields** (deep links, QR data, transaction status)

#### Step 5.2: Implement Response Conversion
```rust
impl TryFrom<ResponseRouterData<{GatewayName}PaymentResponse, RouterDataV2<...>>> 
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> {
    // Convert gateway response to domain types
    // Handle UPI-specific response processing
}
```

Use mcp-fdep to extract exact response processing logic from the reference documentation, particularly:
- VPA extraction patterns (regex-based or JSON field-based)
- Transaction status mapping
- Error code handling and retry logic

#### Step 5.3: Compile and Test Response Handling
```bash
cargo build
```

### Phase 6: Implement Connector Integration

#### Step 6.1: Implement Authorize Flow
Use the macro framework to implement the main authorize flow:

```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: {GatewayName},
    curl_request: Json({GatewayName}PaymentRequest),  // or FormData based on gateway
    curl_response: {GatewayName}PaymentResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        // Implement get_headers, get_url, and other required functions
        // based on the reference documentation
    }
);
```

#### Step 6.2: Implement ConnectorCommon Trait
```rust
impl ConnectorCommon for {GatewayName} {
    fn id(&self) -> &'static str { "{gateway_name}" }
    fn get_currency_unit(&self) -> CurrencyUnit { CurrencyUnit::Minor }
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.{gateway_name}.base_url
    }
    // ... other required methods
}
```

#### Step 6.3: Compile and Test Integration
```bash
cargo build
```

### Phase 7: Implement Additional Flows (if required)

#### Step 7.1: Implement CreateOrder Flow (if needed)
If the gateway requires order creation before payment (check reference doc):

1. **Add CreateOrder to macro setup**:
   ```rust
   macros::create_all_prerequisites!(
       connector_name: {GatewayName},
       api: [
           (
               flow: CreateOrder,
               request_body: {GatewayName}OrderRequest,
               response_body: {GatewayName}OrderResponse,
               router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>
           ),
           (
               flow: Authorize,
               request_body: {GatewayName}PaymentRequest,
               response_body: {GatewayName}PaymentResponse,
               router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
           )
       ],
       // ...
   );
   ```

2. **Implement CreateOrder connector integration** using the macro
3. **Override ValidationTrait**:
   ```rust
   impl ValidationTrait for {GatewayName} {
       fn should_do_order_create(&self) -> bool {
           true  // Enable order creation
       }
   }
   ```

#### Step 7.2: Implement CreateSessionToken Flow (if needed) 
If the gateway requires token generation (check reference doc):

1. **Add CreateSessionToken to macro setup**
2. **Implement CreateSessionToken connector integration**
3. **Override ValidationTrait**:
   ```rust
   impl ValidationTrait for {GatewayName} {
       fn should_do_session_token(&self) -> bool {
           true  // Enable session token
       }
   }
   ```

#### Step 7.3: Compile After Each Addition
```bash
cargo build
```
Complete one flow at a time, ensuring compilation success before moving to the next.

### Phase 8: Implement Required Trait Markers

#### Step 8.1: Add Trait Implementations
```rust
impl ConnectorServiceTrait for {GatewayName} {}
impl PaymentAuthorizeV2 for {GatewayName} {}

// Add stub implementations for unsupported flows
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for {GatewayName} {}
impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for {GatewayName} {}
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for {GatewayName} {}
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for {GatewayName} {}
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for {GatewayName} {}
impl ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData> for {GatewayName} {}
impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData> for {GatewayName} {}
impl ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData> for {GatewayName} {}
impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData> for {GatewayName} {}

// Implement trait aliases
impl domain_types::connector_types::RefundV2 for {GatewayName} {}
impl domain_types::connector_types::RefundSyncV2 for {GatewayName} {}
impl domain_types::connector_types::PaymentSyncV2 for {GatewayName} {}
impl domain_types::connector_types::PaymentOrderCreate for {GatewayName} {}
impl domain_types::connector_types::PaymentSessionToken for {GatewayName} {}
impl domain_types::connector_types::PaymentVoidV2 for {GatewayName} {}
impl domain_types::connector_types::IncomingWebhook for {GatewayName} {}
impl domain_types::connector_types::PaymentCapture for {GatewayName} {}
impl domain_types::connector_types::SetupMandateV2 for {GatewayName} {}
impl domain_types::connector_types::AcceptDispute for {GatewayName} {}
impl domain_types::connector_types::SubmitEvidenceV2 for {GatewayName} {}
impl domain_types::connector_types::DisputeDefend for {GatewayName} {}
impl domain_types::connector_types::ValidationTrait for {GatewayName} {}
```

#### Step 8.2: Final Compilation Test
```bash
cargo build
```

## Implementation Guidelines

### Code Quality Requirements
1. **Follow existing patterns**: Study existing UPI connectors (PayU, PhonePe, Paytm) and maintain consistency
2. **Error handling**: Implement comprehensive error handling for UPI-specific error codes
3. **Logging**: Add appropriate logging for debugging and monitoring
4. **Documentation**: Add inline documentation for complex UPI flow logic

### UPI Flow Implementation Details

#### UPI Intent Flow
- Generate deep links for UPI apps
- Handle redirection responses
- Support mobile app detection and appropriate links

#### UPI QR Flow  
- Return QR code data in response
- Handle QR-specific response formats
- Support both static and dynamic QR codes

#### UPI Collect Flow
- Handle VPA validation
- Process collect request responses
- Support both immediate and pending responses

### Reference Documentation Integration
1. **Use mcp-fdep tools** to extract transformation logic from the reference documentation
2. **Never modify** the implementation patterns described in the reference documentation
3. **Map exact field names and structures** from the reference doc to your implementation
4. **Implement signature generation** exactly as specified in the reference doc

### Configuration Management
1. **Add all base URLs** to `development.toml`
2. **Use environment-specific configurations** for test vs production endpoints
3. **Keep sensitive data** in auth types, not in configuration files

### Error Handling Strategy
1. **Map gateway-specific error codes** to appropriate `AttemptStatus` values
2. **Preserve original error messages** for debugging
3. **Handle network timeouts** and connection errors appropriately
4. **Log errors** with sufficient context for troubleshooting

### Testing Approach
1. **Create basic unit tests** for request/response transformations
2. **Test UPI flow differentiation** logic
3. **Validate error handling** for common failure scenarios
4. **Use existing test patterns** from other connectors as reference

## Compilation and Validation

### Continuous Compilation
After each major step:
```bash
cargo build
```
Fix compilation errors immediately before proceeding.

### Code Quality Checks
```bash
cargo +nightly fmt --all
cargo hack clippy --each-feature --no-dev-deps
```

### Final Validation
```bash
cargo test {gateway_name}
```

## Problem Resolution Strategy

### If Stuck on Implementation Details
1. **Add TODO comments** and move forward with basic structure
2. **Reference existing implementations** for similar patterns
3. **Use mcp-fdep** to understand domain type conversions
4. **Focus on core UPI flows** first, add optimizations later

### If Compilation Fails
1. **Fix one error at a time**
2. **Check import statements** and module declarations
3. **Ensure trait implementations** are complete
4. **Verify macro usage** matches existing patterns

### If Unclear About Reference Documentation
1. **Use mcp-fdep** to search for similar transformations in the fdep data
2. **Study the exact function implementations** mentioned in the reference doc
3. **Map data structures** field by field from the reference
4. **Implement core functionality** first, add edge cases later

## Success Criteria

### Gateway Registration Checkmarks
- [ ] ConnectorEnum updated with new gateway
- [ ] Integer mapping added for gRPC identification
- [ ] Module export added to connectors.rs
- [ ] Factory pattern updated in types.rs
- [ ] Configuration struct updated in types.rs
- [ ] Base URL configuration added to development.toml

### Implementation Checkmarks
- [ ] Connector structure created and compiles
- [ ] Authentication implementation complete
- [ ] UPI request structures implemented
- [ ] UPI response handling implemented
- [ ] Authorize flow fully functional
- [ ] CreateOrder flow (if required) implemented
- [ ] CreateSessionToken flow (if required) implemented
- [ ] All trait implementations added
- [ ] Code passes formatting and linting checks
- [ ] Basic tests created and passing

### Functional Requirements
- [ ] UPI Intent flow returns appropriate redirection data
- [ ] UPI QR flow returns QR code information
- [ ] UPI Collect flow handles VPA-based requests
- [ ] Error responses are properly mapped to domain types
- [ ] Gateway-specific authentication works correctly
- [ ] All API endpoints from reference doc are correctly implemented

## Notes for AI Assistant

### Implementation Approach
1. **Start with gateway registration** - ensure the system can route to the new connector
2. **Follow existing patterns** - study PayU, PhonePe, and Paytm implementations closely
3. **Implement incrementally** - build one flow at a time, ensure compilation at each step
4. **Use mcp-fdep extensively** - leverage the functional dependency data for implementation details
5. **Test continuously** - compile after each major change

### Common Pitfalls to Avoid
1. **Don't skip registration steps** - the system must know about the connector before implementation
2. **Don't assume uniformity** - each gateway has unique patterns and requirements
3. **Don't skip trait implementations** - ensure all required traits are implemented
4. **Don't modify reference implementations** - preserve the exact logic from reference docs
5. **Don't ignore error handling** - implement comprehensive error mapping

### Gateway-Specific Customization
When using this prompt for a specific gateway:
1. **Replace `{gateway_name}` and `{GatewayName}`** with actual gateway identifiers
2. **Choose unique integer ID** for the ConnectorEnum mapping (next available number)
3. **Reference the specific gateway analysis document** generated for that gateway
4. **Study the gateway's API documentation** alongside the generated analysis
5. **Adapt authentication patterns** to match the gateway's specific requirements
6. **Implement UPI flow differentiation** exactly as described in the reference analysis

This instruction prompt provides a comprehensive, step-by-step approach to implementing payment gateway integrations with focus on UPI payment methods while maintaining consistency with the existing connector-service architecture and ensuring proper system registration.