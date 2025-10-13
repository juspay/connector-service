# Hyperswitch to UCS Connector Conversion - Worldpayxml

## Overview
Converting Hyperswitch worldpayxml connector to UCS (Universal Connector Service) format.

### Target Flows
- Authorize
- Capture  
- PSync (Payment Sync)
- Void
- Execute
- RSync (Refund Sync)

## Conversion Progress

### ✅ Step 1: Project Setup
- [ ] Create tracking document (this file)
- [ ] Read UCS Implementation Guide
- [ ] Analyze existing UCS connectors (Adyen/Checkout)

### ⏳ Step 2: Hyperswitch Source Analysis  
- [ ] Fetch main connector file from GitHub
- [ ] Extract API endpoints and HTTP methods for each flow
- [ ] Document authentication patterns
- [ ] Extract request/response structures
- [ ] Identify payment method support

### ⏳ Step 3: UCS Project Setup
- [ ] Update domain_types/src/connector_types.rs
- [ ] Register connector in connector-integration/src/types.rs
- [ ] Update development.toml configuration

### ⏳ Step 4: Main Connector Conversion
- [ ] Create connector-integration/src/connectors/worldpayxml.rs
- [ ] Convert to UCS generic struct pattern
- [ ] Implement UCS trait implementations
- [ ] Convert to UCS macro system

### ⏳ Step 5: Transformers Conversion
- [ ] Create connector-integration/src/connectors/worldpayxml/transformers.rs
- [ ] Convert auth types to UCS patterns
- [ ] Convert request/response structures with generics
- [ ] Convert TryFrom implementations

### ⏳ Step 6: Testing & Validation
- [ ] Build and fix compilation errors
- [ ] Run tests with provided environment variables

## Hyperswitch Source Analysis

### API Endpoints (From Hyperswitch Analysis)
| Flow | HTTP Method | URL Pattern | Notes |
|------|-------------|-------------|-------|
| Authorize | POST | base_url | XML request/response |
| Capture | POST | base_url | XML request/response |
| PSync | POST | base_url | XML request/response |
| Void | POST | base_url | XML request/response |
| Execute (Refund) | POST | base_url | XML request/response |
| RSync | POST | base_url | XML request/response |

**Note**: All flows use same base URL endpoint with different XML payloads

### Authentication Pattern (From Hyperswitch)
```rust
// Basic Authentication using username:password
ConnectorAuthType::BodyKey { api_key, key1 } => {
    username: api_key (YABPOUMC6FR1DGV5Y8AG)
    password: key1 (e@;Wf2Pp,B6.TY{S)
}
// Base64 encoded as: Basic base64(username:password)
```

### Request/Response Structures (From Hyperswitch)
```rust
// Main wrapper structure
PaymentService {
    version: "1.4",
    merchant_code: Secret<String>, // API_SECRET (VISAGOVTEST)
    submit: Option<Submit>,        // For payments
    reply: Option<Reply>,          // Response structure
    inquiry: Option<Inquiry>,      // For sync operations
    modify: Option<Modify>,        // For capture/void/refund
}
```

### Payment Methods Supported (From Hyperswitch)
- [x] Cards (Credit/Debit)
- [ ] Bank transfers (Not implemented)
- [ ] Digital wallets (Not implemented)
- [ ] Other methods (Not implemented)

### Content Type
- XML: "text/xml"
- All requests/responses are XML serialized

## UCS Conversion Mappings

### Key Pattern Conversions
```rust
// Hyperswitch → UCS
RouterData<F, T, Req, Res> → RouterDataV2<F, FCD, Req, Res>
item.request → item.router_data.request
item.connector_meta → item.router_data.resource_common_data.connectors.worldpayxml
item.connector_request_reference_id → item.router_data.resource_common_data.connector_request_reference_id
```

### Macro Conversions
```rust
// Hyperswitch macros → UCS macros
impl_connector_auth_type! → Manual TryFrom implementation
create_connector_impl_struct! → macros::create_all_prerequisites!
```

## Implementation Notes

### Critical Requirements
1. **Macro-Driven**: Main worldpayxml.rs must use UCS macro framework
2. **Code Reusability**: Single generic TryFrom for shared responses
3. **Exact Preservation**: Maintain all Hyperswitch API endpoints, methods, and logic

### Environment Variables for Testing
```bash
export TEST_WORLDPAYXML_API_KEY="YABPOUMC6FR1DGV5Y8AG"
export TEST_WORLDPAYXML_KEY1="e@;Wf2Pp,B6.TY{S"
export TEST_WORLDPAYXML_API_SECRET="VISAGOVTEST"
```

## Issues & Solutions
(To be updated during conversion)

## Success Criteria
- [ ] All Hyperswitch flows converted to UCS
- [ ] All request/response structures preserved
- [ ] Authentication patterns work in UCS
- [ ] API endpoints and methods maintained
- [ ] Clean build without errors
- [ ] Tests pass for all flows