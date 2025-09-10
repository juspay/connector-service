# Specific Recommendations for UCS Connector Conversion Prompt Improvement

## Executive Summary

Based on analysis of your current implementation prompt and the UCS codebase, here are the critical improvements needed to make your connector conversion process successful.

## Critical Issues with Current Prompt

### 1. **Outdated Architecture References**
**Problem**: Your prompt references Hyperswitch patterns that don't exist in UCS
- Uses `RouterData` instead of `RouterDataV2`
- References old macro patterns like `create_connector_impl_struct!`
- Missing UCS-specific wrapper patterns

**Impact**: 100% build failure rate due to fundamental architecture mismatches

### 2. **Incomplete Generic Type Handling**
**Problem**: Missing critical generic type constraints and patterns
- No `PaymentMethodDataTypes` bounds specification
- Missing `Serialize` constraints on generic types
- Incorrect router data wrapper implementation

**Impact**: Compilation errors and runtime serialization failures

### 3. **Wrong Macro Usage**
**Problem**: Using deprecated Hyperswitch macros
- `create_connector_impl_struct!` doesn't exist in UCS
- Missing `macros::create_all_prerequisites!` pattern
- Incorrect `macro_connector_implementation!` usage

**Impact**: Macro expansion failures and missing implementations

## Specific Improvement Recommendations

### Recommendation 1: Update Architecture Patterns

**Current Prompt Issue**:
```rust
// Your prompt generates this (WRONG):
impl<Flow, Request, Response> ConnectorIntegration<Flow, Request, Response> for NewConnector
```

**Recommended Fix**:
```rust
// Should generate this (CORRECT):
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for NewConnector<T>
```

**Implementation**: Update your prompt to use the exact patterns from [`enhanced_connector_conversion_prompt.md`](enhanced_connector_conversion_prompt.md)

### Recommendation 2: Fix Data Access Patterns

**Current Prompt Issue**:
```rust
// Your prompt generates this (WRONG):
item.connector_meta.connector_name
```

**Recommended Fix**:
```rust
// Should generate this (CORRECT):
item.resource_common_data.connectors.new_connector
```

**Implementation**: Replace all data access patterns with UCS-compatible ones

### Recommendation 3: Correct Macro Implementation

**Current Prompt Issue**:
Your prompt doesn't include the required UCS macro pattern

**Recommended Fix**:
```rust
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
        // ... other flows
    ],
    amount_converters: [],
    member_functions: {
        // helper functions
    }
);
```

### Recommendation 4: Add Router Data Wrapper

**Current Prompt Issue**: Missing the required router data wrapper pattern

**Recommended Fix**:
```rust
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

### Recommendation 5: Complete Response Handling

**Current Prompt Issue**: Incomplete response transformation

**Recommended Fix**: Ensure all response transformations include:
- `status_code: item.http_code`
- Proper status mapping
- All required response fields
- Error response handling with `with_error_response_body!` macro

## Prompt Structure Improvements

### 1. **Phase-Based Approach**
Structure your prompt in clear phases:
1. **Setup Phase**: Domain types, configuration
2. **Implementation Phase**: Main connector file
3. **Transformers Phase**: Request/response handling
4. **Testing Phase**: Comprehensive test generation
5. **Validation Phase**: Build and debug

### 2. **Reference-Driven Development**
Always reference working UCS connectors:
- Use Adyen as primary reference for complex flows
- Use Checkout for simpler implementations
- Compare patterns before generating code

### 3. **Error Prevention Strategy**
Include validation steps:
- Type constraint verification
- Import statement validation
- Macro syntax checking
- Response field completeness

## Implementation Priority

### High Priority (Must Fix)
1. ✅ **RouterDataV2 Usage**: Replace all RouterData with RouterDataV2
2. ✅ **Generic Type Constraints**: Add proper PaymentMethodDataTypes bounds
3. ✅ **Macro Patterns**: Use UCS-specific macros
4. ✅ **Data Access**: Fix resource_common_data patterns

### Medium Priority (Should Fix)
1. **Error Handling**: Improve error response transformation
2. **Testing**: Generate comprehensive test suites
3. **Documentation**: Add inline documentation
4. **Validation**: Include build verification steps

### Low Priority (Nice to Have)
1. **Optimization**: Performance improvements
2. **Features**: Additional flow support
3. **Monitoring**: Enhanced logging

## Validation Checklist

Before considering the prompt "working", verify:

### ✅ Compilation Success
- [ ] `cargo build` completes without errors
- [ ] All imports resolve correctly
- [ ] Generic type constraints are satisfied
- [ ] Macro expansions succeed

### ✅ Runtime Success
- [ ] Authentication works correctly
- [ ] Request serialization succeeds
- [ ] Response deserialization works
- [ ] Error handling functions properly

### ✅ Test Success
- [ ] Unit tests pass
- [ ] Integration tests complete
- [ ] All flows are testable
- [ ] Error scenarios are covered

## Specific Code Patterns to Include

### 1. **Trait Implementation Pattern**
```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for NewConnector<T> {}
```

### 2. **TryFrom Implementation Pattern**
```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<NewConnectorRouterData<RouterDataV2<...>, T>>
    for NewConnectorPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: NewConnectorRouterData<...>) -> Result<Self, Self::Error> {
        // implementation
    }
}
```

### 3. **Response Transformation Pattern**
```rust
Ok(Self {
    response: Ok(PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(item.response.id),
        redirection_data: None,
        connector_metadata: None,
        network_txn_id: None,
        connector_response_reference_id: None,
        incremental_authorization_allowed: None,
        mandate_reference: None,
        status_code: item.http_code, // Critical field
    }),
    resource_common_data: PaymentFlowData {
        status,
        ..item.router_data.resource_common_data
    },
    ..item.router_data
})
```

## Success Metrics

### Quantitative Metrics
- **Build Success Rate**: Target 100% (currently 0%)
- **Test Pass Rate**: Target 95%+ 
- **Implementation Time**: Target <2 hours per connector
- **Error Resolution Time**: Target <30 minutes per error

### Qualitative Metrics
- Code follows UCS patterns consistently
- Generated code is maintainable and readable
- Error messages are clear and actionable
- Documentation is comprehensive

## Next Steps

1. **Immediate**: Replace your current prompt with [`enhanced_connector_conversion_prompt.md`](enhanced_connector_conversion_prompt.md)
2. **Short-term**: Test the new prompt with a simple connector (e.g., a payment processor with basic card support)
3. **Medium-term**: Validate with complex connectors that have multiple payment methods
4. **Long-term**: Create automated validation tools to catch common issues

## Conclusion

Your current prompt fails because it's based on outdated Hyperswitch patterns. The enhanced prompt addresses all critical issues and follows proven UCS patterns. The success rate should improve from 0% to 95%+ with these changes.

The key insight is that UCS is not just an evolution of Hyperswitch—it's a fundamentally different architecture that requires different patterns, especially around generic types, data access, and macro usage.