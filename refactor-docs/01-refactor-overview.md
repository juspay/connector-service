# Proto Interface Refactor: Complete Implementation Plan

## Overview

This document outlines the comprehensive refactor required to implement the new unified proto interface definitions in the connector service. The refactor involves significant changes to the proto files that impact the entire system architecture.

## Summary of Proto Changes

Based on analysis of the current proto files, the major changes identified are:

### 1. **New Payment Methods Architecture** (`payment_methods.proto`)
- Complete restructure of payment method definitions using a hierarchical approach
- Introduction of a unified `PaymentMethod` message with oneof for different categories
- Currently only `CardPaymentMethodType` and `TokenPaymentMethodType` are implemented
- Extensive TODO comments for future payment method categories (wallets, RTP, bank transfers, etc.)

### 2. **Enhanced Payment Service Messages** (`payment.proto`)
- Field renaming for consistency (e.g., `connector_request_reference_id` → `request_ref_id`)
- New status enums for payments, mandates, refunds, and disputes
- Extended currency and country code enumerations
- Enhanced browser information and authentication data structures
- Unified response messages across services

### 3. **Service Interface Updates** (`services.proto`)
- Simplified service definitions focusing on the core operations
- Unified transform handlers for webhooks
- Updated HTTP endpoint mappings

### 4. **Maintained Health Check** (`health_check.proto`)
- No significant changes to health check interface

## Impact Analysis

### High Impact Areas
1. **Generated Code**: All Rust protobuf generated code needs regeneration
2. **Domain Type Conversions**: Complete rewrite of type conversion logic
3. **gRPC Handlers**: All server handlers need updates for new message structures
4. **Connector Implementations**: All connectors need updates for new field mappings
5. **Client SDKs**: All language SDKs need regeneration and updates

### Medium Impact Areas
1. **Build System**: Proto generation scripts may need updates
2. **Testing**: All tests need updates for new message structures
3. **Documentation**: API docs need complete revision

### Low Impact Areas
1. **Configuration**: Minimal changes to configuration files
2. **Logging**: May need some field name updates

## Refactor Strategy

The refactor is organized into **6 phases** with parallelizable tasks within each phase:

1. **Phase 1**: Infrastructure & Foundation Setup
2. **Phase 2**: Core Proto Integration & Code Generation  
3. **Phase 3**: Domain Types & Conversion Logic
4. **Phase 4**: Server Implementation Updates
5. **Phase 5**: Connector & Client Updates
6. **Phase 6**: Testing & Validation

Each phase contains tasks that can be executed in parallel by different sub-agents, with clear dependencies and handoff points between phases.

## Execution Approach

**Sequential Phases**: Each phase must complete before the next begins  
**Parallel Tasks**: Within each phase, tasks execute simultaneously  
**Rapid Iteration**: Focus on getting each component working quickly  
**Continuous Validation**: Test integration points as soon as dependencies are ready

## Success Criteria

1. All tests pass with new proto interfaces
2. All connector implementations work with new message structures
3. All client SDKs are updated and functional
4. Performance benchmarks meet or exceed current metrics
5. Backward compatibility maintained where specified
6. Documentation is complete and accurate

## Efficiency Optimizations

- **Minimal Viable Implementation**: Get each component working first, optimize later
- **Continuous Integration**: Integrate and test as soon as components are ready
- **Parallel Development**: Maximum parallelization within phase constraints
- **Early Error Detection**: Validate interfaces and contracts immediately
- **Incremental Testing**: Test each component as it becomes available

---

See individual phase documents for detailed task breakdowns and implementation instructions.