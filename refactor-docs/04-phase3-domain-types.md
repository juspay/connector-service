# Phase 3: Domain Types & Conversion Logic

## Overview
Update the domain types and conversion logic to work with the new proto message structures. This phase focuses on the `domain_types` crate and all type conversion logic throughout the system.

## Completion Target
All domain type conversions implemented and tested. No compilation errors in domain_types crate.

## Tasks (Execute in parallel)

### Task 3A: Payment Method Type Conversions
**Assigned to**: Sub-agent Alpha  
**Dependencies**: Phase 2 completion

#### Objectives
- Implement conversions for new PaymentMethod oneof structure
- Handle CardPaymentMethodType and TokenPaymentMethodType
- Create conversion framework for future payment method types

#### Steps
1. **Analyze New PaymentMethod Structure**
   ```rust
   // Study the new payment_methods.proto structure
   // PaymentMethod -> oneof payment_method
   //   - CardPaymentMethodType card
   //   - TokenPaymentMethodType token
   ```

2. **Update domain_types/src/types.rs**
   ```rust
   // Add new conversion traits
   pub trait FromProtoPaymentMethod<T> {
       fn from_proto(proto: T) -> Result<Self, ConversionError>
       where Self: Sized;
   }
   
   pub trait ToProtoPaymentMethod<T> {
       fn to_proto(&self) -> Result<T, ConversionError>;
   }
   ```

3. **Implement Card Payment Conversions**
   ```rust
   impl FromProtoPaymentMethod<grpc_api_types::CardPaymentMethodType> for DomainCardPayment {
       fn from_proto(proto: grpc_api_types::CardPaymentMethodType) -> Result<Self, ConversionError> {
           match proto.card_type {
               Some(card_type) => {
                   // Handle credit, debit, card_redirect variants
               }
               None => Err(ConversionError::MissingField("card_type")),
           }
       }
   }
   ```

4. **Implement Token Payment Conversions**
   ```rust
   impl FromProtoPaymentMethod<grpc_api_types::TokenPaymentMethodType> for DomainTokenPayment {
       fn from_proto(proto: grpc_api_types::TokenPaymentMethodType) -> Result<Self, ConversionError> {
           Ok(DomainTokenPayment {
               token: proto.token,
           })
       }
   }
   ```

5. **Create Payment Method Conversion Factory**
   ```rust
   pub fn convert_payment_method(
       proto: grpc_api_types::PaymentMethod
   ) -> Result<DomainPaymentMethod, ConversionError> {
       match proto.payment_method {
           Some(grpc_api_types::payment_method::PaymentMethod::Card(card)) => {
               Ok(DomainPaymentMethod::Card(DomainCardPayment::from_proto(card)?))
           }
           Some(grpc_api_types::payment_method::PaymentMethod::Token(token)) => {
               Ok(DomainPaymentMethod::Token(DomainTokenPayment::from_proto(token)?))
           }
           None => Err(ConversionError::MissingField("payment_method")),
       }
   }
   ```

#### Deliverables
- Complete payment method conversion implementations
- Unit tests for all conversion logic
- Documentation of conversion patterns
- Error handling for invalid conversions

#### Acceptance Criteria
- All payment method conversions work correctly
- Comprehensive test coverage (>90%)
- Clear error messages for conversion failures
- Forward compatibility for future payment types

---

### Task 3B: Payment Service Message Conversions
**Assigned to**: Sub-agent Beta  
**Dependencies**: Phase 2 completion

#### Objectives
- Update conversions for all PaymentService request/response messages
- Handle field renames and new structures
- Maintain backward compatibility where possible

#### Steps
1. **Update PaymentServiceAuthorizeRequest Conversions**
   ```rust
   impl TryFrom<grpc_api_types::PaymentServiceAuthorizeRequest> for DomainAuthorizeRequest {
       type Error = ConversionError;
       
       fn try_from(proto: grpc_api_types::PaymentServiceAuthorizeRequest) -> Result<Self, Self::Error> {
           Ok(DomainAuthorizeRequest {
               request_ref_id: convert_identifier(proto.request_ref_id)?, // was connector_request_reference_id
               amount: proto.amount,
               currency: convert_currency(proto.currency)?,
               minor_amount: proto.minor_amount,
               payment_method: convert_payment_method(proto.payment_method.ok_or(ConversionError::MissingField("payment_method"))?)?,
               // ... handle all other fields
           })
       }
   }
   ```

2. **Update PaymentServiceAuthorizeResponse Conversions**
   ```rust
   impl From<DomainAuthorizeResponse> for grpc_api_types::PaymentServiceAuthorizeResponse {
       fn from(domain: DomainAuthorizeResponse) -> Self {
           grpc_api_types::PaymentServiceAuthorizeResponse {
               transaction_id: domain.transaction_id.into(),
               status: domain.status.into(),
               response_ref_id: domain.response_ref_id.map(Into::into), // was connector_response_reference_id
               // ... handle all other fields
           }
       }
   }
   ```

3. **Update All Other PaymentService Messages**
   - PaymentServiceGetRequest/Response
   - PaymentServiceVoidRequest/Response
   - PaymentServiceCaptureRequest/Response
   - PaymentServiceRefundRequest/RefundResponse
   - PaymentServiceRegisterRequest/Response
   - PaymentServiceDisputeRequest/DisputeResponse
   - PaymentServiceTransformRequest/Response

4. **Handle Field Renames Systematically**
   ```rust
   // Create helper functions for common field renames
   fn convert_request_ref_id(proto_id: Option<grpc_api_types::Identifier>) -> Result<DomainIdentifier, ConversionError> {
       proto_id.ok_or(ConversionError::MissingField("request_ref_id"))?.try_into()
   }
   
   fn convert_response_ref_id(domain_id: Option<DomainIdentifier>) -> Option<grpc_api_types::Identifier> {
       domain_id.map(Into::into)
   }
   ```

5. **Create Comprehensive Test Suite**
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       
       #[test]
       fn test_authorize_request_conversion() {
           // Test all field conversions
           // Test error cases
           // Test edge cases
       }
       
       // ... tests for all message types
   }
   ```

#### Deliverables
- Complete PaymentService message conversions
- Comprehensive test suite with >95% coverage
- Documentation of all field changes
- Migration guide for field renames

#### Acceptance Criteria
- All PaymentService conversions work correctly
- All tests pass
- No data loss in conversions
- Clear error messages for invalid data

---

### Task 3C: RefundService and DisputeService Message Conversions
**Assigned to**: Sub-agent Gamma  
**Dependencies**: Phase 2 completion

#### Objectives
- Update conversions for RefundService and DisputeService messages
- Handle unified response types (RefundResponse, DisputeResponse)
- Update dispute evidence handling

#### Steps
1. **Update RefundService Conversions**
   ```rust
   // RefundServiceGetRequest -> RefundResponse (unified)
   impl TryFrom<grpc_api_types::RefundServiceGetRequest> for DomainRefundGetRequest {
       type Error = ConversionError;
       
       fn try_from(proto: grpc_api_types::RefundServiceGetRequest) -> Result<Self, Self::Error> {
           Ok(DomainRefundGetRequest {
               request_ref_id: convert_identifier(proto.request_ref_id)?,
               transaction_id: convert_identifier(proto.transaction_id)?, // was connector_transaction_id
               refund_id: proto.refund_id,
               refund_reason: proto.refund_reason,
           })
       }
   }
   ```

2. **Handle Unified RefundResponse**
   ```rust
   impl From<DomainRefundResponse> for grpc_api_types::RefundResponse {
       fn from(domain: DomainRefundResponse) -> Self {
           grpc_api_types::RefundResponse {
               transaction_id: domain.transaction_id.into(),
               refund_id: domain.refund_id,
               status: domain.status.into(),
               response_ref_id: domain.response_ref_id.map(Into::into),
               // ... all refund-specific fields
               metadata: domain.metadata.unwrap_or_default(),
               refund_metadata: domain.refund_metadata.unwrap_or_default(),
           }
       }
   }
   ```

3. **Update DisputeService Conversions**
   ```rust
   // Handle new dispute messages: DisputeServiceDefendRequest, DisputeServiceAcceptRequest
   impl TryFrom<grpc_api_types::DisputeServiceDefendRequest> for DomainDisputeServiceDefendRequest {
       type Error = ConversionError;
       
       fn try_from(proto: grpc_api_types::DisputeServiceDefendRequest) -> Result<Self, Self::Error> {
           Ok(DomainDisputeServiceDefendRequest {
               request_ref_id: convert_identifier(proto.request_ref_id)?,
               transaction_id: convert_identifier(proto.transaction_id)?,
               dispute_id: proto.dispute_id,
               reason_code: proto.reason_code,
           })
       }
   }
   ```

4. **Update Evidence Document Handling**
   ```rust
   impl TryFrom<grpc_api_types::EvidenceDocument> for DomainEvidenceDocument {
       type Error = ConversionError;
       
       fn try_from(proto: grpc_api_types::EvidenceDocument) -> Result<Self, Self::Error> {
           Ok(DomainEvidenceDocument {
               evidence_type: proto.evidence_type,
               file_content: proto.file_content,
               file_mime_type: proto.file_mime_type,
               provider_file_id: proto.provider_file_id,
               text_content: proto.text_content,
           })
       }
   }
   ```

5. **Create Service-Specific Test Suites**
   ```rust
   #[cfg(test)]
   mod refund_tests {
       // Comprehensive refund conversion tests
   }
   
   #[cfg(test)]
   mod dispute_tests {
       // Comprehensive dispute conversion tests
   }
   ```

#### Deliverables
- Complete RefundService and DisputeService conversions
- Evidence document handling implementation
- Comprehensive test coverage
- Documentation of service-specific changes

#### Acceptance Criteria
- All service conversions work correctly
- Evidence documents are handled properly
- Test coverage >90%
- No functionality regression

---

### Task 3D: Common Type and Enum Conversions
**Assigned to**: Sub-agent Delta  
**Dependencies**: Phase 2 completion

#### Objectives
- Update conversions for all common types and enums
- Handle new status enums and extended enumerations
- Ensure consistent conversion patterns

#### Steps
1. **Update Status Enum Conversions**
   ```rust
   impl From<DomainPaymentStatus> for grpc_api_types::PaymentStatus {
       fn from(domain: DomainPaymentStatus) -> Self {
           match domain {
               DomainPaymentStatus::Started => grpc_api_types::PaymentStatus::Started,
               DomainPaymentStatus::PaymentMethodAwaited => grpc_api_types::PaymentStatus::PaymentMethodAwaited,
               DomainPaymentStatus::DeviceDataCollectionPending => grpc_api_types::PaymentStatus::DeviceDataCollectionPending,
               DomainPaymentStatus::ConfirmationAwaited => grpc_api_types::PaymentStatus::ConfirmationAwaited,
               // ... handle all status mappings
           }
       }
   }
   ```

2. **Update Currency and Country Conversions**
   ```rust
   impl TryFrom<grpc_api_types::Currency> for DomainCurrency {
       type Error = ConversionError;
       
       fn try_from(proto: grpc_api_types::Currency) -> Result<Self, Self::Error> {
           match proto {
               grpc_api_types::Currency::CurrencyUnspecified => Err(ConversionError::InvalidValue("currency_unspecified")),
               grpc_api_types::Currency::Usd => Ok(DomainCurrency::USD),
               grpc_api_types::Currency::Eur => Ok(DomainCurrency::EUR),
               // ... handle all currency codes
           }
       }
   }
   ```

3. **Update Address and Contact Information**
   ```rust
   impl TryFrom<grpc_api_types::Address> for DomainAddress {
       type Error = ConversionError;
       
       fn try_from(proto: grpc_api_types::Address) -> Result<Self, Self::Error> {
           Ok(DomainAddress {
               first_name: proto.first_name,
               last_name: proto.last_name,
               line1: proto.line1,
               line2: proto.line2,
               line3: proto.line3,
               city: proto.city,
               state: proto.state,
               zip_code: proto.zip_code,
               country_alpha2_code: proto.country_alpha2_code.and_then(|c| c.try_into().ok()),
               email: proto.email,
               phone_number: proto.phone_number,
               phone_country_code: proto.phone_country_code,
           })
       }
   }
   ```

4. **Update Browser Information and Authentication Data**
   ```rust
   impl TryFrom<grpc_api_types::BrowserInformation> for DomainBrowserInformation {
       // Handle all browser-related fields
   }
   
   impl TryFrom<grpc_api_types::AuthenticationData> for DomainAuthenticationData {
       // Handle 3DS authentication data
   }
   ```

5. **Create Enum Conversion Tests**
   ```rust
   #[cfg(test)]
   mod enum_tests {
       #[test]
       fn test_all_payment_status_conversions() {
           // Test every enum variant
       }
       
       #[test]
       fn test_currency_conversions() {
           // Test all currency codes
       }
       
       // ... tests for all enums
   }
   ```

#### Deliverables
- Complete common type conversions
- All enum conversion implementations
- Comprehensive enum testing
- Documentation of enum changes

#### Acceptance Criteria
- All common types convert correctly
- Every enum variant is handled
- Test coverage >95%
- No missing enum mappings

---

## Phase 3 Completion Criteria

### Must Complete Before Phase 4
1. All domain type conversions are implemented and tested
2. No compilation errors in domain_types crate
3. All proto <-> domain conversions work bidirectionally
4. Comprehensive test coverage achieved

### Handoff to Phase 4
- **Working domain type conversions** for all proto messages
- **Tested conversion logic** with comprehensive coverage
- **Documentation** of all field changes and mappings
- **Migration patterns** for server implementation

### Risk Mitigation
- **Conversion errors**: Detailed error types with clear messages
- **Data loss**: Comprehensive tests to verify no data is lost
- **Performance**: Benchmark conversion performance
- **Backward compatibility**: Document any breaking changes

### Efficiency Focus
- **Core conversions first**: Implement PaymentMethod and basic types before complex types
- **Test as you go**: Unit test each conversion immediately after implementation
- **Reuse patterns**: Establish conversion patterns early and reuse across all types
- **Validate continuously**: Test conversions with real data as soon as possible

### Dependencies for Phase 4
- Server implementation team needs working conversions
- All conversion functions must be available as public API
- Clear documentation of error handling patterns
- Performance benchmarks for conversion operations