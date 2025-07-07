# Integrity Framework

## Overview

The Integrity Framework ensures data consistency and accuracy throughout the payment processing pipeline by validating that request and response data remain coherent. It automatically compares critical fields (amounts, currencies, transaction IDs) between requests and responses to prevent data corruption and ensure financial accuracy.

**⚠️ Important**: Currently, most connectors have `integrity_object: None`, which bypasses validation entirely. This guide shows how to implement it correctly.

## Core Traits

```rust
pub trait FlowIntegrity {
    type IntegrityObject;
    
    fn compare(
        req_integrity_object: Self::IntegrityObject,
        res_integrity_object: Self::IntegrityObject,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError>;
}

pub trait GetIntegrityObject<T: FlowIntegrity> {
    fn get_response_integrity_object(&self) -> Option<T::IntegrityObject>;
    fn get_request_integrity_object(&self) -> T::IntegrityObject;
}

pub trait CheckIntegrity<Request, T> {
    fn check_integrity(
        &self,
        request: &Request,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError>;
}
```

## Integrity Objects by Flow Type

1. **AuthoriseIntegrityObject**: Validates authorization amounts and currencies
2. **CaptureIntegrityObject**: Ensures capture amounts don't exceed authorization
3. **RefundIntegrityObject**: Validates refund amounts against original payment
4. **PaymentVoidIntegrityObject**: Verifies transaction ID consistency
5. **PaymentSyncIntegrityObject**: Validates sync request data
6. **SetupMandateIntegrityObject**: Verifies mandate setup parameters
7. **AcceptDisputeIntegrityObject**: Validates dispute acceptance data
8. **DefendDisputeIntegrityObject**: Verifies dispute defense parameters
9. **RefundSyncIntegrityObject**: Validates refund sync consistency
10. **SubmitEvidenceIntegrityObject**: Verifies evidence submission data

## Implementation Example

```rust
impl FlowIntegrity for AuthoriseIntegrityObject {
    type IntegrityObject = Self;

    fn compare(
        req_integrity_object: Self,
        res_integrity_object: Self,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError> {
        let mut mismatched_fields = Vec::new();

        // Validate amount consistency
        if req_integrity_object.amount != res_integrity_object.amount {
            mismatched_fields.push(format_mismatch(
                "amount",
                &req_integrity_object.amount.to_string(),
                &res_integrity_object.amount.to_string(),
            ));
        }

        // Validate currency consistency
        if req_integrity_object.currency != res_integrity_object.currency {
            mismatched_fields.push(format_mismatch(
                "currency",
                &req_integrity_object.currency.to_string(),
                &res_integrity_object.currency.to_string(),
            ));
        }

        check_integrity_result(mismatched_fields, connector_transaction_id)
    }
}
```

## Automatic Integration

The framework is automatically integrated into the payment processing pipeline:

```rust
// In external services - automatically called during payment processing
pub async fn execute_connector_processing_step<T, F, ResourceCommonData, Req, Resp>(
    // ... parameters
) -> CustomResult<RouterDataV2<F, ResourceCommonData, Req, Resp>, ConnectorError>
where
    T: FlowIntegrity,
    Req: Clone + GetIntegrityObject<T> + CheckIntegrity<Req, T>,
{
    // Process connector request/response
    let response_data = connector_integration.handle_response_v2(
        &router_data,
        event_builder.as_mut(),
        res,
    )?;

    // Automatic integrity validation
    response_data.check_integrity(&request, connector_transaction_id)?;

    Ok(response_data)
}
```

## Benefits
- **Data Consistency**: Prevents processing of corrupted or inconsistent data
- **Early Error Detection**: Catches discrepancies before they affect downstream systems
- **Financial Accuracy**: Ensures amount and currency integrity across all operations
- **Audit Trail**: Provides detailed mismatch information for debugging

## Connector Integration Guide

### 🚀 Quick Start for New Connectors

When integrating a new connector, you MUST implement integrity checking in 3 places:

#### **Step 1: Request Data Population**
**Location**: `/backend/domain_types/src/types.rs`

Replace `integrity_object: None` with actual object creation:

```rust
// ❌ Current (bypasses validation)
integrity_object: None,

// ✅ Correct implementation
integrity_object: Some(AuthoriseIntegrityObject {
    amount: value.minor_amount,
    currency: value.currency,
}),
```

#### **Step 2: Response Data Extraction** 
**Location**: `/backend/connector-integration/src/connectors/{connector}/transformers.rs`

Implement `GetIntegrityObject` trait for your response types:

```rust
impl GetIntegrityObject<AuthoriseIntegrityObject> for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> {
    fn get_response_integrity_object(&self) -> Option<AuthoriseIntegrityObject> {
        // Extract from connector response
        match &self.response {
            Ok(PaymentsResponseData::TransactionResponse { amount, currency, .. }) => {
                Some(AuthoriseIntegrityObject {
                    amount: *amount,
                    currency: *currency,
                })
            }
            _ => None, // Failed responses don't need integrity check
        }
    }

    fn get_request_integrity_object(&self) -> AuthoriseIntegrityObject {
        self.request.integrity_object.clone().unwrap_or_else(|| {
            // Fallback: create from request data
            AuthoriseIntegrityObject {
                amount: self.request.amount,
                currency: self.request.currency,
            }
        })
    }
}
```

#### **Step 3: Connector Response Parsing**
**Location**: `/backend/connector-integration/src/connectors/{connector}/transformers.rs`

Ensure your response transformers extract integrity data from connector's JSON:

```rust
// Example for Adyen
fn build_authorize_response(item_response: AdyenPaymentResponse) -> PaymentsResponseData {
    let integrity_object = Some(AuthoriseIntegrityObject {
        amount: MinorUnit::new(item_response.amount.value),
        currency: Currency::from_str(&item_response.amount.currency).unwrap_or_default(),
    });
    
    PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(item_response.psp_reference),
        redirection_data: None,
        mandate_reference: None,
        connector_metadata: None,
        network_transaction_id: None,
        connector_response_reference_id: Some(item_response.psp_reference.clone()),
        incremental_authorization_allowed: None,
        charge_id: None,
        integrity_object, // ✅ Include extracted integrity data
    }
}
```

### 🔧 Implementation by Flow Type

#### **Authorization Flow**
```rust
// Request: PaymentsAuthorizeData
integrity_object: Some(AuthoriseIntegrityObject {
    amount: self.amount,
    currency: self.currency,
})

// Response: Extract from connector
Some(AuthoriseIntegrityObject {
    amount: response.amount,
    currency: response.currency,
})
```

#### **Capture Flow**
```rust
// Request: PaymentsCaptureData  
integrity_object: Some(CaptureIntegrityObject {
    amount_to_capture: self.amount_to_capture,
    currency: self.currency,
})

// Response: Validate capture amount
Some(CaptureIntegrityObject {
    amount_to_capture: response.captured_amount,
    currency: response.currency,
})
```

#### **Refund Flow**
```rust
// Request: RefundsData
integrity_object: Some(RefundIntegrityObject {
    refund_amount: self.refund_amount,
    currency: self.currency,
})

// Response: Validate refund amount
Some(RefundIntegrityObject {
    refund_amount: response.refunded_amount,
    currency: response.currency,
})
```

### 🧪 Testing Your Implementation

#### **1. Unit Tests**
Add integrity validation tests to your connector:

```rust
#[test]
fn test_authorize_integrity_validation() {
    let request_data = PaymentsAuthorizeData {
        amount: MinorUnit::new(1000),
        currency: Currency::USD,
        integrity_object: Some(AuthoriseIntegrityObject {
            amount: MinorUnit::new(1000),
            currency: Currency::USD,
        }),
        // ... other fields
    };
    
    // Mock response with matching integrity
    let response = PaymentsResponseData::TransactionResponse {
        integrity_object: Some(AuthoriseIntegrityObject {
            amount: MinorUnit::new(1000), // ✅ Matches request
            currency: Currency::USD,      // ✅ Matches request
        }),
        // ... other fields
    };
    
    // This should pass integrity check
    assert!(response.check_integrity(&request_data, None).is_ok());
}

#[test]
fn test_authorize_integrity_mismatch() {
    let request_data = PaymentsAuthorizeData {
        amount: MinorUnit::new(1000),
        currency: Currency::USD,
        integrity_object: Some(AuthoriseIntegrityObject {
            amount: MinorUnit::new(1000),
            currency: Currency::USD,
        }),
        // ... other fields
    };
    
    // Mock response with mismatched amount
    let response = PaymentsResponseData::TransactionResponse {
        integrity_object: Some(AuthoriseIntegrityObject {
            amount: MinorUnit::new(1500), // ❌ Doesn't match request
            currency: Currency::USD,
        }),
        // ... other fields
    };
    
    // This should fail integrity check
    assert!(response.check_integrity(&request_data, None).is_err());
}
```

#### **2. Integration Tests**
Run end-to-end tests to ensure integrity validation works:

```bash
cargo test --test integration_tests -- test_payment_authorize_integrity
```

### ✅ Implementation Checklist

Before marking your connector as "integrity-ready":

- [ ] **Request Data**: Replaced all `integrity_object: None` with actual objects
- [ ] **Response Parsing**: Implemented `GetIntegrityObject` trait for all flow types
- [ ] **Transformer Updates**: Extract integrity data from connector responses
- [ ] **Unit Tests**: Added tests for both successful validation and mismatch detection
- [ ] **Integration Tests**: Verified end-to-end integrity checking works
- [ ] **Error Handling**: Graceful handling when connector doesn't return expected fields
- [ ] **Documentation**: Updated connector-specific docs with integrity implementation notes

### 🚨 Common Pitfalls

1. **Forgetting GRPC Server**: Update `/backend/grpc-server/src/server/payments.rs` to create integrity objects
2. **Currency Mismatches**: Ensure currency parsing is consistent between request/response
3. **Amount Precision**: Handle minor unit conversions correctly
4. **Optional Fields**: Some connectors may not return all fields - handle gracefully
5. **Failed Responses**: Don't validate integrity for failed payment responses

### 🔍 Debugging Integrity Issues

When integrity checks fail, you'll get detailed error information:

```rust
IntegrityCheckError {
    field_names: vec!["amount: expected 1000, got 1500", "currency: expected USD, got EUR"],
    connector_transaction_id: Some("adyen_12345"),
}
```

Use this information to identify:
- Data transformation bugs in your connector
- Currency conversion issues
- Amount calculation errors
- Field mapping problems

## Best Practices for Connector Developers

1. **Always Implement Integrity**:
   - Never leave `integrity_object: None` in production code
   - Ensure response objects include all critical fields
   - Handle partial responses gracefully
   - Provide detailed error information for mismatches