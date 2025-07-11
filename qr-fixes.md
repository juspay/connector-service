# PayTM UPI QR Flow Fix Plan - Using AmountConverter Framework

## Strategy Overview
1. **Bypass CreateSessionToken entirely** for QR flows via `should_do_session_token()` 
2. **Use AmountConverter framework** for proper amount handling (no manual conversions)
3. **Handle all QR logic in Authorize flow** without session token dependency

## Root Cause Analysis
- **Issue 1**: QR flow incorrectly expects session tokens
- **Issue 2**: Amount conversion not using proper AmountConverter framework
- **Issue 3**: Manual hardcoded conversions instead of framework usage

## Detailed Implementation Plan

### Phase 1: Fix Session Token Bypass for QR Flows
**Challenge**: `should_do_session_token()` doesn't have payment method context
**Solution**: Handle QR flows in Authorize flow by making session token optional

### Phase 2: Fix Amount Conversion Using Framework
**File**: `backend/connector-integration/src/connectors/paytm/transformers.rs`

#### 2.1 Update PaytmQRRequest::try_from_with_auth Signature
**Current** (Line 822):
```rust
pub fn try_from_with_auth(
    item: &PaytmAuthorizeRouterData,
    auth: &PaytmAuthType,
) -> CustomResult<Self, errors::ConnectorError>
```

**Fix**: Add amount converter parameter
```rust
pub fn try_from_with_auth(
    item: &PaytmAuthorizeRouterData,
    auth: &PaytmAuthType,
    amount_converter: &dyn AmountConvertor<Output = StringMajorUnit>,
) -> CustomResult<Self, errors::ConnectorError>
```

#### 2.2 Fix Amount Conversion Using Framework
**Current Problem** (Line 836):
```rust
amount: item.amount.to_string(), // Manual conversion - WRONG
```

**Fix**: Use AmountConverter framework
```rust
let amount_value = amount_converter.convert(
    MinorUnit::new(item.amount), 
    Currency::from_str(&item.currency)?
).change_context(errors::ConnectorError::AmountConversionFailed)?;

// Use in request body:
amount: amount_value.get_amount_as_string(), // Framework conversion - CORRECT
```

### Phase 3: Fix Session Token Handling for QR
**File**: `backend/connector-integration/src/connectors/paytm/transformers.rs` (Lines 703-710)

**Current Problem**:
```rust
let session_token = item.resource_common_data.get_session_token()
    .ok()
    .ok_or(errors::ConnectorError::MissingRequiredField {
        field_name: "session_token",
    })?
    .clone();
```

**Fix**: Make session token optional for QR flows
```rust
let upi_flow = determine_upi_flow(&item.payment_method_data)?;
let session_token = match upi_flow {
    UpiFlowType::QrCode => String::new(), // QR doesn't need session token
    _ => {
        // Intent/Collect flows require session token
        item.resource_common_data.get_session_token()
            .ok()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "session_token",
            })?
            .clone()
    }
};
```

### Phase 4: Update Authorize Flow to Pass AmountConverter
**File**: `backend/connector-integration/src/connectors/paytm.rs` (Line 341)

**Current**:
```rust
paytm::UpiFlowType::QrCode => {
    let connector_req = paytm::PaytmQRRequest::try_from_with_auth(&connector_router_data, &auth)?;
    Ok(Some(RequestContent::Json(Box::new(connector_req))))
}
```

**Fix**: Pass amount converter
```rust
paytm::UpiFlowType::QrCode => {
    let connector_req = paytm::PaytmQRRequest::try_from_with_auth(
        &connector_router_data, 
        &auth,
        self.amount_converter // Pass the framework converter
    )?;
    Ok(Some(RequestContent::Json(Box::new(connector_req))))
}
```

### Phase 5: Update Currency Handling in PaytmAuthorizeRouterData
**File**: `backend/connector-integration/src/connectors/paytm/transformers.rs` (Line 714)

**Current**:
```rust
currency: item.request.currency.to_string(),
```

**Fix**: Keep as Currency enum for proper framework usage
```rust
currency: item.request.currency, // Keep as Currency enum, not string
```

**Update PaytmAuthorizeRouterData struct** (Line 590):
```rust
pub struct PaytmAuthorizeRouterData {
    pub amount: i64,
    pub currency: Currency, // Change from String to Currency enum
    // ... rest unchanged
}
```

## Framework Integration Points

### 1. AmountConverter Usage Pattern
```rust
// Import required types
use common_utils::types::{AmountConvertor, StringMajorUnit, MinorUnit};
use common_enums::Currency;

// Proper conversion in QR request
let amount_value = amount_converter.convert(
    MinorUnit::new(item.amount),     // Input: minor units (paise)
    item.currency                    // Currency enum
).change_context(errors::ConnectorError::AmountConversionFailed)?;

// Use framework result
amount: amount_value.get_amount_as_string() // Output: "10.50"
```

### 2. Connector AmountConverter Access
**Available in connector**: `self.amount_converter: &'static (dyn AmountConvertor<Output = StringMajorUnit> + Sync)`
**Type**: `StringMajorUnitForConnector` which converts to decimal string format

## Specific Code Changes Summary

### 1. **PaytmQRRequest::try_from_with_auth** Updates
- Add `amount_converter` parameter
- Use framework for amount conversion
- Remove manual conversion logic

### 2. **PaytmAuthorizeRouterData** Updates  
- Change `currency` field from `String` to `Currency`
- Update transformation logic accordingly

### 3. **Authorize Flow Request Body** Updates
- Pass `self.amount_converter` to QR request builder
- Ensure proper framework usage

### 4. **Session Token Handling** Updates
- Detect UPI flow type before session token extraction
- Skip session token for QR flows
- Maintain requirement for Intent/Collect flows

## Framework Benefits

### ✅ **Consistency**
- Uses same conversion logic as other connectors
- Follows established patterns in codebase

### ✅ **Maintainability**  
- No hardcoded conversion factors
- Framework handles edge cases and validation

### ✅ **Flexibility**
- Supports different currency formats
- Handles locale-specific formatting if needed

### ✅ **Error Handling**
- Framework provides proper error handling for conversion failures
- Consistent error types across codebase

## Testing Strategy

### Amount Conversion Tests
1. **Framework Usage**: Verify AmountConverter.convert() called correctly
2. **Output Format**: Ensure decimal string format ("10.50")
3. **Currency Support**: Test with different currencies
4. **Error Cases**: Test invalid amounts and conversion failures

### QR Flow Tests  
1. **No Session Token**: QR works without CreateSessionToken
2. **Single API Call**: Direct QR endpoint call
3. **Response Handling**: QR metadata extraction
4. **Amount Accuracy**: Correct amount formatting in QR request

### Regression Tests
1. **Intent/Collect**: Unchanged behavior with session tokens
2. **Amount Conversion**: Other flows still use framework correctly
3. **Flow Routing**: Proper endpoint selection maintained

## Expected Behavior

### QR Flow (After Fix):
1. ❌ **Skip**: CreateSessionToken entirely
2. ✅ **Amount**: Framework converts `1050` paise → `"10.50"` INR  
3. ✅ **Request**: Single API call to `/paymentservices/qr/create`
4. ✅ **Response**: QR data in connector metadata

### Framework Integration:
- ✅ **No Manual Math**: No hardcoded `/100` conversions
- ✅ **Proper Types**: Uses MinorUnit → StringMajorUnit conversion
- ✅ **Error Handling**: Framework error handling for conversion failures
- ✅ **Consistency**: Same pattern as other connector implementations

## Implementation Steps

1. **Uncomment QR Code** in domain types, transformers, and connector files
2. **Add UpiQrCode variant** back to UpiFlowType enum
3. **Fix session token handling** in PaytmAuthorizeRouterData transformation
4. **Update QR request builder** to use AmountConverter framework
5. **Pass amount converter** from connector to QR request builder
6. **Update currency field** to use Currency enum instead of String
7. **Test QR flow** end-to-end with proper amount conversion
8. **Verify regression** tests for Intent/Collect flows

## Key Files to Modify

1. **`backend/domain_types/src/payment_method_data.rs`**
   - Uncomment UpiQr variant and UpiQrData struct

2. **`backend/connector-integration/src/connectors/paytm/transformers.rs`**
   - Uncomment QR-related structs and implementations
   - Lines 703-710: Session token handling
   - Line 836: Amount conversion
   - Lines 822-856: QR request builder
   - Line 590: PaytmAuthorizeRouterData currency field

3. **`backend/connector-integration/src/connectors/paytm.rs`**
   - Uncomment QR flow handling in URL generation, request body, and response handling
   - Update request body generation to pass amount converter