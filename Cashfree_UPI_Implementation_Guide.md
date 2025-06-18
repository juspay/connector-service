# Cashfree UPI Implementation Guide

## Table of Contents
1. [Overview](#overview)
2. [UPI Flow Types](#upi-flow-types)
3. [Entry Point Analysis](#entry-point-analysis)
4. [API Flow Paths](#api-flow-paths)
5. [Data Structures](#data-structures)
6. [API Endpoints](#api-endpoints)
7. [Signature Generation](#signature-generation)
8. [Implementation Examples](#implementation-examples)
9. [Complete Code Reference](#complete-code-reference)

## Overview

The Cashfree gateway supports three distinct UPI payment flows through a unified codebase:

- **UPI Intent**: Deep-link based payments for mobile app integration
- **UPI QR**: QR code based payments for in-store/web checkout
- **UPI Collect**: VPA-based collect request payments

All flows share the same entry point (`getSdkParams`) but differentiate through conditional logic based on transaction parameters.

## UPI Flow Types

### Flow Determination Matrix

| Flow Type | Source Object | Channel Type | UPI ID | UPI Mode | Use Case |
|-----------|---------------|--------------|--------|----------|----------|
| **UPI Intent** | `"UPI_PAY"` | `"link"` | `""` | `"link"` | Mobile app deep links |
| **UPI QR** | `"UPI_QR"` | `"link"` | `""` | `"link"` | QR code scanning |
| **UPI Collect** | Other values | `"collect"` | Customer VPA | `null` | VPA-based payment |

### Key Differentiators

```haskell
-- Flow determination logic (Gateway.Cashfree.Transforms:1037-1048)
upiPayTxnType = ["UPI_PAY", "UPI_QR"]

channel = if elem (txnDetail.sourceObject) upiPayTxnType 
          then "link"     -- Intent & QR flows
          else "collect"  -- Collect flow

upi_id = if channel == "collect" 
         then txnCardInfo.paymentSource  -- Customer VPA
         else ""                         -- Empty for intent/QR
```

## Entry Point Analysis

### getSdkParams Function Flow

**Location**: `Gateway.Cashfree.Flow:getSdkParams:3158-3200`

```haskell
getSdkParams orderRef txnDetail gatewayAccount merchantAccount testMode 
             cardInfo metadata secondFactor mandate customer meshEnabled subscription = do
  
  -- Skip e-mandate check for standard UPI flows
  if isEmandateRegisterTOT(txnDetail.txnObjectType) then
    callUPIIntentCreateAuth ...  -- E-mandate flow (not covered here)
  else do
    -- Standard UPI payment flows
    addr <- getBillingAddress orderRef
    cust <- getJuspayCustomer orderRef merchantAccount
    
    -- API version check
    isMerchantEnabledForNewAPI <- isFeatureEnabled 
      Constants.cashfreeNewTxnFlowCutover (txnDetail.merchantId)
    
    if isMerchantEnabledForNewAPI then
      intentNewApi orderRef txnDetail gatewayAccount testMode 
                   cardInfo addr cust meshEnabled metadata
    else
      legacyUpiFlow ...
```

### Flow Decision Tree

```
getSdkParams
├── isEmandateRegisterTOT? → callUPIIntentCreateAuth (E-mandate)
└── Standard Flow
    ├── isFeatureEnabled(newTxnFlow)?
    │   ├── YES → intentNewApi (New API)
    │   └── NO → legacyUpiFlow (Legacy API)
    └── UPI Type determined by sourceObject
        ├── "UPI_PAY" → UPI Intent
        ├── "UPI_QR" → UPI QR  
        └── Other → UPI Collect
```

## API Flow Paths

### New API Flow (Primary)

**Location**: `Gateway.Cashfree.Flow:intentNewApi:3263-3301`

#### Step 1: Order Creation
```haskell
gwOrder <- createOrder (gatewayAccount.accountDetails) txnDetail orderRef 
                       customer meshEnabled addr testMode cardInfo metadata
```

#### Step 2: Version-Specific Processing
```haskell
case gwOrder of
  GT.CashFreeOrderV3 res -> 
    intentApiV3 res cardInfo testMode txnDetail addr gatewayAccount
    
  GT.CashFreeOrder resp -> do
    let token = resp.order_token
        req = makeNewUpiReq token txnDetail cardInfo  -- UPI request builder
        apiTag = GW_INIT_INTENT
    
    resp <- initCashfreeNewTxn apiTag testMode req txnDetail Nothing
    
    case resp.response of
      CT.TxnSucResp txResponse -> do
        let payload = txResponse.data.payload
        case payload of
          Just payloadData -> do
            let link = payloadData.default
                trimlink = truncateIntentLink "?" link
                convertResp = convertResponseToStrMap trimlink
            pure $ Right $ makeCashfreeSdkParams convertResp addr
```

### Legacy API Flow

**Location**: `Gateway.Cashfree.Flow:getSdkParams:3170-3200`

#### Step 1: Payment Details Construction
```haskell
cashfreeDetails <- getCashfreeDetails gatewayAccount
response <- makeCollectingPaymentDetailsRequest 
              cashfreeDetails orderRef addr Nothing txnDetail cardInfo 
              defaultCardData Nothing customer meshEnabled cashfreeMetadata
```

#### Step 2: UPI Intent Transaction
```haskell
if isJust(response.upiMode) then do
  let apiTag = GW_INIT_INTENT
  cashfreeResp <- initCashfreeUpiIntentTransaction apiTag testMode txnDetail 
                    (Just merchantAccount) (unwrap response)
  
  case cashfreeResp of
    Right val -> do
      case val.response of
        CT.ValidResponse cashfreeTxnIntentResp -> do
          let link = cashfreeTxnIntentResp.link
              trimlink = truncateIntentLink "?" link
              convertResp = convertResponseToStrMap trimlink
          pure $ Right $ makeCashfreeSdkParams convertResp addr
```

## Data Structures

### UPI Payment Method Type

**Function**: `makeCashfreeUPIPaymentMethodType`
**Location**: `Gateway.Cashfree.Transforms:946-956`

```haskell
makeCashfreeUPIPaymentMethodType txnDetail txnCardInfo =
  CashfreePaymentMethodType {
    upi = just $ makeCashFreeUpiType txnDetail txnCardInfo,
    app = nothing,
    netbanking = nothing, 
    card = nothing,
    emi = nothing,
    paypal = nothing,
    paylater = nothing,
    cardless_emi = nothing
  }
```

### UPI Type Configuration

**Function**: `makeCashFreeUpiType`
**Location**: `Gateway.Cashfree.Transforms:1037-1048`

```haskell
makeCashFreeUpiType txnDetail txnCardInfo = 
  let channel = if elem (txnDetail.sourceObject) upiPayTxnType 
                then "link"    -- UPI Intent/QR
                else "collect" -- UPI Collect
  in CashFreeUpiType {
    channel = channel,
    upi_id = if channel == "collect" 
             then txnCardInfo.paymentSource  -- VPA for collect
             else ""                         -- Empty for intent/QR
  }
```

### New UPI Request Structure

**Function**: `makeNewUpiReq`
**Location**: `Gateway.Cashfree.Transforms:926-930`

```haskell
makeNewUpiReq token txnDetail txnCardInfo =
  CashfreeNewTxnReq {
    order_token = token,
    payment_method = makeCashfreeUPIPaymentMethodType txnDetail txnCardInfo
  }
```

## API Endpoints

### 1. UPI Intent Transaction API (Legacy)

**Function**: `initCashfreeUpiIntentTransaction`
**Location**: `Gateway.Cashfree.Flow:1540`

```haskell
initCashfreeUpiIntentTransaction apiTag testMode txn mAcc req =
  callingGenericMerchantProxy
    (getProxyCategoryTxn txn mAcc) apiTag EXTERNAL False
    make_CashFreeHeaderFn (CT.TB req testMode)
```

**Request Structure**:
```typescript
interface UpiIntentRequest {
  appId: string;
  orderId: string;
  orderAmount: string;
  orderCurrency: string;
  orderNote: string;
  customerName: string;
  customerPhone: string;
  customerEmail: string;
  returnUrl: string;
  notifyUrl: string;
  signature: string;        // HMAC-SHA256
  upiMode: "link" | null;   // "link" for intent/QR
  paymentOption: "upi";     // Always "upi" for UPI flows
  upi_vpa: string;          // VPA for collect, empty for intent/QR
  secretKey?: string;       // Conditional inclusion
  responseType?: "json";    // Conditional inclusion
}
```

**Response Structure**:
```typescript
interface UpiIntentResponse {
  response: {
    type: "ValidResponse";
    link: string;  // UPI intent deep link or QR data
  } | {
    type: "CashfreeIntentErrorResponse";
    status: string;
    message: string;
  }
}
```

### 2. New Transaction API

**Function**: `initCashfreeNewTxn`
**Location**: `Gateway.Cashfree.Flow:1552`

**Request Structure**:
```typescript
interface NewTxnRequest {
  order_token: string;
  payment_method: {
    upi: {
      channel: "link" | "collect";
      upi_id: string;  // VPA for collect, empty for intent/QR
    }
  }
}
```

**Response Structure**:
```typescript
interface NewTxnResponse {
  response: {
    type: "TxnSucResp";
    data: {
      payload: {
        default: string;  // Payment URL/intent link
      }
    }
  } | {
    type: "TxnFailResp";
    code: string;
    message: string;
  }
}
```

## Signature Generation

### UPI-Specific Signature Logic

**Function**: `makeConstructSignatureRequest`
**Location**: `Gateway.Cashfree.Transforms:356-440`

```haskell
makeConstructSignatureRequest cashfreeDetails orderRef orderAddress emiCode 
                             txnDetail txnCardInfo cardData gatewayCode 
                             maybeCust meshEnabled maybeCashfreeMeta = do
  
  -- UPI VPA determination
  let vpa = if (txnCardInfo.paymentMethodType == PMT.UPI) 
            then txnCardInfo.paymentSource 
            else ""
  
  -- Payment option (always "upi" for UPI flows)
  paymentOption = if isPushPay then "upi" else gatewayPaymentMethod
  
  -- UPI mode determination
  upiMode = if elem txnDetail.sourceObject upiPayTxnType 
            then just "link"    -- UPI Intent/QR
            else if isPushPay 
                 then just "gpay" 
                 else nothing   -- UPI Collect
  
  -- Secret key inclusion
  secretKey = if elem txnDetail.sourceObject txnTypeList 
              then just cashfreeDetails.secretKey
              else nothing
  
  -- Response type
  responseType = if elem txnDetail.sourceObject txnTypeList 
                 then just "json"
                 else nothing

where
  isPushPay = txnDetail.sourceObject == just "PUSH_PAY"
  txnTypeList = ["UPI_PAY", "PUSH_PAY", "UPI_QR"]
```

### Signature Generation Process

**Function**: `make_cashFreeSignature`
**Location**: `Gateway.Cashfree.Transforms:448`

```haskell
make_cashFreeSignature cashfreeSignatureRequest cashfreeDetails =
  hmac256base64
    (generateKeyValue $ jsonStringify $ encode cashfreeSignatureRequest)
    (cashfreeDetails.secretKey)
```

**Process Steps**:
1. JSON encode the signature request object
2. Convert to string format (`jsonStringify`)
3. Generate key-value format (`generateKeyValue`)
4. Create HMAC-SHA256 signature
5. Encode result as Base64

## Implementation Examples

### Complete UPI Flow Implementation

```javascript
// Main UPI entry point
async function getSdkParamsForUPI(orderRef, txnDetail, gatewayAccount, 
                                 merchantAccount, testMode, cardInfo, metadata) {
  
  // Determine UPI flow type
  const upiFlowType = determineUpiFlowType(txnDetail.sourceObject);
  console.log(`Processing UPI flow: ${upiFlowType}`);
  
  // Get required data
  const billingAddress = await getBillingAddress(orderRef);
  const customer = await getJuspayCustomer(orderRef, merchantAccount);
  
  // Check API version
  const useNewApi = await isFeatureEnabled('cashfreeNewTxnFlowCutover', txnDetail.merchantId);
  
  if (useNewApi) {
    return await processNewApiUpiFlow(orderRef, txnDetail, gatewayAccount, 
                                     testMode, cardInfo, billingAddress, 
                                     customer, metadata, upiFlowType);
  } else {
    return await processLegacyApiUpiFlow(orderRef, txnDetail, gatewayAccount, 
                                        testMode, cardInfo, billingAddress, 
                                        customer, metadata, upiFlowType);
  }
}

// UPI flow type determination
function determineUpiFlowType(sourceObject) {
  const upiPayTxnTypes = ["UPI_PAY", "UPI_QR"];
  
  switch (sourceObject) {
    case "UPI_PAY":
      return "UPI_INTENT";
    case "UPI_QR":
      return "UPI_QR";
    default:
      return "UPI_COLLECT";
  }
}

// New API UPI flow
async function processNewApiUpiFlow(orderRef, txnDetail, gatewayAccount, 
                                   testMode, cardInfo, address, customer, 
                                   metadata, upiFlowType) {
  
  // Step 1: Create order
  const orderResponse = await createOrder({
    accountDetails: gatewayAccount.accountDetails,
    txnDetail: txnDetail,
    orderRef: orderRef,
    customer: customer,
    meshEnabled: false,
    address: address,
    testMode: testMode,
    cardInfo: cardInfo,
    metadata: metadata
  });
  
  // Step 2: Process based on order type
  if (orderResponse.type === 'CashFreeOrderV3') {
    return await processV3Order(orderResponse.data, cardInfo, testMode, 
                               txnDetail, address, gatewayAccount);
  }
  else if (orderResponse.type === 'CashFreeOrder') {
    const token = orderResponse.data.order_token;
    
    // Build UPI-specific request
    const upiRequest = buildNewUpiRequest(token, txnDetail, cardInfo, upiFlowType);
    
    // Make transaction API call
    const response = await initCashfreeNewTxn('GW_INIT_INTENT', testMode, 
                                             upiRequest, txnDetail, null);
    
    if (response.success && response.data.response.type === 'TxnSucResp') {
      const payloadData = response.data.response.data.payload;
      
      if (payloadData) {
        const paymentUrl = payloadData.default;
        const processedUrl = processUpiResponse(paymentUrl, upiFlowType);
        const sdkResponse = convertResponseToStrMap(processedUrl);
        
        return makeCashfreeSdkParams(sdkResponse, address);
      }
    }
  }
  
  throw new Error(`UPI ${upiFlowType} order creation failed`);
}

// Build new API UPI request
function buildNewUpiRequest(token, txnDetail, cardInfo, upiFlowType) {
  return {
    order_token: token,
    payment_method: {
      upi: buildUpiPaymentMethod(txnDetail, cardInfo, upiFlowType)
    }
  };
}

// Build UPI payment method
function buildUpiPaymentMethod(txnDetail, cardInfo, upiFlowType) {
  const isLinkBasedFlow = (upiFlowType === "UPI_INTENT" || upiFlowType === "UPI_QR");
  
  return {
    channel: isLinkBasedFlow ? "link" : "collect",
    upi_id: isLinkBasedFlow ? "" : cardInfo.paymentSource || ""
  };
}

// Legacy API UPI flow
async function processLegacyApiUpiFlow(orderRef, txnDetail, gatewayAccount, 
                                      testMode, cardInfo, address, customer, 
                                      metadata, upiFlowType) {
  
  const cashfreeDetails = getCashfreeDetails(gatewayAccount);
  
  // Build comprehensive payment request
  const paymentRequest = await makeCollectingPaymentDetailsRequest({
    cashfreeDetails: cashfreeDetails,
    orderRef: orderRef,
    address: address,
    emiCode: null,
    txnDetail: txnDetail,
    cardInfo: cardInfo,
    cardData: getDefaultCardData(),
    gatewayCode: null,
    customer: customer,
    meshEnabled: false,
    metadata: metadata
  });
  
  if (!paymentRequest.secretKey) {
    throw new Error('Authentication failed - missing secret key');
  }
  
  if (paymentRequest.upiMode) {
    const response = await initCashfreeUpiIntentTransaction(
      'GW_INIT_INTENT', 
      testMode, 
      txnDetail, 
      null, 
      paymentRequest
    );
    
    if (response.success && response.data.response.type === 'ValidResponse') {
      const intentLink = response.data.response.link;
      const processedLink = processUpiResponse(intentLink, upiFlowType);
      const sdkResponse = convertResponseToStrMap(processedLink);
      
      return makeCashfreeSdkParams(sdkResponse, address);
    }
  }
  
  throw new Error(`UPI ${upiFlowType} payment processing failed`);
}

// UPI response processing
function processUpiResponse(responseUrl, upiFlowType) {
  switch (upiFlowType) {
    case "UPI_INTENT":
      // Truncate intent link at query parameters for deep linking
      return truncateIntentLink("?", responseUrl);
      
    case "UPI_QR":
      // QR codes typically use the full URL for complete payment data
      return responseUrl;
      
    case "UPI_COLLECT":
      // Collect responses may need query parameter truncation
      return truncateIntentLink("?", responseUrl);
      
    default:
      return responseUrl;
  }
}

// UPI signature generation
async function generateUpiSignatureRequest(cashfreeDetails, orderRef, address, 
                                          txnDetail, cardInfo, customer, upiFlowType) {
  
  const isLinkBasedFlow = (upiFlowType === "UPI_INTENT" || upiFlowType === "UPI_QR");
  const isPushPay = txnDetail.sourceObject === "PUSH_PAY";
  
  // UPI-specific parameter handling
  const upiVpa = (cardInfo.paymentMethodType === "UPI" && !isLinkBasedFlow) 
                 ? cardInfo.paymentSource : "";
  
  const paymentOption = "upi";  // Always "upi" for UPI flows
  
  // UPI mode determination
  let upiMode = null;
  if (isLinkBasedFlow) {
    upiMode = "link";
  } else if (isPushPay) {
    upiMode = "gpay";
  }
  // else remains null for collect flows
  
  // Build complete signature request
  const signatureRequest = {
    appId: cashfreeDetails.appId,
    orderId: txnDetail.txnId,
    orderAmount: await getMoneyInText(txnDetail, orderRef),
    orderCurrency: orderRef.currency || "INR",
    orderNote: orderRef.description,
    customerName: getCustomerName(customer, address),
    customerPhone: isPushPay ? cardInfo.paymentSource : getCustomerPhone(orderRef),
    customerEmail: getCustomerEmail(orderRef, customer),
    returnUrl: await getHandleRespUrl(txnDetail),
    notifyUrl: await getWebhookUrl(txnDetail),
    pc: "",
    upi_vpa: upiVpa,
    paymentOption: paymentOption,
    upiMode: upiMode,
    secretKey: shouldIncludeSecretKey(txnDetail.sourceObject) ? cashfreeDetails.secretKey : null,
    responseType: shouldIncludeSecretKey(txnDetail.sourceObject) ? "json" : null
  };
  
  return signatureRequest;
}

// Helper function to determine secret key inclusion
function shouldIncludeSecretKey(sourceObject) {
  const txnTypesRequiringKey = ["UPI_PAY", "PUSH_PAY", "UPI_QR"];
  return txnTypesRequiringKey.includes(sourceObject);
}

// Generate HMAC-SHA256 signature
function generateCashfreeSignature(signatureRequest, secretKey) {
  // Convert request to JSON string
  const jsonString = JSON.stringify(signatureRequest);
  
  // Generate key-value string format (implementation specific)
  const keyValueString = generateKeyValue(jsonString);
  
  // Create HMAC-SHA256 signature
  const signature = crypto
    .createHmac('sha256', secretKey)
    .update(keyValueString)
    .digest('base64');
  
  return signature;
}
```

## Complete Code Reference

### Key Function Locations

| Function | Module | Location | Purpose |
|----------|--------|----------|---------|
| `getSdkParams` | `Gateway.Cashfree.Flow` | 3158-3200 | Main entry point |
| `intentNewApi` | `Gateway.Cashfree.Flow` | 3263-3301 | New API flow |
| `makeCashFreeUpiType` | `Gateway.Cashfree.Transforms` | 1037-1048 | UPI type builder |
| `makeNewUpiReq` | `Gateway.Cashfree.Transforms` | 926-930 | New API request |
| `makeCashfreeUPIPaymentMethodType` | `Gateway.Cashfree.Transforms` | 946-956 | Payment method |
| `makeConstructSignatureRequest` | `Gateway.Cashfree.Transforms` | 356-440 | Signature request |
| `make_cashFreeSignature` | `Gateway.Cashfree.Transforms` | 448 | HMAC generation |
| `initCashfreeUpiIntentTransaction` | `Gateway.Cashfree.Flow` | 1540 | Legacy API call |
| `initCashfreeNewTxn` | `Gateway.Cashfree.Flow` | 1552 | New API call |
| `upiPayTxnType` | `Engineering.Common` | 653 | Flow type constants |

### UPI Flow Constants

```haskell
-- UPI transaction types that use "link" channel
upiPayTxnType = ["UPI_PAY", "UPI_QR"]

-- Transaction types requiring secret key in signature
txnTypeList = ["UPI_PAY", "PUSH_PAY", "UPI_QR"]
```

### Request/Response Type Mappings

**New API Flow**:
- Request: `CashfreeNewTxnReq`
- Response: `CashfreeNewTxnResponse`

**Legacy API Flow**:
- Request: `CollectingPaymentDetailsRequest`  
- Response: `CashfreeUpiIntentInitPayResponse`

**Payment Method Structure**:
```haskell
CashfreePaymentMethodType {
  upi = CashFreeUpiType {
    channel: "link" | "collect",
    upi_id: String  -- VPA or empty
  }
}
```

This implementation guide provides complete coverage of all three UPI flows with detailed code references, data structures, and implementation examples suitable for reproduction in any programming language.