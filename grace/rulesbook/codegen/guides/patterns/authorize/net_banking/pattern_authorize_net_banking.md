# Net Banking Authorize Flow Pattern Guide

## Overview

This document provides comprehensive patterns for implementing Net Banking (online banking) payment authorization flows in Grace-UCS connectors. Net banking enables customers to complete payments by logging into their bank's internet banking portal, authorizing the transaction, and returning to the merchant. It is widely used in India and other Asian markets.

### What is Net Banking

Net Banking (also called Internet Banking or Online Banking) involves:
- **Bank Selection**: Customer selects their bank from a list of supported banks
- **Redirect to Bank**: Customer is redirected to their bank's internet banking login page
- **Authentication**: Customer logs in and authorizes the payment on the bank's website
- **Callback/Return**: Customer is redirected back to the merchant after authorization
- **No Sensitive Data**: No card numbers or bank account details are handled by the merchant

### Net Banking vs Bank Redirect

While Net Banking is conceptually similar to Bank Redirect, it is a distinct payment method in the Grace-UCS system:

| Aspect | Net Banking | Bank Redirect |
|--------|-------------|---------------|
| **Payment Method Type** | `PaymentMethodData::Netbanking` | `PaymentMethodData::BankRedirect` |
| **Data Structure** | `NetbankingData` | `BankRedirectData` |
| **Primary Markets** | India, Southeast Asia | Europe |
| **Bank Identification** | `bank_code` (string code) | Variant-specific (issuer, bank_name) |
| **Examples** | SBI, HDFC, ICICI, Axis | iDEAL, Sofort, Giropay, EPS |

### Net Banking Data Structure

```rust
// From crates/types-traits/domain_types/src/payment_method_data.rs

#[derive(Eq, PartialEq, Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct NetbankingData {
    pub bank_code: String,
    pub bank_name: Option<String>,
}

// Used in the PaymentMethodData enum:
pub enum PaymentMethodData<T: PaymentMethodDataTypes> {
    // ... other variants ...
    Netbanking(NetbankingData),
}
```

### Key Characteristics

| Characteristic | Value |
|----------------|-------|
| Default Request Format | JSON |
| Amount Unit | MinorUnit (paise for INR) |
| Response Type | Async/Redirect |
| 3DS Support | Not applicable (bank handles auth) |
| Webhook Support | Required for final status confirmation |
| Mandate Support | Not supported |
| Refund Support | Connector-dependent |

---

## Table of Contents

1. [Quick Reference](#quick-reference)
2. [Supported Connectors](#supported-connectors)
3. [Common Indian Bank Codes](#common-indian-bank-codes)
4. [Pattern Categories](#pattern-categories)
   - [Standard JSON Redirect Pattern](#1-standard-json-redirect-pattern)
   - [Form-Encoded Pattern](#2-form-encoded-pattern)
   - [Encrypted Payload Pattern](#3-encrypted-payload-pattern)
5. [Request Patterns](#request-patterns)
6. [Response Patterns](#response-patterns)
7. [Implementation Templates](#implementation-templates)
8. [Common Pitfalls](#common-pitfalls)
9. [Testing Patterns](#testing-patterns)
10. [Implementation Checklist](#implementation-checklist)

---

## Quick Reference

### Pattern Summary Table

| Pattern | Request Format | Response Type | Amount Unit | Connectors |
|---------|---------------|---------------|-------------|------------|
| Standard JSON Redirect | JSON | Async/Redirect | MinorUnit | Razorpay, Cashfree |
| Form-Encoded | FormUrlEncoded | Redirect | MinorUnit | Paytm (legacy) |
| Encrypted Payload | Base64+JSON | Redirect | MinorUnit | PhonePe |
| Two-Phase (Order+Pay) | JSON | Redirect | MinorUnit/FloatMajor | Cashfree |

### Authorization Flow

```
                                    Net Banking Flow

Customer selects bank               Connector creates payment
        |                                     |
        v                                     v
┌──────────────┐    ┌───────────────┐    ┌──────────────┐
│ Bank Code    │───>│ Create Payment│───>│ Redirect URL │
│ Selection    │    │ Request       │    │ Response     │
└──────────────┘    └───────────────┘    └──────┬───────┘
                                                │
                                                v
┌──────────────┐    ┌───────────────┐    ┌──────────────┐
│ Payment      │<───│ Bank Auth     │<───│ Customer     │
│ Confirmation │    │ Page          │    │ Redirected   │
└──────┬───────┘    └───────────────┘    └──────────────┘
       │
       v
┌──────────────┐
│ Webhook /    │
│ PSync        │
└──────────────┘
```

---

## Supported Connectors

| Connector | Request Format | Auth Method | Amount Unit | Bank Code Mapping | Webhook Support |
|-----------|---------------|-------------|-------------|-------------------|-----------------|
| **Razorpay** | JSON | Basic Auth | MinorUnit | Direct bank code | Yes |
| **Cashfree** | JSON | API Key | FloatMajorUnit | Connector-specific mapping | Yes |
| **PhonePe** | Base64+JSON | HMAC Signature | MinorUnit | Connector-specific mapping | Yes |
| **Paytm** | JSON | AES Signature | MinorUnit | Channel code mapping | Yes |
| **Adyen** | JSON | API Key | MinorUnit | Custom bank mapping | Yes |
| **Stripe** | JSON | API Key | MinorUnit | Not directly supported | N/A |

---

## Common Indian Bank Codes

Net banking bank codes vary by connector. Here are common banks and typical code patterns:

| Bank Name | Common Code | Razorpay | Cashfree | PhonePe |
|-----------|-------------|----------|----------|---------|
| State Bank of India | `SBIN` | `SBIN` | `SBI` | `SBI` |
| HDFC Bank | `HDFC` | `HDFC` | `HDFC` | `HDFC` |
| ICICI Bank | `ICIC` | `ICIC` | `ICICI` | `ICICI` |
| Axis Bank | `UTIB` | `UTIB` | `AXIS` | `AXIS` |
| Kotak Mahindra | `KKBK` | `KKBK` | `KOTAK` | `KOTAK` |
| Bank of Baroda | `BARB` | `BARB_R` | `BOB` | `BOB` |
| Punjab National Bank | `PUNB` | `PUNB_R` | `PNB` | `PNB` |
| Yes Bank | `YESB` | `YESB` | `YES` | `YES` |
| Union Bank | `UBIN` | `UBIN` | `UNION` | `UNION` |
| IndusInd Bank | `INDB` | `INDB` | `INDUSIND` | `INDUSIND` |
| Federal Bank | `FDRL` | `FDRL` | `FEDERAL` | `FEDERAL` |
| IDBI Bank | `IBKL` | `IBKL` | `IDBI` | `IDBI` |
| Canara Bank | `CNRB` | `CNRB` | `CANARA` | `CANARA` |

**Note**: Bank codes are connector-specific. Always refer to the connector's API documentation for the exact bank code mapping required.

---

## Pattern Categories

### 1. Standard JSON Redirect Pattern

**Applies to**: Razorpay, Cashfree

**Characteristics**:
- Request Format: JSON
- Response Type: Async with redirect URL
- Amount Unit: MinorUnit
- Single-phase: Direct payment creation returns redirect URL
- Content-Type: `application/json`

#### Implementation Template

```rust
#[derive(Debug, Serialize)]
pub struct NetbankingPaymentRequest {
    pub amount: MinorUnit,
    pub currency: String,
    pub method: String,                    // "netbanking"
    pub bank: String,                       // Bank code from NetbankingData
    pub callback_url: String,               // Return URL after bank auth
    pub order_id: String,                   // Reference ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<Email>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<HashMap<String, String>>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        &ConnectorRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for NetbankingPaymentRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &ConnectorRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let nb_data = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Netbanking(nb) => nb,
            _ => {
                return Err(ConnectorError::MissingRequiredField {
                    field_name: "netbanking payment_method_data",
                }
                .into())
            }
        };

        Ok(Self {
            amount: item.amount,
            currency: item.router_data.request.currency.to_string(),
            method: "netbanking".to_string(),
            bank: nb_data.bank_code.clone(),
            callback_url: item.router_data.request.get_router_return_url()?,
            order_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            email: item
                .router_data
                .resource_common_data
                .get_billing_email()
                .ok(),
            contact: item
                .router_data
                .resource_common_data
                .get_billing_phone_number()
                .ok(),
            description: None,
            notes: None,
        })
    }
}
```

#### Connector Example: Razorpay

```rust
// From crates/integrations/connector-integration/src/connectors/razorpay/transformers.rs

#[derive(Debug, Serialize)]
pub struct RazorpayNetbankingRequest {
    pub amount: MinorUnit,
    pub currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<Email>,
    pub order_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Secret<String>>,
    pub method: String,           // Always "netbanking"
    pub bank: String,             // Bank code e.g., "SBIN", "HDFC"
    pub callback_url: String,
    pub ip: Secret<String>,
    pub referer: String,
    pub user_agent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<HashMap<String, String>>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        &RazorpayRouterData<
            &RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RazorpayNetbankingRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RazorpayRouterData<
            &RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let nb_data = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Netbanking(nb) => nb,
            _ => {
                return Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "netbanking payment_method_data",
                }
                .into())
            }
        };

        let order_id = item
            .router_data
            .resource_common_data
            .reference_id
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "order_id (reference_id)",
            })?
            .clone();

        let metadata_map = item
            .router_data
            .request
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.peek().as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), json_value_to_string(v)))
                    .collect::<HashMap<String, String>>()
            });

        Ok(Self {
            currency: item.router_data.request.currency.to_string(),
            amount: item.amount,
            email: item
                .router_data
                .resource_common_data
                .get_billing_email()
                .ok(),
            order_id: order_id.to_string(),
            contact: item
                .router_data
                .resource_common_data
                .get_billing_phone_number()
                .ok(),
            method: "netbanking".to_string(),
            bank: nb_data.bank_code.clone(),
            callback_url: item.router_data.request.get_router_return_url()?,
            ip: item
                .router_data
                .request
                .get_ip_address_as_optional()
                .map(|ip| Secret::new(ip.expose()))
                .unwrap_or_else(|| Secret::new("127.0.0.1".to_string())),
            referer: item
                .router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|info| info.get_referer().ok())
                .unwrap_or_else(|| "https://example.com".to_string()),
            user_agent: item
                .router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|info| info.get_user_agent().ok())
                .unwrap_or_else(|| "Mozilla/5.0".to_string()),
            description: None,
            notes: metadata_map,
        })
    }
}
```

---

### 2. Form-Encoded Pattern

**Applies to**: Legacy payment gateways, some Indian connectors

**Characteristics**:
- Request Format: `application/x-www-form-urlencoded`
- Response Type: Redirect (HTML form POST)
- Amount Unit: MinorUnit or StringMinorUnit
- May require checksum/signature generation

#### Implementation Template

```rust
#[derive(Debug, Serialize)]
pub struct FormEncodedNetbankingRequest {
    #[serde(rename = "MID")]
    pub merchant_id: Secret<String>,
    #[serde(rename = "ORDER_ID")]
    pub order_id: String,
    #[serde(rename = "CUST_ID")]
    pub customer_id: String,
    #[serde(rename = "TXN_AMOUNT")]
    pub amount: String,                    // Amount as string
    #[serde(rename = "CHANNEL_ID")]
    pub channel_id: String,                // "NET" for net banking
    #[serde(rename = "PAYMENT_MODE_ONLY")]
    pub payment_mode: String,              // "NB" for net banking
    #[serde(rename = "BANK_CODE")]
    pub bank_code: String,                 // Bank code from NetbankingData
    #[serde(rename = "CALLBACK_URL")]
    pub callback_url: String,
    #[serde(rename = "CHECKSUMHASH")]
    pub checksum: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        &ConnectorRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for FormEncodedNetbankingRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &ConnectorRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let nb_data = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Netbanking(nb) => nb,
            _ => {
                return Err(ConnectorError::NotImplemented(
                    get_unimplemented_payment_method_error_message("connector_name"),
                )
                .into())
            }
        };

        let auth = ConnectorAuth::try_from(&item.router_data.connector_auth_type)?;

        Ok(Self {
            merchant_id: auth.merchant_id,
            order_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            customer_id: item
                .router_data
                .resource_common_data
                .get_customer_id()?
                .to_string(),
            amount: item.amount.to_string(),
            channel_id: "NET".to_string(),
            payment_mode: "NB".to_string(),
            bank_code: nb_data.bank_code.clone(),
            callback_url: item.router_data.request.get_router_return_url()?,
            checksum: String::new(), // Computed after struct creation
        })
    }
}
```

---

### 3. Encrypted Payload Pattern

**Applies to**: PhonePe, connectors requiring signed/encrypted payloads

**Characteristics**:
- Request body is Base64-encoded JSON
- Includes HMAC-SHA256 signature/checksum
- Response: Async with redirect deep links
- Amount Unit: MinorUnit

#### Implementation Template

```rust
#[derive(Debug, Serialize)]
pub struct EncryptedNetbankingRequest {
    pub request: String,                   // Base64-encoded JSON payload
    pub checksum: String,                  // HMAC-SHA256 checksum
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetbankingPayload {
    pub merchant_id: Secret<String>,
    pub merchant_transaction_id: String,
    pub amount: MinorUnit,
    pub merchant_redirect_url: String,
    pub payment_instrument: NetbankingInstrument,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetbankingInstrument {
    #[serde(rename = "type")]
    pub instrument_type: String,           // "NET_BANKING"
    pub bank_id: String,                   // Connector-specific bank code
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        &ConnectorRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for EncryptedNetbankingRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &ConnectorRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let nb_data = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Netbanking(nb) => nb,
            _ => {
                return Err(ConnectorError::NotImplemented(
                    get_unimplemented_payment_method_error_message("connector_name"),
                )
                .into())
            }
        };

        let auth = ConnectorAuth::try_from(&item.router_data.connector_auth_type)?;

        let payload = NetbankingPayload {
            merchant_id: auth.merchant_id,
            merchant_transaction_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount: item.amount,
            merchant_redirect_url: item.router_data.request.get_router_return_url()?,
            payment_instrument: NetbankingInstrument {
                instrument_type: "NET_BANKING".to_string(),
                bank_id: map_bank_code_to_connector(&nb_data.bank_code)?,
            },
        };

        let payload_json = serde_json::to_string(&payload)
            .change_context(ConnectorError::RequestEncodingFailed)?;
        let encoded = BASE64_ENGINE.encode(payload_json.as_bytes());

        let checksum = compute_hmac_sha256(&encoded, &auth.api_key)?;

        Ok(Self {
            request: encoded,
            checksum,
        })
    }
}

/// Map generic bank codes to connector-specific codes
fn map_bank_code_to_connector(bank_code: &str) -> Result<String, ConnectorError> {
    match bank_code {
        "SBIN" => Ok("SBI".to_string()),
        "HDFC" => Ok("HDFC".to_string()),
        "ICIC" => Ok("ICICI".to_string()),
        "UTIB" => Ok("AXIS".to_string()),
        // ... more mappings
        _ => Ok(bank_code.to_string()), // Pass through unknown codes
    }
}
```

---

## Request Patterns

### Extracting NetbankingData

The core pattern for extracting net banking data from the payment method:

```rust
// Standard extraction pattern
let nb_data = match &item.router_data.request.payment_method_data {
    PaymentMethodData::Netbanking(nb) => nb,
    _ => {
        return Err(ConnectorError::MissingRequiredField {
            field_name: "netbanking payment_method_data",
        }
        .into())
    }
};

// Access fields
let bank_code: &String = &nb_data.bank_code;
let bank_name: &Option<String> = &nb_data.bank_name;
```

### Bank Code Mapping

Most connectors require mapping from the standard bank code to their internal code:

```rust
// Connector-specific bank code mapping
fn map_to_connector_bank_code(bank_code: &str) -> Result<String, ConnectorError> {
    match bank_code {
        "SBIN" | "SBI" => Ok("STATE_BANK_OF_INDIA".to_string()),
        "HDFC" => Ok("HDFC_BANK".to_string()),
        "ICIC" | "ICICI" => Ok("ICICI_BANK".to_string()),
        "UTIB" | "AXIS" => Ok("AXIS_BANK".to_string()),
        "KKBK" | "KOTAK" => Ok("KOTAK_MAHINDRA_BANK".to_string()),
        "PUNB" | "PNB" => Ok("PUNJAB_NATIONAL_BANK".to_string()),
        "BARB" | "BOB" => Ok("BANK_OF_BARODA".to_string()),
        "YESB" | "YES" => Ok("YES_BANK".to_string()),
        "UBIN" | "UNION" => Ok("UNION_BANK".to_string()),
        "INDB" | "INDUSIND" => Ok("INDUSIND_BANK".to_string()),
        "FDRL" | "FEDERAL" => Ok("FEDERAL_BANK".to_string()),
        "IBKL" | "IDBI" => Ok("IDBI_BANK".to_string()),
        "CNRB" | "CANARA" => Ok("CANARA_BANK".to_string()),
        _ => Err(ConnectorError::NotSupported {
            message: format!("Bank code '{}' is not supported", bank_code),
            connector: "connector_name",
            payment_experience: "net_banking",
        }),
    }
}
```

### Browser Info for Redirect Flows

Net banking flows often require browser information for redirect handling:

```rust
// Extract browser info for redirect
let ip = item
    .router_data
    .request
    .get_ip_address_as_optional()
    .map(|ip| Secret::new(ip.expose()))
    .unwrap_or_else(|| Secret::new("127.0.0.1".to_string()));

let referer = item
    .router_data
    .request
    .browser_info
    .as_ref()
    .and_then(|info| info.get_referer().ok())
    .unwrap_or_else(|| "https://example.com".to_string());

let user_agent = item
    .router_data
    .request
    .browser_info
    .as_ref()
    .and_then(|info| info.get_user_agent().ok())
    .unwrap_or_else(|| "Mozilla/5.0".to_string());
```

### Metadata Extraction

Pass-through metadata (notes/custom fields) for net banking:

```rust
let metadata_map = item
    .router_data
    .request
    .metadata
    .as_ref()
    .and_then(|metadata| metadata.peek().as_object())
    .map(|obj| {
        obj.iter()
            .map(|(k, v)| (k.clone(), json_value_to_string(v)))
            .collect::<HashMap<String, String>>()
    });
```

---

## Response Patterns

### Pattern 1: Redirect Response

Net banking payments always return a redirect URL for the customer to authenticate at their bank.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetbankingPaymentResponse {
    pub id: String,
    pub status: NetbankingPaymentStatus,
    pub bank: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetbankingPaymentStatus {
    Created,
    Authorized,
    Captured,
    Failed,
    Refunded,
}

impl<F, T> TryFrom<ResponseRouterData<NetbankingPaymentResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<NetbankingPaymentResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.status {
            NetbankingPaymentStatus::Created => AttemptStatus::AuthenticationPending,
            NetbankingPaymentStatus::Authorized => AttemptStatus::Authorized,
            NetbankingPaymentStatus::Captured => AttemptStatus::Charged,
            NetbankingPaymentStatus::Failed => AttemptStatus::Failure,
            NetbankingPaymentStatus::Refunded => AttemptStatus::Charged,
        };

        let redirection_data = item.response.redirect_url.map(|url| {
            Box::new(RedirectForm::Form {
                endpoint: url.expose(),
                method: Method::Get,
                form_fields: std::collections::HashMap::new(),
            })
        });

        let payment_response_data = if is_payment_failure(status) {
            Err(ErrorResponse {
                code: item
                    .response
                    .error_code
                    .unwrap_or_else(|| "NETBANKING_FAILED".to_string()),
                message: item
                    .response
                    .error_description
                    .unwrap_or_else(|| "Net banking payment failed".to_string()),
                reason: None,
                status_code: item.http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(item.response.id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.id),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: payment_response_data,
            ..item.router_data
        })
    }
}
```

### Pattern 2: Async Status Mapping

Net banking payments typically go through multiple status transitions:

```rust
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetbankingTransactionStatus {
    Created,
    Pending,
    Authorized,
    Captured,
    Failed,
    Cancelled,
    Expired,
    Refunded,
    PartiallyRefunded,
}

fn get_attempt_status(
    status: NetbankingTransactionStatus,
    capture_method: Option<CaptureMethod>,
) -> AttemptStatus {
    match status {
        NetbankingTransactionStatus::Created => AttemptStatus::AuthenticationPending,
        NetbankingTransactionStatus::Pending => AttemptStatus::Pending,
        NetbankingTransactionStatus::Authorized => {
            match capture_method {
                Some(CaptureMethod::Automatic) | None => AttemptStatus::Charged,
                Some(CaptureMethod::Manual) => AttemptStatus::Authorized,
                _ => AttemptStatus::Pending,
            }
        }
        NetbankingTransactionStatus::Captured => AttemptStatus::Charged,
        NetbankingTransactionStatus::Failed => AttemptStatus::Failure,
        NetbankingTransactionStatus::Cancelled => AttemptStatus::Voided,
        NetbankingTransactionStatus::Expired => AttemptStatus::Failure,
        NetbankingTransactionStatus::Refunded
        | NetbankingTransactionStatus::PartiallyRefunded => AttemptStatus::Charged,
    }
}
```

### Pattern 3: Redirect Form Construction

For net banking, the response will contain a redirect URL to the bank's portal:

```rust
fn build_netbanking_redirect(
    redirect_url: String,
    transaction_id: &str,
) -> Result<PaymentsResponseData, Error> {
    let redirect_form = RedirectForm::Form {
        endpoint: redirect_url,
        method: Method::Get,
        form_fields: std::collections::HashMap::new(),
    };

    Ok(PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(transaction_id.to_string()),
        redirection_data: Some(Box::new(redirect_form)),
        mandate_reference: None,
        connector_metadata: None,
        network_txn_id: None,
        connector_response_reference_id: Some(transaction_id.to_string()),
        incremental_authorization_allowed: None,
        status_code: 200,
    })
}

// Some connectors return a POST redirect with form fields
fn build_netbanking_post_redirect(
    redirect_url: String,
    transaction_id: &str,
    payment_id: &str,
) -> Result<PaymentsResponseData, Error> {
    let mut form_fields = std::collections::HashMap::new();
    form_fields.insert("paymentId".to_string(), payment_id.to_string());

    let redirect_form = RedirectForm::Form {
        endpoint: redirect_url,
        method: Method::Post,
        form_fields,
    };

    Ok(PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(transaction_id.to_string()),
        redirection_data: Some(Box::new(redirect_form)),
        mandate_reference: None,
        connector_metadata: None,
        network_txn_id: None,
        connector_response_reference_id: Some(transaction_id.to_string()),
        incremental_authorization_allowed: None,
        status_code: 200,
    })
}
```

---

## Implementation Templates

### Complete Macro-Based Implementation

```rust
use macros;

pub struct MyConnector<T: PaymentMethodDataTypes> {
    _phantom: std::marker::PhantomData<T>,
}

macros::create_amount_converter_wrapper!(
    connector_name: MyConnector,
    amount_type: MinorUnit
);

macros::create_all_prerequisites!(
    connector_name: MyConnector,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: MyConnectorNetbankingRequest,
            response_body: MyConnectorNetbankingResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            response_body: MyConnectorSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: MyConnectorRefundRequest,
            response_body: MyConnectorRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            response_body: MyConnectorRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            Ok(vec![
                ("Content-Type".to_string(), "application/json".to_string().into()),
                ("Authorization".to_string(), self.get_auth_header(&req.connector_auth_type)?),
            ])
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.my_connector.base_url
        }
    }
);

impl<T: PaymentMethodDataTypes> ConnectorCommon for MyConnector<T> {
    fn id(&self) -> &'static str {
        "my_connector"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.my_connector.base_url.as_ref()
    }
}
```

### Manual Implementation (Non-Macro)

For connectors requiring custom net banking logic:

```rust
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for MyConnector<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let auth = ConnectorAuth::try_from(&req.connector_auth_type)?;
        Ok(vec![
            (
                "Content-Type".to_string(),
                "application/json".to_string().into(),
            ),
            (
                "Authorization".to_string(),
                format!("Bearer {}", auth.api_key.peek()).into_masked(),
            ),
        ])
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!(
            "{}/v1/payments/netbanking",
            self.base_url(&req.resource_common_data.connectors)
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let connector_router_data = ConnectorRouterData::from((self.amount_converter(), req));
        let request = MyConnectorNetbankingRequest::try_from(&connector_router_data)?;
        Ok(RequestContent::Json(Box::new(request)))
    }

    fn handle_response(
        &self,
        data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ConnectorError,
    > {
        let response: MyConnectorNetbankingResponse = res
            .response
            .parse_struct("MyConnectorNetbankingResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}
```

---

## Common Pitfalls

### 1. Missing Bank Code Mapping

**Problem**: Passing the raw bank code without mapping to connector-specific codes.

**Solution**: Always implement a bank code mapping function:
```rust
// WRONG: Passing bank code directly
bank: nb_data.bank_code.clone(),

// CORRECT: Map to connector-specific code
bank: map_to_connector_bank_code(&nb_data.bank_code)?,
```

**Note**: Some connectors (like Razorpay) accept standard IFSC-style bank codes directly. Always check the connector's API documentation.

### 2. Missing Callback/Return URL

**Problem**: Not providing a return URL for the redirect flow.

**Solution**: Always extract and validate the return URL:
```rust
let callback_url = item.router_data.request.get_router_return_url()?;

// For connectors requiring separate success/failure URLs:
let return_urls = ReturnUrls {
    success: item.router_data.request.router_return_url.clone(),
    failure: item.router_data.request.router_return_url.clone(),
    cancel: item.router_data.request.router_return_url.clone(),
};
```

### 3. Incorrect Status Handling

**Problem**: Treating net banking responses as synchronous when they are async.

**Solution**: Always set `AuthenticationPending` status when returning a redirect:
```rust
// WRONG: Setting status as Charged immediately
let status = AttemptStatus::Charged;

// CORRECT: Set AuthenticationPending for redirect flows
let status = if redirect_url.is_some() {
    AttemptStatus::AuthenticationPending
} else {
    map_connector_status(&response.status)
};
```

### 4. Currency Mismatch

**Problem**: Net banking in India only supports INR, but not validating currency.

**Solution**: Validate currency for India-only connectors:
```rust
let currency = item.router_data.request.currency;
if currency != Currency::INR {
    return Err(ConnectorError::CurrencyNotSupported {
        message: format!("Net banking only supports INR, got {}", currency),
        connector: "connector_name",
    }
    .into());
}
```

### 5. Missing Browser Info Defaults

**Problem**: Browser info fields (IP, user agent, referer) may not always be present.

**Solution**: Always provide fallback defaults:
```rust
let ip = item
    .router_data
    .request
    .get_ip_address_as_optional()
    .map(|ip| Secret::new(ip.expose()))
    .unwrap_or_else(|| Secret::new("127.0.0.1".to_string()));

let user_agent = item
    .router_data
    .request
    .browser_info
    .as_ref()
    .and_then(|info| info.get_user_agent().ok())
    .unwrap_or_else(|| "Mozilla/5.0".to_string());
```

### 6. Order ID vs Reference ID Confusion

**Problem**: Using wrong reference field for the order ID.

**Solution**: Check connector requirements - some need `reference_id`, others need `connector_request_reference_id`:
```rust
// For connectors that create orders first (e.g., Razorpay)
let order_id = item
    .router_data
    .resource_common_data
    .reference_id
    .as_ref()
    .ok_or(ConnectorError::MissingRequiredField {
        field_name: "order_id (reference_id)",
    })?
    .clone();

// For connectors that use request reference ID
let reference_id = item
    .router_data
    .resource_common_data
    .connector_request_reference_id
    .clone();
```

---

## Testing Patterns

### Unit Test Template

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netbanking_request_transformation() {
        let nb_data = NetbankingData {
            bank_code: "SBIN".to_string(),
            bank_name: Some("State Bank of India".to_string()),
        };

        let router_data = create_test_router_data_with_payment_method(
            PaymentMethodData::Netbanking(nb_data),
        );

        let request = MyConnectorNetbankingRequest::try_from(&router_data);
        assert!(request.is_ok());

        let req = request.unwrap();
        assert_eq!(req.bank, "SBIN");
        assert_eq!(req.method, "netbanking");
        assert_eq!(req.currency, "INR");
    }

    #[test]
    fn test_bank_code_mapping() {
        assert_eq!(
            map_to_connector_bank_code("SBIN").unwrap(),
            "STATE_BANK_OF_INDIA"
        );
        assert_eq!(
            map_to_connector_bank_code("HDFC").unwrap(),
            "HDFC_BANK"
        );
        assert_eq!(
            map_to_connector_bank_code("ICIC").unwrap(),
            "ICICI_BANK"
        );
    }

    #[test]
    fn test_unsupported_payment_method_returns_error() {
        let card_data = PaymentMethodData::Card(create_test_card());
        let router_data = create_test_router_data_with_payment_method(card_data);

        let request = MyConnectorNetbankingRequest::try_from(&router_data);
        assert!(request.is_err());
    }

    #[test]
    fn test_netbanking_status_mapping() {
        assert_eq!(
            get_attempt_status(
                NetbankingTransactionStatus::Created,
                Some(CaptureMethod::Automatic)
            ),
            AttemptStatus::AuthenticationPending
        );
        assert_eq!(
            get_attempt_status(
                NetbankingTransactionStatus::Captured,
                Some(CaptureMethod::Automatic)
            ),
            AttemptStatus::Charged
        );
        assert_eq!(
            get_attempt_status(
                NetbankingTransactionStatus::Failed,
                Some(CaptureMethod::Automatic)
            ),
            AttemptStatus::Failure
        );
    }

    #[test]
    fn test_redirect_response_construction() {
        let response = NetbankingPaymentResponse {
            id: "pay_123456".to_string(),
            status: NetbankingPaymentStatus::Created,
            bank: Some("SBIN".to_string()),
            redirect_url: Some(Secret::new("https://bank.example.com/auth".to_string())),
            error_code: None,
            error_description: None,
        };

        let router_data = create_test_router_data();
        let result = RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data,
            http_code: 200,
        });

        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(
            data.resource_common_data.status,
            AttemptStatus::AuthenticationPending
        );
        assert!(data.response.unwrap().redirection_data.is_some());
    }
}
```

### Integration Test Scenarios

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| **Successful Payment** | Valid bank code, sufficient balance | `AttemptStatus::Charged` (via webhook) |
| **Bank Authentication** | Valid bank code | `AttemptStatus::AuthenticationPending` + redirect URL |
| **Invalid Bank Code** | Unsupported bank code | `ConnectorError::NotSupported` |
| **Cancelled by User** | User cancels at bank page | `AttemptStatus::Failure` (via webhook) |
| **Bank Timeout** | Session expires at bank | `AttemptStatus::Failure` (via webhook) |
| **Insufficient Funds** | Valid bank, low balance | `AttemptStatus::Failure` (via webhook) |
| **Currency Validation** | Non-INR currency | `ConnectorError::CurrencyNotSupported` |
| **Missing Callback URL** | No return URL provided | `ConnectorError::MissingRequiredField` |
| **PSync After Redirect** | Check status after redirect | Updated `AttemptStatus` |
| **Refund** | Successful netbanking payment | `AttemptStatus::Charged` with refund |

---

## Implementation Checklist

When implementing Net Banking payments for a new connector:

### Pre-Implementation
- [ ] Verify connector supports net banking in their API documentation
- [ ] Identify supported Indian banks and their connector-specific codes
- [ ] Determine request format (JSON, Form-Encoded, Encrypted)
- [ ] Determine amount unit (MinorUnit, StringMinorUnit, FloatMajorUnit)
- [ ] Check if connector requires order creation before payment
- [ ] Check authentication method (API Key, Basic Auth, HMAC, OAuth)

### Implementation
- [ ] Extract `NetbankingData` from `PaymentMethodData::Netbanking`
- [ ] Implement bank code mapping (if connector uses different codes)
- [ ] Build request struct with required fields (amount, currency, bank, callback_url)
- [ ] Include browser info (IP, user agent, referer) if required
- [ ] Handle redirect URL in response
- [ ] Set status to `AuthenticationPending` for redirect flows
- [ ] Implement status mapping for all connector statuses
- [ ] Implement error response handling
- [ ] Handle webhook for final payment status
- [ ] Implement PSync for status polling

### Testing
- [ ] Unit tests for request transformation
- [ ] Unit tests for bank code mapping
- [ ] Unit tests for response/status mapping
- [ ] Unit tests for error handling
- [ ] Test unsupported payment method returns proper error
- [ ] Integration tests with sandbox credentials
- [ ] Test redirect flow end-to-end
- [ ] Test webhook status updates
- [ ] Test PSync after redirect

### Validation
- [ ] Bank code mapping covers all supported banks
- [ ] Return URL is always present in redirect responses
- [ ] Currency validation (INR-only for Indian connectors)
- [ ] Amount unit conversion is correct
- [ ] Error messages are descriptive for unsupported banks
- [ ] Sensitive data (bank credentials) never logged or exposed

---

## Cross-References

- [pattern_authorize.md](../../pattern_authorize.md) - General authorize flow patterns
- [pattern_authorize_bank_redirect.md](../bank_redirect/pattern_authorize_bank_redirect.md) - Related bank redirect patterns
- [pattern_authorize_upi.md](../upi/pattern_authorize_upi.md) - Related UPI patterns (also India-focused)
- [pattern_psync.md](../../pattern_psync.md) - Payment sync for async net banking status
- [pattern_refund.md](../../pattern_refund.md) - Refund implementation patterns
- [pattern_IncomingWebhook_flow.md](../../pattern_IncomingWebhook_flow.md) - Webhook handling for async status updates
- [payment_method_data.rs](../../../../../crates/types-traits/domain_types/src/payment_method_data.rs) - NetbankingData struct definition

---

**Document Version**: 1.0
**Last Updated**: 2026-03-26
**Maintained By**: Grace-UCS Connector Team
