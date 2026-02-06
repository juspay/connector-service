# BankRedirect Authorize Flow Pattern for Connector Implementation

**🎯 GENERIC PATTERN FILE FOR ANY NEW CONNECTOR**

This document provides comprehensive, reusable patterns for implementing BankRedirect payment flows in **ANY** payment connector. These patterns are extracted from successful connector implementations (Stripe, Trustpay, Volt, Nexinets, Multisafepay) and can be consumed by AI to generate consistent, production-ready BankRedirect authorize flow code for any payment gateway that supports bank redirect payment methods.

## 🚀 Quick Start Guide

To implement BankRedirect flows for a new connector:

1. **Identify Supported Types**: Determine which bank redirect types your connector supports (iDEAL, Giropay, EPS, Sofort, Bancontact, etc.)
2. **Choose Pattern**: Use [Modern Pattern](#modern-bankredirect-pattern-recommended) for JSON APIs or [Form-Encoded Pattern](#form-encoded-pattern) for form-based APIs
3. **Configure Callbacks**: Set up callback URL structures for redirect flow
4. **Map Payment Methods**: Create transformations from router's `BankRedirectData` to connector-specific format
5. **Handle Responses**: Implement redirect response handling with proper status mapping
6. **⚠️ Avoid Critical Pitfalls**: Read [Critical Pitfalls](#critical-pitfalls-to-avoid) to prevent common failures

### Example: Implementing BankRedirect for "NewBank" Connector

```bash
# Connector supports: iDEAL, Giropay, Sofort
# API format: JSON
# Callback pattern: Success/Cancel/Error URLs

{ConnectorName} → NewBank
{connector_name} → new_bank
BankRedirect types: Ideal, Giropay, Sofort
Callback URLs: 3 separate (success, cancel, error)
Bank selection: Required for iDEAL, optional for others
```

**✅ Result**: Production-ready BankRedirect implementation in ~45 minutes

## Table of Contents

1. [Overview](#overview)
2. [BankRedirect Payment Method Types](#bankredirect-payment-method-types)
3. [Modern BankRedirect Pattern (Recommended)](#modern-bankredirect-pattern-recommended)
4. [Form-Encoded Pattern](#form-encoded-pattern)
5. [Callback URL Patterns](#callback-url-patterns)
6. [Bank Selection Patterns](#bank-selection-patterns)
7. [Request Transformation Patterns](#request-transformation-patterns)
8. [Response Handling Patterns](#response-handling-patterns)
9. [Status Mapping Patterns](#status-mapping-patterns)
10. [Common Helper Functions](#common-helper-functions)
11. [Critical Pitfalls to Avoid](#critical-pitfalls-to-avoid)
12. [Integration Checklist](#integration-checklist)
13. [Real-World Examples](#real-world-examples)

## Overview

BankRedirect flows enable customers to pay using their online banking systems through redirect-based authentication. The flow typically involves:

1. **Request Creation**: Build connector-specific request with bank redirect details
2. **User Redirection**: Redirect user to their bank's authentication page
3. **Authentication**: User authenticates and approves payment at their bank
4. **Callback**: Bank redirects user back to merchant with payment result
5. **Status Sync**: Verify payment status via sync call or webhook

### Key Components:
- **Payment Method Mapping**: Transform router's `BankRedirectData` to connector format
- **Callback URLs**: Success, cancel, and error return URLs
- **Bank Selection**: Optional bank identifier for methods like iDEAL
- **Redirect Response**: Extract redirect URL from connector response
- **Status Tracking**: Map redirect statuses (typically `AuthenticationPending` initially)

### Common BankRedirect Types:
- **iDEAL** (Netherlands)
- **Giropay** (Germany)
- **EPS** (Austria)
- **Sofort/Klarna** (Europe)
- **Bancontact** (Belgium)
- **Przelewy24** (Poland)
- **BLIK** (Poland)
- **Trustly** (Europe)
- **OpenBanking UK** (United Kingdom)
- **Online Banking** (various countries)

## BankRedirect Payment Method Types

### Payment Method Data Structure

The router provides bank redirect data via the `BankRedirectData` enum:

```rust
pub enum BankRedirectData {
    BancontactCard {
        card_number: Option<CardNumber>,
        // ... other fields
    },
    Blik {
        blik_code: Option<String>,
    },
    Eps {
        bank_name: Option<BankNames>,
        billing_details: Option<BillingDetails>,
    },
    Giropay {
        billing_details: Option<BillingDetails>,
    },
    Ideal {
        bank_name: Option<BankNames>,
        billing_details: Option<BillingDetails>,
    },
    Interac {
        // ... fields
    },
    OnlineBankingCzechRepublic {
        issuer: OnlineBankingCzechRepublicBanks,
    },
    OnlineBankingFinland {
        // ... fields
    },
    OnlineBankingPoland {
        issuer: OnlineBankingPolandBanks,
    },
    OnlineBankingSlovakia {
        issuer: OnlineBankingSlovakiaBanks,
    },
    OnlineBankingFpx {
        issuer: OnlineBankingFpxBanks,
    },
    OnlineBankingThailand {
        issuer: OnlineBankingThailandBanks,
    },
    OpenBankingUk {
        issuer: Option<OpenBankingUkBanks>,
    },
    Przelewy24 {
        bank_name: Option<BankNames>,
        billing_details: Option<BillingDetails>,
    },
    Sofort {
        country: Option<Country>,
        billing_details: Option<BillingDetails>,
    },
    Trustly {
        country: Country,
    },
    // ... other variants
}
```

## Modern BankRedirect Pattern (Recommended)

This pattern is used for JSON-based APIs with modern redirect flow support.

### Connector File Pattern

```rust
// File: backend/connector-integration/src/connectors/{connector_name}.rs

pub mod transformers;

use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2,
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;
use transformers::{
    {ConnectorName}AuthorizeRequest, {ConnectorName}AuthorizeResponse,
    {ConnectorName}ErrorResponse,
};

use super::macros;
use crate::types::ResponseRouterData;

// Set up connector using macros
macros::create_all_prerequisites!(
    connector_name: {ConnectorName},
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: {ConnectorName}AuthorizeRequest<T>,
            response_body: {ConnectorName}AuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
    ],
    amount_converters: [
        amount_converter: MinorUnit  // or StringMinorUnit, StringMajorUnit
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                "Content-Type".to_string(),
                "application/json".to_string().into(),
            )];
            let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut auth_header);
            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.{connector_name}.base_url
        }
    }
);

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommon for {ConnectorName}<T>
{
    fn id(&self) -> &'static str {
        "{connector_name}"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn base_url<'a>(&self, connectors: &'a domain_types::types::Connectors) -> &'a str {
        &connectors.{connector_name}.base_url
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let auth = transformers::{ConnectorName}AuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        Ok(vec![(
            "Authorization".to_string(),
            format!("Bearer {}", auth.api_key.peek()).into_masked(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: {ConnectorName}ErrorResponse = if res.response.is_empty() {
            {ConnectorName}ErrorResponse::default()
        } else {
            res.response
                .parse_struct("ErrorResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?
        };

        if let Some(i) = event_builder {
            i.set_error_response_body(&response);
        }

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.unwrap_or_default(),
            message: response.error_message.unwrap_or_default(),
            reason: response.error_description,
            attempt_status: None,
            connector_transaction_id: response.transaction_id,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// Implement Authorize flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: {ConnectorName},
    curl_request: Json({ConnectorName}AuthorizeRequest),
    curl_response: {ConnectorName}AuthorizeResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{base_url}/payments"))
        }
    }
);
```

### Transformers File Pattern for BankRedirect

```rust
// File: backend/connector-integration/src/connectors/{connector_name}/transformers.rs

use std::collections::HashMap;
use common_utils::{ext_traits::OptionExt, pii, request::Method, types::MinorUnit};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::{
        BankRedirectData, PaymentMethodData, PaymentMethodDataTypes,
    },
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use hyperswitch_masking::{ExposeInterface, Secret, PeekInterface};
use serde::{Deserialize, Serialize};

// ===== AUTHENTICATION =====

#[derive(Debug)]
pub struct {ConnectorName}AuthType {
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for {ConnectorName}AuthType {
    type Error = ConnectorError;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType),
        }
    }
}

// ===== REQUEST STRUCTURES =====

#[derive(Debug, Serialize)]
pub struct {ConnectorName}AuthorizeRequest<
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
> {
    pub amount: MinorUnit,
    pub currency: String,
    pub payment_method: {ConnectorName}PaymentMethod,
    pub merchant_reference: String,
    pub customer: {ConnectorName}Customer,
    pub callback_urls: {ConnectorName}CallbackUrls,
}

#[derive(Debug, Serialize)]
pub struct {ConnectorName}Customer {
    pub email: Option<Email>,
    pub first_name: Option<Secret<String>>,
    pub last_name: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct {ConnectorName}CallbackUrls {
    pub success_url: String,
    pub cancel_url: Option<String>,
    pub error_url: Option<String>,
}

// Payment Method Structures
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum {ConnectorName}PaymentMethod {
    BankRedirect({ConnectorName}BankRedirect),
}

#[derive(Debug, Serialize)]
pub struct {ConnectorName}BankRedirect {
    pub bank_type: {ConnectorName}BankType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_code: Option<{ConnectorName}BankCode>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum {ConnectorName}BankType {
    Ideal,
    Giropay,
    Sofort,
    Eps,
    Bancontact,
    Przelewy24,
    Blik,
    Trustly,
    OpenBanking,
}

// Bank codes for methods that support bank selection
#[derive(Debug, Serialize)]
pub enum {ConnectorName}BankCode {
    // iDEAL banks
    #[serde(rename = "ABNANL2A")]
    AbnAmro,
    #[serde(rename = "INGBNL2A")]
    Ing,
    #[serde(rename = "RABONL2U")]
    Rabobank,
    // ... add other banks as needed
}

// ===== RESPONSE STRUCTURES =====

#[derive(Debug, Deserialize)]
pub struct {ConnectorName}AuthorizeResponse {
    pub id: String,
    pub status: {ConnectorName}PaymentStatus,
    #[serde(rename = "redirect_url")]
    pub redirect_url: Option<String>,
    pub amount: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum {ConnectorName}PaymentStatus {
    Pending,
    RequiresAction,
    Succeeded,
    Failed,
    Canceled,
}

#[derive(Debug, Deserialize)]
pub struct {ConnectorName}ErrorResponse {
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub error_description: Option<String>,
    pub transaction_id: Option<String>,
}

impl Default for {ConnectorName}ErrorResponse {
    fn default() -> Self {
        Self {
            error_code: Some("UNKNOWN_ERROR".to_string()),
            error_message: Some("Unknown error occurred".to_string()),
            error_description: None,
            transaction_id: None,
        }
    }
}

// ===== REQUEST TRANSFORMATION =====

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<{ConnectorName}RouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for {ConnectorName}AuthorizeRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: {ConnectorName}RouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Extract payment method
        let payment_method = match &router_data.request.payment_method_data {
            PaymentMethodData::BankRedirect(bank_redirect_data) => {
                {ConnectorName}PaymentMethod::BankRedirect(
                    {ConnectorName}BankRedirect::try_from(bank_redirect_data)?
                )
            },
            _ => return Err(ConnectorError::NotImplemented(
                "Payment method not supported".to_string()
            ).into()),
        };

        // Extract customer details
        let customer = {ConnectorName}Customer {
            email: router_data.request.email.clone(),
            first_name: router_data.resource_common_data.get_billing_first_name().ok(),
            last_name: router_data.resource_common_data.get_billing_last_name().ok(),
        };

        // Build callback URLs
        let return_url = router_data.request.get_router_return_url()?;
        let callback_urls = {ConnectorName}CallbackUrls {
            success_url: format!("{return_url}?status=success"),
            cancel_url: Some(format!("{return_url}?status=cancel")),
            error_url: Some(format!("{return_url}?status=error")),
        };

        Ok(Self {
            amount: item.amount,
            currency: router_data.request.currency.to_string(),
            payment_method,
            merchant_reference: router_data.resource_common_data.connector_request_reference_id.clone(),
            customer,
            callback_urls,
        })
    }
}

// ===== BANKREDIRECT DATA TRANSFORMATION =====

impl TryFrom<&BankRedirectData> for {ConnectorName}BankRedirect {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(bank_redirect: &BankRedirectData) -> Result<Self, Self::Error> {
        match bank_redirect {
            BankRedirectData::Ideal { bank_name, .. } => Ok(Self {
                bank_type: {ConnectorName}BankType::Ideal,
                bank_code: bank_name
                    .as_ref()
                    .map(|name| {ConnectorName}BankCode::try_from(name))
                    .transpose()?,
            }),
            BankRedirectData::Giropay { .. } => Ok(Self {
                bank_type: {ConnectorName}BankType::Giropay,
                bank_code: None,
            }),
            BankRedirectData::Sofort { .. } => Ok(Self {
                bank_type: {ConnectorName}BankType::Sofort,
                bank_code: None,
            }),
            BankRedirectData::Eps { bank_name, .. } => Ok(Self {
                bank_type: {ConnectorName}BankType::Eps,
                bank_code: bank_name
                    .as_ref()
                    .map(|name| {ConnectorName}BankCode::try_from(name))
                    .transpose()?,
            }),
            BankRedirectData::BancontactCard { .. } => Ok(Self {
                bank_type: {ConnectorName}BankType::Bancontact,
                bank_code: None,
            }),
            BankRedirectData::Przelewy24 { bank_name, .. } => Ok(Self {
                bank_type: {ConnectorName}BankType::Przelewy24,
                bank_code: bank_name
                    .as_ref()
                    .map(|name| {ConnectorName}BankCode::try_from(name))
                    .transpose()?,
            }),
            BankRedirectData::Blik { .. } => Ok(Self {
                bank_type: {ConnectorName}BankType::Blik,
                bank_code: None,
            }),
            BankRedirectData::Trustly { .. } => Ok(Self {
                bank_type: {ConnectorName}BankType::Trustly,
                bank_code: None,
            }),
            BankRedirectData::OpenBankingUk { .. } => Ok(Self {
                bank_type: {ConnectorName}BankType::OpenBanking,
                bank_code: None,
            }),
            _ => Err(ConnectorError::NotImplemented(
                format!("Bank redirect type not supported: {:?}", bank_redirect)
            ).into()),
        }
    }
}

// ===== RESPONSE TRANSFORMATION =====

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<{ConnectorName}AuthorizeResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<{ConnectorName}AuthorizeResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Map connector status to router status
        let status = match response.status {
            {ConnectorName}PaymentStatus::Succeeded => common_enums::AttemptStatus::Charged,
            {ConnectorName}PaymentStatus::Pending
            | {ConnectorName}PaymentStatus::RequiresAction => {
                common_enums::AttemptStatus::AuthenticationPending
            },
            {ConnectorName}PaymentStatus::Failed => common_enums::AttemptStatus::Failure,
            {ConnectorName}PaymentStatus::Canceled => common_enums::AttemptStatus::Voided,
        };

        // Build redirection data if redirect URL is present
        let redirection_data = response.redirect_url.as_ref().map(|url| {
            RedirectForm::Uri { uri: url.clone() }
        });

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
            redirection_data,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// Helper struct for router data transformation
pub struct {ConnectorName}RouterData<T, U> {
    pub amount: MinorUnit,
    pub router_data: T,
    pub connector: U,
}

impl<T, U> TryFrom<(MinorUnit, T, U)> for {ConnectorName}RouterData<T, U> {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from((amount, router_data, connector): (MinorUnit, T, U)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data,
            connector,
        })
    }
}
```

## Form-Encoded Pattern

This pattern is used for connectors that use form-urlencoded format (like Stripe).

### Key Differences from JSON Pattern

1. **Serialization Format**: Form-urlencoded with nested field notation
2. **Field Naming**: Uses `[bracket]` notation for nested fields
3. **Flattening**: Often uses `#[serde(flatten)]` for grouping

### Form-Encoded Request Structure

```rust
#[derive(Debug, Serialize)]
pub struct {ConnectorName}BankRedirectFormRequest<
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
> {
    #[serde(rename = "amount")]
    pub amount: StringMinorUnit,

    #[serde(rename = "currency")]
    pub currency: String,

    #[serde(rename = "payment_method_data[type]")]
    pub payment_method_type: {ConnectorName}PaymentMethodType,

    // Bank-specific fields
    #[serde(rename = "payment_method_data[ideal][bank]", skip_serializing_if = "Option::is_none")]
    pub ideal_bank: Option<{ConnectorName}BankNames>,

    #[serde(rename = "payment_method_data[przelewy24][bank]", skip_serializing_if = "Option::is_none")]
    pub p24_bank: Option<{ConnectorName}BankNames>,

    #[serde(rename = "payment_method_options[blik][code]", skip_serializing_if = "Option::is_none")]
    pub blik_code: Option<Secret<String>>,

    #[serde(rename = "return_url")]
    pub return_url: String,

    #[serde(flatten)]
    pub billing_details: {ConnectorName}BillingDetails,
}

#[derive(Debug, Serialize)]
pub struct {ConnectorName}BillingDetails {
    #[serde(rename = "billing_details[name]")]
    pub name: Option<Secret<String>>,

    #[serde(rename = "billing_details[email]")]
    pub email: Option<Email>,

    #[serde(rename = "billing_details[phone]")]
    pub phone: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub enum {ConnectorName}PaymentMethodType {
    #[serde(rename = "ideal")]
    Ideal,
    #[serde(rename = "giropay")]
    Giropay,
    #[serde(rename = "eps")]
    Eps,
    #[serde(rename = "sofort")]
    Sofort,
    #[serde(rename = "bancontact")]
    Bancontact,
    #[serde(rename = "p24")]
    Przelewy24,
    #[serde(rename = "blik")]
    Blik,
}
```

### Form-Encoded Transformation

```rust
impl<T> TryFrom<&BankRedirectData> for {ConnectorName}BankRedirectFormRequest<T> {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(bank_redirect: &BankRedirectData) -> Result<Self, Self::Error> {
        match bank_redirect {
            BankRedirectData::Ideal { bank_name, billing_details } => {
                let payment_method_type = {ConnectorName}PaymentMethodType::Ideal;
                let ideal_bank = bank_name
                    .as_ref()
                    .map(|name| {ConnectorName}BankNames::try_from(name))
                    .transpose()?;

                Ok(Self {
                    payment_method_type,
                    ideal_bank,
                    p24_bank: None,
                    blik_code: None,
                    // ... other fields
                })
            },
            BankRedirectData::Giropay { billing_details } => Ok(Self {
                payment_method_type: {ConnectorName}PaymentMethodType::Giropay,
                ideal_bank: None,
                p24_bank: None,
                blik_code: None,
                // ... other fields
            }),
            BankRedirectData::Blik { blik_code } => Ok(Self {
                payment_method_type: {ConnectorName}PaymentMethodType::Blik,
                ideal_bank: None,
                p24_bank: None,
                blik_code: blik_code.clone().map(Secret::new),
                // ... other fields
            }),
            // ... other variants
        }
    }
}
```

## Callback URL Patterns

### Pattern 1: Multiple Dedicated URLs (Comprehensive)

Used by: Volt, similar pattern in others

```rust
pub struct CallbackUrls {
    pub success_url: String,
    pub failure_url: String,
    pub pending_url: String,
    pub cancel_url: String,
}

// Implementation
let return_url = router_data.request.get_router_return_url()?;
let callback_urls = CallbackUrls {
    success_url: return_url.clone(),
    failure_url: return_url.clone(),
    pending_url: return_url.clone(),
    cancel_url: return_url,
};
```

**Characteristics:**
- Four separate URL fields
- All typically point to same base URL
- Bank/connector handles routing based on outcome

### Pattern 2: Status Query Parameters (Explicit)

Used by: Trustpay

```rust
pub struct CallbackUrls {
    pub success: String,
    pub cancel: String,
    pub error: String,
}

// Implementation
let return_url = router_data.request.get_router_return_url()?;
let callback_urls = CallbackUrls {
    success: format!("{return_url}?status=SuccessOk"),
    cancel: return_url.clone(),
    error: return_url,
};
```

**Characteristics:**
- Three URL fields (success, cancel, error)
- Success URL includes explicit status parameter
- Clear differentiation via query params

### Pattern 3: Success/Cancel/Failure (Standard)

Used by: Nexinets, many others

```rust
pub struct AsyncDetails {
    pub success_url: Option<String>,
    pub cancel_url: Option<String>,
    pub failure_url: Option<String>,
}

// Implementation
let return_url = router_data.request.get_router_return_url()?;
let async_details = AsyncDetails {
    success_url: Some(format!("{return_url}?status=success")),
    cancel_url: Some(format!("{return_url}?status=cancel")),
    failure_url: Some(format!("{return_url}?status=failure")),
};
```

**Characteristics:**
- Optional URLs
- Three states: success, cancel, failure
- Query parameters for differentiation

### Pattern 4: Single Return URL (Simple)

Used by: Stripe, some simpler APIs

```rust
pub struct RequestData {
    pub return_url: String,
    // ... other fields
}

// Implementation
let return_url = router_data.request.get_router_return_url()?;
```

**Characteristics:**
- Single URL for all outcomes
- Connector adds status information to redirect
- Simplest pattern

### Choosing the Right Pattern

| Pattern | Use When | Pros | Cons |
|---------|----------|------|------|
| Multiple Dedicated | Connector requires separate URLs | Clear separation, explicit handling | More configuration |
| Status Query Params | Need explicit status tracking | Easy debugging, clear intent | URL manipulation required |
| Success/Cancel/Failure | Standard three-state flow | Industry standard, flexible | Moderate complexity |
| Single Return URL | Connector handles routing | Simplest, least configuration | Less control over routing |

## Bank Selection Patterns

### Pattern 1: BIC/SWIFT Codes (International Standard)

Used by: Nexinets

```rust
pub enum {ConnectorName}BIC {
    #[serde(rename = "ABNANL2A")]
    AbnAmro,
    #[serde(rename = "INGBNL2A")]
    Ing,
    #[serde(rename = "RABONL2U")]
    Rabobank,
    #[serde(rename = "KNABNL2H")]
    Knab,
    #[serde(rename = "BUNQNL2A")]
    Bunq,
}

impl TryFrom<&BankNames> for {ConnectorName}BIC {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(bank_name: &BankNames) -> Result<Self, Self::Error> {
        match bank_name {
            BankNames::AbnAmro => Ok(Self::AbnAmro),
            BankNames::Ing => Ok(Self::Ing),
            BankNames::Rabobank => Ok(Self::Rabobank),
            _ => Err(ConnectorError::NotSupported {
                message: format!("Bank {} not supported", bank_name),
            }.into()),
        }
    }
}
```

**Characteristics:**
- Uses international BIC/SWIFT codes
- Standardized across banking systems
- Best for international connectors

### Pattern 2: Connector-Specific Bank Codes

Used by: Stripe, Multisafepay

```rust
pub enum {ConnectorName}BankNames {
    #[serde(rename = "abn_amro")]
    AbnAmro,
    #[serde(rename = "ing")]
    Ing,
    #[serde(rename = "rabobank")]
    Rabobank,
}

impl TryFrom<&BankNames> for {ConnectorName}BankNames {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(bank_name: &BankNames) -> Result<Self, Self::Error> {
        match bank_name {
            BankNames::AbnAmro => Ok(Self::AbnAmro),
            BankNames::Ing => Ok(Self::Ing),
            BankNames::Rabobank => Ok(Self::Rabobank),
            _ => Err(ConnectorError::NotSupported {
                message: format!("Bank {} not supported", bank_name),
            }.into()),
        }
    }
}
```

**Characteristics:**
- Connector-defined bank identifiers
- Requires mapping from router's BankNames
- Flexible for connector-specific needs

### Pattern 3: Optional Bank Selection

Used by: Most connectors for Giropay, EPS, Sofort

```rust
pub struct BankRedirectData {
    pub payment_type: PaymentType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank: Option<BankCode>,
}

// For methods without bank selection
BankRedirectData {
    payment_type: PaymentType::Giropay,
    bank: None,  // Bank selection happens on redirect page
}
```

**Characteristics:**
- Bank selection happens on connector's page
- Simpler integration
- Common for Giropay, EPS, Sofort

### Bank Selection by Payment Method

| Payment Method | Bank Selection | Pattern |
|----------------|----------------|---------|
| iDEAL | Required/Optional | BIC or custom codes |
| Giropay | Not required | Optional field, typically None |
| EPS | Optional | Bank codes for Austria |
| Sofort | Not required | Optional field |
| Bancontact | Not required | No selection |
| Przelewy24 | Optional | Polish bank codes |
| BLIK | Required (code) | 6-digit BLIK code |
| Trustly | Not required | No selection |

## Request Transformation Patterns

### Pattern 1: Match-Based Transformation

```rust
impl<T> TryFrom<&PaymentMethodData<T>> for {ConnectorName}PaymentMethod {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(pm_data: &PaymentMethodData<T>) -> Result<Self, Self::Error> {
        match pm_data {
            PaymentMethodData::BankRedirect(bank_redirect) => {
                match bank_redirect {
                    BankRedirectData::Ideal { bank_name, billing_details } => {
                        Ok(Self::Ideal {
                            bank: bank_name
                                .as_ref()
                                .map(|b| {ConnectorName}Bank::try_from(b))
                                .transpose()?,
                            customer: extract_customer_from_billing(billing_details)?,
                        })
                    },
                    BankRedirectData::Giropay { billing_details } => {
                        Ok(Self::Giropay {
                            customer: extract_customer_from_billing(billing_details)?,
                        })
                    },
                    BankRedirectData::Sofort { country, billing_details } => {
                        Ok(Self::Sofort {
                            country: country.clone().ok_or(
                                ConnectorError::MissingRequiredField {
                                    field_name: "country"
                                }
                            )?,
                            customer: extract_customer_from_billing(billing_details)?,
                        })
                    },
                    _ => Err(ConnectorError::NotImplemented(
                        "Bank redirect type not supported".into()
                    ).into()),
                }
            },
            _ => Err(ConnectorError::NotImplemented(
                "Payment method not supported".into()
            ).into()),
        }
    }
}
```

### Pattern 2: Helper Function-Based Transformation

```rust
// Used by Trustpay
fn get_bank_redirection_request_data<T>(
    item: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    bank_redirection_data: &BankRedirectData,
    params: MandatoryParams,
    amount: StringMajorUnit,
    auth: AuthType,
) -> Result<PaymentsRequest<T>, error_stack::Report<ConnectorError>> {
    let payment_method = PaymentMethod::try_from(bank_redirection_data)?;
    let return_url = item.request.get_router_return_url()?;

    let payment_request = PaymentsRequest::BankRedirectPaymentRequest(Box::new(
        PaymentRequestBankRedirect {
            payment_method,
            merchant_identification: MerchantIdentification {
                project_id: auth.project_id,
            },
            payment_information: PaymentInformation {
                amount: Amount {
                    amount,
                    currency: item.request.currency.to_string(),
                },
                references: References {
                    merchant_reference: item.resource_common_data.connector_request_reference_id.clone(),
                },
                debtor: get_debtor_info(item, payment_method, params)?,
            },
            callback_urls: CallbackUrls {
                success: format!("{return_url}?status=SuccessOk"),
                cancel: return_url.clone(),
                error: return_url,
            },
        }
    ));

    Ok(payment_request)
}
```

### Pattern 3: Product/Gateway-Based Transformation

```rust
// Used by Nexinets, Multisafepay
fn get_payment_details_and_product<T>(
    payment_method_data: &PaymentMethodData<T>,
) -> Result<(Option<PaymentDetails>, Product), ConnectorError> {
    match payment_method_data {
        PaymentMethodData::BankRedirect(bank_redirect) => match bank_redirect {
            BankRedirectData::Eps { .. } => Ok((
                None,  // No additional details needed
                Product::Eps
            )),
            BankRedirectData::Giropay { .. } => Ok((
                None,
                Product::Giropay
            )),
            BankRedirectData::Ideal { bank_name, .. } => Ok((
                Some(PaymentDetails::BankRedirects(Box::new(BankRedirectDetails {
                    bic: bank_name
                        .map(|name| BIC::try_from(&name))
                        .transpose()?,
                }))),
                Product::Ideal
            )),
            _ => Err(ConnectorError::NotImplemented(...)),
        },
    }
}
```

## Response Handling Patterns

### Pattern 1: Redirect URL Extraction

```rust
impl<T> TryFrom<ResponseRouterData<AuthorizeResponse, ...>> for RouterDataV2<...> {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: ResponseRouterData<AuthorizeResponse, ...>) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Map status - BankRedirect flows typically start as AuthenticationPending
        let status = match response.status {
            PaymentStatus::RequiresAction
            | PaymentStatus::Pending => common_enums::AttemptStatus::AuthenticationPending,
            PaymentStatus::Succeeded => common_enums::AttemptStatus::Charged,
            PaymentStatus::Failed => common_enums::AttemptStatus::Failure,
        };

        // Extract redirect URL and create redirect form
        let redirection_data = response.redirect_url.as_ref().map(|url| {
            // Simple URI redirect (most common)
            RedirectForm::Uri { uri: url.clone() }
        });

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
            redirection_data,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}
```

### Pattern 2: Form POST Redirect

Some connectors require form-based POST redirect:

```rust
// Extract form fields and endpoint from response
let redirection_data = if let (Some(form_url), Some(form_fields)) =
    (&response.form_url, &response.form_fields)
{
    Some(RedirectForm::Form {
        endpoint: form_url.clone(),
        method: Method::Post,
        form_fields: form_fields.clone(),
    })
} else {
    response.redirect_url.as_ref().map(|url| {
        RedirectForm::Uri { uri: url.clone() }
    })
};
```

### Pattern 3: HTML Redirect Content

Some connectors return HTML content:

```rust
let redirection_data = if let Some(html_content) = &response.html_redirect {
    Some(RedirectForm::Html { html_data: html_content.clone() })
} else {
    response.redirect_url.as_ref().map(|url| {
        RedirectForm::Uri { uri: url.clone() }
    })
};
```

## Status Mapping Patterns

### Pattern 1: BankRedirect Flow Status Mapping

```rust
fn map_bank_redirect_status(
    connector_status: &PaymentStatus,
    has_redirect_url: bool,
) -> common_enums::AttemptStatus {
    match connector_status {
        // Initial states - requires user action
        PaymentStatus::Pending
        | PaymentStatus::RequiresAction
        | PaymentStatus::AwaitingAuthentication
        | PaymentStatus::AuthenticationRedirected => {  // <-- Add this status
            if has_redirect_url {
                common_enums::AttemptStatus::AuthenticationPending
            } else {
                common_enums::AttemptStatus::Pending
            }
        },

        // Success states
        PaymentStatus::Completed
        | PaymentStatus::Settled
        | PaymentStatus::Succeeded => {
            common_enums::AttemptStatus::Charged
        },

        // Processing states
        PaymentStatus::Processing
        | PaymentStatus::DelayedAtBank => {
            common_enums::AttemptStatus::Pending
        },

        // Failure states
        PaymentStatus::Failed
        | PaymentStatus::Declined
        | PaymentStatus::RefusedByBank
        | PaymentStatus::RefusedByRisk => {
            common_enums::AttemptStatus::Failure
        },

        // Cancellation states
        PaymentStatus::Canceled
        | PaymentStatus::CanceledByUser
        | PaymentStatus::AbandonedByUser => {
            common_enums::AttemptStatus::Voided
        },

        // Unknown - maintain current
        PaymentStatus::Unknown => {
            common_enums::AttemptStatus::Pending
        },
    }
}
```

### Pattern 2: Status as Part of Enum (Volt Pattern)

```rust
fn get_attempt_status(
    (connector_status, current_status): (VoltPaymentStatus, AttemptStatus)
) -> AttemptStatus {
    match connector_status {
        VoltPaymentStatus::Received
        | VoltPaymentStatus::Settled => AttemptStatus::Charged,

        VoltPaymentStatus::Completed
        | VoltPaymentStatus::DelayedAtBank => AttemptStatus::Pending,

        VoltPaymentStatus::NewPayment
        | VoltPaymentStatus::BankRedirect  // <-- BankRedirect as status
        | VoltPaymentStatus::AwaitingCheckoutAuthorisation => {
            AttemptStatus::AuthenticationPending
        },

        VoltPaymentStatus::RefusedByBank
        | VoltPaymentStatus::RefusedByRisk
        | VoltPaymentStatus::NotReceived
        | VoltPaymentStatus::ErrorAtBank
        | VoltPaymentStatus::CancelledByUser
        | VoltPaymentStatus::AbandonedByUser
        | VoltPaymentStatus::Failed => AttemptStatus::Failure,

        VoltPaymentStatus::Unknown => current_status,
    }
}
```

### Common Status Mappings

| Connector Status | Router AttemptStatus | Notes |
|------------------|---------------------|-------|
| Pending/RequiresAction | AuthenticationPending | When redirect URL present |
| AwaitingAuthentication | AuthenticationPending | User needs to authenticate |
| **AUTHENTICATION_REDIRECTED** | AuthenticationPending | **Important: Handle this status explicitly** |
| Processing | Pending | Payment being processed |
| Completed/Succeeded | Charged | Payment successful |
| Failed/Declined | Failure | Payment failed |
| Canceled/Voided | Voided | User or system canceled |
| RefusedByBank | Failure | Bank declined |
| Unknown | Pending (or current) | Maintain current status |

## Common Helper Functions

### 1. Customer Information Extraction

```rust
pub fn extract_customer_info<F, Req, Res>(
    router_data: &RouterDataV2<F, PaymentFlowData, Req, Res>,
) -> Result<CustomerInfo, ConnectorError> {
    Ok(CustomerInfo {
        email: router_data.request.email.clone(),
        first_name: router_data
            .resource_common_data
            .get_billing_first_name()
            .ok(),
        last_name: router_data
            .resource_common_data
            .get_billing_last_name()
            .ok(),
        phone: router_data
            .resource_common_data
            .address
            .get_payment_billing()
            .and_then(|billing| billing.phone.as_ref())
            .and_then(|phone| phone.number.clone()),
    })
}
```

### 2. Callback URL Builder

```rust
pub fn build_callback_urls(
    return_url: String,
    pattern: CallbackPattern,
) -> CallbackUrls {
    match pattern {
        CallbackPattern::StatusQueryParams => CallbackUrls {
            success: format!("{return_url}?status=success"),
            cancel: format!("{return_url}?status=cancel"),
            error: format!("{return_url}?status=error"),
        },
        CallbackPattern::Simple => CallbackUrls {
            success: return_url.clone(),
            cancel: return_url.clone(),
            error: return_url,
        },
    }
}
```

### 3. Bank Code Mapper

```rust
pub fn map_bank_name_to_code(
    bank_name: &BankNames,
    supported_banks: &[BankNames],
) -> Result<String, ConnectorError> {
    if !supported_banks.contains(bank_name) {
        return Err(ConnectorError::NotSupported {
            message: format!("Bank {} not supported by connector", bank_name),
        });
    }

    // Map to connector-specific code
    let bank_code = match bank_name {
        BankNames::AbnAmro => "ABNANL2A",
        BankNames::Ing => "INGBNL2A",
        BankNames::Rabobank => "RABONL2U",
        // ... other mappings
        _ => return Err(ConnectorError::NotSupported {
            message: format!("Bank mapping not found for {}", bank_name),
        }),
    };

    Ok(bank_code.to_string())
}
```

### 4. Redirect Form Builder

```rust
pub fn build_redirect_form(
    redirect_url: Option<String>,
    form_url: Option<String>,
    form_fields: Option<HashMap<String, String>>,
    html_content: Option<String>,
) -> Option<RedirectForm> {
    // Priority: HTML > Form POST > URI
    if let Some(html) = html_content {
        return Some(RedirectForm::Html { html_data: html });
    }

    if let (Some(endpoint), Some(fields)) = (form_url, form_fields) {
        return Some(RedirectForm::Form {
            endpoint,
            method: Method::Post,
            form_fields: fields,
        });
    }

    redirect_url.map(|uri| RedirectForm::Uri { uri })
}
```

### 5. Billing Details Extractor

```rust
pub fn extract_billing_details<F, Req, Res>(
    router_data: &RouterDataV2<F, PaymentFlowData, Req, Res>,
) -> Option<BillingDetails> {
    router_data
        .resource_common_data
        .address
        .get_payment_billing()
        .map(|billing| BillingDetails {
            name: router_data.request.customer_name.clone(),
            email: router_data.request.email.clone(),
            phone: billing.phone.as_ref().and_then(|p| p.number.clone()),
            address_line1: billing.line1.clone(),
            address_line2: billing.line2.clone(),
            city: billing.city.clone(),
            state: billing.state.clone(),
            zip: billing.zip.clone(),
            country: billing.country,
        })
}
```

## Critical Pitfalls to Avoid

This section highlights the most common issues that cause payment method failures and connector errors. These are learned from real production issues across multiple connectors.

### 🚨 BankRedirect Critical Issues

#### 1. **Missing BankRedirect Handler in Payment Request**
**Issue:** "Payment Method is not supported by {Connector}" error
**Root Cause:** Forgetting to add BankRedirect match arm in payment method transformation
**Example (Airwallex):**
```rust
// ❌ WRONG - Missing BankRedirect handler
let payment_method = match item.router_data.request.payment_method_data {
    PaymentMethodData::Card(card_data) => { /* handle card */ },
    _ => { return Err(ConnectorError::NotSupported { /* ... */ }) }
};

// ✅ CORRECT - Add BankRedirect handler
let payment_method = match item.router_data.request.payment_method_data {
    PaymentMethodData::Card(card_data) => { /* handle card */ },
    PaymentMethodData::BankRedirect(bank_redirect_data) => {
        let connector_bank_redirect: ConnectorBankRedirectData = (&bank_redirect_data).try_into()?;
        PaymentMethodType::BankRedirect(connector_bank_redirect)
    },
    _ => { return Err(ConnectorError::NotSupported { /* ... */ }) }
};
```

#### 2. **Missing Status Variants in Enum**
**Issue:** "Failed to deserialize connector response - unknown variant 'STATUS_NAME'" error
**Root Cause:** Connector returns a status not defined in your status enum
**Example (AUTHENTICATION_REDIRECTED):**
```rust
// ❌ WRONG - Missing AUTHENTICATION_REDIRECTED
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaymentStatus {
    RequiresPaymentMethod,
    RequiresCustomerAction,
    // Missing AUTHENTICATION_REDIRECTED!
    Failed,
}

// ✅ CORRECT - Include all possible statuses
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaymentStatus {
    RequiresPaymentMethod,
    RequiresCustomerAction,
    AuthenticationRedirected,  // <-- ADD THIS!
    RequiresCapture,
    Failed,
    // ... add ALL statuses the connector might return
}
```

#### 3. **Special Field Requirements**
**Issue:** Some connectors require specific fields to be set to None or special values
**Root Cause:** Undocumented connector-specific requirements

**Common Patterns:**
```rust
// Airwallex iDEAL - Must ignore bank selection
BankRedirectData::Ideal { .. } => {
    BankRedirect::Ideal(IdealData {
        bank_name: None,  // ✅ ALWAYS None, never send bank_id
        payment_method_type: PaymentType::Ideal,
    })
}

// Stripe - Some methods need expand parameters
PaymentMethodData::Wallet(WalletData::PayPal(_)) => {
    PaymentMethod::PayPal {
        expand: Some(vec!["payment_method".to_string()]),  // Required field
    }
}

// Nordea - Requires complete metadata setup
PaymentMethodData::BankRedirect(BankRedirectData::SepaDebit { iban, .. }) => {
    PaymentMethod::Sepa {
        creditor_account: Some(CreditorAccount {
            iban: connector_config.creditor_iban.clone(),  // Required from config
        }),
        debtor_account: Some(DebtorAccount { iban }),
    }
}
```

### 🚨 General Payment Method Pitfalls

#### 4. **Incomplete Payment Method Support**
**Issue:** Most connectors only support a subset of available payment methods

**The Scale of the Problem:**
- **Wallet**: 70+ variants, most connectors support 3-5
- **BankRedirect**: 19 variants, most support 2-3
- **PayLater/BNPL**: 9 variants, most support 1-2
- **BankDebit**: 6 variants, most support only SEPA

**Solution Strategy:**
1. **Prioritize by Region**: Support payment methods popular in your target markets
2. **Implement Incrementally**: Start with top 5 for each category
3. **Document Gaps**: Clearly list what's not supported in README
4. **Use Descriptive Errors**: Instead of generic "NotImplemented", specify which variant

```rust
// ❌ BAD - Generic error
_ => Err(ConnectorError::NotImplemented("Payment method".to_string()))

// ✅ GOOD - Specific error
PaymentMethodData::Wallet(WalletData::MomoWallet(_)) => {
    Err(ConnectorError::NotSupported {
        message: "MomoWallet is not supported by {Connector}".to_string(),
        connector: "{connector}",
    })
}
```

#### 5. **Exhaustive Pattern Matching Traps**
**Issue:** Rust forces exhaustive patterns, leading to catch-all `_` arms that hide missing variants

**Problem Pattern:**
```rust
// ❌ This hides which specific variant is missing
PaymentMethodData::Wallet(_)
| PaymentMethodData::BankRedirect(_)
| PaymentMethodData::Crypto(_)
| PaymentMethodData::PayLater(_) => {
    // Which variant failed? Find out at runtime!
}
```

**Better Pattern:**
```rust
// ✅ Be explicit about what's implemented
PaymentMethodData::Card(card_data) => { /* implemented */ },
PaymentMethodData::Window => { ... },
// Everything else explicitly unimplemented
payment_method => {
    Err(ConnectorError::NotSupported {
        message: format!("Payment method '{:?}' is not supported", payment_method),
        connector: "{connector}",
    })
}
```

### 🚨 Status Mapping Pitfalls

#### 6. **Missing Status Transitions**
**Issue:** Connector adds new status variants that break deserialization

**Prevention:**
```rust
// ✅ Use #[serde(other)] to handle unknown statuses gracefully
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaymentStatus {
    RequiresPaymentMethod,
    RequiresCustomerAction,
    Succeeded,
    Failed,
    #[serde(other)]
    Unknown,  // Catch-all for new statuses
}

// Then handle Unknown gracefully
fn map_status(status: PaymentStatus) -> AttemptStatus {
    match status {
        PaymentStatus::RequiresPaymentMethod => AttemptStatus::PaymentMethodAwaited,
        PaymentStatus::RequiresCustomerAction => AttemptStatus::AuthenticationPending,
        PaymentStatus::Succeeded => AttemptStatus::Charged,
        PaymentStatus::Failed => AttemptStatus::Failure,
        PaymentStatus::Unknown => AttemptStatus::Pending,  // Safe default
    }
}
```

#### 7. **Flow-Specific Status Requirements**
**Issue:** Different payment flows (Authorize, Capture, Refund) may have different status requirements

**Example:** Some statuses only appear in certain flows:
- `CAPTURE_REQUESTED` appears in Authorize flow
- `REFUND_INITIATED` appears in Refund flow
- `CONFIRMATION_AWAITED` appears in BankDebit flows

### 🚨 Field Mapping Pitfalls

#### 8. **Case Sensitivity Issues**
**Issue:** Connector expects specific case but you send wrong case

**Common Examples:**
```rust
// ❌ Bank names are case-sensitive
BankRedirectData::Ideal { bank_name: Some(BankNames::Ing) } // lowercase "ing"

// ✅ Convert to expected case
IdealData {
    bank_name: bank_name
        .and_then(|name| Some(name.to_lowercase()))  // "ING" -> "ing"
}
```

#### 9. **Required vs Optional Fields**
**Issue:** Some fields are required by connector APIs but optional in our data structures

**Examples:**
- **Nordea**: `creditor.account` and `debtor.account` are mandatory from config
- **Stripe**: `customer` object required for some payment methods
- **Adyen**: `shopperEmail` required for certain flows

#### 10. **Nested Field Flatten Requirements**
**Issue:** Connector expects flattened structure but you send nested (or vice versa)

**Example:**
```rust
// ❌ Nested (incorrect for form-urlencoded)
payment_method_data: {
    "ideal": { "bank": "ing" }
}

// ✅ Flattened (correct for form-urlencoded)
payment_method_data[type]: "ideal",
payment_method_data[ideal][bank]: "ing"
```

### 🚨 Testing Pitfalls

#### 11. **Testing with Production Credentials**
**Issue:** Using live keys leads to real transactions in tests

**Prevention:**
1. Always sandbox credentials in tests
2. Use test card/bank numbers provided by connector
3. Mock responses for status validation
4. Never commit credentials to git

#### 12. **Insufficient Status Testing**
**Issue:** Only testing success path, not failure/edge cases

**Test Checklist:**
- [ ] Success flow with redirect URL
- [ ] User cancellation at bank page
- [ ] Bank decline/insufficient funds
- [ ] Network timeout during redirect
- [ ] Invalid bank selection
- [ ] Missing required fields
- [ ] All supported payment method variants

### 🚨 Integration Pitfalls

#### 13. ** webhook Processing Gaps**
**Issue:** Payment succeeds but webhook processing fails due to missing status handlers

**Prevention:**
```rust
// ✅ Handle webhook events that might arrive before sync
fn process_webhook(event: WebhookEvent) -> Result<WebhookResponse, Error> {
    match event.event_type {
        WebhookEventType::PaymentIntentSucceeded => handle_success(event),
        WebhookEventType::PaymentIntentFailed => handle_failure(event),
        WebhookEventType::PaymentAttemptAuthenticationRedirected => {
            // Special handler for AUTHENTICATION_REDIRECTED webhook
            handle_authentication_redirected(event)
        },
_ => Err(Error::UnknownWebhookType(event.event_type)),
    }
}
```

#### 14. **Configuration Dependencies**
**Issue**: Connector requires configuration values that aren't clearly documented

**Common Config Needs:**
- **Nordea**: `CREDITOR_ACCOUNT`, `DEBTOR_ACCOUNT`
- **Paysafe**: `ACCOUNT_ID`, `CURRENCY`
- **Connect2Pay**: `SECRET_KEY`, `WEBSITE_ID`
- **All connectors**: Base URL, API version, timeout settings

### Summary of Most Critical Issues

| # | Issue | Impact | Frequency |
|---|-------|---------|------------|
| 1 | Missing BankRedirect handler | ❌ Complete failure | High |
| 2 | Missing status variants | ❌ Deserialization error | Medium |
| 3 | Special field requirements | ❌ API rejection | Medium |
| 4 | Incomplete payment method support | ⚠️ Limited functionality | High |
| 5 | Generic error messages | 🔧 Hard to debug | High |

**Key Takeaway**: Most failures occur because connectors require **specific implementation details** that aren't immediately obvious from API documentation. Always check existing implementations for hidden requirements.

## 📋 Appendix: Other Payment Method Critical Patterns

This section briefly covers critical patterns found for other payment methods during hyperswitch analysis. While this guide focuses on BankRedirect, be aware of similar patterns in other payment method categories.

### 🪪 Wallet Payment Methods (70+ variants)

**Critical Issues:**
- Most connectors only support 3-5 out of 70+ wallet variants
- Missing variants cause "Payment method not supported" errors
- Regional preferences vary significantly

**Quick Fix Strategy:**
```rust
// Prioritize by market
const TOP_WALLETS: &[&str] = &[
    "PayPal", "ApplePay", "GooglePay",   // Global
    "Alipay", "WeChatPay",             // China
    "PayPalVenmo", "CashApp",          // US
    "Trace", "MomoWallet",             // Asia
    "Skrill", "Neteller",              // EU
];

// Check connector documentation for supported variants
match &payment_method {
    WalletData::PayPal(data) => handle_paypal(data),
    WalletData::ApplePay(data) => handle_applepay(data),
    // Add only what connector supports
    _ => Err(ConnectorError::NotSupported {
        message: format!("{} is not supported by {} connector",
            wallet_variant_name(wallet), connector_name),
        connector: connector_name,
    })
}
```

### 🏦 BankDebit Payment Methods (6 variants)

**Critical Issues:**
- Most connectors implement only SEPA Direct Debit
- Missing IBAN validation for non-SEPA variants
- Country-specific requirements

**Common Pattern:**
```rust
// Most connectors - only SEPA implemented
BankDebitData::SepaBankDebit { iban, .. } => {
    // Implemented
},

BankDebitData::AchBankDebit { .. }      // US
| BankDebitData::BacsBankDebit { .. }   // UK
| BankDebitData::BecsBankDebit { .. }   // AU
| BankDebitData::SepaGuarenteedBankDebit { .. }
| BankDebitData::InstantBankTransfer { .. } => {
    // Not implemented - market-specific
    Err(ConnectorError::NotSupported { ... })
}
```

### 📅 PayLater/BNPL Payment Methods (9 variants)

**Critical Issues:**
- Irony: Klarna connector doesn't support Klarna BNPL in some implementations
- PayPal-related PayLater variants often missing
- Country-specific BNPL availability

**Quick Pattern:**
```rust
// Most common BNPL implementations
PayLaterData::Klarna(data) => handle_klarna(data),
PayLaterData::Afterpay(data) => handle_afterpay(data),
PayLaterData::Affirm(data) => handle_affirm(data),

// Often missing
PayLaterData::PayPalPayLater(_)      // PayPal BNPL
| PayLaterData::PayPalCredit(_)      // PayPal credit
| PayLaterData::Klarna(_)           // Some Klarna implementations
| PayLaterData::Walley(_)
| PayLaterData::Atome(_) => {
    Err(ConnectorError::NotSupported { ... })
}
```

### 💳 Card Payment Methods (3 main + variants)

**Critical Issues:**
- CardDetails vs CardRedirect vs CardDetailsForNetworkTransactionId
- Some connectors only handle standard card tokenization
- Network token support varies

**Pattern to Avoid:**
```rust
// ❌ Don't group all card types unless truly supported
PaymentMethodData::Card(_)
| PaymentMethodData::CardRedirect(_)
| PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
    // This hides specific card requirements
}
```

**Better Pattern:**
```rust
// ✅ Handle explicitly or reject clearly
PaymentMethodData::Card(card) => handle_card(card),
PaymentMethodData::CardRedirect(redirect) => handle_card_redirect(redirect),
PaymentMethodData::CardDetailsForNetworkTransactionId(network) => {
    // Many connectors don't support network tokens
    Err(ConnectorError::NotSupported {
        message: "Network tokens not supported",
        connector: connector_name,
    })
}
```

### 🎯 Key Implementation Strategy

When implementing ANY payment method:

1. **Start with Market Needs**:
   - Europe: SEPA, iDEAL, Giropay, Sofort
   - UK: BACS, FasterPayments
   - US: ACH, Venmo, CashApp
   - Asia: Alipay, WeChatPay, PromptPay, GrabPay

2. **Progressive Implementation**:
   ```rust
   // Phase 1: Core methods
   PaymentMethodData::Card(card) => implemented,
   PaymentMethodData::BankRedirect(Ideal) => implemented,

   // Phase 2: Market expansion
   PaymentMethodData::Wallet(ApplePay) => implemented,
   PaymentMethodData::Wallet(WeChatPay) => placeholder,

   // Phase 3: Full support
   // Add all remaining methods
   ```

3. **Always Document Gaps**:
   ```markdown
   # Supported Payment Methods

   ✅ Fully Supported:
   - Card (Credit/Debit)
   - iDEAL (NL)
   - PayPal (Global)

   🚧 Partially Supported:
   - ApplePay (iOS only)
   - GooglePay (Android only)

   ❌ Not Supported:
   - All other BankRedirect variants
   - Crypto payments
   - BNPL methods
   ```

### 💡 Remember: The `bank_name: None` Pattern

The iDEAL `bank_name: None` requirement in Airwallex is just one example of many undocumented requirements found across connectors. Always:

1. **Check hyperswitch implementation** for the same connector
2. **Look for special field handling** in existing connectors
3. **Test with different bank variants** even if you think None is correct
4. **Document ALL special requirements** in your connector README

## Integration Checklist

### Pre-Implementation Checklist

- [ ] **API Documentation Review**
  - [ ] Identify supported bank redirect types (iDEAL, Giropay, etc.)
  - [ ] Review authentication requirements
  - [ ] Understand redirect flow (URI, Form POST, HTML)
  - [ ] Document callback URL requirements
  - [ ] Identify required customer fields
  - [ ] Review status codes and flow states

- [ ] **Bank Redirect Specifics**
  - [ ] Determine which redirect types are supported
  - [ ] Identify bank selection requirements (BIC, custom codes, none)
  - [ ] Review redirect response format
  - [ ] Understand callback mechanism
  - [ ] Check for special fields (BLIK code, country, etc.)

### Implementation Checklist

- [ ] **Main Connector File**
  - [ ] Add BankRedirect payment method support to trait implementations
  - [ ] Configure macro with appropriate amount converter
  - [ ] Implement authorize flow for redirects
  - [ ] Add PSync implementation for status checks

- [ ] **Transformers File - Request**
  - [ ] Create BankRedirect request structures
  - [ ] Implement payment method mapping from `BankRedirectData`
  - [ ] **CRITICAL: Add BankRedirect match arm in payment request transformation** (like Airwallex example)
  - [ ] Add bank selection logic (if applicable)
  - [ ] Build callback URL structures
  - [ ] Extract customer/debtor information
  - [ ] Implement request transformation with proper error handling

- [ ] **Transformers File - Response**
  - [ ] Create response structures
  - [ ] **CRITICAL: Include AUTHENTICATION_REDIRECTED in status enum**
  - [ ] Implement redirect URL extraction
  - [ ] Build RedirectForm (URI, Form, or HTML)
  - [ ] Map connector statuses to router statuses
  - [ ] Handle AuthenticationPending status correctly
  - [ ] Implement error response handling

- [ ] **Bank Selection (if applicable)**
  - [ ] Create bank code/BIC enum
  - [ ] Implement bank name to code mapping
  - [ ] Add validation for unsupported banks
  - [ ] Handle optional bank selection correctly

### Testing Checklist

- [ ] **Unit Tests**
  - [ ] Test each bank redirect type transformation
  - [ ] Test bank selection mapping (if applicable)
  - [ ] Test callback URL generation
  - [ ] Test status mapping for all states
  - [ ] Test error handling for unsupported types
  - [ ] Test customer information extraction

- [ ] **Integration Tests**
  - [ ] Test complete authorize flow with redirect
  - [ ] Test redirect URL extraction
  - [ ] Test callback handling
  - [ ] Test PSync after redirect
  - [ ] Test different bank redirect types
  - [ ] Test error scenarios

### Validation Checklist

- [ ] **Functionality**
  - [ ] Authorize creates proper redirect response
  - [ ] Redirect URL is correctly formatted
  - [ ] Callback URLs are properly constructed
  - [ ] Status mapping works for all states
  - [ ] PSync retrieves updated status
  - [ ] Error handling works correctly

- [ ] **Data Integrity**
  - [ ] Customer information properly extracted
  - [ ] Bank selection correctly passed (if applicable)
  - [ ] Amount and currency correct
  - [ ] Transaction references maintained
  - [ ] Billing details included when required

### Pattern 3: Complete BankRedirect Implementation Example (Airwallex-style)

For connectors using the newer unified response structure with separate payment attempt tracking:

```rust
// ===== PAYMENT STATUS ENUM =====
// Important: Include all statuses returned by the connector, including AUTHENTICATION_REDIRECTED
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AirwallexPaymentStatus {
    RequiresPaymentMethod,
    RequiresCustomerAction,
    RequiresCapture,
    Authorized,
    Paid,
    CaptureRequested,
    Processing,
    Succeeded,
    Settled,
    Cancelled,
    Failed,
    AuthenticationRedirected,  // <-- CRITICAL: Handle this status explicitly
}

// ===== STATUS MAPPING FUNCTION =====
fn get_payment_status(
    status: &AirwallexPaymentStatus,
    next_action: &Option<AirwallexNextAction>,
) -> AttemptStatus {
    match status {
        // ... other status mappings ...
        AirwallexPaymentStatus::AuthenticationRedirected => {
            // This status indicates the payment is ready for user authentication/redirect
            AttemptStatus::AuthenticationPending
        }
        // ... rest of mappings ...
    }
}

// ===== BANKREDIRECT HANDLER IN REQUEST TRANSFORMATION =====
// Important: Add BankRedirect handling in payment request
impl<T> TryFrom<&PaymentMethodData<T>> for AirwallexPaymentMethod {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(pm_data: &PaymentMethodData<T>) -> Result<Self, Self::Error> {
        match pm_data {
            PaymentMethodData::Card(card_data) => {
                // Handle card payments
            },
            PaymentMethodData::BankRedirect(bank_redirect_data) => {
                // CRITICAL: Handle BankRedirect - without this, you'll get "Payment Method not supported"
                let airwallex_bank_redirect: AirwallexBankRedirectData = (&bank_redirect_data).try_into()?;
                AirwallexPaymentMethod::BankRedirect(airwallex_bank_redirect)
            },
            _ => return Err(ConnectorError::NotSupported {
                message: "Payment Method".to_string(),
                connector: "Airwallex",
            }.into()),
        }
    }
}

// ===== BANKREDIRECT DATA TRANSFORMATION IGNORES bank_id =====
// For connectors like Airwallex that don't use/accept bank selection
impl TryFrom<&BankRedirectData> for AirwallexBankRedirectData {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(bank_redirect: &BankRedirectData) -> Result<Self, Self::Error> {
        match bank_redirect {
            BankRedirectData::Ideal { .. } => {
                // Note: Airwallex ignores bank_name - always use None
                Ok(AirwallexBankRedirectData::Ideal(IdealData {
                    ideal: IdealDetails { bank_name: None },  // Important: Don't send bank_id
                    payment_method_type: AirwallexPaymentType::Ideal,
                }))
            },
            // ... handle other bank redirect types ...
        }
    }
}
```

## Real-World Examples

### Example 1: Modern JSON API (Trustpay-style)

```rust
// Supports: iDEAL, Giropay, Sofort
// Format: JSON
// Callback: Success/Cancel/Error with query params

PaymentRequestBankRedirect {
    payment_method: PaymentMethod::Ideal,
    merchant_identification: MerchantIdentification {
        project_id: "project_123",
    },
    payment_information: PaymentInformation {
        amount: Amount {
            amount: "10.00",
            currency: "EUR",
        },
        references: References {
            merchant_reference: "order_456",
        },
        debtor: DebtorInfo {
            email: "customer@example.com",
            name: "John Doe",
        },
    },
    callback_urls: CallbackUrls {
        success: "https://merchant.com/return?status=SuccessOk",
        cancel: "https://merchant.com/return",
        error: "https://merchant.com/return",
    },
}
```

### Example 2: Form-Encoded API (Stripe-style)

```rust
// Supports: iDEAL, Giropay, EPS, Bancontact, etc.
// Format: Form-urlencoded
// Callback: Single return URL

StripePaymentIntent {
    amount: "1000",  // cents
    currency: "eur",
    payment_method_data[type]: "ideal",
    payment_method_data[ideal][bank]: "ing",
    return_url: "https://merchant.com/return",
    billing_details[email]: "customer@example.com",
    billing_details[name]: "John Doe",
}
```

### Example 3: OpenBanking Specialist (Volt-style)

```rust
// Supports: OpenBanking UK
// Format: JSON
// Callback: Four separate URLs

VoltPaymentRequest {
    amount: 1000,  // Minor units
    currency_code: "GBP",
    type: "SERVICES",
    merchant_internal_reference: "order_789",
    shopper: ShopperDetails {
        reference: "customer_123",
        email: "customer@example.com",
        first_name: "John",
        last_name: "Doe",
    },
    payment_success_url: "https://merchant.com/return",
    payment_failure_url: "https://merchant.com/return",
    payment_pending_url: "https://merchant.com/return",
    payment_cancel_url: "https://merchant.com/return",
}
```

## Best Practices

1. **Always Extract Return URL Early**: Get `router_return_url` at the start of transformation
2. **Use AuthenticationPending Status**: BankRedirect flows should initially return `AuthenticationPending`
3. **Handle Optional Bank Selection**: Many methods don't require bank selection - make it optional
4. **Validate Supported Types**: Explicitly list supported redirect types and return `NotImplemented` for others
5. **Extract Customer Info Safely**: Use helper functions with proper error handling for missing data
6. **Build Callback URLs Consistently**: Follow connector's required pattern (query params, multiple URLs, etc.)
7. **Map Status Carefully**: Understand connector's status flow and map appropriately
8. **Test All Redirect Types**: Each bank redirect type may have subtle differences
9. **Document Bank Codes**: Clearly document bank code mappings and supported banks
10. **Implement PSync**: BankRedirect flows require PSync for status verification after redirect
11. **Handle AUTHENTICATION_REDIRECTED Status**: Some connectors like Airwallex return `AUTHENTICATION_REDIRECTED` as a distinct status - ensure your status enum includes this variant

## Placeholder Reference Guide

| Placeholder | Description | Example Values |
|-------------|-------------|----------------|
| `{ConnectorName}` | PascalCase connector name | `Trustpay`, `MyBank`, `IdealPayments` |
| `{connector_name}` | snake_case connector name | `trustpay`, `my_bank`, `ideal_payments` |
| `{BankType}` | Redirect type enum variant | `Ideal`, `Giropay`, `Sofort` |
| `CallbackPattern` | URL structure pattern | `StatusQueryParams`, `MultipleDedicated`, `Simple` |

## Summary

BankRedirect flows require careful handling of:

1. **Payment Method Mapping**: Transform from router's unified `BankRedirectData` to connector-specific format
2. **Callback URLs**: Configure appropriate success/cancel/error URLs
3. **Bank Selection**: Handle optional bank identifiers when required
4. **Redirect Handling**: Extract redirect URL and build proper `RedirectForm`
5. **Status Management**: Use `AuthenticationPending` for initial state, update via PSync/webhook
6. **Customer Data**: Extract and format customer information as required
7. **Error Handling**: Gracefully handle unsupported redirect types

By following these patterns, you can implement robust BankRedirect support for any connector that supports redirect-based bank payment methods.
